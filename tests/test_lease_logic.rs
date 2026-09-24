//! Regression tests for the lease-management logic in `examples/server.rs`.
//!
//! The example server is not a library, so its `available` / `current_lease`
//! helpers are copied here verbatim (same constants, same expressions) to
//! lock their exact current behavior, including quirks:
//! - usable pool is `[IP_START_NUM, IP_START_NUM+LEASE_NUM)` (exclusive upper)
//! - infinite leases (`None` expiry, from the `leases` file) are reported as
//!   `available` to *any* MAC (map_or(true)) — i.e. stealable (bug locked)
//! - expired leases are reusable; unexpired leases owned by another MAC block
//! - `current_lease` returns *some* IP for a MAC when present (HashMap order
//!   means which one is unspecified when a MAC holds several)

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// --- copied constants from examples/server.rs ---
const IP_START: [u8; 4] = [192, 168, 2, 2];
const LEASE_NUM: u32 = 252;
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);

// --- copied helpers from examples/server.rs (renamed, same bodies) ---
fn available(
    leases: &HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
    chaddr: &[u8; 6],
    addr: &Ipv4Addr,
) -> bool {
    let pos: u32 = (*addr).into();
    pos >= IP_START_NUM
        && pos < IP_START_NUM + LEASE_NUM
        && match leases.get(addr) {
            Some((mac, expiry)) => {
                *mac == *chaddr || expiry.map_or(true, |exp| Instant::now().gt(&exp))
            }
            None => true,
        }
}

fn current_lease(
    leases: &HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
    chaddr: &[u8; 6],
) -> Option<Ipv4Addr> {
    for (i, v) in leases {
        if v.0 == *chaddr {
            return Some(*i);
        }
    }
    None
}

fn parse_leases_line(line: &str) -> Option<([u8; 6], Ipv4Addr)> {
    // Mirrors the parsing loop in examples/server.rs main().
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() != 2 {
        return None;
    }
    let mac_parts: Vec<u8> = parts[0]
        .split(':')
        .filter_map(|part| u8::from_str_radix(part, 16).ok())
        .collect();
    if mac_parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&mac_parts);
    let ip = parts[1].trim().parse::<Ipv4Addr>().ok()?;
    Some((mac, ip))
}

#[test]
fn pool_boundaries_are_exact() {
    let leases = HashMap::new();
    let mac = [1, 2, 3, 4, 5, 6];
    assert!(available(&leases, &mac, &Ipv4Addr::new(192, 168, 2, 2)), "first IP usable");
    assert!(available(&leases, &mac, &Ipv4Addr::new(192, 168, 2, 253)), "last IP (.2+251) usable");
    assert!(!available(&leases, &mac, &Ipv4Addr::new(192, 168, 2, 254)), "exclusive upper bound");
    assert!(!available(&leases, &mac, &Ipv4Addr::new(192, 168, 2, 1)), "server IP below pool");
    assert!(!available(&leases, &mac, &Ipv4Addr::new(192, 168, 2, 255)), "broadcast above pool");
    assert!(!available(&leases, &mac, &Ipv4Addr::new(192, 168, 3, 2)), "next subnet blocked");
    assert!(!available(&leases, &mac, &Ipv4Addr::new(10, 0, 0, 5)), "other subnet blocked");
}

#[test]
fn unleased_ip_in_pool_is_available() {
    let leases = HashMap::new();
    assert!(available(&leases, &[9, 9, 9, 9, 9, 9], &Ipv4Addr::new(192, 168, 2, 100)));
}

#[test]
fn own_lease_is_available_even_if_unexpired() {
    let mac = [1, 2, 3, 4, 5, 6];
    let mut leases = HashMap::new();
    leases.insert(
        Ipv4Addr::new(192, 168, 2, 10),
        (mac, Some(Instant::now() + Duration::from_secs(3600))),
    );
    assert!(available(&leases, &mac, &Ipv4Addr::new(192, 168, 2, 10)));
}

#[test]
fn others_unexpired_lease_blocks() {
    let mut leases = HashMap::new();
    leases.insert(
        Ipv4Addr::new(192, 168, 2, 10),
        ([1, 1, 1, 1, 1, 1], Some(Instant::now() + Duration::from_secs(3600))),
    );
    assert!(!available(&leases, &[2, 2, 2, 2, 2, 2], &Ipv4Addr::new(192, 168, 2, 10)));
}

#[test]
fn expired_lease_is_reusable_quirk() {
    let mut leases = HashMap::new();
    leases.insert(
        Ipv4Addr::new(192, 168, 2, 10),
        (
            [1, 1, 1, 1, 1, 1],
            Some(Instant::now() - Duration::from_secs(1)),
        ),
    );
    assert!(available(&leases, &[2, 2, 2, 2, 2, 2], &Ipv4Addr::new(192, 168, 2, 10)));
}

#[test]
fn infinite_lease_is_reported_available_to_anyone_quirk() {
    // Leases loaded from the `leases` file use None expiry (INFINITE_LEASE).
    // map_or(true, ..) makes them look available even to a different MAC.
    let mut leases = HashMap::new();
    leases.insert(Ipv4Addr::new(192, 168, 2, 90), ([0xF4, 0x5C, 0x19, 0xAF, 0x96, 0x8D], None));
    assert!(available(
        &leases,
        &[0xF4, 0x5C, 0x19, 0xAF, 0x96, 0x8D],
        &Ipv4Addr::new(192, 168, 2, 90)
    ));
    assert!(
        available(&leases, &[1, 2, 3, 4, 5, 6], &Ipv4Addr::new(192, 168, 2, 90)),
        "infinite lease stealable (bug locked)"
    );
}

#[test]
fn out_of_pool_never_available_even_if_unleased() {
    let leases = HashMap::new();
    assert!(!available(&leases, &[1, 2, 3, 4, 5, 6], &Ipv4Addr::new(192, 168, 2, 1)));
}

#[test]
fn current_lease_finds_mac() {
    let mac_a = [1, 2, 3, 4, 5, 6];
    let mac_b = [9, 9, 9, 9, 9, 9];
    let mut leases = HashMap::new();
    leases.insert(Ipv4Addr::new(192, 168, 2, 10), (mac_a, None));
    leases.insert(Ipv4Addr::new(192, 168, 2, 11), (mac_b, None));
    assert_eq!(current_lease(&leases, &mac_a), Some(Ipv4Addr::new(192, 168, 2, 10)));
    assert_eq!(current_lease(&leases, &mac_b), Some(Ipv4Addr::new(192, 168, 2, 11)));
    assert_eq!(current_lease(&leases, &[0, 0, 0, 0, 0, 0]), None);
}

#[test]
fn current_lease_empty_is_none() {
    let leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)> = HashMap::new();
    assert_eq!(current_lease(&leases, &[1, 2, 3, 4, 5, 6]), None);
}

#[test]
fn leases_file_line_parsing_matches_example() {
    // Example from README
    let (mac, ip) = parse_leases_line("f4:5c:19:af:96:8d,192.168.2.90").unwrap();
    assert_eq!(mac, [0xF4, 0x5C, 0x19, 0xAF, 0x96, 0x8D]);
    assert_eq!(ip, Ipv4Addr::new(192, 168, 2, 90));

    // whitespace around IP trimmed
    let (_, ip) = parse_leases_line("aa:bb:cc:dd:ee:ff, 192.168.2.10 ").unwrap();
    assert_eq!(ip, Ipv4Addr::new(192, 168, 2, 10));

    // malformed MAC -> None (filtered, line skipped)
    assert!(parse_leases_line("zz:zz:zz:zz:zz:zz,192.168.2.10").is_none());
    assert!(parse_leases_line("aa:bb:cc,192.168.2.10").is_none());
    // wrong field count -> None
    assert!(parse_leases_line("justonefield").is_none());
    assert!(parse_leases_line("a,b,c").is_none());
    // bad IP -> None (example would unwrap+panic; helper returns None to avoid panic in tests)
    assert!(parse_leases_line("aa:bb:cc:dd:ee:ff,not-an-ip").is_none());
}
