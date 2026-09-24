//! Extra example coverage: `chaddr` formatting and the full
//! `src/main.rs` MyServer state machine (Discover / Request /
//! Release / Decline), including the Request-not-gated vs Release-gated quirk.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// monitor::chaddr copy (examples/monitor.rs)
// ---------------------------------------------------------------------------

fn chaddr(a: &[u8]) -> String {
    a[1..].iter().fold(format!("{:02x}", a[0]), |acc, &b| {
        format!("{}:{:02x}", acc, &b)
    })
}

#[test]
fn chaddr_formats_six_byte_mac_lowercase_colon() {
    assert_eq!(chaddr(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]), "aa:bb:cc:dd:ee:ff");
    assert_eq!(chaddr(&[0xF4, 0x5C, 0x19, 0xAF, 0x96, 0x8D]), "f4:5c:19:af:96:8d");
}

#[test]
fn chaddr_pads_single_nibbles_with_zero() {
    assert_eq!(chaddr(&[1, 2, 3]), "01:02:03");
    assert_eq!(chaddr(&[0, 0, 0, 0, 0, 0]), "00:00:00:00:00:00");
    assert_eq!(chaddr(&[255, 255]), "ff:ff");
}

#[test]
fn chaddr_single_byte_has_no_colon() {
    assert_eq!(chaddr(&[0xAB]), "ab");
    assert_eq!(chaddr(&[0]), "00");
}

#[test]
#[should_panic]
fn chaddr_empty_panics_quirk() {
    let _ = chaddr(&[]);
}

// ---------------------------------------------------------------------------
// examples/server.rs constants locked numerically
// ---------------------------------------------------------------------------

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 2, 1);
const IP_START: [u8; 4] = [192, 168, 2, 2];
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);
const LEASE_NUM: u32 = 252;
const LEASE_DURATION_SECS: u32 = 86400;

#[test]
fn example_constants_are_exact() {
    assert_eq!(SERVER_IP, Ipv4Addr::new(192, 168, 2, 1));
    assert_eq!(IP_START_NUM, 0xC0A8_0202);
    assert_eq!(IP_START_NUM, 3232236034);
    assert_eq!(LEASE_NUM, 252);
    assert_eq!(LEASE_DURATION_SECS, 86400);
    assert_eq!(Ipv4Addr::from(IP_START_NUM), Ipv4Addr::new(192, 168, 2, 2));
    assert_eq!(
        Ipv4Addr::from(IP_START_NUM + LEASE_NUM - 1),
        Ipv4Addr::new(192, 168, 2, 253),
        "last usable IP"
    );
}

// ---------------------------------------------------------------------------
// MyServer replica (same fields, same method bodies as examples/server.rs)
// ---------------------------------------------------------------------------

struct Replica {
    leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
    last_lease: u32,
    lease_duration: Duration,
}

impl Replica {
    fn new() -> Self {
        Self {
            leases: HashMap::new(),
            last_lease: 0,
            lease_duration: Duration::new(LEASE_DURATION_SECS as u64, 0),
        }
    }
    fn available(&self, chaddr: &[u8; 6], addr: &Ipv4Addr) -> bool {
        let pos: u32 = (*addr).into();
        pos >= IP_START_NUM
            && pos < IP_START_NUM + LEASE_NUM
            && match self.leases.get(addr) {
                Some((mac, expiry)) => {
                    *mac == *chaddr || expiry.map_or(true, |exp| Instant::now().gt(&exp))
                }
                None => true,
            }
    }
    fn current_lease(&self, chaddr: &[u8; 6]) -> Option<Ipv4Addr> {
        for (i, v) in &self.leases {
            if v.0 == *chaddr {
                return Some(*i);
            }
        }
        None
    }
    /// Mirrors Discover branch: returns offered IP (no insert).
    fn discover(&mut self, chaddr: &[u8; 6]) -> Option<Ipv4Addr> {
        if let Some(ip) = self.current_lease(chaddr) {
            return Some(ip);
        }
        for _ in 0..LEASE_NUM {
            self.last_lease = (self.last_lease + 1) % LEASE_NUM;
            let cand: Ipv4Addr = (IP_START_NUM + self.last_lease).into();
            if self.available(chaddr, &cand) {
                return Some(cand);
            }
        }
        None
    }
    /// Mirrors Request branch. `for_this` is computed by caller but IGNORED
    /// (the `if !for_this { return; }` is commented out in the example).
    /// Returns Ack(ip) or Nak.
    fn request(
        &mut self,
        chaddr: &[u8; 6],
        requested: Option<Ipv4Addr>,
        ciaddr: Ipv4Addr,
        _for_this: bool,
    ) -> Result<Ipv4Addr, &'static str> {
        let req_ip = requested.unwrap_or(ciaddr);
        if let Some(ip) = self.current_lease(chaddr) {
            return Ok(ip);
        }
        if !self.available(chaddr, &req_ip) {
            return Err("Requested IP not available");
        }
        self.leases.insert(
            req_ip,
            (chaddr.to_owned(), Some(Instant::now().add(self.lease_duration))),
        );
        Ok(req_ip)
    }
    /// Mirrors Release/Decline branch: gated on for_this_server.
    /// Returns true if a lease was removed.
    fn release(&mut self, chaddr: &[u8; 6], for_this: bool) -> bool {
        if !for_this {
            return false;
        }
        if let Some(ip) = self.current_lease(chaddr) {
            self.leases.remove(&ip);
            return true;
        }
        false
    }
}

#[test]
fn discover_prefers_existing_even_if_expired() {
    let mut s = Replica::new();
    let mac = [1, 2, 3, 4, 5, 6];
    // expired lease still returned (current_lease ignores expiry)
    s.leases.insert(
        Ipv4Addr::new(192, 168, 2, 50),
        (mac, Some(Instant::now() - Duration::from_secs(10))),
    );
    assert_eq!(s.discover(&mac), Some(Ipv4Addr::new(192, 168, 2, 50)));
    assert_eq!(s.last_lease, 0, "existing path must not bump last_lease");
}

#[test]
fn discover_prefers_infinite_lease() {
    let mut s = Replica::new();
    let mac = [0xF4, 0x5C, 0x19, 0xAF, 0x96, 0x8D];
    s.leases.insert(Ipv4Addr::new(192, 168, 2, 90), (mac, None));
    assert_eq!(s.discover(&mac), Some(Ipv4Addr::new(192, 168, 2, 90)));
}

#[test]
fn discover_round_robin_increments_and_wraps() {
    let mut s = Replica::new();
    let mac = [9, 9, 9, 9, 9, 9];
    // last_lease 0 -> first offer .3 (0+1), then .4, ...
    assert_eq!(s.discover(&mac), Some(Ipv4Addr::new(192, 168, 2, 3)));
    assert_eq!(s.last_lease, 1);
    // occupy .4 with another MAC so it is skipped
    s.leases.insert(
        Ipv4Addr::new(192, 168, 2, 4),
        ([8, 8, 8, 8, 8, 8], Some(Instant::now() + Duration::from_secs(3600))),
    );
    assert_eq!(s.discover(&mac), Some(Ipv4Addr::new(192, 168, 2, 5)));
    // wrap: set to last index, next is 0 -> IP_START (.2). Use fresh MAC with no lease.
    s.last_lease = LEASE_NUM - 1;
    let mac2 = [7, 7, 7, 7, 7, 7];
    assert_eq!(s.discover(&mac2), Some(Ipv4Addr::new(192, 168, 2, 2)));
    assert_eq!(s.last_lease, 0);
}

#[test]
fn discover_returns_none_when_pool_full() {
    let mut s = Replica::new();
    // fill entire pool with other MACs, unexpired
    for i in 0..LEASE_NUM {
        let ip: Ipv4Addr = (IP_START_NUM + i).into();
        s.leases.insert(
            ip,
            ([8, 8, 8, 8, 8, 8], Some(Instant::now() + Duration::from_secs(3600))),
        );
    }
    // infinite leases are stealable per available() quirk, so use unexpired
    // timed leases above to truly fill. New MAC gets None.
    assert_eq!(s.discover(&[1, 2, 3, 4, 5, 6]), None);
}

#[test]
fn request_prefers_current_lease_without_insert_or_renew_quirk() {
    let mut s = Replica::new();
    let mac = [1, 2, 3, 4, 5, 6];
    let before = Instant::now() + Duration::from_secs(3600);
    s.leases.insert(Ipv4Addr::new(192, 168, 2, 20), (mac, Some(before)));
    let n_before = s.leases.len();
    // request different IP, but current_lease wins and no insert happens
    let res = s.request(&mac, Some(Ipv4Addr::new(192, 168, 2, 99)), Ipv4Addr::new(0, 0, 0, 0), true);
    assert_eq!(res, Ok(Ipv4Addr::new(192, 168, 2, 20)));
    assert_eq!(s.leases.len(), n_before, "no new insert on current_lease path");
    assert!(!s.leases.contains_key(&Ipv4Addr::new(192, 168, 2, 99)));
}

#[test]
fn request_inserts_with_future_expiry_and_acks() {
    let mut s = Replica::new();
    let mac = [2, 2, 2, 2, 2, 2];
    let before = Instant::now();
    let res = s.request(&mac, Some(Ipv4Addr::new(192, 168, 2, 60)), Ipv4Addr::new(0, 0, 0, 0), true);
    assert_eq!(res, Ok(Ipv4Addr::new(192, 168, 2, 60)));
    let (_, expiry) = s.leases.get(&Ipv4Addr::new(192, 168, 2, 60)).unwrap();
    let exp = expiry.expect("new lease must have Some expiry");
    assert!(exp > before, "expiry must be in the future");
    assert!(exp <= Instant::now().add(s.lease_duration + Duration::from_secs(5)));
}

#[test]
fn request_uses_ciaddr_when_no_requested_ip() {
    let mut s = Replica::new();
    let mac = [3, 3, 3, 3, 3, 3];
    let res = s.request(&mac, None, Ipv4Addr::new(192, 168, 2, 70), true);
    assert_eq!(res, Ok(Ipv4Addr::new(192, 168, 2, 70)));
    assert!(s.leases.contains_key(&Ipv4Addr::new(192, 168, 2, 70)));
}

#[test]
fn request_naks_when_unavailable() {
    let mut s = Replica::new();
    s.leases.insert(
        Ipv4Addr::new(192, 168, 2, 80),
        ([8, 8, 8, 8, 8, 8], Some(Instant::now() + Duration::from_secs(3600))),
    );
    let res = s.request(&[1, 2, 3, 4, 5, 6], Some(Ipv4Addr::new(192, 168, 2, 80)), Ipv4Addr::new(0, 0, 0, 0), true);
    assert_eq!(res, Err("Requested IP not available"));
    // out-of-pool also Naks
    let res = s.request(&[1, 2, 3, 4, 5, 6], Some(Ipv4Addr::new(10, 0, 0, 5)), Ipv4Addr::new(0, 0, 0, 0), true);
    assert!(res.is_err());
}

#[test]
fn request_ignores_for_this_server_quirk() {
    // In examples/server.rs the Request gate is commented out, so even
    // for_this==false still processes (unlike Release).
    let mut s = Replica::new();
    let mac = [4, 4, 4, 4, 4, 4];
    let res = s.request(&mac, Some(Ipv4Addr::new(192, 168, 2, 61)), Ipv4Addr::new(0, 0, 0, 0), false);
    assert_eq!(res, Ok(Ipv4Addr::new(192, 168, 2, 61)), "Request must proceed even when not for this server");
}

#[test]
fn release_gated_on_for_this_server_and_removes() {
    let mut s = Replica::new();
    let mac = [5, 5, 5, 5, 5, 5];
    s.leases.insert(Ipv4Addr::new(192, 168, 2, 62), (mac, Some(Instant::now() + Duration::from_secs(100))));
    // not for this server -> no removal
    assert!(!s.release(&mac, false));
    assert!(s.leases.contains_key(&Ipv4Addr::new(192, 168, 2, 62)));
    // for this server -> removed
    assert!(s.release(&mac, true));
    assert!(!s.leases.contains_key(&Ipv4Addr::new(192, 168, 2, 62)));
    // no lease -> false
    assert!(!s.release(&mac, true));
}

#[test]
fn current_lease_with_two_ips_returns_one_of_them() {
    let mut s = Replica::new();
    let mac = [6, 6, 6, 6, 6, 6];
    s.leases.insert(Ipv4Addr::new(192, 168, 2, 30), (mac, None));
    s.leases.insert(Ipv4Addr::new(192, 168, 2, 31), (mac, None));
    let got = s.current_lease(&mac).expect("must find one");
    assert!(
        got == Ipv4Addr::new(192, 168, 2, 30) || got == Ipv4Addr::new(192, 168, 2, 31),
        "got {:?}",
        got
    );
}

#[test]
fn leases_line_uppercase_and_single_digit_parse() {
    // from_str_radix is case-insensitive and accepts single digits
    let parse = |line: &str| {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() != 2 {
            return None;
        }
        let mac_parts: Vec<u8> = parts[0]
            .split(':')
            .filter_map(|p| u8::from_str_radix(p, 16).ok())
            .collect();
        if mac_parts.len() != 6 {
            return None;
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&mac_parts);
        let ip = parts[1].trim().parse::<Ipv4Addr>().ok()?;
        Some((mac, ip))
    };
    let (mac, _) = parse("F4:5C:19:AF:96:8D,192.168.2.90").unwrap();
    assert_eq!(mac, [0xF4, 0x5C, 0x19, 0xAF, 0x96, 0x8D]);
    let (mac, _) = parse("1:2:3:4:5:6,192.168.2.10").unwrap();
    assert_eq!(mac, [1, 2, 3, 4, 5, 6]);
    assert!(parse("aa:bb:cc:dd:ee:ff:00,192.168.2.10").is_none(), "7 octets rejected");
    assert!(parse("").is_none());
    // trim() strips trailing newline, so an explicit \n still parses
    assert!(parse("aa:bb:cc:dd:ee:ff,192.168.2.10\n").is_some());
}
