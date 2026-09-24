//! DHCP security gaps, part 2.
//!
//! Covers security-relevant behavior NOT locked by `test_security.rs` or the
//! RFC suites, so refactors cannot silently change attacker-visible handling:
//!
//! - wire-length lies (declared `len` past end of datagram) are swallowed,
//!   keeping the prefix — no panic, but trailing options are lost
//! - all-zero option area (no END) panics the decoder thread (DoS primitive)
//! - a lone oversized option yields a bare END-only packet, never corrupt framing
//! - example handler blind spots: INFORM and forged Offer get no reply
//! - NAK wire shape: exact message text, zeroed addrs, Server ID present
//! - Router present on the wire but dropped on decode (both quirks compound)
//! - Request precedence: Requested IP beats `ciaddr`; bare Requests NAK cleanly
//! - config trust: out-of-pool reservations offered verbatim, duplicate file
//!   lines last-win, sloppy MAC lines silently skipped
//! - wire lease time ignored: server always sends its fixed duration
//!
//! `*_quirk` tests lock currently-unsafe behavior for review, not approval.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::ops::Add;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// helpers (same patterns as test_security.rs)
// ---------------------------------------------------------------------------

fn unwrap_packet(r: Result<Packet, CustomErr<&[u8]>>) -> Packet {
    match r {
        Ok(p) => p,
        Err(_) => panic!("expected Ok Packet"),
    }
}

fn test_packet(xid: u32, chaddr: [u8; 6], opts: Vec<DhcpOption>) -> Packet {
    Packet {
        reply: false,
        hops: 0,
        xid,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr,
        options: opts,
    }
}

fn make_raw(
    op: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: [u8; 2],
    ci: [u8; 4],
    yi: [u8; 4],
    si: [u8; 4],
    gi: [u8; 4],
    chaddr: [u8; 6],
    opts_after_cookie: Vec<u8>,
) -> Vec<u8> {
    let mut v = vec![0u8; 236];
    v[0] = op;
    v[1] = 1;
    v[2] = hlen;
    v[3] = hops;
    v[4..8].copy_from_slice(&xid.to_be_bytes());
    v[8..10].copy_from_slice(&secs.to_be_bytes());
    v[10] = flags[0];
    v[11] = flags[1];
    v[12..16].copy_from_slice(&ci);
    v[16..20].copy_from_slice(&yi);
    v[20..24].copy_from_slice(&si);
    v[24..28].copy_from_slice(&gi);
    v[28..34].copy_from_slice(&chaddr);
    v.extend_from_slice(&[99, 130, 83, 99]);
    v.extend_from_slice(&opts_after_cookie);
    v
}

// Replica of examples/server.rs lease state (bodies identical).
const IP_START: [u8; 4] = [192, 168, 2, 2];
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);
const LEASE_NUM: u32 = 252;
const LEASE_DURATION_SECS: u32 = 86400;

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
    #[allow(dead_code)]
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

// Lenient leases-line parser (same shape as test_lease_logic helper).
fn parse_leases_line(line: &str) -> Option<([u8; 6], Ipv4Addr)> {
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

// Example-like handler: Discover->Offer, Request->Ack, Release|Decline gated,
// everything else (Offer/Ack/Nak/Inform/errors) ignored. Mirrors
// examples/server.rs match arms for integration tests below.
struct ExampleLike {
    leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
    last_lease: u32,
    lease_duration: Duration,
    #[allow(dead_code)]
    server_ip: Ipv4Addr,
}

impl ExampleLike {
    fn new(server_ip: Ipv4Addr) -> Self {
        Self {
            leases: HashMap::new(),
            last_lease: 0,
            lease_duration: Duration::new(LEASE_DURATION_SECS as u64, 0),
            server_ip,
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
}

impl server::Handler for ExampleLike {
    fn handle_request(&mut self, server: &server::Server, in_packet: Packet) {
        match in_packet.message_type() {
            Ok(MessageType::Discover) => {
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    let _ = server.reply(
                        MessageType::Offer,
                        vec![DhcpOption::IpAddressLeaseTime(LEASE_DURATION_SECS)],
                        ip,
                        in_packet,
                    );
                    return;
                }
                for _ in 0..LEASE_NUM {
                    self.last_lease = (self.last_lease + 1) % LEASE_NUM;
                    let cand: Ipv4Addr = (IP_START_NUM + self.last_lease).into();
                    if self.available(&in_packet.chaddr, &cand) {
                        let _ = server.reply(
                            MessageType::Offer,
                            vec![DhcpOption::IpAddressLeaseTime(LEASE_DURATION_SECS)],
                            cand,
                            in_packet,
                        );
                        break;
                    }
                }
            }
            Ok(MessageType::Request) => {
                // NOTE: mirrors the example — the for_this_server gate is
                // commented out upstream, so Requests are honored regardless.
                let req_ip = match in_packet.option(REQUESTED_IP_ADDRESS) {
                    Some(DhcpOption::RequestedIpAddress(x)) => *x,
                    _ => in_packet.ciaddr,
                };
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    let _ = server.reply(
                        MessageType::Ack,
                        vec![DhcpOption::IpAddressLeaseTime(LEASE_DURATION_SECS)],
                        ip,
                        in_packet,
                    );
                    return;
                }
                if !self.available(&in_packet.chaddr, &req_ip) {
                    let _ = server.reply(
                        MessageType::Nak,
                        vec![DhcpOption::Message("Requested IP not available".to_string())],
                        Ipv4Addr::UNSPECIFIED,
                        in_packet,
                    );
                    return;
                }
                self.leases.insert(
                    req_ip,
                    (
                        in_packet.chaddr,
                        Some(Instant::now().add(self.lease_duration)),
                    ),
                );
                let _ = server.reply(
                    MessageType::Ack,
                    vec![DhcpOption::IpAddressLeaseTime(LEASE_DURATION_SECS)],
                    req_ip,
                    in_packet,
                );
            }
            Ok(MessageType::Release) | Ok(MessageType::Decline) => {
                if !server.for_this_server(&in_packet) {
                    return;
                }
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    self.leases.remove(&ip);
                }
            }
            _ => {}
        }
    }
}

fn serve_example_like() -> (std::net::SocketAddr, Ipv4Addr) {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(192, 168, 2, 1);
    let handler = ExampleLike::new(server_ip);
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            server_ip,
            Ipv4Addr::new(192, 168, 2, 255),
            handler,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    (srv_addr, server_ip)
}

// ===========================================================================
// A. Wire-length lies and hostile framing stay safe
// ===========================================================================

/// Declared `len` 255 with 1 byte present: `decode_option` errors
/// `InvalidHlen`, `Packet::from` swallows it, keeps the valid prefix, and
/// never panics — a lying length cannot crash the decoder nor inject bytes.
#[test]
fn sec_truncated_len_past_end_swallowed_keeps_prefix() {
    let raw = make_raw(
        1, 6, 0, 0xD001, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1; 6],
        vec![53, 1, 1, 200, 255, 7], // Discover + lying option, no END
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 1, "valid prefix kept, lie dropped");
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
}

/// 100 zero bytes with no END: each `[0,0]` pair decodes as
/// `Unrecognized(0, [])`, then the exhausted buffer fails and the missing
/// END kills the thread via `split_at(1)`. Minimal DoS datagram — locked.
#[test]
#[should_panic]
fn sec_all_zero_options_no_end_panics_quirk() {
    let raw = make_raw(
        1, 6, 0, 0xD002, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [2; 6],
        vec![0u8; 100], // no END anywhere
    );
    let _ = Packet::from(&raw);
}

/// A lone oversized option (no fitting prefix) encodes to a bare END-only
/// packet (241 bytes) — never corrupt framing — but decoding bare-END
/// panics on `assert!(code != END)` (same known quirk as the empty-options
/// case), so such a datagram is a thread-killer on receipt. Locked.
#[test]
fn sec_only_giant_option_yields_bare_end_packet() {
    let p = test_packet(
        0xD003,
        [3; 6],
        vec![DhcpOption::Unrecognized(RawDhcpOption {
            code: 200,
            data: vec![9u8; 300],
        })],
    );
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(enc.len(), 241, "nothing fits: header+cookie+END only");
    assert_eq!(enc[240], 255);
    let r = std::panic::catch_unwind(move || {
        let _ = Packet::from(&enc);
    });
    assert!(r.is_err(), "bare END must panic on decode (known quirk)");
}

// ===========================================================================
// B. Example-handler blind spots: silently ignored message types
// ===========================================================================

/// DHCPINFORM gets NO reply from the example logic (the `_ => {}` arm;
/// upstream even has a TODO for it). A live INFORM with valid shape times
/// out — locked so adding Inform support later is a deliberate change.
#[test]
fn sec_inform_gets_no_reply_live() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let p = Packet {
        reply: false,
        hops: 0,
        xid: 0xD010,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 2, 60),
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xAA; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Inform),
            DhcpOption::ParameterRequestList(vec![1, 15]),
        ],
    };
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert!(
        client.recv_from(&mut rbuf).is_err(),
        "INFORM must get no reply from example logic"
    );
}

/// A forged server Offer (op=2) IS dispatched (no op check) but the example
/// match ignores it — full-stack proof that spoofed server packets cost CPU
/// but earn no reply.
#[test]
fn sec_forged_offer_gets_no_reply_live() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let p = Packet {
        reply: true, // forged BOOTREPLY
        hops: 0,
        xid: 0xD011,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xBB; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Offer)],
    };
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert!(
        client.recv_from(&mut rbuf).is_err(),
        "forged Offer must get no reply"
    );
}

// ===========================================================================
// C. NAK wire shape, Router-on-wire, Request precedence, bare Request
// ===========================================================================

/// Live NAK carries zeroed addrs, Server ID, and — under the 300-byte cap —
/// the example's 26-byte explanation text (249+2+26 = 277 < 300), so NAK
/// clients now see a reason string.
#[test]
fn sec_nak_wire_message_text_and_addrs() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // Occupy .50 with another MAC so this request NAKs.
    let squatter = [0xCC; 6];
    let victim = [0xDD; 6];
    let occupier = Packet {
        reply: false, hops: 0, xid: 0xD020, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: squatter,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 50)),
        ],
    };
    client.send_to(&occupier.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("occupier Ack");
    assert_eq!(unwrap_packet(Packet::from(&rbuf[..n])).message_type(), Ok(MessageType::Ack));
    // Victim asks for the taken IP -> NAK with exact text.
    let req = Packet {
        reply: false, hops: 0, xid: 0xD021, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 50)),
        ],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("NAK");
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(MessageType::Nak));
    assert_eq!(rep.ciaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(rep.yiaddr, Ipv4Addr::UNSPECIFIED);
    assert!(
        rep.option(MESSAGE) == Some(&DhcpOption::Message("Requested IP not available".to_string())),
        "26-byte NAK text reaches the wire under the 300 cap (249+2+26 = 277)"
    );
    assert_eq!(
        rep.option(SERVER_IDENTIFIER),
        Some(&DhcpOption::ServerIdentifier(server_ip))
    );
    // A short message DOES fit alongside 53+54: control proof the path works.
    let short = DhcpOption::Message("no".to_string()).to_raw();
    assert_eq!(short.data.len(), 2);
}

/// Router IS present on the wire of an example Offer (code 3, len 4) even
/// though this library's own decoder drops it — proves the server really
/// sends the gateway and only the local decode path is blind.
#[test]
fn sec_router_present_on_wire_but_dropped_on_decode() {
    let p = Packet {
        reply: true,
        hops: 0,
        xid: 1,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::new(192, 168, 2, 90),
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Offer),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 2, 1)),
            DhcpOption::IpAddressLeaseTime(86400),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 2, 1)]),
        ],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(
        enc.windows(6).any(|w| w == [3, 4, 192, 168, 2, 1]),
        "router TLV must be on the wire"
    );
    let q = unwrap_packet(Packet::from(&enc));
    assert!(
        q.option(ROUTER).is_none(),
        "local decode drops Router (known quirk)"
    );
    assert_eq!(
        q.options.iter().map(|o| o.code()).collect::<Vec<u8>>(),
        vec![53, 54, 51, 1],
        "decodable prefix kept in order"
    );
}

/// When both Requested IP and `ciaddr` are set, Requested IP wins — `ciaddr`
/// is only a fallback (RENEWING). An attacker setting both cannot smuggle a
/// different `ciaddr` past the selection.
#[test]
fn sec_requested_ip_beats_ciaddr_when_both_set() {
    let mut s = Replica::new();
    let mac = [0x11; 6];
    let got = s
        .request(
            &mac,
            Some(Ipv4Addr::new(192, 168, 2, 80)),
            Ipv4Addr::new(192, 168, 2, 70),
            true,
        )
        .unwrap();
    assert_eq!(got, Ipv4Addr::new(192, 168, 2, 80));
    assert!(s.leases.contains_key(&Ipv4Addr::new(192, 168, 2, 80)));
    assert!(!s.leases.contains_key(&Ipv4Addr::new(192, 168, 2, 70)));
}

/// A bare Request (no Requested IP, `ciaddr` 0.0.0.0, no current lease) NAKs
/// cleanly with NO insert — 0.0.0.0 never enters the lease table, no panic.
#[test]
fn sec_bare_request_naks_without_insert() {
    let mut s = Replica::new();
    let mac = [0x22; 6];
    assert!(s
        .request(&mac, None, Ipv4Addr::UNSPECIFIED, true)
        .is_err());
    assert!(s.leases.is_empty(), "0.0.0.0 must never be leased");
}

// ===========================================================================
// D. Config trust: reservations, duplicates, sloppy lines
// ===========================================================================

/// QUIRK: a `leases`-file reservation outside the pool is offered verbatim —
/// no validation that reserved IPs lie in `[START, START+NUM)`. A bad config
/// line makes the server offer off-subnet addresses. Locked.
#[test]
fn sec_out_of_pool_reservation_offered_verbatim_quirk() {
    let mut s = Replica::new();
    let mac = [0x33; 6];
    s.leases.insert(Ipv4Addr::new(10, 0, 0, 5), (mac, None));
    assert_eq!(s.discover(&mac), Some(Ipv4Addr::new(10, 0, 0, 5)));
}

/// Duplicate `leases` lines for one IP: last line wins silently (plain
/// `HashMap::insert`, no conflict error) — locked so rotation mistakes stay
/// visible in review rather than changing meaning.
#[test]
fn sec_duplicate_leases_ip_last_wins() {
    let mut leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)> = HashMap::new();
    for line in [
        "aa:bb:cc:dd:ee:01,192.168.2.10",
        "aa:bb:cc:dd:ee:02,192.168.2.10",
    ] {
        let (mac, ip) = parse_leases_line(line).unwrap();
        leases.insert(ip, (mac, None));
    }
    assert_eq!(leases.len(), 1);
    assert_eq!(
        leases[&Ipv4Addr::new(192, 168, 2, 10)].0,
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02],
        "second line overwrites first"
    );
}

/// QUIRK: a trailing space in the MAC (`"...ee:ff ,ip"`) makes the last octet
/// fail `from_str_radix`, so `filter_map` drops it, the 6-octet check fails,
/// and the whole reservation line is silently skipped. Locked.
#[test]
fn sec_trailing_space_mac_line_skipped_quirk() {
    assert_eq!(parse_leases_line("aa:bb:cc:dd:ee:ff ,192.168.2.10"), None);
}

/// QUIRK: one non-hex octet (`zz`) is filtered out, leaving 5 octets, so the
/// line is silently skipped with no error — a typo can silently drop a
/// reservation. Locked.
#[test]
fn sec_bad_octet_mac_line_skipped() {
    assert_eq!(parse_leases_line("aa:bb:cc:dd:ee:zz,192.168.2.10"), None);
    assert_eq!(parse_leases_line("aa::cc:dd:ee:ff,192.168.2.10"), None);
}

// ===========================================================================
// E. Server-authoritative lease time: wire value from client ignored
// ===========================================================================

/// A client requesting lease 60s still gets an Ack for 86400s with a full
/// 86400s server-side expiry — the Request's option-51 value is never
/// consulted (example handler hard-codes the duration). Locks that clients
/// cannot shrink/extend their own lease.
#[test]
fn sec_request_lease_time_ignored_server_sends_fixed() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = Packet {
        reply: false,
        hops: 0,
        xid: 0xD030,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0x44; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 71)),
            DhcpOption::IpAddressLeaseTime(60), // client asks short
        ],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("Ack");
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(MessageType::Ack));
    assert_eq!(
        rep.option(IP_ADDRESS_LEASE_TIME),
        Some(&DhcpOption::IpAddressLeaseTime(86400)),
        "server duration wins over requested 60s"
    );
    // Replica-level: expiry is always full duration from now.
    let mut s = Replica::new();
    let before = Instant::now();
    let mac = [0x45; 6];
    s.request(&mac, Some(Ipv4Addr::new(192, 168, 2, 72)), Ipv4Addr::UNSPECIFIED, true)
        .unwrap();
    let (_, expiry) = &s.leases[&Ipv4Addr::new(192, 168, 2, 72)];
    let exp = expiry.expect("timed lease");
    assert!(exp >= before.add(Duration::from_secs(u64::from(LEASE_DURATION_SECS - 5))));
}
