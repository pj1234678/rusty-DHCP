//! DHCP security regression suite.
//!
//! Locks security-relevant behavior of this DHCP stack so refactors cannot
//! silently open (or silently "fix" without review) attacker-visible holes.
//! All tests assert the *current* behavior and pass against it; tests for
//! known-unsafe behavior end in `_quirk` and state the threat in the docs.
//!
//! Threat model: untrusted bytes arrive via UDP (`Server::serve`), and any
//! peer can spoof `chaddr`/`xid`/`ciaddr`/`giaddr`/flags/options — there is
//! no authentication (RFC 3118 is not implemented) and identity is the raw
//! 6-byte `chaddr`. Lease state lives in the example `MyServer` replica here
//! (same bodies as `examples/server.rs`); the library itself trusts its
//! caller for `offer_ip` selection.
//!
//! Groups:
//! - A. Parser hardening: oversized / bomb packets stay bounded, no panics
//! - B. Malformed-option desync: first error truncates the option list
//! - C. Trust boundaries: op not validated, broadcast controls delivery,
//!   `offer_ip`/`ciaddr`/`xid` echoed without validation
//! - D. Lease abuse: starvation, infinite-lease theft, release spoofing
//! - E. Config DoS: malformed `leases` line panics the example parser

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::ops::Add;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// helpers
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

// Exact replica of examples/server.rs lease state (see test_examples_extra).
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

// ===========================================================================
// A. Parser hardening: oversized / hostile packets stay bounded, no panics
// ===========================================================================

/// A 300-byte HostName cannot fit the 300-byte wire cap, so `encode` drops
/// the option instead of truncating the length byte (`as u8` wrap) — the
/// packet stays well-formed with just Discover + END. No panic, no corrupt
/// length prefix an attacker could use for framing confusion.
#[test]
fn sec_oversized_hostname_dropped_packet_stays_valid() {
    let big = "A".repeat(300);
    let p = test_packet(
        0xB001,
        [1; 6],
        vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::HostName(big),
        ],
    );
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(enc.len() < 300, "oversized option must not bloat packet");
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(q.options.len(), 1, "only Discover survives");
    assert_eq!(q.message_type(), Ok(MessageType::Discover));
}

/// A 1500-byte MTU-full datagram of tiny options decodes without panic and
/// the option Vec stays bounded by the datagram (~419 entries); re-encoding
/// truncates back to the 300 cap with Discover first. No amplification past
/// the cap and no allocator blowup beyond one datagram.
#[test]
fn sec_1500_byte_option_bomb_decodes_bounded() {
    let mut opts = vec![53, 1, 1]; // Discover
    for _ in 0..418 {
        opts.extend_from_slice(&[200, 1, 7]);
    }
    opts.push(255); // END
    let raw = make_raw(
        1, 6, 0, 0xB002, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [2; 6], opts,
    );
    assert!(raw.len() <= 1500);
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 419, "1 Discover + 418 Unrecognized");
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(enc.len() <= 300, "re-encode capped, no amplification");
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(q.message_type(), Ok(MessageType::Discover), "Discover kept first");
    assert_eq!(q.options.len(), 19, "Discover + 18 fillers + END accounting");
}

/// A 255-byte Parameter Request List (max `len` byte) decodes fully but can
/// never be re-encoded (240+2+255 >= 300), so it is dropped on reply —
//  bounded in both directions, never wraps the length byte.
#[test]
fn sec_prl_255_bytes_decodes_but_encode_drops_quirk() {
    let data = vec![1u8; 255];
    let mut wire = vec![55, 255];
    wire.extend_from_slice(&data);
    match decode_option(&wire) {
        Ok((rest, DhcpOption::ParameterRequestList(v))) => {
            assert_eq!(v.len(), 255);
            assert!(rest.is_empty());
        }
        _ => panic!("255-byte PRL must decode"),
    }
    let p = test_packet(
        0xB003,
        [3; 6],
        vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::ParameterRequestList(data),
        ],
    );
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
    assert_eq!(q.options.len(), 1, "giant PRL dropped, Discover kept");
}

// ===========================================================================
// B. Malformed-option desync: first error truncates the option list
// ===========================================================================

/// An attacker-controlled malformed option (bad UTF-8 HostName) placed before
/// Server Identifier strips the identifier: decoded options end at the error
/// (plus one desync byte skipped), so `for_this_server`-style checks see
/// "no Server ID". The packet is still accepted as Discover.
#[test]
fn sec_bad_option_strips_following_server_id() {
    let mut opts = vec![53, 1, 1]; // Discover
    opts.extend_from_slice(&[12, 2, 0xFF, 0xFE]); // bad UTF-8 HostName
    opts.extend_from_slice(&[54, 4, 10, 20, 30, 40]); // Server ID (lost)
    opts.push(255);
    let raw = make_raw(
        1, 6, 0, 0xB010, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [4; 6], opts,
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 1, "list truncated at bad option");
    assert_eq!(p.message_type(), Ok(MessageType::Discover), "leading type survives");
    assert!(p.option(SERVER_IDENTIFIER).is_none(), "Server ID stripped");
}

/// Same desync with a bad message-type value as the *second* option: the
/// leading Discover survives while the bogus trailing type is dropped.
#[test]
fn sec_bad_trailing_msgtype_dropped_leading_kept() {
    let raw = make_raw(
        1, 6, 0, 0xB011, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [5; 6],
        vec![53, 1, 1, 53, 1, 9, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 1);
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
}

/// Two option-53s in one datagram: `message_type()` returns the FIRST, the
/// second is silently ignored — an attacker cannot override the type by
/// appending, but a naive reader of `options[1]` would disagree. Locked.
#[test]
fn sec_duplicate_msgtype_first_wins_confusion() {
    let raw = make_raw(
        1, 6, 0, 0xB012, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [6; 6],
        vec![53, 1, 1, 53, 1, 3, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 2);
    assert_eq!(p.message_type(), Ok(MessageType::Discover), "first wins");
    let raw2 = make_raw(
        1, 6, 0, 0xB013, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [6; 6],
        vec![53, 1, 3, 53, 1, 1, 255],
    );
    assert_eq!(
        unwrap_packet(Packet::from(&raw2)).message_type(),
        Ok(MessageType::Request),
        "order matters, first wins"
    );
}

/// Unknown message-type value (9): the datagram still decodes Ok with empty
/// options, so the server ignores it via the catch-all instead of erroring.
/// No crash, no reply — attacker learns nothing.
#[test]
fn sec_unknown_msgtype_decodes_but_handler_ignores() {
    let raw = make_raw(
        1, 6, 0, 0xB014, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [7; 6],
        vec![53, 1, 9, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert!(p.options.is_empty());
    assert!(p.message_type().is_err(), "example match falls to catch-all arm");
}

// ===========================================================================
// C. Trust boundaries: op, broadcast delivery, unvalidated echo fields
// ===========================================================================

/// QUIRK (spoofing): `Server::serve` never checks `op` — a forged BOOTREPLY
/// (op=2, i.e. a "server" packet) from any peer is still dispatched to the
/// handler as if it were a client request. Locked so the missing validation
/// cannot change silently.
#[test]
fn sec_bootreply_still_dispatched_to_handler_quirk() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<(bool, u32)>();
    struct H {
        tx: std::sync::mpsc::Sender<(bool, u32)>,
    }
    impl server::Handler for H {
        fn handle_request(&mut self, _s: &server::Server, p: Packet) {
            let _ = self.tx.send((p.reply, p.xid));
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 255),
            H { tx },
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    // forged server-to-server reply carrying a Discover option
    let p = Packet {
        reply: true,
        hops: 0,
        xid: 0xC001,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [8; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let mut buf = [0u8; 1500];
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        (true, 0xC001),
        "BOOTREPLY must reach handler (no op validation)"
    );
}

/// The attacker-controlled broadcast flag decides unicast vs subnet
/// broadcast delivery: `false` answers only the peer, `true` sprays the
/// configured broadcast address (amplification primitive — locked).
#[test]
fn sec_broadcast_flag_controls_subnet_delivery() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = s.reply(
                MessageType::Offer,
                vec![],
                Ipv4Addr::new(192, 168, 9, 10),
                p,
            );
        }
    }
    std::thread::spawn(move || {
        // broadcast goes to 127.0.0.2: no listener there, peer gets nothing
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 9, 1),
            Ipv4Addr::new(127, 0, 0, 2),
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // unicast: reply returns to the peer
    let p = test_packet(0xC002, [9; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Discover,
    )]);
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("unicast reply");
    assert_eq!(unwrap_packet(Packet::from(&rbuf[..n])).yiaddr, Ipv4Addr::new(192, 168, 9, 10));
    // broadcast: reply sprays 127.0.0.2, this peer sees nothing
    let mut raw = vec![0u8; 236];
    raw[0] = 1;
    raw[1] = 1;
    raw[2] = 6;
    raw[4..8].copy_from_slice(&0xC003u32.to_be_bytes());
    raw[10] = 0;
    raw[11] = 128; // low-byte 0x80 -> decodes broadcast=true (quirk)
    raw[28..34].copy_from_slice(&[9; 6]);
    raw.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1, 255]);
    client.send_to(&raw, srv_addr).unwrap();
    assert!(
        client.recv_from(&mut rbuf).is_err(),
        "broadcast reply must NOT reach the unicast peer"
    );
}

/// Library performs NO validation that the offered address belongs to the
/// served subnet — whatever `offer_ip` the handler passes is echoed
/// verbatim. Caller (example: `available()`) is the only guard. Locked.
#[test]
fn sec_offer_ip_out_of_subnet_used_verbatim() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = s.reply(MessageType::Offer, vec![], Ipv4Addr::new(8, 8, 8, 8), p);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 9, 1),
            Ipv4Addr::new(192, 168, 9, 255),
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let p = test_packet(0xC004, [10; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Discover,
    )]);
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("reply");
    assert_eq!(
        unwrap_packet(Packet::from(&rbuf[..n])).yiaddr,
        Ipv4Addr::new(8, 8, 8, 8),
        "library echoes any offer_ip, even off-subnet"
    );
}

/// `ciaddr` is echoed verbatim into non-NAK replies with no ownership check —
/// a spoofed `ciaddr` is reflected back (delivery still uses the peer
/// socket, so this is a reflection quirk, not a redirect).
#[test]
fn sec_ciaddr_spoof_echoed_in_ack() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = s.reply(MessageType::Ack, vec![], Ipv4Addr::new(192, 168, 9, 20), p);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 9, 1),
            Ipv4Addr::new(192, 168, 9, 255),
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let mut p = test_packet(0xC005, [11; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Request,
    )]);
    p.ciaddr = Ipv4Addr::new(1, 2, 3, 4); // victim address, not ours
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("reply");
    assert_eq!(
        unwrap_packet(Packet::from(&rbuf[..n])).ciaddr,
        Ipv4Addr::new(1, 2, 3, 4),
        "ciaddr reflected without validation"
    );
}

/// `xid` is echoed with no randomness/sequence check — edge values 0 and
/// MAX round-trip exactly, so xid alone authenticates nothing.
#[test]
fn sec_xid_edge_values_echoed_without_validation() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = s.reply(MessageType::Offer, vec![], Ipv4Addr::new(192, 168, 9, 30), p);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 9, 1),
            Ipv4Addr::new(192, 168, 9, 255),
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    for xid in [0u32, u32::MAX] {
        let p = test_packet(xid, [12; 6], vec![DhcpOption::DhcpMessageType(
            MessageType::Discover,
        )]);
        client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
        let (n, _) = client.recv_from(&mut rbuf).expect("reply");
        assert_eq!(unwrap_packet(Packet::from(&rbuf[..n])).xid, xid);
    }
}

// ===========================================================================
// D. Lease abuse: starvation, theft, release spoofing (example replica)
// ===========================================================================

/// Classic DHCP starvation: 252 distinct spoofed `chaddr`s each REQUEST a
/// distinct pool IP. No rate limiting exists, so the pool fills and the next
/// legitimate client gets NAK (Request) / no offer (Discover). Locked.
#[test]
fn sec_starvation_via_distinct_chaddrs_fills_pool() {
    let mut s = Replica::new();
    for i in 0..LEASE_NUM {
        let mac = [(i >> 16) as u8, (i >> 8) as u8, i as u8, 0xAA, 0xBB, 0xCC];
        let ip: Ipv4Addr = (IP_START_NUM + i).into();
        assert_eq!(s.request(&mac, Some(ip), Ipv4Addr::UNSPECIFIED, true), Ok(ip));
    }
    assert_eq!(s.leases.len(), LEASE_NUM as usize);
    let legit = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    assert_eq!(s.discover(&legit), None, "pool exhausted: no offer");
    assert!(
        s.request(&legit, Some(Ipv4Addr::new(192, 168, 2, 50)), Ipv4Addr::UNSPECIFIED, true).is_err(),
        "pool exhausted: NAK path"
    );
}

/// Infinite (file-reserved, `None` expiry) leases are stealable: `available`
/// reports them free to ANY mac, so a stranger's Request overwrites the
/// reservation with a timed lease. Integrity hole — locked.
#[test]
fn sec_infinite_lease_overwritten_by_stranger_request() {
    let mut s = Replica::new();
    let victim = [0xF4, 0x5C, 0x19, 0xAF, 0x96, 0x8D];
    let reserved = Ipv4Addr::new(192, 168, 2, 90);
    s.leases.insert(reserved, (victim, None)); // permanent reservation
    let attacker = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
    assert_eq!(
        s.request(&attacker, Some(reserved), Ipv4Addr::UNSPECIFIED, true),
        Ok(reserved),
        "stranger Acked for reserved IP"
    );
    let (owner, expiry) = &s.leases[&reserved];
    assert_eq!(*owner, attacker, "reservation now owned by attacker");
    assert!(expiry.is_some(), "permanent became timed");
}

/// Release/Decline only checks the 6 raw `chaddr` bytes — anyone spoofing the
/// victim MAC deletes its lease (no authentication). A wrong chaddr deletes
/// nothing and never panics.
#[test]
fn sec_release_requires_victim_chaddr_spoof() {
    let mut s = Replica::new();
    let victim = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let ip = Ipv4Addr::new(192, 168, 2, 60);
    assert_eq!(s.request(&victim, Some(ip), Ipv4Addr::UNSPECIFIED, true), Ok(ip));
    // wrong chaddr: no-op, lease kept
    assert!(!s.release(&[9; 6], true));
    assert!(s.leases.contains_key(&ip));
    // spoofed victim chaddr: lease deleted
    assert!(s.release(&victim, true));
    assert!(!s.leases.contains_key(&ip));
}

/// Release for an unknown chaddr is a silent no-op (returns false).
#[test]
fn sec_release_unknown_chaddr_noop() {
    let mut s = Replica::new();
    assert!(!s.release(&[9; 6], true));
    assert!(s.leases.is_empty());
}

// ===========================================================================
// E. Config DoS: malformed `leases` line panics the example parser
// ===========================================================================

/// QUIRK (startup DoS): `examples/server.rs` parses the IP with `.unwrap()`,
/// so ONE bad line with a valid MAC but garbage IP panics the whole server
/// at startup. (The `test_lease_logic` helper uses `.ok()?` instead and
/// hides this.) A single attacker/contributor-written line kills the daemon.
#[test]
#[should_panic]
fn sec_leases_file_bad_ip_panics_example_parser_quirk() {
    // byte-for-byte replica of examples/server.rs main() parsing incl. unwrap
    let line = String::from("aa:bb:cc:dd:ee:ff,not-an-ip");
    let parts: Vec<&str> = line.split(',').collect();
    assert_eq!(parts.len(), 2);
    let mac_parts: Vec<u8> = parts[0]
        .split(':')
        .filter_map(|part| u8::from_str_radix(part, 16).ok())
        .collect();
    assert_eq!(mac_parts.len(), 6);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&mac_parts);
    let _mac = mac;
    let _ip: Ipv4Addr = parts[1].trim().parse::<Ipv4Addr>().unwrap();
}
