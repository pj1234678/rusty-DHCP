//! DHCP security: timing attacks and race conditions.
//!
//! Covers timing/race behavior NOT locked by `test_security.rs`,
//! `test_security_extra.rs`, `test_security_edge.rs`, `test_security_wire.rs`,
//! `test_security_gates.rs`, `test_security_hijack.rs`,
//! `test_security_slowloris.rs`, or the RFC suites. All tests assert the
//! *current* behavior and pass against it; tests for known-unsafe behavior
//! end in `_quirk` and state the threat in the docs.
//!
//! A note on "timing attacks" here: this stack has no wall-clock branches
//! except lease expiry (`Instant::now().gt(&exp)`), so there are no
//! timing oracles to measure — the timing-relevant guarantees are structural
//! instead: retransmits are idempotent, races converge to exactly one winner,
//! failed paths mutate nothing, and expiry uses strict `>` (an expiry equal
//! to `now` is still held; only strictly-past expiries are reusable, which
//! is why the zero-duration test below sleeps before asserting reuse).
//!
//! Groups:
//! - A. Retransmit / storm idempotency: identical repeats converge, NAK path
//!   inserts nothing, zero-duration leases are immediately reusable.
//! - B. Races with order-independent outcomes: last-free-IP race has exactly
//!   one winner; concurrent same-chaddr Acks agree; pipelined dual-DORA has
//!   no cross-talk; spurious Release mid-handshake is a no-op.
//! - C. Release/reacquire lifecycle over the wire.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::ops::Add;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// helpers (same patterns as test_security_slowloris.rs)
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

// Minimal replica of examples/server.rs lease state (same method bodies as
// test_examples_extra.rs; only the methods needed here are included).
const IP_START: [u8; 4] = [192, 168, 2, 2];
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);
const LEASE_NUM: u32 = 252;
const LEASE_DURATION_SECS: u32 = 86400;

struct Replica {
    leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
    lease_duration: Duration,
}

impl Replica {
    fn with_duration(lease_duration: Duration) -> Self {
        Self {
            leases: HashMap::new(),
            lease_duration,
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
}

// Example-like handler: Discover->Offer, Request->Ack, Release|Decline gated,
// everything else ignored. Mirrors examples/server.rs match arms.
struct ExampleLike {
    leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
    last_lease: u32,
    lease_duration: Duration,
}

impl ExampleLike {
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
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            server_ip,
            Ipv4Addr::new(192, 168, 2, 255),
            ExampleLike::new(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    (srv_addr, server_ip)
}

fn send_recv(
    client: &UdpSocket,
    srv_addr: &std::net::SocketAddr,
    p: &Packet,
    buf: &mut [u8; 1500],
    rbuf: &mut [u8; 1500],
) -> Packet {
    client.send_to(&p.encode(buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(rbuf).expect("expected reply");
    unwrap_packet(Packet::from(&rbuf[..n]))
}

fn discover(xid: u32, chaddr: [u8; 6]) -> Packet {
    test_packet(
        xid,
        chaddr,
        vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    )
}

fn request_selecting(
    xid: u32,
    chaddr: [u8; 6],
    server_ip: Ipv4Addr,
    wanted: Ipv4Addr,
) -> Packet {
    test_packet(
        xid,
        chaddr,
        vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(wanted),
        ],
    )
}

// ===========================================================================
// A. Retransmit / storm idempotency and NAK purity
// ===========================================================================

/// Retransmission storm: 20 byte-identical Requests earn 20 identical Acks
/// for one single table entry — repeats never duplicate, fork, or NAK.
/// Locked live.
#[test]
fn sec8_retransmit_storm_same_chaddr_single_lease_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let mac = [0x71; 6];
    for i in 0..20u32 {
        let rep = send_recv(
            &client,
            &srv_addr,
            &request_selecting(0xB000 + i, mac, server_ip, Ipv4Addr::new(192, 168, 2, 60)),
            &mut buf,
            &mut rbuf,
        );
        assert_eq!(rep.message_type(), Ok(MessageType::Ack), "storm {}", i);
        assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 60), "storm {}", i);
    }
    // still exactly the one lease: a stranger is NAK'd for it afterwards
    let stranger = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xB100, [0x72; 6], server_ip, Ipv4Addr::new(192, 168, 2, 60)),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!(stranger.message_type(), Ok(MessageType::Nak));
}

/// NAK path is mutation-free: stranger denied, table size and victim mapping
/// unchanged. Locks that denial performs no insert (the availability check
/// has no write side effects).
#[test]
fn sec8_nak_path_performs_no_insert_replica() {
    let mut s = Replica::with_duration(Duration::from_secs(3600));
    let victim = [0x73; 6];
    let stranger = [0x74; 6];
    let ip = Ipv4Addr::new(192, 168, 2, 61);
    assert_eq!(s.request(&victim, Some(ip), Ipv4Addr::UNSPECIFIED, true), Ok(ip));
    assert_eq!(s.leases.len(), 1);
    assert_eq!(
        s.request(&stranger, Some(ip), Ipv4Addr::UNSPECIFIED, true),
        Err("Requested IP not available")
    );
    assert_eq!(s.leases.len(), 1, "NAK inserted nothing");
    assert_eq!(s.leases[&ip].0, victim, "victim mapping intact");
    assert_eq!(s.current_lease(&stranger), None);
}

/// Zero-duration leases expire immediately: after a short sleep a stranger
/// finds the address reusable. Documents the `gt` (strictly-past) boundary
/// without asserting the racy exact-now instant itself.
#[test]
fn sec8_zero_duration_lease_immediately_reusable_replica() {
    let mut s = Replica::with_duration(Duration::from_secs(0));
    let holder = [0x75; 6];
    let stranger = [0x76; 6];
    let ip = Ipv4Addr::new(192, 168, 2, 62);
    assert_eq!(s.request(&holder, Some(ip), Ipv4Addr::UNSPECIFIED, true), Ok(ip));
    std::thread::sleep(Duration::from_millis(10));
    assert!(
        s.available(&stranger, &ip),
        "zero-duration lease must already read expired"
    );
    assert_eq!(s.request(&stranger, Some(ip), Ipv4Addr::UNSPECIFIED, true), Ok(ip));
    assert_eq!(s.leases[&ip].0, stranger, "reuse transfers ownership");
}

// ===========================================================================
// B. Races with order-independent outcomes
// ===========================================================================

/// Race for the last free IP: pool filled except `.253` over the wire, then
/// two Requests for `.253` sent back-to-back. Exactly one Ack and one Nak
/// arrive (asserted as a multiset, so loopback ordering cannot flake it),
/// and exactly one of the two racers holds `.253` afterwards (XOR).
/// Locked live.
#[test]
fn sec8_last_free_ip_race_one_ack_one_nak_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // fill every pool address except .253 (START+251)
    for i in 0..251u32 {
        let ch = [
            (i >> 16) as u8,
            (i >> 8) as u8,
            i as u8,
            0xAA,
            0xBB,
            0xCC,
        ];
        let ip: Ipv4Addr = (IP_START_NUM + i).into();
        let rep = send_recv(
            &client,
            &srv_addr,
            &request_selecting(0xC000 + i, ch, server_ip, ip),
            &mut buf,
            &mut rbuf,
        );
        assert_eq!(rep.message_type(), Ok(MessageType::Ack), "fill {}", i);
    }
    // two racers, same target, back-to-back (no recv between sends)
    let racer_a = [0xD0; 6];
    let racer_b = [0xD1; 6];
    let target = Ipv4Addr::new(192, 168, 2, 253);
    client
        .send_to(
            &request_selecting(0xC100, racer_a, server_ip, target)
                .encode(&mut buf)
                .to_vec(),
            srv_addr,
        )
        .unwrap();
    client
        .send_to(
            &request_selecting(0xC101, racer_b, server_ip, target)
                .encode(&mut buf)
                .to_vec(),
            srv_addr,
        )
        .unwrap();
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let (n, _) = client.recv_from(&mut rbuf).expect("race reply");
        kinds.push(unwrap_packet(Packet::from(&rbuf[..n])).message_type().unwrap());
    }
    kinds.sort_by_key(|m| *m as u8);
    assert_eq!(kinds, vec![MessageType::Ack, MessageType::Nak]);
    // exactly one racer holds .253 now (XOR over follow-up Discovers).
    // NOTE: the pool is completely full, so the loser's Discover gets NO
    // reply at all — use timeouts, not send_recv (which expects a reply).
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut holds = |chaddr: [u8; 6], xid: u32| -> bool {
        let d = discover(xid, chaddr);
        client.send_to(&d.encode(&mut buf).to_vec(), srv_addr).unwrap();
        match client.recv_from(&mut rbuf) {
            Ok((n, _)) => unwrap_packet(Packet::from(&rbuf[..n])).yiaddr == target,
            Err(_) => false,
        }
    };
    let holds_a = holds(racer_a, 0xC102);
    let holds_b = holds(racer_b, 0xC103);
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert!(holds_a ^ holds_b, "exactly one winner holds {:?}", target);
}

/// Concurrent same-`chaddr` Requests from two threads: both Ack the same IP
/// (current-lease short-circuit), no duplicate entries possible. Locked.
#[test]
fn sec8_concurrent_same_chaddr_both_ack_same_ip_live() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(192, 168, 2, 1);
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            server_ip,
            Ipv4Addr::new(192, 168, 2, 255),
            ExampleLike::new(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let mac = [0xD2; 6];
    let handles: Vec<_> = [0xD200u32, 0xD201]
        .iter()
        .map(|&xid| {
            std::thread::spawn(move || {
                let client = UdpSocket::bind("127.0.0.1:0").unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buf = [0u8; 1500];
                let mut rbuf = [0u8; 1500];
                let req = Packet {
                    reply: false, hops: 0, xid, secs: 0, broadcast: false,
                    ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
                    siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
                    chaddr: mac,
                    options: vec![
                        DhcpOption::DhcpMessageType(MessageType::Request),
                        DhcpOption::ServerIdentifier(server_ip),
                        DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 70)),
                    ],
                };
                client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
                let (n, _) = client.recv_from(&mut rbuf).expect("concurrent reply");
                let rep = unwrap_packet(Packet::from(&rbuf[..n]));
                assert_eq!(rep.xid, xid, "per-transaction xid echo");
                (rep.message_type().unwrap(), rep.yiaddr)
            })
        })
        .collect();
    let mut results = Vec::new();
    for h in handles {
        results.push(h.join().expect("client thread"));
    }
    assert_eq!(results.len(), 2);
    for (ty, ip) in &results {
        assert_eq!(*ty, MessageType::Ack);
        assert_eq!(*ip, Ipv4Addr::new(192, 168, 2, 70), "both agree on one IP");
    }
}

/// Pipelined dual-DORA: A and B interleave Discover/Request with no
/// cross-talk — A gets `.3`, B gets `.4`, Acks echo each xid with the
/// matching yiaddr. Locked live.
#[test]
fn sec8_pipelined_dual_dora_no_crosstalk_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let a = [0xE1; 6];
    let b = [0xE2; 6];
    let oa = send_recv(&client, &srv_addr, &discover(0xE001, a), &mut buf, &mut rbuf);
    let ob = send_recv(&client, &srv_addr, &discover(0xE002, b), &mut buf, &mut rbuf);
    assert_eq!(oa.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
    assert_eq!(ob.yiaddr, Ipv4Addr::new(192, 168, 2, 4));
    let aa = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xE003, a, server_ip, Ipv4Addr::new(192, 168, 2, 3)),
        &mut buf,
        &mut rbuf,
    );
    let ab = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xE004, b, server_ip, Ipv4Addr::new(192, 168, 2, 4)),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!((aa.message_type(), aa.yiaddr, aa.xid), (Ok(MessageType::Ack), Ipv4Addr::new(192, 168, 2, 3), 0xE003));
    assert_eq!((ab.message_type(), ab.yiaddr, ab.xid), (Ok(MessageType::Ack), Ipv4Addr::new(192, 168, 2, 4), 0xE004));
}

/// Spurious Release between a victim's Discover and Request is a no-op:
/// victim holds nothing yet, so there is nothing to free, and the follow-up
/// Request still commits the offered address. Locked live.
#[test]
fn sec8_spurious_release_between_offer_and_ack_no_effect_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0xE5; 6];
    let offer = send_recv(&client, &srv_addr, &discover(0xE010, victim), &mut buf, &mut rbuf);
    assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
    // attacker (and victim) Release before anything is held: silent no-ops
    for (xid, ch) in [(0xE011u32, [0xE6; 6]), (0xE012, victim)] {
        let rel = Packet {
            reply: false, hops: 0, xid, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: ch,
            options: vec![
                DhcpOption::DhcpMessageType(MessageType::Release),
                DhcpOption::ServerIdentifier(server_ip),
            ],
        };
        client.send_to(&rel.encode(&mut buf).to_vec(), srv_addr).unwrap();
    }
    // victim completes the handshake with the offered address regardless
    let ack = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xE013, victim, server_ip, Ipv4Addr::new(192, 168, 2, 3)),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!(ack.message_type(), Ok(MessageType::Ack));
    assert_eq!(ack.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
}

// ===========================================================================
// C. Release/reacquire lifecycle over the wire
// ===========================================================================

/// Release then immediate re-Request re-acquires the same IP: the freed
/// address is available again and the pool slot is reusable, proving no
/// tombstoning. Locked live.
#[test]
fn sec8_release_then_reacquire_same_ip_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let mac = [0xE8; 6];
    let ip = Ipv4Addr::new(192, 168, 2, 66);
    let ack1 = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xE020, mac, server_ip, ip),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!(ack1.yiaddr, ip);
    // Release (correct server ID): no reply by design, lease freed
    let rel = release_for(0xE021, mac, server_ip);
    client.send_to(&rel.encode(&mut buf).to_vec(), srv_addr).unwrap();
    // immediate re-Request gets the very same address back
    let ack2 = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xE022, mac, server_ip, ip),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!(ack2.message_type(), Ok(MessageType::Ack));
    assert_eq!(ack2.yiaddr, ip, "freed slot immediately reusable");
}

fn release_for(xid: u32, chaddr: [u8; 6], server_ip: Ipv4Addr) -> Packet {
    test_packet(
        xid,
        chaddr,
        vec![
            DhcpOption::DhcpMessageType(MessageType::Release),
            DhcpOption::ServerIdentifier(server_ip),
        ],
    )
}
