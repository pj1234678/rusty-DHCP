//! DHCP security: denial-of-service behavior, part 6.
//!
//! Covers DOS-relevant behavior NOT locked by `test_security.rs`,
//! `test_security_extra.rs`, `test_security_edge.rs`, `test_security_wire.rs`,
//! `test_security_gates.rs`, `test_security_hijack.rs`,
//! `test_security_slowloris.rs`, or the RFC suites. All tests assert the
//! *current* behavior and pass against it; tests for known-unsafe behavior
//! end in `_quirk` and state the threat in the docs.
//!
//! Findings locked here: the server performs NO rate limiting (every
//! unsatisfiable Request earns a NAK, every Release/Inform is processed),
//! the single-threaded loop serializes parallel clients without drops,
//! replies bear no relation to request count, and both decode and encode
//! paths stay bounded (option count capped by datagram size on decode and
//! by the 300-byte wire cap on encode, including the reply path).
//!
//! Groups:
//! - A. No rate limiting: NAK storms, Release storms, Inform floods are all
//!   processed; the server stays responsive throughout.
//! - B. Concurrency: parallel clients are serialized without drops,
//!   cross-talk, or xid confusion.
//! - C. Allocation bounds: minimal-option bomb hits the theoretical decoder
//!   maximum; a 500-option reply is capped to 300 bytes on the wire.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::collections::{HashMap, HashSet};
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

// Exact replica of examples/server.rs lease state (see test_examples_extra).
const IP_START: [u8; 4] = [192, 168, 2, 2];
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);
const LEASE_NUM: u32 = 252;
const LEASE_DURATION_SECS: u32 = 86400;

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

fn drain_replies(client: &UdpSocket, rbuf: &mut [u8; 1500], wait_ms: u64) -> usize {
    client
        .set_read_timeout(Some(Duration::from_millis(wait_ms)))
        .unwrap();
    let mut count = 0;
    loop {
        match client.recv_from(rbuf) {
            Ok(_) => count += 1,
            Err(_) => break,
        }
    }
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    count
}

// ===========================================================================
// A. No rate limiting: storms are fully processed, server stays responsive
// ===========================================================================

/// QUIRK (NAK storm): 20 rapid Requests for a taken IP each earn a full NAK
/// — no suppression, no backoff — then the victim still holds the lease.
/// An attacker can elicit unbounded replies at roughly 1:1 cost. Locked.
#[test]
fn sec7_nak_storm_all_answered_no_suppression() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x71; 6];
    // victim takes .60
    let req = request_selecting(0xA001, victim, server_ip, Ipv4Addr::new(192, 168, 2, 60));
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).message_type(),
        Ok(MessageType::Ack)
    );
    // storm: 20 distinct chaddrs hammer the taken IP, every one NAK'd
    for i in 0..20u32 {
        let ch = [0x70 + i as u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let grab = request_selecting(0xA100 + i, ch, server_ip, Ipv4Addr::new(192, 168, 2, 60));
        let rep = send_recv(&client, &srv_addr, &grab, &mut buf, &mut rbuf);
        assert_eq!(rep.message_type(), Ok(MessageType::Nak), "storm {}", i);
        assert_eq!(rep.xid, 0xA100 + i, "per-request xid echo in storm");
    }
    // victim still holds .60 afterwards
    let still = send_recv(&client, &srv_addr, &discover(0xA002, victim), &mut buf, &mut rbuf);
    assert_eq!(still.yiaddr, Ipv4Addr::new(192, 168, 2, 60));
}

/// 50 Releases for unknown chaddrs are silent no-ops that still cost a
/// decode + HashMap lookup each — then a valid Discover is answered,
/// proving the storm neither crashed the loop nor planted state.
#[test]
fn sec7_release_storm_unknown_chaddrs_no_state_no_crash() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    for i in 0..50u32 {
        let ch = [0x80 + (i % 250) as u8, 0x11, 0x22, 0x33, 0x44, 0x55];
        let rel = Packet {
            reply: false, hops: 0, xid: 0xB000 + i, secs: 0, broadcast: false,
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
    // no state planted: fresh client gets the first offer, server alive
    let rep = send_recv(&client, &srv_addr, &discover(0xB100, [0x99; 6]), &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
}

/// 20 INFORMs earn zero replies (each ignored) yet each is fully decoded —
/// pure inbound processing cost with no outbound traffic and no state.
/// Drain proves the count is exactly 0, then Discover proves liveness.
#[test]
fn sec7_inform_flood_zero_replies_no_state() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    for i in 0..20u32 {
        let ch = [0x90 + i as u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let inf = Packet {
            reply: false, hops: 0, xid: 0xC000 + i, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::new(192, 168, 2, 60), yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: ch,
            options: vec![
                DhcpOption::DhcpMessageType(MessageType::Inform),
                DhcpOption::ParameterRequestList(vec![1, 15]),
            ],
        };
        client.send_to(&inf.encode(&mut buf).to_vec(), srv_addr).unwrap();
    }
    assert_eq!(drain_replies(&client, &mut rbuf, 400), 0, "INFORM flood: no replies");
    let rep = send_recv(&client, &srv_addr, &discover(0xC100, [0x9A; 6]), &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 3), "no state planted");
}

// ===========================================================================
// B. Concurrency: parallel clients serialized without drops or cross-talk
// ===========================================================================

/// Five threads × 8 Discovers (40 distinct identities) run concurrently
/// against the single-threaded loop: all 40 Offers arrive, xids echo
/// per-transaction, and all 40 yiaddrs are distinct pool addresses.
/// Locked: serialization is correct under parallel load.
#[test]
fn sec7_concurrent_clients_all_answered_distinct() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            // fixed offer allocator keyed off the full client identity:
            // stateless, so concurrent order cannot affect correctness.
            let n = p.chaddr[0] as u16 * 8 + p.chaddr[5] as u16;
            let _ = s.reply(
                MessageType::Offer,
                vec![],
                Ipv4Addr::new(192, 168, 9, 10 + (n % 200) as u8),
                p,
            );
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
    let mut handles = Vec::new();
    for t in 0..5u32 {
        let srv = srv_addr;
        handles.push(std::thread::spawn(move || {
            let client = UdpSocket::bind("127.0.0.1:0").unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 1500];
            let mut rbuf = [0u8; 1500];
            let mut out = Vec::new();
            for i in 0..8u32 {
                // distinct chaddr per request; first octet unique per thread
                let ch = [(10 + t) as u8, 0xAA, 0xBB, 0xCC, 0xDD, i as u8];
                let xid = 0xD000 + t * 100 + i;
                let p = discover(xid, ch);
                client.send_to(&p.encode(&mut buf).to_vec(), srv).unwrap();
                let (n, _) = client.recv_from(&mut rbuf).expect("concurrent reply");
                let rep = unwrap_packet(Packet::from(&rbuf[..n]));
                out.push((rep.xid, rep.yiaddr, rep.chaddr));
            }
            out
        }));
    }
    let mut xids = HashSet::new();
    let mut ips = HashSet::new();
    for h in handles {
        for (xid, ip, ch) in h.join().expect("client thread") {
            // xid echoed for its own transaction: full identity inverts
            // cleanly from it, proving the reply matches its requester.
            let expect_t = (xid - 0xD000) / 100;
            let expect_i = (xid - 0xD000) % 100;
            assert!(expect_t < 5 && expect_i < 8);
            assert_eq!(
                [10 + expect_t as u8, 0xAA, 0xBB, 0xCC, 0xDD, expect_i as u8],
                ch,
                "reply matches its requester"
            );
            xids.insert(xid);
            ips.insert(ip);
        }
    }
    assert_eq!(xids.len(), 40, "every transaction answered exactly once");
    assert_eq!(ips.len(), 40, "no cross-talk between concurrent clients");
}

/// Same xid from two distinct chaddrs: both answered independently with the
/// same xid echoed and different yiaddrs — the server keys nothing on xid,
/// so collisions cannot confuse or suppress a peer. Locked.
#[test]
fn sec7_same_xid_distinct_chaddrs_independent() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let a = send_recv(&client, &srv_addr, &discover(0xD0D0, [0xA1; 6]), &mut buf, &mut rbuf);
    let b = send_recv(&client, &srv_addr, &discover(0xD0D0, [0xA2; 6]), &mut buf, &mut rbuf);
    assert_eq!(a.xid, 0xD0D0);
    assert_eq!(b.xid, 0xD0D0);
    assert_ne!(a.yiaddr, b.yiaddr, "distinct clients, distinct offers");
    assert_eq!(a.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
    assert_eq!(b.yiaddr, Ipv4Addr::new(192, 168, 2, 4));
}

// ===========================================================================
// C. Allocation bounds: decoder maximum and reply-path cap
// ===========================================================================

/// Minimal 2-byte options hit the theoretical decoder maximum: header+cookie
/// (240) + Discover (3) + 628×`[200,0]` (1256) + END (1) = exactly 1500.
/// All 629 decode without panic; re-encode caps at 300 with Discover first.
/// Tightens the 419-entry bomb test to the true bound. Locked.
#[test]
fn sec7_minimal_option_bomb_hits_decoder_maximum() {
    let mut opts = vec![53, 1, 1];
    for _ in 0..628 {
        opts.extend_from_slice(&[200, 0]);
    }
    opts.push(255);
    let mut raw = vec![0u8; 236];
    raw[0] = 1;
    raw[1] = 1;
    raw[2] = 6;
    raw[4..8].copy_from_slice(&0xE001u32.to_be_bytes());
    raw[28..34].copy_from_slice(&[0xE1; 6]);
    raw.extend_from_slice(&[99, 130, 83, 99]);
    raw.extend_from_slice(&opts);
    assert_eq!(raw.len(), 1500, "construction must fill the MTU exactly");
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 629, "1 Discover + 628 minimal fillers");
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(enc.len() <= 300, "re-encode capped");
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(q.message_type(), Ok(MessageType::Discover), "Discover kept first");
    assert_eq!(q.options.len(), 29, "Discover + 28 fillers + END accounting");
}

/// Reply path with 500 extra options still emits at most 300 bytes: the
/// encode cap applies to server replies too, so a greedy handler config
/// cannot bloat answers (no reply-side amplification past the cap). Locked.
#[test]
fn sec7_reply_with_hundreds_of_options_capped_live() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let mut extra = Vec::with_capacity(500);
            for i in 0..500u16 {
                extra.push(DhcpOption::Unrecognized(RawDhcpOption {
                    code: 200,
                    data: vec![(i & 0xFF) as u8],
                }));
            }
            let _ = s.reply(MessageType::Offer, extra, Ipv4Addr::new(192, 168, 8, 10), p);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 8, 1),
            Ipv4Addr::new(192, 168, 8, 255),
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
    let p = discover(0xE010, [0xE1; 6]);
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("capped reply");
    assert!(n <= 300, "reply capped at wire cap, got {}", n);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 8, 10));
}
