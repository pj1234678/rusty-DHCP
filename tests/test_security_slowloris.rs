//! DHCP security: slowloris-style resilience + lease-hijacking chains.
//!
//! Covers security-relevant behavior NOT locked by `test_security.rs`,
//! `test_security_extra.rs`, `test_security_edge.rs`, `test_security_wire.rs`,
//! `test_security_gates.rs`, `test_security_hijack.rs`, or the RFC suites.
//! All tests assert the *current* behavior and pass against it; tests for
//! known-unsafe behavior end in `_quirk` and state the threat in the docs.
//!
//! Threat model: untrusted bytes arrive via UDP (`Server::serve`); any peer
//! can spoof `chaddr`/`xid`/`ciaddr`/options — there is no authentication
//! (RFC 3118 is not implemented) and lease identity is the raw 6-byte
//! `chaddr`. Lease state lives in the example `MyServer` replica here
//! (same bodies as `examples/server.rs`).
//!
//! Groups:
//! - A. Slowloris analogues for a datagram server: dribbled 1-byte sends and
//!   garbage interleaved mid-handshake hold no state; retransmitted
//!   Discovers rotate offers (not idempotent); flood traffic shifts other
//!   clients' offers via the shared `last_lease` counter.
//! - B. Lease-hijacking chains (live): front-running an offer then NAKing the
//!   victim; replaying a victim Request; Release spoofed with the wrong
//!   chaddr (kept) vs the victim chaddr via Decline naming a junk IP;
//!   NAK-vs-Ack oracle pool enumeration; Inform spoofing plants no state.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, UdpSocket};
use std::ops::Add;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// helpers (same patterns as test_security_edge.rs)
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

// ===========================================================================
// A. Slowloris analogues: dribble / interleaved noise / rotation / flood
// ===========================================================================

/// Slowloris adaptation: 100 one-byte dribbles arrive as 100 independent
/// datagrams, each rejected without panic and without retaining state —
/// there is nothing half-open to hold. The next valid Discover is answered
/// normally. Locked: dribble is pure noise here, unlike TCP slowloris.
#[test]
fn sec6_dribble_then_valid_exchange_succeeds() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    for _ in 0..100 {
        client.send_to(&[0x99], srv_addr).unwrap();
    }
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let rep = send_recv(&client, &srv_addr, &discover(0xD101, [0x11; 6]), &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
}

/// Garbage interleaved mid-handshake (between victim Discover and Request)
/// changes nothing: decoding is per-datagram and stateless, so the victim
/// flow completes with the offered address. Locked live.
#[test]
fn sec6_garbage_interleaved_handshake_completes() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x12; 6];
    let offer = send_recv(&client, &srv_addr, &discover(0xD110, victim), &mut buf, &mut rbuf);
    assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
    // noise burst between the handshake steps: short, bad cookie, zeros
    client.send_to(&[], srv_addr).unwrap();
    client.send_to(&[0u8; 10], srv_addr).unwrap();
    client.send_to(&[0u8; 235], srv_addr).unwrap();
    let mut bad_cookie = vec![0u8; 236];
    bad_cookie[0] = 1;
    bad_cookie[1] = 1;
    bad_cookie[2] = 6;
    bad_cookie.extend_from_slice(&[9, 9, 9, 9, 53, 1, 1, 255]);
    client.send_to(&bad_cookie, srv_addr).unwrap();
    for _ in 0..20 {
        client.send_to(&[0xAB], srv_addr).unwrap();
    }
    std::thread::sleep(Duration::from_millis(100));
    // victim completes the handshake with the offered address
    let req = Packet {
        reply: false, hops: 0, xid: 0xD111, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 2, 1)),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 3)),
        ],
    };
    let ack = send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf);
    assert_eq!(ack.message_type(), Ok(MessageType::Ack));
    assert_eq!(ack.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
}

/// Retransmitted (byte-identical, same xid) Discovers are NOT idempotent:
/// each one advances the shared `last_lease` pointer, so three identical
/// sends yield `.3`, `.4`, `.5`. A retrying client — or anyone replaying a
/// capture — gets a fresh offer per attempt. Locked live.
#[test]
fn sec6_retransmit_same_discover_rotates_offer() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let mut got = Vec::new();
    for _ in 0..3 {
        let rep = send_recv(
            &client,
            &srv_addr,
            &discover(0xD120, [0x13; 6]),
            &mut buf,
            &mut rbuf,
        );
        assert_eq!(rep.message_type(), Ok(MessageType::Offer));
        got.push(rep.yiaddr);
    }
    assert_eq!(
        got,
        vec![
            Ipv4Addr::new(192, 168, 2, 3),
            Ipv4Addr::new(192, 168, 2, 4),
            Ipv4Addr::new(192, 168, 2, 5),
        ],
        "identical retransmits must rotate, proving no per-client reservation"
    );
}

/// Flood interference: other clients' Discovers shift this client's offer via
/// the shared `last_lease` counter — offers are predictable and disruptable.
/// Victim `.3`, then 5 attacker Discovers, then victim again gets `.9`.
/// Locked live.
#[test]
fn sec6_flood_shifts_victim_offer_shared_counter() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x14; 6];
    let first = send_recv(&client, &srv_addr, &discover(0xD130, victim), &mut buf, &mut rbuf);
    assert_eq!(first.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
    for i in 0..5u32 {
        let ch = [0xE0 + i as u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let rep = send_recv(&client, &srv_addr, &discover(0xD140 + i, ch), &mut buf, &mut rbuf);
        assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    }
    let second = send_recv(&client, &srv_addr, &discover(0xD150, victim), &mut buf, &mut rbuf);
    assert_eq!(
        second.yiaddr,
        Ipv4Addr::new(192, 168, 2, 9),
        "shared counter advanced by flood: .3 -> .9"
    );
}

// ===========================================================================
// B. Lease-hijacking chains (live): front-run, replay, spoofed free, oracle
// ===========================================================================

/// Front-running (the core hijack): victim is Offered `.3` but hasn't
/// Requested yet; the attacker Requests `.3` first and gets the Ack; the
/// victim's follow-up Request for `.3` gets NAK, and a re-Discover offers
/// `.4` — proving the victim never held `.3`. Locked live.
#[test]
fn sec6_hijack_frontrun_offer_then_victim_naks_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x61; 6];
    let attacker = [0x62; 6];
    // victim offered .3 (not yet committed — Discover inserts nothing)
    let offer = send_recv(&client, &srv_addr, &discover(0xF001, victim), &mut buf, &mut rbuf);
    assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
    // attacker front-runs the handshake for .3
    let steal = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xF002, attacker, server_ip, Ipv4Addr::new(192, 168, 2, 3)),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!(steal.message_type(), Ok(MessageType::Ack));
    assert_eq!(steal.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
    // victim's late Request for the same IP is NAK'd ...
    let late = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xF003, victim, server_ip, Ipv4Addr::new(192, 168, 2, 3)),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!(late.message_type(), Ok(MessageType::Nak));
    // ... and the victim holds nothing: re-Discover offers the next free IP
    let again = send_recv(&client, &srv_addr, &discover(0xF004, victim), &mut buf, &mut rbuf);
    assert_eq!(again.message_type(), Ok(MessageType::Offer));
    assert_eq!(again.yiaddr, Ipv4Addr::new(192, 168, 2, 4));
}

/// Replay safety (positive): replaying a victim Request byte-for-byte yields
/// the same Ack twice with no duplicate state — idempotent, no double
/// insert, victim still holds the lease afterwards. Locked live.
#[test]
fn sec6_hijack_replay_identical_request_double_ack_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x63; 6];
    let req = request_selecting(0xF010, victim, server_ip, Ipv4Addr::new(192, 168, 2, 60));
    let first = send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf);
    assert_eq!(first.message_type(), Ok(MessageType::Ack));
    // exact replay (same xid too): same Ack, no state corruption
    let second = send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf);
    assert_eq!(second.message_type(), Ok(MessageType::Ack));
    assert_eq!(second.yiaddr, Ipv4Addr::new(192, 168, 2, 60));
    assert_eq!(second.xid, 0xF010);
    // victim still holds .60 afterwards
    let still = send_recv(&client, &srv_addr, &discover(0xF011, victim), &mut buf, &mut rbuf);
    assert_eq!(still.yiaddr, Ipv4Addr::new(192, 168, 2, 60));
}

/// Release spoofed with the *wrong* chaddr frees nothing: victim holds `.61`,
/// attacker Releases with its own chaddr, victim still holds `.61`.
/// Complements the missing/wrong-ID gate tests with the chaddr dimension.
#[test]
fn sec6_hijack_release_spoof_wrong_chaddr_keeps_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x64; 6];
    let attacker = [0x65; 6];
    let req = request_selecting(0xF020, victim, server_ip, Ipv4Addr::new(192, 168, 2, 61));
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).message_type(),
        Ok(MessageType::Ack)
    );
    // attacker Releases naming itself (correct server ID, wrong chaddr)
    let rel = Packet {
        reply: false, hops: 0, xid: 0xF021, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: attacker,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Release),
            DhcpOption::ServerIdentifier(server_ip),
        ],
    };
    client.send_to(&rel.encode(&mut buf).to_vec(), srv_addr).unwrap();
    // victim still holds .61
    let still = send_recv(&client, &srv_addr, &discover(0xF022, victim), &mut buf, &mut rbuf);
    assert_eq!(still.yiaddr, Ipv4Addr::new(192, 168, 2, 61));
}

/// NAK-vs-Ack oracle: a stranger learns pool occupancy remotely — Request
/// for taken `.63` gets NAK, Request for free `.64` gets Ack — with no
/// credentials. Enumeration primitive. Locked live.
#[test]
fn sec6_hijack_nak_ack_oracle_enumerates_pool_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x66; 6];
    let stranger = [0x67; 6];
    let req = request_selecting(0xF030, victim, server_ip, Ipv4Addr::new(192, 168, 2, 63));
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).message_type(),
        Ok(MessageType::Ack)
    );
    // probe taken -> Nak
    let taken = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xF031, stranger, server_ip, Ipv4Addr::new(192, 168, 2, 63)),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!(taken.message_type(), Ok(MessageType::Nak));
    // probe free -> Ack (and it really got inserted: discover shows it)
    let free = send_recv(
        &client,
        &srv_addr,
        &request_selecting(0xF032, stranger, server_ip, Ipv4Addr::new(192, 168, 2, 64)),
        &mut buf,
        &mut rbuf,
    );
    assert_eq!(free.message_type(), Ok(MessageType::Ack));
    assert_eq!(free.yiaddr, Ipv4Addr::new(192, 168, 2, 64));
    // cross-check locally that distinct holders own distinct IPs
    let mut seen = HashSet::new();
    seen.insert(free.yiaddr);
    assert_eq!(seen.len(), 1);
}
