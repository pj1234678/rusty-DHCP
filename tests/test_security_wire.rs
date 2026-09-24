//! DHCP security wire + gate composition, part 4.
//!
//! Covers security-relevant behavior NOT locked by `test_security.rs`,
//! `test_security_extra.rs`, `test_security_edge.rs`, or the RFC suites:
//!
//! - malformed Server ID on a Release is stripped by the decoder, so the
//!   `for_this_server` gate fails closed and the lease survives (live)
//! - wrong (but well-formed) Server ID on Release likewise keeps the lease
//! - malformed Requested IP falls back to `ciaddr` per the example match
//! - framing is purely length-delimited: fake cookies, fake option headers
//!   and END bytes inside option data never resync parsing; END bytes in
//!   `chaddr` don't confuse framing either
//! - oversized inputs stay bounded (4096-byte datagram decodes, re-encodes
//!   capped); empty PRL still yields the required defaults live
//! - critical-address Requests (server IP, broadcast, 0.0.0.0) NAK cleanly
//!   with no table insert; max `secs`/`hops` decode exactly
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

#[allow(clippy::too_many_arguments)]
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

// Replica of examples/server.rs lease state (bodies identical; only the
// methods needed here are included).
const IP_START: [u8; 4] = [192, 168, 2, 2];
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);
const LEASE_NUM: u32 = 252;
const LEASE_DURATION_SECS: u32 = 86400;

struct Replica {
    leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
    #[allow(dead_code)]
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
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            server_ip,
            Ipv4Addr::new(192, 168, 2, 255),
            ExampleLike::new(server_ip),
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

// ===========================================================================
// A. Malformed vs wrong Server ID on Release: both fail closed (live)
// ===========================================================================

/// A Release whose Server Identifier is truncated on the wire (`len` 3)
/// decodes to *no* Server ID at all, so `for_this_server` is false and the
/// lease survives. Wire-levelzott malformation fails closed for Release.
/// Locked live.
#[test]
fn sec3_truncated_server_id_release_keeps_lease_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x31; 6];
    // occupy .61 with a well-formed Request
    let req = Packet {
        reply: false, hops: 0, xid: 0xF001, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 61)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).message_type(),
        Ok(MessageType::Ack)
    );
    // Release with truncated Server ID [54,3,10,20,30]: stripped on decode
    let raw = make_raw(
        1, 6, 0, 0xF002, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        victim, vec![53, 1, 7, 54, 3, 10, 20, 30, 255],
    );
    // sanity: decoder really drops the identifier (fail-closed precondition)
    let decoded = unwrap_packet(Packet::from(&raw));
    assert!(decoded.option(SERVER_IDENTIFIER).is_none());
    client.send_to(&raw, srv_addr).unwrap();
    // lease kept: Discover still offers .61
    let disc = Packet {
        reply: false, hops: 0, xid: 0xF003, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let offer = send_recv(&client, &srv_addr, &disc, &mut buf, &mut rbuf);
    assert_eq!(offer.message_type(), Ok(MessageType::Offer));
    assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 2, 61), "lease kept");
}

/// A well-formed Release naming the WRONG server is likewise ignored live —
/// the lease survives and Discover still offers it. Complements the
/// missing-ID case with a wrong-value case.
#[test]
fn sec3_wrong_server_id_release_keeps_lease_live() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x32; 6];
    let req = Packet {
        reply: false, hops: 0, xid: 0xF010, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 2, 1)),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 62)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).message_type(),
        Ok(MessageType::Ack)
    );
    // Release naming a different server: ignored
    let rel = Packet {
        reply: false, hops: 0, xid: 0xF011, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Release),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 99, 99, 99)),
        ],
    };
    client.send_to(&rel.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let disc = Packet {
        reply: false, hops: 0, xid: 0xF012, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let offer = send_recv(&client, &srv_addr, &disc, &mut buf, &mut rbuf);
    assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 2, 62), "lease kept");
}

// ===========================================================================
// B. Malformed Requested IP falls back to ciaddr (no crash, no bypass)
// ===========================================================================

/// A Requested-IP option truncated to 3 bytes is stripped by the decoder, so
/// the example `match option(50) / _ => ciaddr` falls back to `ciaddr`.
/// The fallback address (.71) is Acked and inserted — never the truncated
/// bytes, never a panic. Locked.
#[test]
fn sec3_malformed_requested_ip_falls_back_to_ciaddr() {
    let raw = make_raw(
        1, 6, 0, 0xF020, 0, [0, 0],
        [192, 168, 2, 71], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [0x33; 6],
        vec![53, 1, 3, 50, 3, 10, 0, 0, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.message_type(), Ok(MessageType::Request));
    assert!(p.option(REQUESTED_IP_ADDRESS).is_none(), "truncated option stripped");
    // byte-for-byte example selection: RequestedIp else ciaddr
    let req_ip = match p.option(REQUESTED_IP_ADDRESS) {
        Some(DhcpOption::RequestedIpAddress(x)) => *x,
        _ => p.ciaddr,
    };
    assert_eq!(req_ip, Ipv4Addr::new(192, 168, 2, 71), "falls back to ciaddr");
    let mut s = Replica::new();
    assert_eq!(
        s.request(&[0x33; 6], p.option(REQUESTED_IP_ADDRESS).and_then(|o| match o {
            DhcpOption::RequestedIpAddress(x) => Some(*x),
            _ => None,
        }), p.ciaddr, true),
        Ok(Ipv4Addr::new(192, 168, 2, 71))
    );
    assert!(s.leases.contains_key(&Ipv4Addr::new(192, 168, 2, 71)));
}

// ===========================================================================
// C. Framing is purely length-delimited (no sentinel scanning)
// ===========================================================================

/// Fake magic cookie, fake option header and END *byte values* inside option
/// data never resync parsing: decode consumes exactly `len` bytes, so the
/// real Offer option after them still decodes and `message_type()` finds it.
#[test]
fn sec3_embedded_cookie_and_end_bytes_ignored_in_data() {
    let mut opts = vec![200, 6, 99, 130, 83, 99, 255, 53]; // data: cookie+END+53
    opts.extend_from_slice(&[53, 1, 2, 255]); // real Offer
    let raw = make_raw(
        1, 6, 0, 0xF030, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [0x34; 6], opts,
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 2);
    match &p.options[0] {
        DhcpOption::Unrecognized(r) => {
            assert_eq!(r.code, 200);
            assert_eq!(r.data, vec![99, 130, 83, 99, 255, 53]);
        }
        _ => panic!("first option must be the Unrecognized carrier"),
    }
    assert_eq!(p.message_type(), Ok(MessageType::Offer));
}

/// END bytes (255) in `chaddr` don't confuse framing: the 6-byte field is
/// positional, so `chaddr == [255; 6]` round-trips exactly with options intact.
#[test]
fn sec3_end_bytes_in_chaddr_no_confusion() {
    let raw = make_raw(
        1, 6, 0, 0xF031, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [255; 6],
        vec![53, 1, 1, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.chaddr, [255; 6]);
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
}

// ===========================================================================
// D. Oversized inputs stay bounded; empty PRL still yields defaults
// ===========================================================================

/// A 4096-byte datagram (past the 1500 MTU buffers) decodes with the option
/// Vec bounded by the input (~1285 entries, no amplification) and re-encodes
/// capped at 300 with Discover first. No panic at either size.
#[test]
fn sec3_4096_byte_datagram_decodes_bounded() {
    let mut opts = vec![53, 1, 1];
    for _ in 0..1284 {
        opts.extend_from_slice(&[200, 1, 7]);
    }
    opts.push(255);
    let raw = make_raw(
        1, 6, 0, 0xF040, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [0x35; 6], opts,
    );
    assert_eq!(raw.len(), 4096);
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 1285, "1 Discover + 1284 fillers");
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(enc.len() <= 300, "re-encode capped");
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(q.message_type(), Ok(MessageType::Discover));
    assert_eq!(q.options.len(), 19, "Discover + 18 fillers");
}

/// Empty PRL (`len` 0) is valid and live-filters to the required defaults:
/// a Request asking for nothing extra still gets `[53,54,51]`. An attacker
/// cannot use an empty list to strip Server ID / lease time. Locked live.
#[test]
fn sec3_empty_prl_returns_defaults_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = Packet {
        reply: false, hops: 0, xid: 0xF041, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0x36; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 72)),
            DhcpOption::ParameterRequestList(vec![]),
        ],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("Ack");
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(MessageType::Ack));
    assert_eq!(
        rep.options.iter().map(|o| o.code()).collect::<Vec<u8>>(),
        vec![53, 54, 51],
        "empty PRL keeps required + defaults"
    );
}

// ===========================================================================
// E. Critical-address Requests NAK cleanly; secs/hops extremes preserved
// ===========================================================================

/// Requests for the server's own IP, the subnet broadcast, and explicit
/// 0.0.0.0 all NAK with no table insert — critical identities can never be
/// handed out, and 0.0.0.0 never enters the map. Locked.
#[test]
fn sec3_critical_and_unspecified_requests_nak_without_insert() {
    let mut s = Replica::new();
    for ip in [
        Ipv4Addr::new(192, 168, 2, 1),   // server identity
        Ipv4Addr::new(192, 168, 2, 255), // subnet broadcast
        Ipv4Addr::new(0, 0, 0, 0),       // unspecified
    ] {
        assert!(
            s.request(&[0x37; 6], Some(ip), Ipv4Addr::UNSPECIFIED, true).is_err(),
            "must NAK {}",
            ip
        );
    }
    assert!(s.leases.is_empty(), "nothing critical/unspecified may be leased");
}

/// Max `secs` (0xFFFF) and `hops` 255 decode exactly — no clamping that could
/// desync retransmission/loop accounting between peers. Locked.
#[test]
fn sec3_secs_hops_max_preserved_on_decode() {
    let raw = make_raw(
        1, 6, 255, 0xF050, 0xFFFF, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [0x38; 6],
        vec![53, 1, 1, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.secs, 0xFFFF);
    assert_eq!(p.hops, 255);
}
