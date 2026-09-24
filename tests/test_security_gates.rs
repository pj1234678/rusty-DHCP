//! DHCP security gates + filter/framing compositions, part 5.
//!
//! Covers security-relevant behavior NOT locked by `test_security.rs`,
//! `test_security_extra.rs`, `test_security_edge.rs`, `test_security_wire.rs`
//! or the RFC suites — mostly *compositions* of individually-tested quirks:
//!
//! - PRL filtering (not just the 300 cap) strips the NAK Message text live
//! - an RFC-valid PAD byte before END truncates the option list (desync via
//!   spec-compliant bytes, unlike the malformed-option tests)
//! - zero-length option matrix: which empty options decode vs reject,
//!   including the Router/DNS-empty quirk
//! - empty Router/DNS encode to `[3,0]`/`[6,0]` on the wire but decode-drop,
//!   while empty PRL survives (asymmetry)
//! - garbage-datagram battery (empty/1-byte/short/bad-cookie) keeps the
//!   server alive for the next valid Discover
//! - kernel-style truncation of an oversized datagram decodes without panic
//! - Request with a *wrong* (not just missing) Server ID is still honored
//! - Decline from an unknown chaddr is a silent no-op with no reply
//! - broadcast-flagged Release still frees when the gate passes
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
// helpers (same patterns as test_security_wire.rs)
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
// A. PRL filtering (not size) strips the NAK text; RFC-valid PAD desyncs
// ===========================================================================

/// The NAK Message is dropped by *PRL filtering* here, not just the 300 cap:
/// unit-level, `[53,54,56]` filtered by req `[1]` keeps `[53,54]` although
/// the 7-byte packet would easily fit. Live, a victim Request carrying
/// PRL=`[1]` gets a textless NAK. Locked (both mechanisms coincide live).
#[test]
fn sec4_nak_message_dropped_by_prl_filter_not_size() {
    // unit: short text fits size-wise, filter drops it anyway
    let mut opts = vec![
        DhcpOption::DhcpMessageType(MessageType::Nak),
        DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 2, 1)),
        DhcpOption::Message("no".to_string()),
    ];
    server::filter_options_by_req(&mut opts, &[1]);
    assert_eq!(
        opts.iter().map(|o| o.code()).collect::<Vec<u8>>(),
        vec![53, 54],
        "PRL [1] drops Message even though it fits"
    );
    // live: occupier takes .50, victim asks with PRL=[1] -> textless NAK
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let occupier = Packet {
        reply: false, hops: 0, xid: 0xA001, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xA0; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 50)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &occupier, &mut buf, &mut rbuf).message_type(),
        Ok(MessageType::Ack)
    );
    let req = Packet {
        reply: false, hops: 0, xid: 0xA002, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xA1; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 50)),
            DhcpOption::ParameterRequestList(vec![1]),
        ],
    };
    let rep = send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Nak));
    assert!(rep.option(MESSAGE).is_none(), "PRL filter strips NAK text");
    assert_eq!(
        rep.option(SERVER_IDENTIFIER),
        Some(&DhcpOption::ServerIdentifier(server_ip))
    );
}

/// RFC 2132 says receivers MUST handle PAD octets, but here a single
/// spec-compliant `0x00` before END truncates the option list exactly like a
/// malformed option: Server ID after the PAD is stripped, leading Discover
/// survives. Desync with fully valid bytes — locked.
#[test]
fn sec4_rfc_pad_byte_before_end_truncates_list() {
    let raw = make_raw(
        1, 6, 0, 0xA010, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [0xA2; 6],
        vec![53, 1, 1, 0, 54, 4, 10, 20, 30, 40, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 1, "PAD truncates like a bad option");
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
    assert!(p.option(SERVER_IDENTIFIER).is_none(), "Server ID stripped");
}

// ===========================================================================
// B. Zero-length option matrix (decode edges per code)
// ===========================================================================

/// Zero-length options split by kind: variable-length/text codes accept
/// empty (`55`/`12`/`56`/unrecognized incl. PAD-as-TLV `0`), while every
/// fixed-size code rejects — including Router/DNS, which fail even empty
/// (same `custom_many0` quirk as populated ones). Exact errors locked.
#[test]
fn sec4_zero_length_option_matrix() {
    // accepted as empty
    match decode_option(&[55, 0]) {
        Ok((_, DhcpOption::ParameterRequestList(v))) => assert!(v.is_empty()),
        _ => panic!("[55,0] must decode to empty PRL"),
    }
    match decode_option(&[12, 0]) {
        Ok((_, DhcpOption::HostName(s))) => assert_eq!(s, ""),
        _ => panic!("[12,0] must decode to empty HostName"),
    }
    match decode_option(&[56, 0]) {
        Ok((_, DhcpOption::Message(s))) => assert_eq!(s, ""),
        _ => panic!("[56,0] must decode to empty Message"),
    }
    match decode_option(&[99, 0]) {
        Ok((_, DhcpOption::Unrecognized(r))) => {
            assert_eq!(r.code, 99);
            assert!(r.data.is_empty());
        }
        _ => panic!("[99,0] must decode to empty Unrecognized"),
    }
    match decode_option(&[0, 0]) {
        Ok((_, DhcpOption::Unrecognized(r))) => {
            assert_eq!(r.code, 0);
            assert!(r.data.is_empty());
        }
        _ => panic!("[0,0] must decode to empty Unrecognized"),
    }
    // rejected: fixed-size codes need payload bytes
    for wire in [
        vec![53, 0],       // message type needs 1 byte
        vec![54, 0],       // server id needs 4
        vec![50, 0],       // requested ip needs 4
        vec![1, 0],        // subnet mask needs 4
        vec![51, 0],       // lease time needs 4
    ] {
        assert!(
            matches!(decode_option(&wire), Err(CustomErr::InvalidHlen)),
            "{:?} must be InvalidHlen",
            wire
        );
    }
    // rejected quirk: Router/DNS fail even with empty data
    for wire in [vec![3, 0], vec![6, 0]] {
        assert!(
            matches!(decode_option(&wire), Err(CustomErr::InvalidHlen)),
            "{:?} must be InvalidHlen (many0 quirk)",
            wire
        );
    }
}

/// Empty Router/DNS encode to `[3,0]`/`[6,0]` on the wire but decode-drop,
/// while empty PRL survives the round-trip — the asymmetry, end to end.
#[test]
fn sec4_empty_router_dns_dropped_empty_prl_kept() {
    let p = Packet {
        reply: false, hops: 0, xid: 0xA020, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xA3; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::ParameterRequestList(vec![]),
            DhcpOption::Router(vec![]),
            DhcpOption::DomainNameServer(vec![]),
        ],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    for needle in [vec![55u8, 0], vec![3u8, 0], vec![6u8, 0]] {
        assert!(
            enc.windows(2).any(|w| w == needle.as_slice()),
            "{:?} must be on the wire",
            needle
        );
    }
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(
        q.options.iter().map(|o| o.code()).collect::<Vec<u8>>(),
        vec![53, 55],
        "empty Router/DNS dropped, empty PRL kept"
    );
}

// ===========================================================================
// C. Garbage survival + kernel-style truncation (live + unit)
// ===========================================================================

/// Battery of garbage datagrams (empty, 1 byte, short header, bad cookie)
/// keeps the server alive: the next valid Discover still gets Offer `.3`.
/// Malformed input never kills the loop when the END-skip lands non-empty.
#[test]
fn sec4_garbage_datagram_battery_server_survives_live() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = s.reply(
                MessageType::Offer,
                vec![],
                Ipv4Addr::new(192, 168, 7, 10),
                p,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 7, 1),
            Ipv4Addr::new(192, 168, 7, 255),
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
    // each of these decodes to Err (no panic: tiny inputs fail before split)
    client.send_to(&[], srv_addr).unwrap();
    client.send_to(&[0u8], srv_addr).unwrap();
    client.send_to(&[0u8; 10], srv_addr).unwrap();
    client.send_to(&[0u8; 235], srv_addr).unwrap();
    let mut bad_cookie = vec![0u8; 236];
    bad_cookie[0] = 1;
    bad_cookie[1] = 1;
    bad_cookie[2] = 6;
    bad_cookie.extend_from_slice(&[9, 9, 9, 9, 53, 1, 1, 255]);
    client.send_to(&bad_cookie, srv_addr).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    // server still alive and answering
    let disc = Packet {
        reply: false, hops: 0, xid: 0xA030, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xA4; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    client.send_to(&disc.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("server survived garbage");
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 7, 10));
}

/// An 1844-byte datagram sliced to 1500 (kernel-style truncation) still
/// decodes: the cut lands mid-TLV, the swallow skips one byte, options stay
/// bounded, and re-encode caps at 300 with Discover first. No panic.
#[test]
fn sec4_kernel_style_truncation_decodes_without_panic() {
    let mut opts = vec![53, 1, 1];
    for _ in 0..400 {
        opts.extend_from_slice(&[200, 2, 7, 8]);
    }
    opts.push(255);
    let raw = make_raw(
        1, 6, 0, 0xA031, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [0xA5; 6], opts,
    );
    assert_eq!(raw.len(), 1844);
    let truncated = &raw[..1500]; // what recv_into-1500 would deliver
    let p = unwrap_packet(Packet::from(truncated));
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
    assert!(p.options.len() < 402, "truncated tail lost, prefix kept");
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(enc.len() <= 300, "re-encode capped");
}

// ===========================================================================
// D. Gate compositions: wrong-ID Request honored; Decline no-lease silent
// ===========================================================================

/// A Request naming a *wrong* (but well-formed) server is still Acked —
/// complements the missing-ID renew test: the gate is disabled for values
/// too, not just absence. Locked live.
#[test]
fn sec4_wrong_id_request_honored_live() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = Packet {
        reply: false, hops: 0, xid: 0xA040, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xA6; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 99, 99, 99)),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 73)),
        ],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("Ack despite wrong ID");
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(MessageType::Ack));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 73));
}

/// Decline from an unknown chaddr (no lease anywhere) is a silent no-op with
/// no reply and no state change — documents the quiet failure mode live.
#[test]
fn sec4_decline_no_lease_no_reply_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let dec = Packet {
        reply: false, hops: 0, xid: 0xA041, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xA7; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Decline),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 74)),
        ],
    };
    client.send_to(&dec.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert!(
        client.recv_from(&mut rbuf).is_err(),
        "Decline with no lease must get no reply"
    );
}

// ===========================================================================
// E. Broadcast Release still gated only on server ID, not flags
// ===========================================================================

/// A broadcast-flagged Release with the correct Server ID still frees the
/// lease — flags play no role in the gate; only the identifier matters.
/// Locked live (precondition asserts the flag survived decode).
#[test]
fn sec4_broadcast_release_still_gated_only_on_id_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0xA8; 6];
    // occupy .75
    let req = Packet {
        reply: false, hops: 0, xid: 0xA050, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 75)),
        ],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("Ack");
    assert_eq!(unwrap_packet(Packet::from(&rbuf[..n])).message_type(), Ok(MessageType::Ack));
    // broadcast Release naming the right server: freed (flag irrelevant)
    let raw = make_raw(
        1, 6, 0, 0xA051, 0, [0, 128], // low-byte 0x80 -> broadcast=true
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        victim,
        vec![53, 1, 7, 54, 4, 192, 168, 2, 1, 255],
    );
    assert!(unwrap_packet(Packet::from(&raw)).broadcast, "precondition");
    client.send_to(&raw, srv_addr).unwrap();
    // prove freed: a stranger can now take .75
    let stranger = Packet {
        reply: false, hops: 0, xid: 0xA052, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xA9; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 75)),
        ],
    };
    client.send_to(&stranger.encode(&mut buf).to_vec(), srv_addr).unwrap();
    // Release itself gets no reply; the stranger's unicast Ack proves the
    // Release freed .75 regardless of the broadcast flag.
    let (n, _) = client.recv_from(&mut rbuf).expect("stranger Ack");
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(MessageType::Ack));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 75), "freed by broadcast Release");
}
