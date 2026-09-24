//! DHCP security edges, part 3.
//!
//! Covers security-relevant behavior NOT locked by `test_security.rs`,
//! `test_security_extra.rs`, or the RFC suites, so refactors cannot silently
//! change attacker-visible handling:
//!
//! - handler-state blind spots: Decline frees the *current* lease even when
//!   it names someone else's IP; Release without Server ID is ignored live;
//!   renew-via-`ciaddr` bypasses the (commented-out) server gate live
//! - allocation ignores `ciaddr`/Requested-IP on Discover and any Server ID
//!   on Discover — offers stay round-robin
//! - example Offer wire shape with the real 4-option reply: Router fits on
//!   the wire, DNS is truncated off it, decode keeps `[53,54,51,1]`
//! - framing: bare-`ciaddr` renew shape, out-of-pool Request NAKs cleanly,
//!   max-length HostName decodes, holder asking for a victim IP keeps their
//!   own lease (no NAK, victim untouched)
//! - lease-state hygiene: Discover inserts nothing; broadcast/zero `chaddr`
//!   get leases (no MAC validation); infinite reservations surface via
//!   Discover to strangers
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

// ===========================================================================
// A. Decline / Release handler blind spots (live, example-faithful)
// ===========================================================================

/// QUIRK: Decline frees the sender's *current* lease and never looks at the
/// named Requested IP — Decline for someone else's `.99` still deletes your
/// own `.60`. An attacker naming arbitrary IPs frees nothing extra, but the
/// named address is unauthenticated decoration. Locked live.
#[test]
fn sec2_decline_names_wrong_ip_still_frees_current() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x21; 6];
    let other = [0x22; 6];
    // victim takes .60
    let req = Packet {
        reply: false, hops: 0, xid: 0xE001, secs: 0, broadcast: false,
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
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).message_type(),
        Ok(MessageType::Ack)
    );
    // victim Declines naming .99 (someone else's / nobody's address)
    let decline = Packet {
        reply: false, hops: 0, xid: 0xE002, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Decline),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 99)),
        ],
    };
    client
        .send_to(&decline.encode(&mut buf).to_vec(), srv_addr)
        .unwrap();
    // victim's Discover no longer returns .60: it was freed anyway
    let disc = Packet {
        reply: false, hops: 0, xid: 0xE003, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let offer = send_recv(&client, &srv_addr, &disc, &mut buf, &mut rbuf);
    assert_eq!(offer.message_type(), Ok(MessageType::Offer));
    assert_ne!(
        offer.yiaddr,
        Ipv4Addr::new(192, 168, 2, 60),
        "current lease freed despite naming .99"
    );
    // and .60 is back in the pool for anyone
    let grab = Packet {
        reply: false, hops: 0, xid: 0xE004, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: other,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 60)),
        ],
    };
    let ack = send_recv(&client, &srv_addr, &grab, &mut buf, &mut rbuf);
    assert_eq!(ack.message_type(), Ok(MessageType::Ack));
    assert_eq!(ack.yiaddr, Ipv4Addr::new(192, 168, 2, 60));
}

/// Release WITHOUT Server Identifier is ignored live (`for_this_server` is
/// false) — the lease survives. Complements the Replica-level gate test with
/// the real wire path (missing option, not just `for_this=false`).
#[test]
fn sec2_release_missing_server_id_keeps_lease_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let victim = [0x23; 6];
    let req = Packet {
        reply: false, hops: 0, xid: 0xE010, secs: 0, broadcast: false,
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
    // Release with NO Server Identifier option at all
    let rel = Packet {
        reply: false, hops: 0, xid: 0xE011, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![DhcpOption::DhcpMessageType(MessageType::Release)],
    };
    client.send_to(&rel.encode(&mut buf).to_vec(), srv_addr).unwrap();
    // Discover still returns the kept lease .61
    let disc = Packet {
        reply: false, hops: 0, xid: 0xE012, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: victim,
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let offer = send_recv(&client, &srv_addr, &disc, &mut buf, &mut rbuf);
    assert_eq!(offer.message_type(), Ok(MessageType::Offer));
    assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 2, 61), "lease kept");
}

/// RENEWING shape (ciaddr set, no Server ID, no Requested IP) is Acked live
/// even though `for_this_server` is false — the commented-out gate applies
/// to the ciaddr fallback path too, not just Requested-IP selects.
#[test]
fn sec2_renew_without_server_id_acked_via_ciaddr_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let mac = [0x24; 6];
    // establish .70 the normal way first
    let req = Packet {
        reply: false, hops: 0, xid: 0xE020, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: mac,
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 70)),
        ],
    };
    assert_eq!(
        send_recv(&client, &srv_addr, &req, &mut buf, &mut rbuf).yiaddr,
        Ipv4Addr::new(192, 168, 2, 70)
    );
    // renew: ciaddr set, no Server ID at all
    let renew = Packet {
        reply: false, hops: 0, xid: 0xE021, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 2, 70), yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: mac,
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    let ack = send_recv(&client, &srv_addr, &renew, &mut buf, &mut rbuf);
    assert_eq!(ack.message_type(), Ok(MessageType::Ack));
    assert_eq!(ack.yiaddr, Ipv4Addr::new(192, 168, 2, 70));
}

// ===========================================================================
// B. Allocation ignores everything but chaddr on Discover
// ===========================================================================

/// Discover carrying a Server ID plus a Requested IP is still offered
/// round-robin (.3 on a fresh server) — Discover ignores both options.
/// A spoofed Server ID / requested address steers nothing on this path.
#[test]
fn sec2_discover_ignores_server_id_and_requested_ip_live() {
    let (srv_addr, server_ip) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let disc = Packet {
        reply: false, hops: 0, xid: 0xE030, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0x25; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 99, 99, 99)),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 99)),
        ],
    };
    client.send_to(&disc.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("offer");
    let offer = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(offer.message_type(), Ok(MessageType::Offer));
    assert_eq!(
        offer.yiaddr,
        Ipv4Addr::new(192, 168, 2, 3),
        "round-robin, not the requested .99"
    );
    let _ = server_ip;
}

/// Discover with a spoofed `ciaddr` is offered round-robin all the same —
/// `ciaddr` steers nothing on the Discover path (only Request reads it).
#[test]
fn sec2_discover_ignores_ciaddr_for_selection_live() {
    let (srv_addr, _) = serve_example_like();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let disc = Packet {
        reply: false, hops: 0, xid: 0xE031, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 2, 99), yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0x26; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    client.send_to(&disc.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("offer");
    assert_eq!(
        unwrap_packet(Packet::from(&rbuf[..n])).yiaddr,
        Ipv4Addr::new(192, 168, 2, 3)
    );
}

/// The real 4-option example Offer on the wire: the full set fits the
/// 300-byte cap, decode keeps `[53,54,51,1]` (Router still poisons the
/// decoder loop). Locks the exact on-air shape of example Offers end to end.
#[test]
fn sec2_example_offer_full_wire_shape_live() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct FullExample;
    impl server::Handler for FullExample {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            // byte-for-byte example reply() option set
            let _ = s.reply(
                MessageType::Offer,
                vec![
                    DhcpOption::IpAddressLeaseTime(86400),
                    DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                    DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 2, 1)]),
                    DhcpOption::DomainNameServer(vec![Ipv4Addr::new(8, 8, 8, 8)]),
                ],
                Ipv4Addr::new(192, 168, 2, 90),
                p,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 2, 1),
            Ipv4Addr::new(192, 168, 2, 255),
            FullExample,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let disc = test_packet(0xE032, [0x27; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Discover,
    )]);
    client.send_to(&disc.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("offer");
    assert!(
        rbuf[..n].windows(6).any(|w| w == [3, 4, 192, 168, 2, 1]),
        "router TLV on the wire"
    );
    assert!(
        rbuf[..n].windows(6).any(|w| w == [6, 4, 8, 8, 8, 8]),
        "DNS TLV reaches the wire under the 300 cap"
    );
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(
        rep.options.iter().map(|o| o.code()).collect::<Vec<u8>>(),
        vec![53, 54, 51, 1]
    );
}

// ===========================================================================
// C. Lease-state hygiene: insertion rules and identity laxity
// ===========================================================================

/// Discover is read-only: offers create no table entry. Only Request inserts.
/// A Discover flood alone therefore cannot fill the pool — starvation needs
/// completed Requests. Locked at the state level.
#[test]
fn sec2_discover_read_only_no_insert() {
    let mut s = Replica::new();
    let mac = [0x31; 6];
    assert_eq!(s.discover(&mac), Some(Ipv4Addr::new(192, 168, 2, 3)));
    assert!(s.leases.is_empty(), "Discover must not insert");
    assert_eq!(
        s.request(&mac, Some(Ipv4Addr::new(192, 168, 2, 3)), Ipv4Addr::UNSPECIFIED, true),
        Ok(Ipv4Addr::new(192, 168, 2, 3))
    );
    assert_eq!(s.leases.len(), 1, "only Request inserts");
}

/// No MAC validation at all: broadcast `ff:ff:ff:ff:ff:ff` and all-zero
/// `chaddr` are both offered distinct pool addresses like any client.
#[test]
fn sec2_broadcast_and_zero_chaddr_get_leases() {
    let mut s = Replica::new();
    let bcast = s.discover(&[0xFF; 6]);
    let zero = s.discover(&[0x00; 6]);
    assert!(bcast.is_some() && zero.is_some());
    assert_ne!(bcast, zero, "distinct identities, distinct offers");
}

/// An infinite (file-reserved) lease also surfaces via Discover to a
/// stranger once the scan reaches it — the theft primitive is not
/// Request-specific. Fills the rest of the pool so `.90` is next.
#[test]
fn sec2_infinite_reservation_offered_to_stranger_via_discover() {
    let mut s = Replica::new();
    let owner = [0x41; 6];
    let stranger = [0x42; 6];
    s.leases.insert(Ipv4Addr::new(192, 168, 2, 90), (owner, None));
    // fill every other pool address with timed stranger-held leases
    for i in 0..LEASE_NUM {
        let ip: Ipv4Addr = (IP_START_NUM + i).into();
        if ip == Ipv4Addr::new(192, 168, 2, 90) {
            continue;
        }
        s.leases.insert(
            ip,
            ([0x43; 6], Some(Instant::now().add(Duration::from_secs(3600)))),
        );
    }
    assert_eq!(s.discover(&stranger), Some(Ipv4Addr::new(192, 168, 2, 90)));
}

/// A lease holder asking for a victim's IP keeps their own lease with no
/// NAK and no theft in that call — the current-lease short-circuit runs
/// before any availability check. Locked.
#[test]
fn sec2_holder_asking_victim_ip_keeps_own_lease() {
    let mut s = Replica::new();
    let holder = [0x51; 6];
    let victim = [0x52; 6];
    let victim_ip = Ipv4Addr::new(192, 168, 2, 80);
    let holder_ip = Ipv4Addr::new(192, 168, 2, 81);
    assert_eq!(s.request(&victim, Some(victim_ip), Ipv4Addr::UNSPECIFIED, true), Ok(victim_ip));
    assert_eq!(s.request(&holder, Some(holder_ip), Ipv4Addr::UNSPECIFIED, true), Ok(holder_ip));
    // holder now asks for the victim's IP: gets own lease back, no NAK
    assert_eq!(
        s.request(&holder, Some(victim_ip), Ipv4Addr::UNSPECIFIED, true),
        Ok(holder_ip)
    );
    assert_eq!(s.leases[&victim_ip].0, victim, "victim untouched");
}

/// Out-of-pool Requested IP NAKs with no table insert — 10.0.0.1 never
/// enters the map, no panic on the range check.
#[test]
fn sec2_out_of_pool_request_naks_without_insert() {
    let mut s = Replica::new();
    assert!(s
        .request(&[0x61; 6], Some(Ipv4Addr::new(10, 0, 0, 1)), Ipv4Addr::UNSPECIFIED, true)
        .is_err());
    assert!(s.leases.is_empty());
}

// ===========================================================================
// D. Parser edges: max-length text, truncation accounting
// ===========================================================================

/// 255-byte HostName (max `len` byte) of valid UTF-8 decodes exactly —
/// complements the 255-byte PRL test and proves text options use the full
/// length range.
#[test]
fn sec2_hostname_255_byte_max_decodes() {
    let data = vec![0x41u8; 255];
    let mut wire = vec![12, 255];
    wire.extend_from_slice(&data);
    match decode_option(&wire) {
        Ok((rest, DhcpOption::HostName(s))) => {
            assert_eq!(s.len(), 255);
            assert!(rest.is_empty());
        }
        _ => panic!("255-byte HostName must decode"),
    }
}
