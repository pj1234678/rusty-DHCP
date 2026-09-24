//! Tests for DHCP Rapid Commit (RFC 4039 option 80 for IPv4, RFC 8415
//! option 14 for IPv6), gated by `enable_rapid_commit` in `dhcp.conf`.
//!
//! Design under test (mirrors `examples/server.rs`): with the flag off, or
//! without the option on the wire, behavior is exactly the legacy 4-message
//! (Discover->Offer) / Solicit->Advertise flow. With both present, the
//! server commits immediately (Ack/Reply: 2-message exchange). Both options
//! decode as `Unrecognized` — there is deliberately no typed variant, so the
//! branch-matrix test's typed set is unchanged.

use dhcp4r::{dhcpv6, options, packet, server};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::ops::Add;
use std::time::{Duration, Instant};

fn unwrap_packet(r: Result<packet::Packet, packet::CustomErr<&[u8]>>) -> packet::Packet {
    match r {
        Ok(p) => p,
        Err(_) => panic!("expected Ok Packet"),
    }
}

fn test_packet(xid: u32, chaddr: [u8; 6], opts: Vec<options::DhcpOption>) -> packet::Packet {
    packet::Packet {
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

fn recv_with_timeout(sock: &UdpSocket, buf: &mut [u8]) -> (usize, std::net::SocketAddr) {
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.recv_from(buf).expect("timed out waiting for reply")
}

fn rapid_opt() -> options::DhcpOption {
    options::DhcpOption::Unrecognized(options::RawDhcpOption {
        code: options::RAPID_COMMIT,
        data: vec![],
    })
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

// ---------------------------------------------------------------------------
// v4 wire: option 80 is Unrecognized, no typed variant by design
// ---------------------------------------------------------------------------

#[test]
fn rapid_commit_v4_const_and_title() {
    assert_eq!(options::RAPID_COMMIT, 80);
    assert_eq!(options::title(80), Some("Rapid Commit"));
}

#[test]
fn rapid_commit_v4_decodes_as_unrecognized() {
    // empty (the RFC 4039 shape) and non-empty payloads alike passthrough
    for data in [vec![], vec![1, 2, 3]] {
        let mut wire = vec![80, data.len() as u8];
        wire.extend_from_slice(&data);
        match packet::decode_option(&wire) {
            Ok((rest, options::DhcpOption::Unrecognized(r))) => {
                assert_eq!(r.code, 80);
                assert_eq!(r.data, data);
                assert!(rest.is_empty());
            }
            _ => panic!("option 80 must decode as Unrecognized"),
        }
    }
    // round-trips through a full packet like any Unrecognized option
    let p = test_packet(
        1,
        [0; 6],
        vec![
            options::DhcpOption::DhcpMessageType(options::MessageType::Discover),
            rapid_opt(),
        ],
    );
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(packet::Packet::from(&p.encode(&mut buf).to_vec()));
    assert_eq!(q.option(80), Some(&rapid_opt()));
}

// ---------------------------------------------------------------------------
// v4 live: rapid-aware handler replica mirroring the example Discover arm
// ---------------------------------------------------------------------------

const IP_START: [u8; 4] = [192, 168, 2, 2];
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);
const LEASE_NUM: u32 = 252;
const LEASE_SECS: u32 = 86400;

struct RapidV4 {
    leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
    last_lease: u32,
    lease_duration: Duration,
    enable_rapid_commit: bool,
}

impl RapidV4 {
    fn new(enabled: bool) -> Self {
        Self {
            leases: HashMap::new(),
            last_lease: 0,
            lease_duration: Duration::from_secs(LEASE_SECS as u64),
            enable_rapid_commit: enabled,
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

impl server::Handler for RapidV4 {
    fn handle_request(&mut self, server: &server::Server, in_packet: packet::Packet) {
        match in_packet.message_type() {
            Ok(options::MessageType::Discover) => {
                // Rapid Commit (RFC 4039): commit immediately with an Ack.
                if self.enable_rapid_commit
                    && in_packet.option(options::RAPID_COMMIT).is_some()
                {
                    if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                        let _ = server.reply(
                            options::MessageType::Ack,
                            vec![options::DhcpOption::IpAddressLeaseTime(LEASE_SECS)],
                            ip,
                            in_packet,
                        );
                        return;
                    }
                    for _ in 0..LEASE_NUM {
                        self.last_lease = (self.last_lease + 1) % LEASE_NUM;
                        let cand: Ipv4Addr = (IP_START_NUM + self.last_lease).into();
                        if self.available(&in_packet.chaddr, &cand) {
                            self.leases.insert(
                                cand,
                                (
                                    in_packet.chaddr,
                                    Some(Instant::now().add(self.lease_duration)),
                                ),
                            );
                            let _ = server.reply(
                                options::MessageType::Ack,
                                vec![options::DhcpOption::IpAddressLeaseTime(LEASE_SECS)],
                                cand,
                                in_packet,
                            );
                            break;
                        }
                    }
                    return;
                }
                // Legacy path: prefer existing, else round-robin Offer.
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    let _ = server.reply(
                        options::MessageType::Offer,
                        vec![options::DhcpOption::IpAddressLeaseTime(LEASE_SECS)],
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
                            options::MessageType::Offer,
                            vec![options::DhcpOption::IpAddressLeaseTime(LEASE_SECS)],
                            cand,
                            in_packet,
                        );
                        break;
                    }
                }
            }
            _ => {}
        }
    }
}

fn serve_rapid(enabled: bool) -> std::net::SocketAddr {
    serve_rapid_with_leases(enabled, HashMap::new())
}

fn serve_rapid_with_leases(
    enabled: bool,
    leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>)>,
) -> std::net::SocketAddr {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let mut handler = RapidV4::new(enabled);
    handler.leases = leases;
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 255),
            handler,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    srv_addr
}

fn rapid_discover(xid: u32, chaddr: [u8; 6]) -> packet::Packet {
    test_packet(
        xid,
        chaddr,
        vec![
            options::DhcpOption::DhcpMessageType(options::MessageType::Discover),
            rapid_opt(),
        ],
    )
}

#[test]
fn rapid_discover_acks_and_inserts_live() {
    let srv_addr = serve_rapid(true);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    client
        .send_to(&rapid_discover(0xB001, [1; 6]).encode(&mut buf).to_vec(), srv_addr)
        .unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(packet::Packet::from(&rbuf[..n]));
    // 2-message exchange: Ack (not Offer) straight away...
    assert_eq!(rep.message_type(), Ok(options::MessageType::Ack));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
    // ...and the lease was committed: a plain Discover is offered the same IP
    // via the current-lease path instead of rotating to .4.
    let plain = test_packet(
        0xB002,
        [1; 6],
        vec![options::DhcpOption::DhcpMessageType(options::MessageType::Discover)],
    );
    client.send_to(&plain.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    assert_eq!(
        unwrap_packet(packet::Packet::from(&rbuf[..n])).yiaddr,
        Ipv4Addr::new(192, 168, 2, 3)
    );
}

#[test]
fn rapid_disabled_ignores_option_live() {
    let srv_addr = serve_rapid(false);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // flag off: rapid-looking Discover is a plain Discover (Offer + no insert)
    client
        .send_to(&rapid_discover(0xB010, [2; 6]).encode(&mut buf).to_vec(), srv_addr)
        .unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(packet::Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(options::MessageType::Offer));
    // no insert happened: next Discover rotates instead of sticking
    let plain = test_packet(
        0xB011,
        [2; 6],
        vec![options::DhcpOption::DhcpMessageType(options::MessageType::Discover)],
    );
    client.send_to(&plain.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    assert_eq!(
        unwrap_packet(packet::Packet::from(&rbuf[..n])).yiaddr,
        Ipv4Addr::new(192, 168, 2, 4)
    );
}

#[test]
fn rapid_without_option_is_plain_discover_live() {
    let srv_addr = serve_rapid(true);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // flag on but no option 80 on the wire: legacy Offer path
    let plain = test_packet(
        0xB020,
        [3; 6],
        vec![options::DhcpOption::DhcpMessageType(options::MessageType::Discover)],
    );
    client.send_to(&plain.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    assert_eq!(
        unwrap_packet(packet::Packet::from(&rbuf[..n])).message_type(),
        Ok(options::MessageType::Offer)
    );
}

#[test]
fn rapid_pool_exhausted_silent_live() {
    // fill every address with other MACs so nothing is available
    let mut leases = HashMap::new();
    for i in 0..LEASE_NUM {
        let ip: Ipv4Addr = (IP_START_NUM + i).into();
        leases.insert(
            ip,
            (
                [0xCC, 0xDD, (i >> 8) as u8, i as u8, 0xEE, 0xFF],
                Some(Instant::now() + Duration::from_secs(3600)),
            ),
        );
    }
    let srv_addr = serve_rapid_with_leases(true, leases);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    client
        .send_to(&rapid_discover(0xB030, [4; 6]).encode(&mut buf).to_vec(), srv_addr)
        .unwrap();
    assert!(
        client.recv_from(&mut rbuf).is_err(),
        "exhausted rapid Discover must get no reply, like Discover"
    );
}

#[test]
fn rapid_existing_lease_acked_without_moving_counter() {
    let srv_addr = serve_rapid(true);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // take .3 via rapid commit first
    client
        .send_to(&rapid_discover(0xB040, [5; 6]).encode(&mut buf).to_vec(), srv_addr)
        .unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    assert_eq!(
        unwrap_packet(packet::Packet::from(&rbuf[..n])).yiaddr,
        Ipv4Addr::new(192, 168, 2, 3)
    );
    // rapid Discover again (even naming another IP): Ack for the held lease.
    // Requested IP is ignored on the rapid path by design (Discover-style
    // selection), so the stray option must not steer the answer.
    let mut opts = vec![
        options::DhcpOption::DhcpMessageType(options::MessageType::Discover),
        rapid_opt(),
    ];
    opts.push(options::DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 99)));
    let retry = test_packet(0xB041, [5; 6], opts);
    client.send_to(&retry.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(packet::Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(options::MessageType::Ack));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 3), "held lease wins");
}

#[test]
fn rapid_truncated_option_falls_back_to_offer_live() {
    let srv_addr = serve_rapid(true);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut rbuf = [0u8; 1500];
    // option 80 declares len 3 but only 1 byte follows: InvalidHlen swallows
    // it, so option(80) is absent and the normal Offer path runs, not Ack.
    let raw = make_raw(
        1, 6, 0, 0xB050, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [6; 6],
        vec![53, 1, 1, 80, 3, 0xAA, 255],
    );
    client.send_to(&raw, srv_addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("reply");
    let rep = unwrap_packet(packet::Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(options::MessageType::Offer));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 3));
}

// ---------------------------------------------------------------------------
// v6: option 14 handling + rapid TestV6Server replica
// ---------------------------------------------------------------------------

const V6_SERVER_DUID: [u8; 10] =
    [0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0xaa, 0xbb, 0xcc];
const V6_LEASE_SECS: u32 = 86400;

fn v6(a: [u16; 8]) -> Ipv6Addr {
    Ipv6Addr::new(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
}

fn v6pool() -> dhcpv6::V6Pool {
    dhcpv6::V6Pool::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100),
        1000,
        Duration::from_secs(V6_LEASE_SECS as u64),
    )
}

fn v6ip(n: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, n)
}

fn rapid6_opt() -> dhcpv6::Dhcpv6Option {
    dhcpv6::Dhcpv6Option::Unrecognized(dhcpv6::RawDhcpv6Option {
        code: dhcpv6::OPT_RAPID_COMMIT,
        data: vec![],
    })
}

struct RapidV6Server {
    pool: dhcpv6::V6Pool,
    server_duid: Vec<u8>,
    lease_secs: u32,
    dns: Vec<Ipv6Addr>,
    enable_rapid_commit: bool,
}

impl RapidV6Server {
    fn new(enabled: bool) -> Self {
        Self {
            pool: v6pool(),
            server_duid: V6_SERVER_DUID.to_vec(),
            lease_secs: V6_LEASE_SECS,
            dns: vec![v6([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888])],
            enable_rapid_commit: enabled,
        }
    }

    fn success(
        &self,
        req: &dhcpv6::Packet,
        msg_type: dhcpv6::MsgType,
        ip: Ipv6Addr,
    ) -> dhcpv6::Packet {
        let iaid = req.first_iana().map(|ia| ia.iaid).unwrap_or(0);
        let (t1, t2) = dhcpv6::default_t1_t2(self.lease_secs);
        let duid = match req.option(dhcpv6::OPT_CLIENTID) {
            Some(dhcpv6::Dhcpv6Option::ClientId(d)) => d.clone(),
            _ => vec![],
        };
        let mut options = vec![
            dhcpv6::Dhcpv6Option::ServerId(self.server_duid.clone()),
            dhcpv6::Dhcpv6Option::ClientId(duid),
            dhcpv6::Dhcpv6Option::IaNa(dhcpv6::IaNa {
                iaid,
                t1,
                t2,
                addrs: vec![dhcpv6::IaAddr {
                    addr: ip,
                    preferred: self.lease_secs,
                    valid: self.lease_secs,
                }],
            }),
        ];
        if !self.dns.is_empty() {
            options.push(dhcpv6::Dhcpv6Option::DnsServers(self.dns.clone()));
        }
        dhcpv6::Packet { msg_type, transaction_id: req.transaction_id, options }
    }

    fn nodata(&self, req: &dhcpv6::Packet, msg_type: dhcpv6::MsgType) -> dhcpv6::Packet {
        let iaid = req.first_iana().map(|ia| ia.iaid).unwrap_or(0);
        let duid = match req.option(dhcpv6::OPT_CLIENTID) {
            Some(dhcpv6::Dhcpv6Option::ClientId(d)) => d.clone(),
            _ => vec![],
        };
        dhcpv6::Packet {
            msg_type,
            transaction_id: req.transaction_id,
            options: vec![
                dhcpv6::Dhcpv6Option::ServerId(self.server_duid.clone()),
                dhcpv6::Dhcpv6Option::ClientId(duid),
                dhcpv6::Dhcpv6Option::IaNa(dhcpv6::IaNa {
                    iaid,
                    t1: 0,
                    t2: 0,
                    addrs: vec![],
                }),
                dhcpv6::Dhcpv6Option::StatusCode(
                    dhcpv6::STATUS_NO_ADDRS_AVAIL,
                    "NoAddrsAvail".to_string(),
                ),
            ],
        }
    }

    // Mirrors the updated examples/server.rs serve_v6 Solicit arm, pure return.
    fn handle_solicit(&mut self, req: &dhcpv6::Packet) -> Option<dhcpv6::Packet> {
        let duid = match req.option(dhcpv6::OPT_CLIENTID) {
            Some(dhcpv6::Dhcpv6Option::ClientId(d)) => d.clone(),
            _ => return None,
        };
        debug_assert_eq!(req.msg_type, dhcpv6::MsgType::Solicit);
        if self.enable_rapid_commit && req.option(dhcpv6::OPT_RAPID_COMMIT).is_some() {
            return match self.pool.discover(&duid) {
                Some(offered) => match self.pool.request(&duid, offered) {
                    Ok(ip) => Some(self.success(req, dhcpv6::MsgType::Reply, ip)),
                    Err(_) => Some(self.nodata(req, dhcpv6::MsgType::Reply)),
                },
                None => Some(self.nodata(req, dhcpv6::MsgType::Reply)),
            };
        }
        match self.pool.discover(&duid) {
            Some(ip) => Some(self.success(req, dhcpv6::MsgType::Advertise, ip)),
            None => Some(self.nodata(req, dhcpv6::MsgType::Advertise)),
        }
    }
}

fn solicit6(duid_bytes: &[u8], iaid: u32, rapid: bool) -> dhcpv6::Packet {
    let mut options = vec![
        dhcpv6::Dhcpv6Option::ClientId(duid_bytes.to_vec()),
        dhcpv6::Dhcpv6Option::IaNa(dhcpv6::IaNa { iaid, t1: 0, t2: 0, addrs: vec![] }),
    ];
    if rapid {
        options.push(rapid6_opt());
    }
    dhcpv6::Packet { msg_type: dhcpv6::MsgType::Solicit, transaction_id: 0x112233, options }
}

fn v6codes(p: &dhcpv6::Packet) -> Vec<u16> {
    p.options.iter().map(|o| o.code()).collect()
}

#[test]
fn v6_rapid_title_present() {
    assert_eq!(dhcpv6::title(dhcpv6::OPT_RAPID_COMMIT), Some("Rapid Commit"));
}

#[test]
fn v6_rapid_solicit_replies_committed() {
    let mut s = RapidV6Server::new(true);
    let rep = s.handle_solicit(&solicit6(&[1], 0x01020304, true)).unwrap();
    assert_eq!(rep.msg_type, dhcpv6::MsgType::Reply, "rapid commit skips Advertise");
    assert_eq!(rep.transaction_id, 0x112233);
    assert_eq!(v6codes(&rep), vec![2, 1, 3, 23]);
    match rep.option(dhcpv6::OPT_IA_NA) {
        Some(dhcpv6::Dhcpv6Option::IaNa(ia)) => {
            assert_eq!(ia.iaid, 0x01020304, "request IAID echoed");
            assert_eq!(ia.addrs.len(), 1);
            assert_eq!(ia.addrs[0].addr, v6ip(0x101), "first free past start");
            assert_eq!((ia.addrs[0].preferred, ia.addrs[0].valid), (86400, 86400));
            assert_eq!((ia.t1, ia.t2), (43200, 75600));
        }
        _ => panic!("Reply must carry IA_NA"),
    }
    assert!(rep.option(dhcpv6::OPT_STATUS_CODE).is_none());
    // committed server-side: pool holds it for this DUID
    assert_eq!(s.pool.current_lease(&[1]), Some(v6ip(0x101)));
}

#[test]
fn v6_solicit_without_rapid_advertises() {
    let mut s = RapidV6Server::new(true);
    let rep = s.handle_solicit(&solicit6(&[2], 0x01020304, false)).unwrap();
    assert_eq!(rep.msg_type, dhcpv6::MsgType::Advertise, "no option 14, no rapid path");
    assert!(s.pool.is_empty());
}

#[test]
fn v6_rapid_disabled_ignores_option() {
    let mut s = RapidV6Server::new(false);
    let rep = s.handle_solicit(&solicit6(&[3], 0x01020304, true)).unwrap();
    assert_eq!(rep.msg_type, dhcpv6::MsgType::Advertise, "flag off: legacy flow");
    assert!(s.pool.is_empty());
}

#[test]
fn v6_rapid_exhausted_nodata_reply() {
    let mut s = RapidV6Server::new(true);
    // fill first 10 of the pool directly (fast, no network)
    for i in 0u8..10 {
        let ip = v6ip(0x100 + i as u16);
        s.pool.request(&[0xA0 + i], ip).unwrap();
    }
    // exhaust the rest through discover+request pairs is slow; instead fill
    // everything except one chunk is overkill — fill via direct inserts.
    for i in 10u16..1000 {
        s.pool.insert(
            v6ip(0x100 + i),
            vec![0xB0, (i & 0xFF) as u8],
            Some(Instant::now() + Duration::from_secs(3600)),
        );
    }
    assert_eq!(s.pool.len(), 1000);
    let rep = s.handle_solicit(&solicit6(&[9], 0x09090909, true)).unwrap();
    assert_eq!(rep.msg_type, dhcpv6::MsgType::Reply, "rapid failure is still a Reply");
    assert_eq!(v6codes(&rep), vec![2, 1, 3, 13]);
    match rep.option(dhcpv6::OPT_IA_NA) {
        Some(dhcpv6::Dhcpv6Option::IaNa(ia)) => {
            assert_eq!(ia.iaid, 0x09090909);
            assert!(ia.addrs.is_empty());
        }
        _ => panic!("nodata Reply keeps an empty IA_NA"),
    }
    assert_eq!(
        rep.option(dhcpv6::OPT_STATUS_CODE),
        Some(&dhcpv6::Dhcpv6Option::StatusCode(
            dhcpv6::STATUS_NO_ADDRS_AVAIL,
            "NoAddrsAvail".to_string()
        ))
    );
}

#[test]
fn v6_rapid_without_iana_acks_iaid_zero() {
    let mut s = RapidV6Server::new(true);
    // ClientId + rapid option but no IA_NA: discover by DUID still works,
    // reply IAID defaults to 0 like the normal path.
    let req = dhcpv6::Packet {
        msg_type: dhcpv6::MsgType::Solicit,
        transaction_id: 0x0A0B0C,
        options: vec![dhcpv6::Dhcpv6Option::ClientId(vec![5]), rapid6_opt()],
    };
    let rep = s.handle_solicit(&req).unwrap();
    assert_eq!(rep.msg_type, dhcpv6::MsgType::Reply);
    match rep.option(dhcpv6::OPT_IA_NA) {
        Some(dhcpv6::Dhcpv6Option::IaNa(ia)) => {
            assert_eq!(ia.iaid, 0);
            assert_eq!(ia.addrs.len(), 1);
        }
        _ => panic!("must still commit"),
    }
    assert_eq!(
        s.pool.current_lease(&[5]),
        rep.option(dhcpv6::OPT_IA_NA).and_then(|ia| match ia {
            dhcpv6::Dhcpv6Option::IaNa(ia) => Some(ia.addrs[0].addr),
            _ => None,
        })
    );
}
