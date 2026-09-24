//! Tests for the example DHCPv6 service logic (`examples/server.rs` v6 half).
//!
//! The example binary cannot be imported, so — following this repo's
//! convention (see `test_examples_extra.rs`) — `TestV6Server` below mirrors
//! the `serve_v6` match arms body-for-body but returns `Option<Packet>`
//! instead of sending on a socket. This locks the Solicit/Request/Renew/
//! Rebind/Release/Decline decisions, the IAID echo, T1/T2 and DNS policy,
//! the NoAddrsAvail shape, and the `leases6` loader's skip rules.

use dhcp4r::dhcpv6::*;
use std::net::Ipv6Addr;
use std::time::Duration;

fn v6(a: [u16; 8]) -> Ipv6Addr {
    Ipv6Addr::new(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
}

const SERVER_DUID: [u8; 10] = [0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0xaa, 0xbb, 0xcc];
const LEASE_SECS: u32 = 86400;

fn pool() -> V6Pool {
    V6Pool::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100),
        1000,
        Duration::from_secs(LEASE_SECS as u64),
    )
}

fn ip(n: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, n)
}

// ---------------------------------------------------------------------------
// TestV6Server: same decisions as examples/server.rs serve_v6, pure return
// ---------------------------------------------------------------------------

struct TestV6Server {
    pool: V6Pool,
    server_duid: Vec<u8>,
    lease_secs: u32,
    dns: Vec<Ipv6Addr>,
}

impl TestV6Server {
    fn new() -> Self {
        Self {
            pool: pool(),
            server_duid: SERVER_DUID.to_vec(),
            lease_secs: LEASE_SECS,
            dns: vec![v6([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888])],
        }
    }

    fn success(&self, req: &Packet, msg_type: MsgType, ip: Ipv6Addr) -> Packet {
        let iaid = req.first_iana().map(|ia| ia.iaid).unwrap_or(0);
        let (t1, t2) = default_t1_t2(self.lease_secs);
        let duid = match req.option(OPT_CLIENTID) {
            Some(Dhcpv6Option::ClientId(d)) => d.clone(),
            _ => vec![],
        };
        let mut options = vec![
            Dhcpv6Option::ServerId(self.server_duid.clone()),
            Dhcpv6Option::ClientId(duid),
            Dhcpv6Option::IaNa(IaNa {
                iaid,
                t1,
                t2,
                addrs: vec![IaAddr { addr: ip, preferred: self.lease_secs, valid: self.lease_secs }],
            }),
        ];
        if !self.dns.is_empty() {
            options.push(Dhcpv6Option::DnsServers(self.dns.clone()));
        }
        Packet { msg_type, transaction_id: req.transaction_id, options }
    }

    fn nodata(&self, req: &Packet, msg_type: MsgType) -> Packet {
        let iaid = req.first_iana().map(|ia| ia.iaid).unwrap_or(0);
        let duid = match req.option(OPT_CLIENTID) {
            Some(Dhcpv6Option::ClientId(d)) => d.clone(),
            _ => vec![],
        };
        Packet {
            msg_type,
            transaction_id: req.transaction_id,
            options: vec![
                Dhcpv6Option::ServerId(self.server_duid.clone()),
                Dhcpv6Option::ClientId(duid),
                Dhcpv6Option::IaNa(IaNa { iaid, t1: 0, t2: 0, addrs: vec![] }),
                Dhcpv6Option::StatusCode(STATUS_NO_ADDRS_AVAIL, "NoAddrsAvail".to_string()),
            ],
        }
    }

    fn handle(&mut self, req: &Packet) -> Option<Packet> {
        let duid = match req.option(OPT_CLIENTID) {
            Some(Dhcpv6Option::ClientId(d)) => d.clone(),
            _ => return None,
        };
        match req.msg_type {
            MsgType::Solicit => match self.pool.discover(&duid) {
                Some(ip) => Some(self.success(req, MsgType::Advertise, ip)),
                None => Some(self.nodata(req, MsgType::Advertise)),
            },
            MsgType::Request | MsgType::Renew | MsgType::Rebind => {
                let wanted = req.first_iana()?.addrs.first()?.addr;
                match self.pool.request(&duid, wanted) {
                    Ok(ip) => Some(self.success(req, MsgType::Reply, ip)),
                    Err(_) => Some(self.nodata(req, MsgType::Reply)),
                }
            }
            MsgType::Release | MsgType::Decline => {
                if !is_for_server(&self.server_duid, req) {
                    return None;
                }
                self.pool.release(&duid);
                None
            }
            _ => None,
        }
    }
}

fn solicit(duid_bytes: &[u8], iaid: Option<u32>) -> Packet {
    let mut options = vec![Dhcpv6Option::ClientId(duid_bytes.to_vec())];
    if let Some(id) = iaid {
        options.push(Dhcpv6Option::IaNa(IaNa { iaid: id, t1: 0, t2: 0, addrs: vec![] }));
    }
    Packet { msg_type: MsgType::Solicit, transaction_id: 0x112233, options }
}

fn request_for(duid_bytes: &[u8], iaid: u32, addr: Ipv6Addr) -> Packet {
    Packet {
        msg_type: MsgType::Request,
        transaction_id: 0x445566,
        options: vec![
            Dhcpv6Option::ClientId(duid_bytes.to_vec()),
            Dhcpv6Option::ServerId(SERVER_DUID.to_vec()),
            Dhcpv6Option::IaNa(IaNa {
                iaid,
                t1: 0,
                t2: 0,
                addrs: vec![IaAddr { addr, preferred: 0, valid: 0 }],
            }),
        ],
    }
}

fn codes(p: &Packet) -> Vec<u16> {
    p.options.iter().map(|o| o.code()).collect()
}

// ---------------------------------------------------------------------------
// Solicit flows
// ---------------------------------------------------------------------------

#[test]
fn solicit_fresh_duid_advertises_first_free() {
    let mut s = TestV6Server::new();
    let rep = s.handle(&solicit(&[1], Some(0x0A0B0C0D))).unwrap();
    assert_eq!(rep.msg_type, MsgType::Advertise);
    assert_eq!(rep.transaction_id, 0x112233, "tid echoed");
    assert_eq!(codes(&rep), vec![2, 1, 3, 23]);
    assert_eq!(
        rep.option(OPT_SERVERID),
        Some(&Dhcpv6Option::ServerId(SERVER_DUID.to_vec()))
    );
    assert_eq!(rep.option(OPT_CLIENTID), Some(&Dhcpv6Option::ClientId(vec![1])));
    match rep.option(OPT_IA_NA) {
        Some(Dhcpv6Option::IaNa(ia)) => {
            assert_eq!(ia.iaid, 0x0A0B0C0D, "request IAID echoed");
            assert_eq!((ia.t1, ia.t2), (43200, 75600));
            assert_eq!(ia.addrs.len(), 1);
            assert_eq!(ia.addrs[0].addr, ip(0x101), "first free past start");
            assert_eq!((ia.addrs[0].preferred, ia.addrs[0].valid), (86400, 86400));
        }
        _ => panic!("Advertise must carry IA_NA"),
    }
    assert!(rep.option(OPT_STATUS_CODE).is_none(), "success has no status");
}

#[test]
fn solicit_prefers_current_lease() {
    let mut s = TestV6Server::new();
    s.pool.request(&[1], ip(0x110)).unwrap();
    let rep = s.handle(&solicit(&[1], Some(7))).unwrap();
    match rep.option(OPT_IA_NA) {
        Some(Dhcpv6Option::IaNa(ia)) => {
            assert_eq!(ia.addrs.len(), 1);
            assert_eq!(ia.addrs[0].addr, ip(0x110));
        }
        _ => panic!("must re-offer current lease"),
    }
}

#[test]
fn solicit_no_clientid_ignored() {
    let mut s = TestV6Server::new();
    let req = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 1,
        options: vec![Dhcpv6Option::IaNa(IaNa { iaid: 1, t1: 0, t2: 0, addrs: vec![] })],
    };
    assert!(s.handle(&req).is_none(), "no DUID means no identity");
}

#[test]
fn solicit_without_iana_advertises_iaid_zero() {
    let mut s = TestV6Server::new();
    let req = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 2,
        options: vec![Dhcpv6Option::ClientId(vec![9])],
    };
    let rep = s.handle(&req).unwrap();
    match rep.option(OPT_IA_NA) {
        Some(Dhcpv6Option::IaNa(ia)) => {
            assert_eq!(ia.iaid, 0, "missing IA_NA defaults IAID to 0");
            assert_eq!(ia.addrs.len(), 1);
        }
        _ => panic!("must still Advertise"),
    }
}

// ---------------------------------------------------------------------------
// Request / Renew / Rebind flows
// ---------------------------------------------------------------------------

#[test]
fn request_commits_and_acks_with_lease() {
    let mut s = TestV6Server::new();
    let rep = s.handle(&request_for(&[2], 0x01020304, ip(0x120))).unwrap();
    assert_eq!(rep.msg_type, MsgType::Reply);
    assert_eq!(rep.transaction_id, 0x445566);
    match rep.option(OPT_IA_NA) {
        Some(Dhcpv6Option::IaNa(ia)) => {
            assert_eq!(ia.iaid, 0x01020304);
            assert_eq!(ia.addrs.len(), 1);
            assert_eq!((ia.addrs[0].preferred, ia.addrs[0].valid), (86400, 86400));
        }
        _ => panic!("Reply must carry IA_NA"),
    }
    assert!(s.pool.get(&ip(0x120)).is_some(), "committed server-side");
    assert!(rep.option(OPT_STATUS_CODE).is_none());
}

#[test]
fn request_without_iana_ignored() {
    let mut s = TestV6Server::new();
    let req = Packet {
        msg_type: MsgType::Request,
        transaction_id: 3,
        options: vec![
            Dhcpv6Option::ClientId(vec![2]),
            Dhcpv6Option::ServerId(SERVER_DUID.to_vec()),
        ],
    };
    assert!(s.handle(&req).is_none(), "no IA_NA means nothing to commit");
    assert!(s.pool.is_empty());
}

#[test]
fn request_unavailable_gets_nodata_status() {
    let mut s = TestV6Server::new();
    s.pool.request(&[8], ip(0x130)).unwrap(); // squatter
    let rep = s.handle(&request_for(&[9], 0x11111111, ip(0x130))).unwrap();
    assert_eq!(rep.msg_type, MsgType::Reply);
    assert_eq!(codes(&rep), vec![2, 1, 3, 13]);
    match rep.option(OPT_IA_NA) {
        Some(Dhcpv6Option::IaNa(ia)) => {
            assert_eq!(ia.iaid, 0x11111111);
            assert!(ia.addrs.is_empty());
            assert_eq!((ia.t1, ia.t2), (0, 0));
        }
        _ => panic!("nodata Reply keeps an empty IA_NA"),
    }
    assert_eq!(
        rep.option(OPT_STATUS_CODE),
        Some(&Dhcpv6Option::StatusCode(STATUS_NO_ADDRS_AVAIL, "NoAddrsAvail".to_string()))
    );
}

#[test]
fn renew_and_rebind_behave_like_request() {
    for mt in [MsgType::Renew, MsgType::Rebind] {
        let mut s = TestV6Server::new();
        let mut req = request_for(&[3], 0x22222222, ip(0x140));
        req.msg_type = mt;
        req.transaction_id = 0x333333;
        let rep = s.handle(&req).unwrap();
        assert_eq!(rep.msg_type, MsgType::Reply, "{:?}", mt);
        assert_eq!(rep.transaction_id, 0x333333);
        match rep.option(OPT_IA_NA) {
            Some(Dhcpv6Option::IaNa(ia)) => {
                assert_eq!(ia.addrs.len(), 1);
                assert_eq!(ia.addrs[0].addr, ip(0x140));
            }
            _ => panic!("{:?} must commit like Request", mt),
        }
    }
}

// ---------------------------------------------------------------------------
// Release / Decline / ignored types
// ---------------------------------------------------------------------------

#[test]
fn release_and_decline_free_with_correct_id() {
    for mt in [MsgType::Release, MsgType::Decline] {
        let mut s = TestV6Server::new();
        s.pool.request(&[4], ip(0x150)).unwrap();
        let pkt = Packet {
            msg_type: mt,
            transaction_id: 4,
            options: vec![
                Dhcpv6Option::ClientId(vec![4]),
                Dhcpv6Option::ServerId(SERVER_DUID.to_vec()),
            ],
        };
        assert!(s.handle(&pkt).is_none(), "{:?} sends no reply", mt);
        assert!(s.pool.get(&ip(0x150)).is_none(), "{:?} must free", mt);
    }
}

#[test]
fn release_wrong_or_missing_id_keeps_lease() {
    for opts in [
        vec![
            Dhcpv6Option::ClientId(vec![5]),
            Dhcpv6Option::ServerId(vec![9, 9, 9]),
        ],
        vec![Dhcpv6Option::ClientId(vec![5])],
    ] {
        let mut s = TestV6Server::new();
        s.pool.request(&[5], ip(0x160)).unwrap();
        let pkt = Packet { msg_type: MsgType::Release, transaction_id: 5, options: opts };
        assert!(s.handle(&pkt).is_none());
        assert!(s.pool.get(&ip(0x160)).is_some(), "lease must survive");
    }
}

#[test]
fn confirm_and_informationrequest_ignored() {
    let mut s = TestV6Server::new();
    for mt in [MsgType::Confirm, MsgType::InformationRequest, MsgType::Reply, MsgType::Reconfigure] {
        let req = Packet {
            msg_type: mt,
            transaction_id: 6,
            options: vec![Dhcpv6Option::ClientId(vec![6])],
        };
        assert!(s.handle(&req).is_none(), "{:?} must be ignored", mt);
    }
    assert!(s.pool.is_empty(), "ignored types insert nothing");
}

// ---------------------------------------------------------------------------
// leases6 loader rules (mirror of examples/server.rs serve_v6 loader)
// ---------------------------------------------------------------------------

fn load_leases6(text: &str) -> V6Pool {
    let mut pool = V6Pool::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100),
        1000,
        Duration::from_secs(86400),
    );
    for line in text.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() == 2 {
            if let (Ok(duid), Ok(ip)) = (
                dhcp4r::config::parse_duid_hex(parts[0].trim()),
                parts[1].trim().parse::<Ipv6Addr>(),
            ) {
                if !duid.is_empty() {
                    pool.insert(ip, duid, None);
                }
            }
        }
    }
    pool
}

#[test]
fn leases6_loader_skips_malformed_keeps_good() {
    let pool = load_leases6(
        "00:03:00:01:02:00:5e:aa:bb:cc,fd00::100\n\
         not-hex-here,fd00::101\n\
         00:03:00:01:02:00:5e:aa:bb:cc,not-an-ip\n\
         singlefield\n\
         a,b,c\n\
         ,fd00::102\n\
         00:03:00:01:02:00:5e:aa:bb:dd,fd00::101\n",
    );
    assert_eq!(pool.len(), 2);
    assert_eq!(
        pool.get(&v6([0xfd00, 0, 0, 0, 0, 0, 0, 0x100])).unwrap().0,
        vec![0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0xaa, 0xbb, 0xcc]
    );
    // infinite (None) expiry like the v4 permanent file
    assert!(pool.get(&v6([0xfd00, 0, 0, 0, 0, 0, 0, 0x100])).unwrap().1.is_none());
    assert_eq!(
        pool.get(&v6([0xfd00, 0, 0, 0, 0, 0, 0, 0x101])).unwrap().0,
        vec![0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0xaa, 0xbb, 0xdd]
    );
}

#[test]
fn leases6_duplicate_ip_last_wins() {
    let pool = load_leases6(
        "00:01,fd00::110\n00:02,fd00::110\n",
    );
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.get(&v6([0xfd00, 0, 0, 0, 0, 0, 0, 0x110])).unwrap().0, vec![0x00, 0x02]);
}

#[test]
fn oro_ignored_dns_always_included() {
    // Option Request asking only for DNS still gets the full success shape
    // incl. DNS — the server does not tailor by ORO (documented).
    let mut s = TestV6Server::new();
    let req = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 7,
        options: vec![
            Dhcpv6Option::ClientId(vec![8]),
            Dhcpv6Option::Unrecognized(dhcp4r::dhcpv6::RawDhcpv6Option {
                code: OPT_ORO,
                data: vec![0, 23],
            }),
        ],
    };
    let rep = s.handle(&req).unwrap();
    assert!(rep.option(OPT_DNS_SERVERS).is_some());
    assert_eq!(codes(&rep), vec![2, 1, 3, 23]);
}
