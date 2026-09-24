//! DHCP standards accuracy suite, part 2.
//!
//! Covers RFC 2131 / RFC 2132 / RFC 951 areas NOT covered by
//! `test_dhcp_rfc.rs`, so refactors cannot silently break accuracy:
//!
//! - full option support matrix (typed vs transparent passthrough)
//! - client packet-shape rules per state (Table 1: SELECTING / INIT-REBOOT /
//!   RENEWING / INFORM / DECLINE / RELEASE)
//! - relay (`giaddr`/`hops`) destination handling and `secs` retransmission
//! - lease-time edge values incl. infinite, plus T1/T2 passthrough
//! - `sname`/`file` precise split and Overload limitation
//! - BOOTP minimum-size / header-size edge cases
//!
//! Naming: `std_*` = asserts RFC-required behavior; `*_quirk` documents a
//! current deviation and asserts present behavior so it cannot change silently.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

// ---------------------------------------------------------------------------
// helpers
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
    sname_fill: u8,
    file_fill: u8,
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
    // chaddr pad (10) + sname (64) + file (128) with distinct fills so tests
    // can prove each region is ignored/zeroed independently.
    for b in v[34..44].iter_mut() {
        *b = 0; // chaddr pad must stay zero in our builder
    }
    for b in v[44..108].iter_mut() {
        *b = sname_fill;
    }
    for b in v[108..236].iter_mut() {
        *b = file_fill;
    }
    v.extend_from_slice(&[99, 130, 83, 99]);
    v.extend_from_slice(&opts_after_cookie);
    v
}

fn simple_raw(opts: Vec<u8>) -> Vec<u8> {
    make_raw(
        1, 6, 0, 0x01020304, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6], 0, 0, opts,
    )
}

fn client_packet(xid: u32, chaddr: [u8; 6], opts: Vec<DhcpOption>) -> Packet {
    Packet {
        reply: false, hops: 0, xid, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr, options: opts,
    }
}

fn reply_once(msg: MessageType, additional: Vec<DhcpOption>, offer: Ipv4Addr, req: Packet) -> Packet {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H {
        msg: MessageType,
        add: Option<Vec<DhcpOption>>,
        offer: Ipv4Addr,
    }
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let add = self.add.take().unwrap();
            let _ = s.reply(self.msg, add, self.offer, p);
        }
    }
    let h = H { msg, add: Some(additional), offer };
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock, Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 255), h,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("no reply");
    unwrap_packet(Packet::from(&rbuf[..n]))
}

// ===========================================================================
// A. RFC 2132 option support matrix — typed vs transparent passthrough
// ===========================================================================

/// RFC 2132: options 52 (Overload), 57 (Max Message Size), 58/59 (T1/T2),
/// 60 (Vendor Class), 61 (Client Identifier) have no typed variant here and
/// MUST survive as transparent `Unrecognized` (code + data preserved).
#[test]
fn std_unsupported_rfc_options_passthrough() {
    let cases: Vec<(u8, Vec<u8>)> = vec![
        (52, vec![1]),                         // Overload: file
        (57, vec![0x02, 0x40]),                // Max DHCP message size 576
        (58, 600u32.to_be_bytes().to_vec()),   // T1 renewal
        (59, 1200u32.to_be_bytes().to_vec()),  // T2 rebinding
        (60, b"test-client".to_vec()),         // Vendor class
        (61, vec![1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]), // Client id (htype+chaddr)
        (66, b"tftp".to_vec()),                // TFTP server name
        (67, b"pxelinux.0".to_vec()),          // Bootfile
        (77, b"user".to_vec()),                // User class
        (82, vec![1, 2, 3]),                   // Relay agent info
        (93, vec![0, 0]),                      // Client architecture
        (100, b"EST5".to_vec()),               // TZ POSIX
        (101, b"Europe/Berlin".to_vec()),      // TZ database
        (121, vec![24, 192, 168, 1, 192, 168, 1, 1]), // Classless route
    ];
    for (code, data) in &cases {
        match decode_option(&[vec![*code, data.len() as u8], data.clone()].concat()) {
            Ok((rest, DhcpOption::Unrecognized(r))) => {
                assert_eq!(r.code, *code);
                assert_eq!(&r.data, data);
                assert!(rest.is_empty());
            }
            _ => panic!("code {} must decode as Unrecognized", code),
        }
        // to_raw preserves code+data byte-for-byte
        let raw = DhcpOption::Unrecognized(RawDhcpOption { code: *code, data: data.clone() }).to_raw();
        assert_eq!(raw.code, *code);
        assert_eq!(&raw.data, data);
    }
    // and they round-trip through a full Packet (no poison like Router/DNS).
    // keep it small: first 4 need 3+4+6+6=19 bytes (240+19+1=260 fits).
    let small: Vec<DhcpOption> = cases[..4]
        .iter()
        .map(|(c, d)| DhcpOption::Unrecognized(RawDhcpOption { code: *c, data: d.clone() }))
        .collect();
    let small_len = small.len();
    let p = Packet {
        reply: false, hops: 0, xid: 0x77, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6], options: small,
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(q.options.len(), small_len);
    for (got, (code, data)) in q.options.iter().zip(cases[..4].iter()) {
        match got {
            DhcpOption::Unrecognized(r) => {
                assert_eq!(r.code, *code);
                assert_eq!(&r.data, data);
            }
            _ => panic!("code {} must stay Unrecognized after round-trip", code),
        }
    }
}

/// RFC 2132 §9.3/§9.10 vs current decoder: Router (3) / DNS (6) encoder output
/// is standards-shaped (N*4 bytes) but `decode_option` always fails, so a
/// Packet carrying them loses them. Locked here as a known non-conformance so
/// a refactor cannot silently change half the behavior.
#[test]
fn std_router_dns_encoder_shaped_decoder_drops_quirk() {
    let r = DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1)]).to_raw();
    assert_eq!(r.code, 3);
    assert_eq!(r.data.len(), 8, "RFC: 2 addrs = 8 bytes");
    let d = DhcpOption::DomainNameServer(vec![Ipv4Addr::new(8, 8, 8, 8)]).to_raw();
    assert_eq!(d.code, 6);
    assert_eq!(d.data.len(), 4);
    // decoder side drops them
    assert!(matches!(decode_option(&[3, 4, 192, 168, 1, 1]), Err(CustomErr::InvalidHlen)));
    assert!(matches!(decode_option(&[6, 4, 8, 8, 8, 8]), Err(CustomErr::InvalidHlen)));
}

/// RFC 2131 §3.5 + RFC 2132 §9.10: Client Identifier (61) SHOULD be used for
/// identity when present; this stack only keys on `chaddr`. Lock that a
/// client-id option is preserved on the wire but never consulted.
#[test]
fn std_client_identifier_ignored_for_identity_quirk() {
    // wire: client-id present alongside chaddr
    let p = Packet {
        reply: false, hops: 0, xid: 0x88, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xAA; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::Unrecognized(RawDhcpOption { code: 61, data: vec![1, 2, 3, 4] }),
        ],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    let q = unwrap_packet(Packet::from(&enc));
    // preserved transparently ...
    assert!(q.options.iter().any(|o| o.code() == 61));
    // ... but identity is still chaddr (option() lookup is by code; there is
    // no typed ClientId branch, so callers can only see the raw bytes)
    assert_eq!(q.chaddr, [0xAA; 6]);
    assert!(matches!(q.option(61), Some(DhcpOption::Unrecognized(_))));
}

// ===========================================================================
// B. RFC 2131 Table 1 / §3.1 client packet-shape rules per state
// ===========================================================================

/// RFC 2131 Table 1, DHCPDISCOVER: Server Identifier MUST NOT, Requested IP
/// MUST NOT appear. Library does not enforce (correct: enforcement is the
/// app's job) but it MUST be able to express the compliant shape.
#[test]
fn std_discover_shape_no_serverid_no_requestedip() {
    let p = client_packet(0xA1, [1; 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Discover),
        DhcpOption::ParameterRequestList(vec![1, 3, 6]),
    ]);
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
    assert!(p.option(SERVER_IDENTIFIER).is_none());
    assert!(p.option(REQUESTED_IP_ADDRESS).is_none());
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
    assert!(q.option(SERVER_IDENTIFIER).is_none());
    assert!(q.option(REQUESTED_IP_ADDRESS).is_none());
}

/// RFC 2131 Table 1, REQUEST SELECTING (after Offer): MUST carry Server ID +
/// Requested IP, MUST NOT carry ciaddr.
#[test]
fn std_request_selecting_shape() {
    let p = Packet {
        reply: false, hops: 0, xid: 0xA2, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [2; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 70)),
        ],
    };
    assert_eq!(p.ciaddr, Ipv4Addr::UNSPECIFIED);
    assert!(p.option(SERVER_IDENTIFIER).is_some());
    assert!(p.option(REQUESTED_IP_ADDRESS).is_some());
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
    assert_eq!(q.option(SERVER_IDENTIFIER), Some(&DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1))));
}

/// RFC 2131 Table 1, REQUEST INIT-REBOOT: Requested IP present, Server ID
/// absent, ciaddr zero (client has no address yet).
#[test]
fn std_request_init_reboot_shape() {
    let p = Packet {
        reply: false, hops: 0, xid: 0xA3, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [3; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 80)),
        ],
    };
    assert!(p.option(SERVER_IDENTIFIER).is_none());
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
    assert!(q.option(SERVER_IDENTIFIER).is_none());
    assert_eq!(
        q.option(REQUESTED_IP_ADDRESS),
        Some(&DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 80)))
    );
}

/// RFC 2131 Table 1, REQUEST RENEWING (T1 unicast): ciaddr set, NO Server ID,
/// NO Requested IP.
#[test]
fn std_request_renewing_shape() {
    let p = Packet {
        reply: false, hops: 0, xid: 0xA4, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 1, 50), yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [4; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    assert_eq!(p.ciaddr, Ipv4Addr::new(192, 168, 1, 50));
    assert!(p.option(SERVER_IDENTIFIER).is_none());
    assert!(p.option(REQUESTED_IP_ADDRESS).is_none());
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
    assert_eq!(q.ciaddr, Ipv4Addr::new(192, 168, 1, 50));
}

/// RFC 2131 Table 1, DHCPINFORM: client already has an address (ciaddr set),
/// asks only for config; MUST NOT carry Requested IP.
#[test]
fn std_inform_shape_ciaddr_no_requestedip() {
    let p = Packet {
        reply: false, hops: 0, xid: 0xA5, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 1, 60), yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [5; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Inform),
            DhcpOption::ParameterRequestList(vec![1, 15]),
        ],
    };
    assert_eq!(p.message_type(), Ok(MessageType::Inform));
    assert!(p.option(REQUESTED_IP_ADDRESS).is_none());
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
    assert_eq!(q.message_type(), Ok(MessageType::Inform));
}

/// RFC 2131 Table 1, DECLINE: Server ID + Requested IP; RELEASE: Server ID +
/// ciaddr. Both must survive encode/decode.
#[test]
fn std_decline_release_shapes() {
    let decline = Packet {
        reply: false, hops: 0, xid: 0xA6, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [6; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Decline),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 70)),
        ],
    };
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&decline.encode(&mut buf).to_vec()));
    assert_eq!(q.message_type(), Ok(MessageType::Decline));

    let release = Packet {
        reply: false, hops: 0, xid: 0xA7, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 1, 70), yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [6; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Release),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)),
        ],
    };
    let q = unwrap_packet(Packet::from(&release.encode(&mut buf).to_vec()));
    assert_eq!(q.message_type(), Ok(MessageType::Release));
    assert_eq!(q.ciaddr, Ipv4Addr::new(192, 168, 1, 70));
}

// ===========================================================================
// C. Relay, secs, hops accuracy
// ===========================================================================

/// RFC 2131 §3.3: relay sets `giaddr` to its own address and bumps `hops`.
/// Decoder MUST preserve both; server reply resets `hops` and echoes `giaddr`.
#[test]
fn std_relay_fields_preserved_and_echoed() {
    let raw = make_raw(
        1, 6, 2, 0xBEEF, 7, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [10, 9, 9, 9],
        [8; 6], 0, 0, vec![53, 1, 1, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.hops, 2);
    assert_eq!(p.giaddr, Ipv4Addr::new(10, 9, 9, 9));
    assert_eq!(p.secs, 7);
    let rep = reply_once(MessageType::Offer, vec![], Ipv4Addr::new(10, 9, 9, 50), p);
    // hmm: reply_once consumes a Packet struct, not raw; rebuild relayed struct
    let _ = rep;
    // struct-level relay echo (no network needed for the rule itself)
    let relayed = Packet {
        reply: false, hops: 2, xid: 0xBEEF, secs: 7, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::new(10, 9, 9, 9),
        chaddr: [8; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let rep2 = reply_once(MessageType::Offer, vec![], Ipv4Addr::new(10, 9, 9, 50), relayed);
    assert_eq!(rep2.hops, 0, "server MUST reset hops");
    assert_eq!(rep2.giaddr, Ipv4Addr::new(10, 9, 9, 9), "server MUST echo giaddr");
}

/// RFC 2131 §4.1 deviation locked: `Server::send` chooses destination from
/// `broadcast`/`src` only — `giaddr` is echoed but NEVER used for routing.
/// A relayed request is still answered at the peer socket, not at `giaddr`.
#[test]
fn std_giaddr_never_selects_destination_quirk() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            assert_eq!(p.giaddr, Ipv4Addr::new(10, 99, 99, 99));
            let _ = s.reply(MessageType::Offer, vec![], Ipv4Addr::new(10, 99, 99, 50), p);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock, Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 255), H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let req = Packet {
        reply: false, hops: 1, xid: 0xC1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::new(10, 99, 99, 99),
        chaddr: [9; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let mut buf = [0u8; 1500];
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut rbuf = [0u8; 1500];
    // arrives back at the peer socket even though giaddr points elsewhere
    let (n, _) = client.recv_from(&mut rbuf).expect("reply must arrive at src, not giaddr");
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.giaddr, Ipv4Addr::new(10, 99, 99, 99));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(10, 99, 99, 50));
}

/// RFC 2131 §4.2: `secs` counts seconds since the client began acquiring;
/// it is filled by the client (preserved on decode) and zeroed by the server.
#[test]
fn std_secs_client_fills_server_zeroes() {
    let raw = make_raw(
        1, 6, 0, 0xC2, 30, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1; 6], 0, 0, vec![53, 1, 1, 255],
    );
    assert_eq!(unwrap_packet(Packet::from(&raw)).secs, 30);
    let req = Packet {
        reply: false, hops: 0, xid: 0xC2, secs: 30, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [1; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let rep = reply_once(MessageType::Offer, vec![], Ipv4Addr::new(192, 168, 1, 90), req);
    assert_eq!(rep.secs, 0);
}

// ===========================================================================
// D. Lease-time accuracy (RFC 2131 §3.5, RFC 2132 §9.10)
// ===========================================================================

/// RFC 2132 §9.10: lease time is uint32 seconds, big-endian; 0xFFFFFFFF =
/// infinite. Must round-trip through packets exactly.
#[test]
fn std_lease_time_edge_values_roundtrip() {
    for secs in [0u32, 1, 60, 3600, 86400, 0x7FFFFFFF, u32::MAX] {
        let p = Packet {
            reply: true, hops: 0, xid: 0xD1, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::new(192, 168, 1, 91),
            siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [2; 6],
            options: vec![
                DhcpOption::DhcpMessageType(MessageType::Ack),
                DhcpOption::IpAddressLeaseTime(secs),
            ],
        };
        let mut buf = [0u8; 1500];
        let enc = p.encode(&mut buf).to_vec();
        let q = unwrap_packet(Packet::from(&enc));
        assert_eq!(
            q.option(IP_ADDRESS_LEASE_TIME),
            Some(&DhcpOption::IpAddressLeaseTime(secs)),
            "lease {}s must survive",
            secs
        );
        // wire is exactly big-endian uint32
        let raw = DhcpOption::IpAddressLeaseTime(secs).to_raw();
        assert_eq!(raw.data, secs.to_be_bytes().to_vec());
    }
}

/// RFC 2132 §9.11/§9.12: T1 (renewal) / T2 (rebinding) are uint32 seconds.
/// This stack has no typed variant, so they MUST survive as `Unrecognized`
/// with 4-byte big-endian payloads (client/server still interoperate).
#[test]
fn std_t1_t2_passthrough_with_be_seconds() {
    let t1: u32 = 1800;
    let t2: u32 = 3150;
    let p = Packet {
        reply: true, hops: 0, xid: 0xD2, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::new(192, 168, 1, 92),
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [3; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Ack),
            DhcpOption::Unrecognized(RawDhcpOption { code: RENEWAL_TIME_VALUE, data: t1.to_be_bytes().to_vec() }),
            DhcpOption::Unrecognized(RawDhcpOption { code: REBINDING_TIME_VALUE, data: t2.to_be_bytes().to_vec() }),
        ],
    };
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
    assert_eq!(
        q.option(RENEWAL_TIME_VALUE),
        Some(&DhcpOption::Unrecognized(RawDhcpOption { code: 58, data: t1.to_be_bytes().to_vec() }))
    );
    assert_eq!(
        q.option(REBINDING_TIME_VALUE),
        Some(&DhcpOption::Unrecognized(RawDhcpOption { code: 59, data: t2.to_be_bytes().to_vec() }))
    );
}

/// RFC 2131 §3.5: `yiaddr` 0.0.0.0 in a NAK means "no address granted".
#[test]
fn std_nak_yiaddr_zero_means_no_grant() {
    let req = Packet {
        reply: false, hops: 0, xid: 0xD3, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [4; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    let rep = reply_once(MessageType::Nak, vec![], Ipv4Addr::UNSPECIFIED, req);
    assert_eq!(rep.message_type(), Ok(MessageType::Nak));
    assert_eq!(rep.yiaddr, Ipv4Addr::UNSPECIFIED);
}

// ===========================================================================
// E. sname/file split + Overload limitation (RFC 2131 §2, RFC 2132 §9.3)
// ===========================================================================

/// RFC 951 §3: `chaddr` field is 16 bytes (6 + 10 pad), `sname` 64, `file`
/// 128. Encoder MUST zero all 202 bytes when unused.
#[test]
fn std_chaddr_sname_file_zero_split() {
    let p = client_packet(0xE1, [0xAA; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Discover,
    )]);
    let mut buf = [0xFFu8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(&enc[28..34], &[0xAA; 6]); // chaddr bytes
    assert!(enc[34..44].iter().all(|&b| b == 0)); // chaddr pad (10)
    assert!(enc[44..108].iter().all(|&b| b == 0)); // sname (64)
    assert!(enc[108..236].iter().all(|&b| b == 0)); // file (128)
}

/// Decoder ignores all three regions except the first 6 `chaddr` bytes.
#[test]
fn std_sname_file_regions_ignored_independently() {
    let raw = make_raw(
        1, 6, 0, 0xE2, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [5; 6], 0x41, 0x42, vec![53, 1, 1, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.chaddr, [5; 6]);
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
}

/// RFC 2132 §9.3 deviation: Overload (52) is decoded as opaque data and the
/// `sname`/`file` regions are NEVER scanned for options. A uniform TLV
/// hidden in `sname` must not appear in `packet.options`.
#[test]
fn std_overload_does_not_trigger_sname_parsing_quirk() {
    // overload=1 ("file holds options") + a well-formed option smuggled
    // into the sname region (bytes 44..): it must be ignored.
    let mut raw = make_raw(
        1, 6, 0, 0xE3, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [6; 6], 0, 0, vec![52, 1, 1, 53, 1, 2, 255],
    );
    // smuggle [1,4,255,255,255,0] (subnet) into sname at offset 44
    raw[44] = 1;
    raw[45] = 4;
    raw[46..50].copy_from_slice(&[255, 255, 255, 0]);
    let p = unwrap_packet(Packet::from(&raw));
    // only the real options area counts: overload + msgtype
    let codes: Vec<u8> = p.options.iter().map(|o| o.code()).collect();
    assert_eq!(codes, vec![52, 53]);
    assert!(p.option(SUBNET_MASK).is_none(), "sname TLV must be ignored");
}

// ===========================================================================
// F. BOOTP compatibility edges: sizes, chaddr field, xid randomness shape
// ===========================================================================

/// Fixed header alone (236 bytes, no cookie/options) is rejected; header +
/// cookie with only END is the smallest decodable datagram.
#[test]
fn std_minimum_decodable_sizes() {
    // all-zero 236 bytes fails hlen first (hlen=0), not the cookie check
    assert!(matches!(Packet::from(&[0u8; 236]), Err(CustomErr::InvalidHlen)));
    // valid header (op=1, htype=1, hlen=6) but no cookie -> NomError(Tag)
    let mut no_cookie = vec![0u8; 236];
    no_cookie[0] = 1;
    no_cookie[1] = 1;
    no_cookie[2] = 6;
    assert!(matches!(Packet::from(&no_cookie), Err(CustomErr::NomError(_))));
    let mut smallest = vec![0u8; 236];
    smallest[0] = 1;
    smallest[1] = 1;
    smallest[2] = 6;
    smallest.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1, 255]);
    assert!(Packet::from(&smallest).is_ok());
    assert!(matches!(Packet::from(&[0u8; 10]), Err(CustomErr::InvalidHlen)));
}

/// RFC 951: `chaddr` on the wire is 16 bytes; only the first `hlen` (6) are
/// significant. Bytes 34..44 MUST be zero and MUST NOT leak into `chaddr`.
#[test]
fn std_chaddr_field_is_16_bytes_first_6_significant() {
    let mut raw = simple_raw(vec![53, 1, 1, 255]);
    raw[28..34].copy_from_slice(&[10, 20, 30, 40, 50, 60]);
    raw[34..44].copy_from_slice(&[99; 10]); // non-zero pad must be ignored
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.chaddr, [10, 20, 30, 40, 50, 60]);
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(enc[34..44].iter().all(|&b| b == 0), "encoder must re-zero pad");
}

/// RFC 2131 §4.2: `xid` is a random transaction id chosen by the client and
/// echoed by the server; distinct requests SHOULD use distinct ids (shape
/// test: 0, 1, MAX all survive the round-trip).
#[test]
fn std_xid_uniqueness_shape() {
    for xid in [0u32, 1, 0x12345678, u32::MAX] {
        let p = client_packet(xid, [7; 6], vec![DhcpOption::DhcpMessageType(
            MessageType::Discover,
        )]);
        let mut buf = [0u8; 1500];
        let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
        assert_eq!(q.xid, xid);
        let rep = reply_once(MessageType::Offer, vec![], Ipv4Addr::new(192, 168, 1, 93), p);
        assert_eq!(rep.xid, xid, "server MUST echo xid");
    }
}

/// RFC 2132 §2: option data length is one byte, so no single option payload
/// may exceed 255 bytes. `to_raw` + `encode` MUST NOT emit a truncated length
/// prefix (lengths used here stay small and exact; 100-byte payloads fit in
/// `to_raw` but would overflow the 300-byte packet, so the Packet-level
/// check uses 20 bytes which fits: 240 + 3 + 22 + 1 = 266).
#[test]
fn std_option_len_single_byte_exact() {
    let big = vec![9u8; 100];
    let raw = DhcpOption::Unrecognized(RawDhcpOption { code: 200, data: big.clone() }).to_raw();
    assert_eq!(raw.data.len(), 100);
    let data = vec![9u8; 20];
    let p = Packet {
        reply: false, hops: 0, xid: 0xF1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::Unrecognized(RawDhcpOption { code: 200, data }),
        ],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    // second option header at 243: code 200, len 20
    assert_eq!(enc[243], 200);
    assert_eq!(enc[244], 20);
}

/// RFC 2131 §3.1: a subnet mask, when present, SHOULD be a contiguous mask.
/// The stack performs no validation (correct layering) and MUST preserve any
/// 4-byte value untouched.
#[test]
fn std_subnet_mask_not_validated() {
    for mask in [Ipv4Addr::new(255, 255, 255, 0), Ipv4Addr::new(1, 2, 3, 4)] {
        let p = Packet {
            reply: true, hops: 0, xid: 0xF2, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 6],
            options: vec![
                DhcpOption::DhcpMessageType(MessageType::Ack),
                DhcpOption::SubnetMask(mask),
            ],
        };
        let mut buf = [0u8; 1500];
        let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
        assert_eq!(q.option(SUBNET_MASK), Some(&DhcpOption::SubnetMask(mask)));
    }
}
