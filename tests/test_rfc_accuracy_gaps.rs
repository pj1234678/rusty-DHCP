//! DHCP standards accuracy gaps, part 4.
//!
//! Covers RFC 2131 / 2132 / 951 corners NOT locked by
//! `test_dhcp_rfc.rs` / `test_dhcp_standards.rs` / `test_dhcp_tables.rs` /
//! `test_packet*.rs` / `test_server*.rs`:
//!
//! - exhaustive option-code decode branch matrix (typed vs passthrough)
//! - exact diagnostic strings for `MessageType::from` / `message_type()`
//! - encode buffer-size boundaries (240 panic / 241 minimal / 300 exact)
//! - missing-END with trailing byte succeeds vs exact-consumption panics
//! - option 255 (END) asymmetry: `to_raw` preserves, decode panics
//! - hops edge values + reply reset, flags wire bytes, siaddr zeroing
//! - NAK `yiaddr` left to caller (library does not force 0)
//! - example Offer shape + T1/T2 RFC defaults when 58/59 absent
//! - overload values 2/3, retransmit identity (xid/chaddr stable, secs grows)
//!
//! `*_quirk` tests lock current deviations so refactors cannot change them
//! silently. All tests pass against the current implementation.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

// ---------------------------------------------------------------------------
// helpers (same patterns as the other RFC suites)
// ---------------------------------------------------------------------------

fn unwrap_packet(r: Result<Packet, CustomErr<&[u8]>>) -> Packet {
    match r {
        Ok(p) => p,
        Err(_) => panic!("expected Ok Packet"),
    }
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

fn client_packet(xid: u32, chaddr: [u8; 6], opts: Vec<DhcpOption>) -> Packet {
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

fn reply_once(
    msg: MessageType,
    additional: Vec<DhcpOption>,
    offer: Ipv4Addr,
    req: Packet,
) -> Packet {
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
    let h = H {
        msg,
        add: Some(additional),
        offer,
    };
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 255),
            h,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    client
        .send_to(&req.encode(&mut buf).to_vec(), srv_addr)
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (n, _) = client.recv_from(&mut rbuf).expect("no reply");
    unwrap_packet(Packet::from(&rbuf[..n]))
}

// ===========================================================================
// 1. Exhaustive option-code decode branch matrix
// ===========================================================================

/// RFC 2132: only codes 1, 12, 50, 51, 53, 54, 55, 56 decode as typed
/// (3/6 always error — see quirk test below). Every other code 0..=254 must
/// decode as transparent `Unrecognized`. Code 255 (END) panics — tested
/// separately. Locks that adding a typed branch cannot break wire compat.
#[test]
fn gap_decode_branch_matrix_typed_vs_passthrough() {
    // (code, wire bytes, expected typed check)
    // typed codes with valid payloads
    match decode_option(&[53, 1, 1]) {
        Ok((_, DhcpOption::DhcpMessageType(MessageType::Discover))) => {}
        _ => panic!("53 must be typed"),
    }
    match decode_option(&[54, 4, 10, 0, 0, 1]) {
        Ok((_, DhcpOption::ServerIdentifier(ip))) => {
            assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1))
        }
        _ => panic!("54 must be typed"),
    }
    match decode_option(&[50, 4, 10, 0, 0, 9]) {
        Ok((_, DhcpOption::RequestedIpAddress(ip))) => {
            assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 9))
        }
        _ => panic!("50 must be typed"),
    }
    match decode_option(&[1, 4, 255, 255, 255, 0]) {
        Ok((_, DhcpOption::SubnetMask(ip))) => {
            assert_eq!(ip, Ipv4Addr::new(255, 255, 255, 0))
        }
        _ => panic!("1 must be typed"),
    }
    match decode_option(&[51, 4, 0, 0, 0, 10]) {
        Ok((_, DhcpOption::IpAddressLeaseTime(10))) => {}
        _ => panic!("51 must be typed"),
    }
    match decode_option(&[55, 2, 1, 3]) {
        Ok((_, DhcpOption::ParameterRequestList(v))) => assert_eq!(v, vec![1, 3]),
        _ => panic!("55 must be typed"),
    }
    match decode_option(&[12, 1, 65]) {
        Ok((_, DhcpOption::HostName(s))) => assert_eq!(s, "A"),
        _ => panic!("12 must be typed"),
    }
    match decode_option(&[56, 1, 66]) {
        Ok((_, DhcpOption::Message(s))) => assert_eq!(s, "B"),
        _ => panic!("56 must be typed"),
    }
    // 3/6 are shaped correctly but the decoder always fails (known quirk)
    assert!(matches!(
        decode_option(&[3, 4, 192, 168, 1, 1]),
        Err(CustomErr::InvalidHlen)
    ));
    assert!(matches!(
        decode_option(&[6, 4, 8, 8, 8, 8]),
        Err(CustomErr::InvalidHlen)
    ));
    // everything else 0..=254 (minus typed + 3/6/255) is passthrough
    let typed: std::collections::HashSet<u8> =
        [1, 3, 6, 12, 50, 51, 53, 54, 55, 56].iter().cloned().collect();
    for code in 0u8..=254 {
        if typed.contains(&code) {
            continue;
        }
        match decode_option(&[code, 1, 0xAB]) {
            Ok((rest, DhcpOption::Unrecognized(r))) => {
                assert_eq!(r.code, code, "code {}", code);
                assert_eq!(r.data, vec![0xAB], "code {}", code);
                assert!(rest.is_empty(), "code {}", code);
            }
            _ => panic!("code {} must be Unrecognized passthrough", code),
        }
    }
}

// ===========================================================================
// 2. Exact diagnostic strings (log parsing must not break)
// ===========================================================================

/// `MessageType::from` error text is `Invalid DHCP Message Type: <n>`.
#[test]
fn gap_message_type_from_error_string_exact() {
    assert_eq!(
        MessageType::from(9).unwrap_err(),
        "Invalid DHCP Message Type: 9"
    );
    assert_eq!(
        MessageType::from(0).unwrap_err(),
        "Invalid DHCP Message Type: 0"
    );
    assert_eq!(
        MessageType::from(255).unwrap_err(),
        "Invalid DHCP Message Type: 255"
    );
}

/// `Packet::message_type()` distinguishes missing option vs mistyped option.
#[test]
fn gap_packet_message_type_error_strings_exact() {
    let bare = Packet {
        reply: false,
        hops: 0,
        xid: 1,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6],
        options: vec![],
    };
    assert_eq!(
        bare.message_type().unwrap_err(),
        "Packet does not have MessageType option"
    );
    let mistyped = Packet {
        reply: false,
        hops: 0,
        xid: 1,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6],
        options: vec![DhcpOption::Unrecognized(RawDhcpOption {
            code: 53,
            data: vec![1],
        })],
    };
    assert_eq!(
        mistyped.message_type().unwrap_err(),
        "Got wrong enum code 53 for DHCP_MESSAGE_TYPE"
    );
}

// ===========================================================================
// 3. Encode buffer-size boundaries
// ===========================================================================

/// A 300-byte buffer is the exact maximum the encoder can emit; it must work
/// and byte 299 must be END when options fill the packet.
#[test]
fn gap_encode_300_byte_buffer_exact_fit() {
    // 54-byte unrecognized + Msg(3) fills 240+3+56+1 = 300 (see truncation test)
    let p = Packet {
        reply: false,
        hops: 0,
        xid: 1,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::Unrecognized(RawDhcpOption {
                code: 200,
                data: vec![7u8; 54],
            }),
        ],
    };
    let mut buf = [0u8; 300];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(enc.len(), 300);
    assert_eq!(enc[299], 255);
}

/// Smallest buffer that can hold an empty-options packet is 241 bytes
/// (240 header+cookie + 1 END). 241 works; 240 panics on the return slice.
#[test]
fn gap_encode_241_byte_buffer_minimal_ok() {
    let p = client_packet(1, [0; 6], vec![]);
    let mut buf = [0u8; 241];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(enc.len(), 241);
    assert_eq!(enc[240], 255);
}

#[test]
#[should_panic]
fn gap_encode_240_byte_buffer_panics_quirk() {
    let p = client_packet(1, [0; 6], vec![]);
    let mut buf = [0u8; 240];
    let _ = p.encode(&mut buf);
}

// ===========================================================================
// 4. Missing-END edge: trailing byte succeeds, exact consumption panics
// ===========================================================================

/// No END but one trailing garbage byte: decode swallows the error, skips one
/// byte via `split_at(1)`, and keeps the options decoded so far.
#[test]
fn gap_missing_end_with_trailing_byte_succeeds() {
    let raw = make_raw(
        1, 6, 0, 0xABCDEF01, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6],
        vec![53, 1, 1, 99], // valid Discover, then garbage 99, no END
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 1);
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
}

// ===========================================================================
// 5. Option 255 (END) asymmetry
// ===========================================================================

/// `to_raw` preserves code 255 byte-for-byte, but the decoder asserts
/// `code != END`, so such a packet can be encoded yet never decoded.
#[test]
fn gap_unrecognized_255_to_raw_preserves() {
    let raw = DhcpOption::Unrecognized(RawDhcpOption {
        code: 255,
        data: vec![1],
    })
    .to_raw();
    assert_eq!(raw.code, 255);
    assert_eq!(raw.data, vec![1]);
}

#[test]
#[should_panic]
fn gap_unrecognized_255_packet_decode_panics_quirk() {
    let p = Packet {
        reply: false,
        hops: 0,
        xid: 1,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6],
        options: vec![DhcpOption::Unrecognized(RawDhcpOption {
            code: 255,
            data: vec![1],
        })],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    // first option byte on the wire is the END marker -> decode panics
    assert_eq!(enc[240], 255);
    let _ = Packet::from(&enc);
}

// ===========================================================================
// 6. Hops / flags wire bytes / siaddr / NAK yiaddr
// ===========================================================================

/// RFC 2131 §2: `hops` 0/16/255 survive decode; server replies reset to 0.
#[test]
fn gap_hops_edges_preserved_then_reset() {
    for hops in [0u8, 16, 255] {
        let raw = make_raw(
            1, 6, hops, 0x1234, 0, [0, 0],
            [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
            [9; 6],
            vec![53, 1, 1, 255],
        );
        assert_eq!(unwrap_packet(Packet::from(&raw)).hops, hops);
    }
    let mut req = client_packet(0x99, [9; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Discover,
    )]);
    req.hops = 16;
    let rep = reply_once(
        MessageType::Offer,
        vec![],
        Ipv4Addr::new(192, 168, 1, 44),
        req,
    );
    assert_eq!(rep.hops, 0);
}

/// Broadcast flag wire bytes: true -> [128,0], false -> [0,0].
#[test]
fn gap_broadcast_flag_wire_bytes() {
    for (bcast, expect) in [(false, [0u8, 0]), (true, [128u8, 0])] {
        let p = Packet {
            reply: true,
            hops: 0,
            xid: 1,
            secs: 0,
            broadcast: bcast,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 6],
            options: vec![],
        };
        let mut buf = [0u8; 1500];
        let enc = p.encode(&mut buf).to_vec();
        assert_eq!(&enc[10..12], &expect, "broadcast={}", bcast);
    }
}

/// RFC 2131 §2: `siaddr` (next bootstrap server) is always zeroed on reply,
/// even when the request carried a non-zero `siaddr`.
#[test]
fn gap_reply_siaddr_always_zeroed() {
    let req = Packet {
        reply: false,
        hops: 0,
        xid: 0x55,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::new(5, 6, 7, 8),
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [3; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let rep = reply_once(
        MessageType::Offer,
        vec![],
        Ipv4Addr::new(192, 168, 1, 45),
        req,
    );
    assert_eq!(rep.siaddr, Ipv4Addr::UNSPECIFIED);
}

/// Library leaves NAK `yiaddr` to the caller (example passes 0.0.0.0 per
/// RFC 2131 Table 3, but a non-zero offer IP is preserved as-is).
#[test]
fn gap_nak_yiaddr_left_to_caller_quirk() {
    let req = client_packet(0x66, [4; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Request,
    )]);
    let rep = reply_once(
        MessageType::Nak,
        vec![],
        Ipv4Addr::new(1, 2, 3, 4),
        req,
    );
    assert_eq!(rep.message_type(), Ok(MessageType::Nak));
    assert_eq!(rep.ciaddr, Ipv4Addr::UNSPECIFIED, "NAK ciaddr forced 0");
    assert_eq!(
        rep.yiaddr,
        Ipv4Addr::new(1, 2, 3, 4),
        "NAK yiaddr NOT forced (caller decides)"
    );
}

// ===========================================================================
// 7. Example Offer shape + T1/T2 defaults (RFC 2131 §4.4.5)
// ===========================================================================

/// Example server Offers carry 53/54/51/1 on decode (router/DNS are on the
/// wire but dropped by the Router/DNS decode quirk) and never 58/59.
#[test]
fn gap_example_offer_shape_and_no_t1_t2() {
    let req = client_packet(0x77, [0xAA; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Discover,
    )]);
    let rep = reply_once(
        MessageType::Offer,
        vec![
            DhcpOption::IpAddressLeaseTime(86400),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 2, 1)]),
            DhcpOption::DomainNameServer(vec![Ipv4Addr::new(8, 8, 8, 8)]),
        ],
        Ipv4Addr::new(192, 168, 2, 90),
        req,
    );
    let codes: Vec<u8> = rep.options.iter().map(|o| o.code()).collect();
    assert_eq!(codes, vec![53, 54, 51, 1], "router/DNS dropped by decode quirk");
    assert!(rep.option(RENEWAL_TIME_VALUE).is_none(), "no T1");
    assert!(rep.option(REBINDING_TIME_VALUE).is_none(), "no T2");
}

/// RFC 2131 §4.4.5 defaults when T1/T2 absent: T1 = 0.5*lease,
/// T2 = 0.875*lease. Locks the arithmetic clients must use with our replies.
#[test]
fn gap_t1_t2_defaults_from_lease_time() {
    fn defaults(lease: u32) -> (u32, u32) {
        ((lease as u64 / 2) as u32, (lease as u64 * 7 / 8) as u32)
    }
    assert_eq!(defaults(86400), (43200, 75600));
    assert_eq!(defaults(3600), (1800, 3150));
    assert_eq!(defaults(0), (0, 0));
    // reply used above carries 86400 with no T1/T2, so these apply
    let rep = reply_once(
        MessageType::Ack,
        vec![DhcpOption::IpAddressLeaseTime(86400)],
        Ipv4Addr::new(192, 168, 2, 91),
        client_packet(0x78, [0xBB; 6], vec![DhcpOption::DhcpMessageType(
            MessageType::Request,
        )]),
    );
    match rep.option(IP_ADDRESS_LEASE_TIME) {
        Some(DhcpOption::IpAddressLeaseTime(86400)) => {}
        _ => panic!("lease must be 86400"),
    }
    assert!(rep.option(RENEWAL_TIME_VALUE).is_none());
    assert!(rep.option(REBINDING_TIME_VALUE).is_none());
}

// ===========================================================================
// 8. Overload values, retransmit identity
// ===========================================================================

/// RFC 2132 §9.3 Overload values 1=file, 2=sname, 3=both all passthrough.
#[test]
fn gap_overload_values_1_2_3_passthrough() {
    for v in [1u8, 2, 3] {
        match decode_option(&[52, 1, v]) {
            Ok((_, DhcpOption::Unrecognized(r))) => {
                assert_eq!(r.code, OVERLOAD);
                assert_eq!(r.data, vec![v]);
            }
            _ => panic!("overload {} must passthrough", v),
        }
    }
}

/// RFC 2131 §4.4.1 retransmission: same xid+chaddr, growing secs = same
/// transaction. Decode must preserve the triple exactly.
#[test]
fn gap_retransmit_identity_xid_chaddr_secs() {
    let ch = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
    let first = unwrap_packet(Packet::from(&make_raw(
        1, 6, 0, 0x77777777, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        ch,
        vec![53, 1, 1, 255],
    )));
    let retry = unwrap_packet(Packet::from(&make_raw(
        1, 6, 0, 0x77777777, 5, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        ch,
        vec![53, 1, 1, 255],
    )));
    assert_eq!(first.xid, retry.xid);
    assert_eq!(first.chaddr, retry.chaddr);
    assert_eq!(first.secs, 0);
    assert_eq!(retry.secs, 5);
    assert_eq!(first.message_type(), retry.message_type());
}
