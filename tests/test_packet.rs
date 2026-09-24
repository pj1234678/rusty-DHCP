//! Exact-functionality regression tests for `dhcp4r::packet`.
//!
//! Locks current wire format, including known quirks:
//! - unknown `op` decodes as request (`reply=false`)
//! - broadcast flag checks `flags & 128` (low byte 0x80), NOT RFC 0x8000,
//!   so `encode(broadcast=true)` -> raw `[128,0]` -> `decode` yields `false`
//! - `decode_option` panics on END (255) as first byte
//! - `Router` / `DomainNameServer` decode ALWAYS fails with `InvalidHlen`
//!   (custom_many0 expects NomError terminator but decode_ipv4 gives InvalidHlen)
//! - `Packet::from` swallows all option-level errors and succeeds with
//!   truncated/empty options; it only errors on header/cookie/hlen issues
//! - missing END with exact consumption panics on `split_at(1)`

use dhcp4r::options::*;
use dhcp4r::packet::*;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// helpers (CustomErr has no Debug, so no unwrap())
// ---------------------------------------------------------------------------

fn unwrap_packet(r: Result<Packet, CustomErr<&[u8]>>) -> Packet {
    match r {
        Ok(p) => p,
        Err(_) => panic!("expected Ok Packet, got Err"),
    }
}

fn is_invalid_hlen(r: &Result<Packet, CustomErr<&[u8]>>) -> bool {
    matches!(r, Err(CustomErr::InvalidHlen))
}

fn is_tag_error(r: &Result<Packet, CustomErr<&[u8]>>) -> bool {
    matches!(r, Err(CustomErr::NomError(_)))
}

/// Build a raw DHCP packet: 236-byte BOOTP header + cookie + options bytes.
/// Header: op,htype=1,hlen,hops,xid,secs,flags,ci,yi,si,gi,chaddr(6)+pad.
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
    // 34..236 already zero (sname/file/chaddr-pad)
    v.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
    v.extend_from_slice(&opts_after_cookie);
    v
}

fn make_simple_raw(op: u8, flags: [u8; 2], hlen: u8, opts: Vec<u8>) -> Vec<u8> {
    make_raw(
        op,
        hlen,
        7,
        0x12345678,
        0x0102,
        flags,
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        [9, 10, 11, 12],
        [13, 14, 15, 16],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        opts,
    )
}

fn opt_raw(code: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![code, data.len() as u8];
    v.extend_from_slice(data);
    v
}

// ---------------------------------------------------------------------------
// decode: header fields
// ---------------------------------------------------------------------------

#[test]
fn decode_valid_discover_preserves_all_header_fields() {
    let raw = make_raw(
        1, 6, 9, 0xAABBCCDD, 0x1122, [0, 0],
        [192, 168, 1, 10], [192, 168, 1, 20], [192, 168, 1, 1], [0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6],
        [vec![53, 1, 1], vec![255]].concat(),
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert!(!p.reply);
    assert_eq!(p.hops, 9);
    assert_eq!(p.xid, 0xAABBCCDD);
    assert_eq!(p.secs, 0x1122);
    assert!(!p.broadcast);
    assert_eq!(p.ciaddr, Ipv4Addr::new(192, 168, 1, 10));
    assert_eq!(p.yiaddr, Ipv4Addr::new(192, 168, 1, 20));
    assert_eq!(p.siaddr, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(p.giaddr, Ipv4Addr::new(0, 0, 0, 0));
    assert_eq!(p.chaddr, [1, 2, 3, 4, 5, 6]);
    assert_eq!(p.options.len(), 1);
    assert_eq!(p.options[0], DhcpOption::DhcpMessageType(MessageType::Discover));
}

#[test]
fn decode_reply_flag_op2_true_op1_false() {
    let req = unwrap_packet(Packet::from(&make_simple_raw(1, [0, 0], 6, vec![53, 1, 1, 255])));
    assert!(!req.reply);
    let rep = unwrap_packet(Packet::from(&make_simple_raw(2, [0, 0], 6, vec![53, 1, 2, 255])));
    assert!(rep.reply);
}

#[test]
fn decode_unknown_op_treated_as_request_quirk() {
    // Current code maps any non-2 op to false (TODO in source).
    for op in [0u8, 3, 99, 255] {
        let p = unwrap_packet(Packet::from(&make_simple_raw(op, [0, 0], 6, vec![53, 1, 1, 255])));
        assert!(!p.reply, "op {} should decode to reply=false", op);
    }
}

#[test]
fn decode_rejects_bad_hlen() {
    for hlen in [0u8, 1, 5, 7, 16, 255] {
        let raw = make_simple_raw(1, [0, 0], hlen, vec![53, 1, 1, 255]);
        let r = Packet::from(&raw);
        assert!(is_invalid_hlen(&r), "hlen {} should be InvalidHlen", hlen);
    }
}

#[test]
fn decode_rejects_short_header() {
    assert!(is_invalid_hlen(&Packet::from(&[1u8; 10])));
    assert!(is_invalid_hlen(&Packet::from(&[0u8; 235])));
    assert!(is_invalid_hlen(&Packet::from(&[])));
}

#[test]
fn decode_rejects_bad_cookie() {
    let mut raw = make_simple_raw(1, [0, 0], 6, vec![53, 1, 1, 255]);
    raw[236] = 0;
    raw[237] = 0;
    raw[238] = 0;
    raw[239] = 0;
    let r = Packet::from(&raw);
    assert!(is_tag_error(&r), "bad cookie should be NomError(Tag)");
}

#[test]
fn decode_broadcast_flag_checks_low_byte_quirk() {
    // encode(true) writes flags [128,0] (0x8000) but decode checks `flags & 128`
    // (0x0080), so it decodes to false. Only [x,128|..] decodes true.
    let p1 = unwrap_packet(Packet::from(&make_simple_raw(1, [128, 0], 6, vec![53, 1, 1, 255])));
    assert!(!p1.broadcast, "[128,0] (0x8000) decodes to false (bug locked)");

    let p2 = unwrap_packet(Packet::from(&make_simple_raw(1, [0, 128], 6, vec![53, 1, 1, 255])));
    assert!(p2.broadcast, "[0,128] (0x0080) decodes to true");

    let p3 = unwrap_packet(Packet::from(&make_simple_raw(1, [0, 0], 6, vec![53, 1, 1, 255])));
    assert!(!p3.broadcast);

    let p4 = unwrap_packet(Packet::from(&make_simple_raw(1, [255, 255], 6, vec![53, 1, 1, 255])));
    assert!(p4.broadcast, "[255,255] contains 0x80 in low byte");
}

// ---------------------------------------------------------------------------
// decode_option direct: each type
// ---------------------------------------------------------------------------

#[test]
fn decode_option_message_type_all_values() {
    for (byte, expect) in [
        (1, MessageType::Discover),
        (2, MessageType::Offer),
        (3, MessageType::Request),
        (4, MessageType::Decline),
        (5, MessageType::Ack),
        (6, MessageType::Nak),
        (7, MessageType::Release),
        (8, MessageType::Inform),
    ] {
        match decode_option(&[53, 1, byte]) {
            Ok((_, DhcpOption::DhcpMessageType(t))) => assert_eq!(t, expect),
            other => panic!("53,1,{} should Ok, got {:?}", byte, other.is_ok()),
        }
    }
}

#[test]
fn decode_option_message_type_invalid_is_unrecognized() {
    assert!(matches!(
        decode_option(&[53, 1, 9]),
        Err(CustomErr::UnrecognizedMessageType)
    ));
    assert!(matches!(
        decode_option(&[53, 1, 0]),
        Err(CustomErr::UnrecognizedMessageType)
    ));
    assert!(matches!(
        decode_option(&[53, 1, 255]),
        Err(CustomErr::UnrecognizedMessageType)
    ));
}

#[test]
fn decode_option_server_id_requested_ip_subnet() {
    match decode_option(&[54, 4, 192, 168, 1, 1]) {
        Ok((_, DhcpOption::ServerIdentifier(ip))) => assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1)),
        _ => panic!("server id failed"),
    }
    match decode_option(&[50, 4, 10, 0, 0, 5]) {
        Ok((_, DhcpOption::RequestedIpAddress(ip))) => assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 5)),
        _ => panic!("requested ip failed"),
    }
    match decode_option(&[1, 4, 255, 255, 255, 0]) {
        Ok((_, DhcpOption::SubnetMask(ip))) => assert_eq!(ip, Ipv4Addr::new(255, 255, 255, 0)),
        _ => panic!("subnet failed"),
    }
}

#[test]
fn decode_option_ipv4_ignores_trailing_bytes_quirk() {
    // decode_ipv4 only reads first 4 bytes, extra ignored.
    match decode_option(&[54, 5, 192, 168, 1, 1, 9]) {
        Ok((_, DhcpOption::ServerIdentifier(ip))) => assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1)),
        _ => panic!("should ignore trailing byte"),
    }
}

#[test]
fn decode_option_ipv4_short_is_invalid_hlen() {
    assert!(matches!(
        decode_option(&[54, 3, 1, 2, 3]),
        Err(CustomErr::InvalidHlen)
    ));
    assert!(matches!(
        decode_option(&[51, 2, 0, 1]),
        Err(CustomErr::InvalidHlen)
    ));
    assert!(matches!(decode_option(&[53, 0]), Err(CustomErr::InvalidHlen)));
    assert!(matches!(decode_option(&[53, 1]), Err(CustomErr::InvalidHlen)));
    assert!(matches!(decode_option(&[]), Err(CustomErr::InvalidHlen)));
    assert!(matches!(decode_option(&[53]), Err(CustomErr::InvalidHlen)));
}

#[test]
fn decode_option_hostname_and_message() {
    match decode_option(&[12, 3, 65, 66, 67]) {
        Ok((_, DhcpOption::HostName(s))) => assert_eq!(s, "ABC"),
        _ => panic!("hostname failed"),
    }
    match decode_option(&[56, 5, 104, 101, 108, 108, 111]) {
        Ok((_, DhcpOption::Message(s))) => assert_eq!(s, "hello"),
        _ => panic!("message failed"),
    }
    assert!(matches!(
        decode_option(&[12, 2, 0xFF, 0xFE]),
        Err(CustomErr::NonUtf8String)
    ));
    assert!(matches!(
        decode_option(&[56, 2, 0xFF, 0xFE]),
        Err(CustomErr::NonUtf8String)
    ));
}

#[test]
fn decode_option_prl_and_lease_and_unrecognized() {
    match decode_option(&[55, 3, 1, 3, 6]) {
        Ok((_, DhcpOption::ParameterRequestList(v))) => assert_eq!(v, vec![1, 3, 6]),
        _ => panic!("prl failed"),
    }
    match decode_option(&[55, 0]) {
        Ok((_, DhcpOption::ParameterRequestList(v))) => assert!(v.is_empty()),
        _ => panic!("empty prl failed"),
    }
    match decode_option(&[51, 4, 0, 0, 0, 10]) {
        Ok((_, DhcpOption::IpAddressLeaseTime(t))) => assert_eq!(t, 10),
        _ => panic!("lease failed"),
    }
    match decode_option(&[99, 2, 1, 2]) {
        Ok((_, DhcpOption::Unrecognized(raw))) => {
            assert_eq!(raw.code, 99);
            assert_eq!(raw.data, vec![1, 2]);
        }
        _ => panic!("unrecognized failed"),
    }
}

#[test]
fn decode_option_router_and_dns_always_fail_quirk() {
    // BUG LOCK: custom_many0(decode_ipv4) can never succeed because
    // decode_ipv4 signals exhaustion with InvalidHlen, not NomError,
    // so the combinator propagates Err instead of terminating.
    // Even a single valid address fails.
    assert!(matches!(
        decode_option(&[3, 4, 192, 168, 1, 1]),
        Err(CustomErr::InvalidHlen)
    ));
    assert!(matches!(
        decode_option(&[3, 8, 192, 168, 1, 1, 10, 0, 0, 1]),
        Err(CustomErr::InvalidHlen)
    ));
    assert!(matches!(decode_option(&[3, 0]), Err(CustomErr::InvalidHlen)));
    assert!(matches!(
        decode_option(&[6, 4, 8, 8, 8, 8]),
        Err(CustomErr::InvalidHlen)
    ));
    assert!(matches!(decode_option(&[6, 0]), Err(CustomErr::InvalidHlen)));
}

#[test]
#[should_panic]
fn decode_option_end_as_first_byte_panics_quirk() {
    let _ = decode_option(&[255, 1, 1]);
}

// ---------------------------------------------------------------------------
// Packet::from swallowing / END handling quirks
// ---------------------------------------------------------------------------

#[test]
fn packet_from_swallows_invalid_msgtype_and_yields_empty_options() {
    // decode_option would Err(UnrecognizedMessageType), but Packet::from
    // catches it in `while let Ok` and still returns Ok with 0 options.
    let raw = make_simple_raw(1, [0, 0], 6, vec![53, 1, 9, 255]);
    let p = unwrap_packet(Packet::from(&raw));
    assert!(p.options.is_empty());
}

#[test]
fn packet_from_swallows_non_utf8_and_yields_empty_options() {
    let raw = make_simple_raw(1, [0, 0], 6, vec![12, 2, 0xFF, 0xFE, 255]);
    let p = unwrap_packet(Packet::from(&raw));
    assert!(p.options.is_empty());
}

#[test]
fn packet_from_swallows_router_and_yields_empty_options() {
    let mut opts = opt_raw(3, &[192, 168, 1, 1]);
    opts.push(255);
    let raw = make_simple_raw(1, [0, 0], 6, opts);
    let p = unwrap_packet(Packet::from(&raw));
    assert!(p.options.is_empty(), "router poisons whole list: {:?}", p.options);
}

#[test]
fn packet_from_keeps_decodable_prefix_before_poison_option() {
    // [MsgType, Subnet] decode, then Router fails -> first two kept.
    let mut opts = vec![];
    opts.extend(opt_raw(53, &[1]));
    opts.extend(opt_raw(1, &[255, 255, 255, 0]));
    opts.extend(opt_raw(3, &[192, 168, 1, 1]));
    opts.push(255);
    let raw = make_simple_raw(1, [0, 0], 6, opts);
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 2);
    assert_eq!(p.options[0], DhcpOption::DhcpMessageType(MessageType::Discover));
    assert_eq!(
        p.options[1],
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))
    );
}

#[test]
fn packet_from_truncated_option_swallows_and_succeeds() {
    // len says 1 but no data and no END: decode_option fails, loop exits,
    // split_at(1) skips one byte, Ok with empty options.
    let raw = make_simple_raw(1, [0, 0], 6, vec![53, 1]);
    let p = unwrap_packet(Packet::from(&raw));
    assert!(p.options.is_empty());
}

#[test]
#[should_panic]
fn packet_from_with_only_end_panics_quirk() {
    let raw = make_simple_raw(1, [0, 0], 6, vec![255, 0, 0]);
    let _ = Packet::from(&raw);
}

#[test]
#[should_panic]
fn packet_from_missing_end_with_exact_consumption_panics_quirk() {
    // One valid option with no END consumes all bytes -> rest empty -> split_at(1) panics.
    let raw = make_simple_raw(1, [0, 0], 6, vec![53, 1, 1]);
    let _ = Packet::from(&raw);
}

#[test]
fn packet_from_ignores_trailing_bytes_after_end() {
    let mut opts = opt_raw(53, &[1]);
    opts.push(255);
    opts.extend_from_slice(&[0, 0, 0, 99, 100]); // PAD + garbage ignored
    let raw = make_simple_raw(1, [0, 0], 6, opts);
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 1);
}

#[test]
fn packet_from_multiple_options_preserves_order() {
    let mut opts = vec![];
    opts.extend(opt_raw(53, &[3]));
    opts.extend(opt_raw(54, &[192, 168, 1, 1]));
    opts.extend(opt_raw(55, &[1, 3, 6]));
    opts.extend(opt_raw(50, &[192, 168, 1, 100]));
    opts.extend(opt_raw(1, &[255, 255, 255, 0]));
    opts.extend(opt_raw(51, &[0, 0, 0, 10]));
    opts.extend(opt_raw(12, b"host"));
    opts.extend(opt_raw(56, b"msg"));
    opts.push(255);
    let raw = make_simple_raw(1, [0, 0], 6, opts);
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.options.len(), 8);
    assert_eq!(p.options[0].code(), 53);
    assert_eq!(p.options[1].code(), 54);
    assert_eq!(p.options[2].code(), 55);
    assert_eq!(p.options[3].code(), 50);
    assert_eq!(p.options[4].code(), 1);
    assert_eq!(p.options[5].code(), 51);
    assert_eq!(p.options[6].code(), 12);
    assert_eq!(p.options[7].code(), 56);
}

// ---------------------------------------------------------------------------
// option() and message_type()
// ---------------------------------------------------------------------------

#[test]
fn packet_option_finds_by_code() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
        ],
    };
    assert!(p.option(53).is_some());
    assert!(p.option(1).is_some());
    assert!(p.option(3).is_none());
    assert!(p.option(255).is_none());
}

#[test]
fn packet_message_type_ok() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    assert_eq!(p.message_type(), Ok(MessageType::Request));
}

#[test]
fn packet_message_type_missing_is_err() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6], options: vec![],
    };
    let r = p.message_type();
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("MessageType"));
}

#[test]
fn packet_message_type_wrong_variant_is_err() {
    // Manually inject Unrecognized with code 53 (decoder never produces this,
    // but message_type() has a branch for it).
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6],
        options: vec![DhcpOption::Unrecognized(RawDhcpOption { code: 53, data: vec![1] })],
    };
    let r = p.message_type();
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("53"));
}

// ---------------------------------------------------------------------------
// encode()
// ---------------------------------------------------------------------------

#[test]
fn encode_header_bytes_are_exact() {
    let p = Packet {
        reply: true, hops: 9, xid: 0xAABBCCDD, secs: 0x1122, broadcast: false,
        ciaddr: Ipv4Addr::new(1, 2, 3, 4), yiaddr: Ipv4Addr::new(5, 6, 7, 8),
        siaddr: Ipv4Addr::new(9, 10, 11, 12), giaddr: Ipv4Addr::new(13, 14, 15, 16),
        chaddr: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Offer)],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    // op=2 (reply), htype always 1, hlen 6, hops
    assert_eq!(enc[0], 2);
    assert_eq!(enc[1], 1);
    assert_eq!(enc[2], 6);
    assert_eq!(enc[3], 9);
    assert_eq!(&enc[4..8], &[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(&enc[8..10], &[0x11, 0x22]);
    assert_eq!(&enc[10..12], &[0, 0]); // broadcast false
    assert_eq!(&enc[12..16], &[1, 2, 3, 4]);
    assert_eq!(&enc[16..20], &[5, 6, 7, 8]);
    assert_eq!(&enc[20..24], &[9, 10, 11, 12]);
    assert_eq!(&enc[24..28], &[13, 14, 15, 16]);
    assert_eq!(&enc[28..34], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    // sname/file/chaddr-pad zeroed
    assert!(enc[34..236].iter().all(|&b| b == 0));
    // cookie
    assert_eq!(&enc[236..240], &[99, 130, 83, 99]);
    // option + END
    assert_eq!(&enc[240..243], &[53, 1, 2]);
    assert_eq!(enc[243], 255);
    assert_eq!(enc.len(), 244);
}

#[test]
fn encode_request_op_and_broadcast_flag() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: true,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6], options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(enc[0], 1);
    assert_eq!(&enc[10..12], &[128, 0], "broadcast true must encode as [128,0]");
}

#[test]
fn encode_empty_options_yields_only_end() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6], options: vec![],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(enc.len(), 241);
    assert_eq!(enc[240], 255);
}

#[test]
fn encode_pads_buffer_to_300_with_zero() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6], options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let mut buf = [0xFFu8; 1500];
    let len = p.encode(&mut buf).len();
    assert_eq!(len, 244);
    // bytes after returned slice up to 300 must be PAD (0)
    assert!(buf[len..300].iter().all(|&b| b == 0));
}

#[test]
fn encode_truncates_options_to_fit_300() {
    // Each Unrecognized(10 bytes data) costs 12 bytes. Start 240, END 1.
    // 240+12*4=288, next would be 300 >= 300 -> break. So 4 fit.
    let many: Vec<DhcpOption> = (0..50)
        .map(|i| DhcpOption::Unrecognized(RawDhcpOption { code: 100, data: vec![i; 10] }))
        .collect();
    let p = Packet {
        reply: true, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(1, 1, 1, 1),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6], options: many,
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(enc.len() <= 300, "len {}", enc.len());
    assert_eq!(enc.len(), 289);
    assert_eq!(enc[enc.len() - 1], 255);
    // only first four options present
    assert_eq!(&enc[240..252], &[100, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn encode_broadcast_roundtrip_loses_flag_quirk() {
    let p = Packet {
        reply: true, hops: 0, xid: 0x12345678, secs: 0, broadcast: true,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(192, 168, 1, 10),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [1, 2, 3, 4, 5, 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Offer)],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(&enc[10..12], &[128, 0]);
    let dec = unwrap_packet(Packet::from(&enc));
    assert!(!dec.broadcast, "roundtrip of broadcast=true yields false (bug locked)");
}

#[test]
fn roundtrip_preserves_decodable_fields() {
    // NOTE: total options must fit in the 300-byte packet (240 + opts + 1 END).
    // 3+6+6+6+5 = 26 bytes -> 267 total, fits. Adding more would trigger
    // truncation (see encode_truncates_options_to_fit_300).
    let p = Packet {
        reply: true, hops: 3, xid: 0xDEADBEEF, secs: 99, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 1, 10), yiaddr: Ipv4Addr::new(192, 168, 1, 20),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(192, 168, 1, 1),
        chaddr: [10, 20, 30, 40, 50, 60],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Ack),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::IpAddressLeaseTime(3600),
            DhcpOption::ParameterRequestList(vec![1, 3, 6]),
        ],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(q.reply, p.reply);
    assert_eq!(q.hops, p.hops);
    assert_eq!(q.xid, p.xid);
    assert_eq!(q.secs, p.secs);
    assert_eq!(q.broadcast, p.broadcast);
    assert_eq!(q.ciaddr, p.ciaddr);
    assert_eq!(q.yiaddr, p.yiaddr);
    assert_eq!(q.siaddr, p.siaddr);
    assert_eq!(q.giaddr, p.giaddr);
    assert_eq!(q.chaddr, p.chaddr);
    assert_eq!(q.options, p.options);
}

#[test]
fn roundtrip_preserves_hostname_message_requestedip_when_fitting() {
    let p = Packet {
        reply: false, hops: 0, xid: 0x99, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [1, 2, 3, 4, 5, 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::HostName("h".to_string()),
            DhcpOption::Message("m".to_string()),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 20)),
        ],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(q.options, p.options);
}

#[test]
fn roundtrip_loses_router_and_dns_quirk() {
    let p = Packet {
        reply: true, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(10, 0, 0, 2),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [1, 2, 3, 4, 5, 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Offer),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 1)),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(10, 0, 0, 1)]),
        ],
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    // raw bytes DO contain router option 3 ...
    assert!(enc.windows(2).any(|w| w == [3, 4]), "raw must contain router");
    // ... but decode drops it and everything after it
    let q = unwrap_packet(Packet::from(&enc));
    assert_eq!(q.options.len(), 3, "router + tail lost: {:?}", q.options);
}
