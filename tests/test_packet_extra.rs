//! Extra packet coverage: header fields the decoder ignores, remainder
//! handling, empty/truncated options, PAD handling, truncation boundaries,
//! tiny-buffer panics, Debug/Clone traits and full MessageType round-trips.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use std::net::Ipv4Addr;

fn unwrap_packet(r: Result<Packet, CustomErr<&[u8]>>) -> Packet {
    match r {
        Ok(p) => p,
        Err(_) => panic!("expected Ok Packet"),
    }
}

fn make_raw(op: u8, htype: u8, sname_fill: u8, opts: Vec<u8>) -> Vec<u8> {
    let mut v = vec![0u8; 236];
    v[0] = op;
    v[1] = htype;
    v[2] = 6;
    v[3] = 0;
    v[4..8].copy_from_slice(&0x01020304u32.to_be_bytes());
    v[28..34].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    for b in v[34..236].iter_mut() {
        *b = sname_fill;
    }
    v.extend_from_slice(&[99, 130, 83, 99]);
    v.extend_from_slice(&opts);
    v
}

#[test]
fn decode_ignores_htype_any_value_succeeds() {
    for htype in [0u8, 1, 2, 99, 255] {
        let raw = make_raw(1, htype, 0, vec![53, 1, 1, 255]);
        let p = unwrap_packet(Packet::from(&raw));
        assert_eq!(p.chaddr, [1, 2, 3, 4, 5, 6], "htype {}", htype);
    }
}

#[test]
fn encode_always_writes_htype_1_even_after_garbage_htype_decode() {
    let raw = make_raw(1, 99, 0, vec![53, 1, 1, 255]);
    let p = unwrap_packet(Packet::from(&raw));
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(enc[1], 1, "encode must always write htype=1");
}

#[test]
fn decode_ignores_sname_file_chaddr_pad_garbage() {
    let raw = make_raw(1, 1, 0xAB, vec![53, 1, 1, 255]);
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.chaddr, [1, 2, 3, 4, 5, 6]);
    assert_eq!(p.options.len(), 1);
}

#[test]
fn decode_option_returns_correct_remainder_for_chaining() {
    let (rest, opt) = match decode_option(&[53, 1, 1, 99, 2, 5, 6]) {
        Ok(v) => v,
        Err(_) => panic!("should decode"),
    };
    assert_eq!(opt, DhcpOption::DhcpMessageType(MessageType::Discover));
    assert_eq!(rest, &[99, 2, 5, 6]);
    let (rest2, opt2) = match decode_option(rest) {
        Ok(v) => v,
        Err(_) => panic!("second should decode"),
    };
    assert_eq!(
        opt2,
        DhcpOption::Unrecognized(RawDhcpOption { code: 99, data: vec![5, 6] })
    );
    assert!(rest2.is_empty());
}

#[test]
fn decode_option_empty_string_options_are_ok() {
    match decode_option(&[12, 0]) {
        Ok((_, DhcpOption::HostName(s))) => assert_eq!(s, ""),
        _ => panic!("empty hostname should Ok"),
    }
    match decode_option(&[56, 0]) {
        Ok((_, DhcpOption::Message(s))) => assert_eq!(s, ""),
        _ => panic!("empty message should Ok"),
    }
    match decode_option(&[55, 0]) {
        Ok((_, DhcpOption::ParameterRequestList(v))) => assert!(v.is_empty()),
        _ => panic!("empty prl should Ok"),
    }
    match decode_option(&[99, 0]) {
        Ok((_, DhcpOption::Unrecognized(r))) => {
            assert_eq!(r.code, 99);
            assert!(r.data.is_empty());
        }
        _ => panic!("empty unrecognized should Ok"),
    }
}

#[test]
fn decode_option_pad_code_zero_is_unrecognized_not_special() {
    // PAD (0) is only special after END (ignored). Before END it decodes
    // as a normal Unrecognized option with length+data.
    match decode_option(&[0, 1, 2]) {
        Ok((_, DhcpOption::Unrecognized(r))) => {
            assert_eq!(r.code, 0);
            assert_eq!(r.data, vec![2]);
        }
        _ => panic!("code 0 should be Unrecognized"),
    }
}

#[test]
fn decode_option_declared_len_longer_than_data_is_invalid_hlen() {
    assert!(matches!(
        decode_option(&[53, 2, 1]),
        Err(CustomErr::InvalidHlen)
    ));
    assert!(matches!(
        decode_option(&[55, 3, 1]),
        Err(CustomErr::InvalidHlen)
    ));
    assert!(matches!(
        decode_option(&[1, 4, 1, 2]),
        Err(CustomErr::InvalidHlen)
    ));
}

#[test]
fn decode_option_msgtype_ignores_trailing_data_bytes() {
    // len 2, first data byte decides type, second ignored.
    match decode_option(&[53, 2, 1, 2]) {
        Ok((_, DhcpOption::DhcpMessageType(t))) => assert_eq!(t, MessageType::Discover),
        _ => panic!("should take first byte"),
    }
    // len 0 has no data byte -> InvalidHlen (not UnrecognizedMessageType)
    assert!(matches!(
        decode_option(&[53, 0]),
        Err(CustomErr::InvalidHlen)
    ));
}

#[test]
fn decode_bad_cookie_is_specifically_tag_kind() {
    let mut raw = make_raw(1, 1, 0, vec![53, 1, 1, 255]);
    raw[236] = 0;
    match Packet::from(&raw) {
        Err(CustomErr::NomError((_, ErrorKind::Tag))) => {}
        _ => panic!("bad cookie must be NomError(Tag)"),
    }
}

#[test]
fn packet_option_returns_first_when_duplicated() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6],
        options: vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(1, 1, 1, 1)),
            DhcpOption::SubnetMask(Ipv4Addr::new(2, 2, 2, 2)),
        ],
    };
    assert_eq!(
        p.option(1),
        Some(&DhcpOption::SubnetMask(Ipv4Addr::new(1, 1, 1, 1)))
    );
}

#[test]
fn packet_message_type_all_eight_variants() {
    for (mt, byte) in [
        (MessageType::Discover, 1),
        (MessageType::Offer, 2),
        (MessageType::Request, 3),
        (MessageType::Decline, 4),
        (MessageType::Ack, 5),
        (MessageType::Nak, 6),
        (MessageType::Release, 7),
        (MessageType::Inform, 8),
    ] {
        let p = Packet {
            reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
            siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
            chaddr: [0; 6],
            options: vec![DhcpOption::DhcpMessageType(mt)],
        };
        assert_eq!(p.message_type(), Ok(mt), "byte {}", byte);
    }
}

#[test]
fn encode_truncation_boundary_299_fits_300_breaks() {
    // start 240, Msg 3 -> 243. Second option 2+N.
    // 243+2+54+1 = 300 fits (condition 243+2+54=299 <300).
    // 243+2+55+1 = 301 would break (243+2+55=300 >=300).
    let mk = |n: usize| Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
            DhcpOption::Unrecognized(RawDhcpOption { code: 200, data: vec![7u8; n] }),
        ],
    };
    let mut buf = [0u8; 1500];
    let enc54 = mk(54).encode(&mut buf).to_vec();
    assert_eq!(enc54.len(), 300, "54-byte data must exactly fill to 300");
    assert!(enc54.windows(2).any(|w| w == [200, 54]));
    assert_eq!(enc54[enc54.len() - 1], 255);

    let enc55 = mk(55).encode(&mut buf).to_vec();
    // 55-byte option does NOT fit, only Msg + END remain.
    assert_eq!(enc55.len(), 244, "55-byte data must be truncated, len={}", enc55.len());
    assert!(!enc55.windows(2).any(|w| w == [200, 55]));
}

#[test]
#[should_panic]
fn encode_tiny_buffer_panics_quirk() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6], options: vec![],
    };
    let mut tiny = [0u8; 10];
    let _ = p.encode(&mut tiny);
}

#[test]
fn encode_overwrites_prior_garbage_in_padding_with_zero() {
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6], options: vec![],
    };
    let mut buf = [0xFFu8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert!(enc[34..236].iter().all(|&b| b == 0));
    assert!(buf[enc.len()..300].iter().all(|&b| b == 0));
}

#[test]
fn encode_decode_xid_secs_edge_values() {
    for (xid, secs) in [(0u32, 0u16), (u32::MAX, u16::MAX), (0x01020304, 0x0506)] {
        let p = Packet {
            reply: true, hops: 255, xid, secs, broadcast: false,
            ciaddr: Ipv4Addr::new(255, 255, 255, 255),
            yiaddr: Ipv4Addr::new(0, 0, 0, 0),
            siaddr: Ipv4Addr::new(0, 0, 0, 0),
            giaddr: Ipv4Addr::new(0, 0, 0, 0),
            chaddr: [255; 6],
            options: vec![DhcpOption::DhcpMessageType(MessageType::Ack)],
        };
        let mut buf = [0u8; 1500];
        let enc = p.encode(&mut buf).to_vec();
        assert_eq!(&enc[4..8], &xid.to_be_bytes());
        assert_eq!(&enc[8..10], &secs.to_be_bytes());
        let q = unwrap_packet(Packet::from(&enc));
        assert_eq!(q.xid, xid);
        assert_eq!(q.secs, secs);
        assert_eq!(q.hops, 255);
    }
}

#[test]
fn all_message_types_roundtrip() {
    for mt in [
        MessageType::Discover, MessageType::Offer, MessageType::Request,
        MessageType::Decline, MessageType::Ack, MessageType::Nak,
        MessageType::Release, MessageType::Inform,
    ] {
        let p = Packet {
            reply: mt as u8 % 2 == 0, hops: 0, xid: 0x42, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
            siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
            chaddr: [0; 6], options: vec![DhcpOption::DhcpMessageType(mt)],
        };
        let mut buf = [0u8; 1500];
        let enc = p.encode(&mut buf).to_vec();
        let q = unwrap_packet(Packet::from(&enc));
        assert_eq!(q.message_type(), Ok(mt));
    }
}

#[test]
fn options_clone_and_debug_locked() {
    let raw = RawDhcpOption { code: 7, data: vec![1, 2] };
    assert_eq!(raw.clone(), raw);
    assert!(format!("{:?}", raw).contains("7"));

    let opt = DhcpOption::DhcpMessageType(MessageType::Discover);
    assert!(format!("{:?}", opt).contains("Discover"));

    let mt = MessageType::Offer;
    let mt2 = mt; // Copy
    assert_eq!(mt, mt2);
    assert!(format!("{:?}", mt).contains("Offer"));

    let p = Packet {
        reply: true, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [0; 6], options: vec![],
    };
    assert!(format!("{:?}", p).contains("reply"));
}

#[test]
fn title_exhaustive_all_256_codes() {
    // Exactly the known codes return Some, all others None (80 = Rapid Commit).
    let known: std::collections::HashSet<u8> = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        58, 59, 60, 61, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77,
        80, 82, 93, 100, 101, 121,
    ]
    .iter()
    .cloned()
    .collect();
    assert_eq!(known.len(), 81);
    for code in 0u8..=255 {
        if known.contains(&code) {
            assert!(title(code).is_some(), "code {} should have title", code);
        } else {
            assert!(title(code).is_none(), "code {} should be None", code);
        }
    }
}
