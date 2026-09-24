//! Tests for `dhcp4r::dhcpv6` (RFC 8415 codec + managed range allocator).
//!
//! Locks the managed DHCPv6 range behavior: message/option wire format,
//! strict all-or-nothing decoding (no v4-style swallow quirk by design),
//! and pool allocation mirroring the v4 example — except infinite leases
//! are NOT stealable here (deliberate difference, see below).
//!
//! Pure codec + allocator tests only (no sockets: loopback IPv6 availability
//! varies by platform, so nothing here binds).

use dhcp4r::dhcpv6::*;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

fn duid(b: &[u8]) -> Vec<u8> {
    b.to_vec()
}

fn v6(a: [u16; 8]) -> Ipv6Addr {
    Ipv6Addr::new(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
}

// ---------------------------------------------------------------------------
// message types
// ---------------------------------------------------------------------------

#[test]
fn msgtype_values_match_rfc8415() {
    assert_eq!(MsgType::Solicit as u8, 1);
    assert_eq!(MsgType::Advertise as u8, 2);
    assert_eq!(MsgType::Request as u8, 3);
    assert_eq!(MsgType::Confirm as u8, 4);
    assert_eq!(MsgType::Renew as u8, 5);
    assert_eq!(MsgType::Rebind as u8, 6);
    assert_eq!(MsgType::Reply as u8, 7);
    assert_eq!(MsgType::Release as u8, 8);
    assert_eq!(MsgType::Decline as u8, 9);
    assert_eq!(MsgType::Reconfigure as u8, 10);
    assert_eq!(MsgType::InformationRequest as u8, 11);
    assert_eq!(MsgType::RelayForward as u8, 12);
    assert_eq!(MsgType::RelayReply as u8, 13);
    for v in 1u8..=13 {
        assert!(MsgType::from(v).is_ok(), "{}", v);
    }
}

#[test]
fn msgtype_from_invalid_is_err() {
    for v in [0u8, 14, 255] {
        assert_eq!(MsgType::from(v), Err(DecodeError::BadMessageType(v)));
    }
}

// ---------------------------------------------------------------------------
// transaction id: 24-bit big-endian, masked on encode
// ---------------------------------------------------------------------------

#[test]
fn transaction_id_three_bytes_be() {
    let p = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 0x12_34_56,
        options: vec![],
    };
    assert_eq!(&p.encode().unwrap()[..4], &[1, 0x12, 0x34, 0x56]);
    assert_eq!(Packet::from(&[7, 0x12, 0x34, 0x56]).unwrap().transaction_id, 0x12_34_56);
}

#[test]
fn transaction_id_top_byte_masked_on_encode() {
    let p = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 0xFF_12_34_56,
        options: vec![],
    };
    let enc = p.encode().unwrap();
    assert_eq!(&enc[1..4], &[0x12, 0x34, 0x56]);
    assert_eq!(Packet::from(&enc).unwrap().transaction_id, 0x12_34_56);
}

// ---------------------------------------------------------------------------
// option encode lengths
// ---------------------------------------------------------------------------

#[test]
fn option_ids_match_rfc8415() {
    assert_eq!(Dhcpv6Option::ClientId(vec![]).code(), 1);
    assert_eq!(Dhcpv6Option::ServerId(vec![]).code(), 2);
    assert_eq!(
        Dhcpv6Option::IaNa(IaNa { iaid: 0, t1: 0, t2: 0, addrs: vec![] }).code(),
        3
    );
    assert_eq!(Dhcpv6Option::DnsServers(vec![]).code(), 23);
    assert_eq!(Dhcpv6Option::StatusCode(0, String::new()).code(), 13);
    assert_eq!(
        Dhcpv6Option::Unrecognized(RawDhcpv6Option { code: 99, data: vec![] }).code(),
        99
    );
}

#[test]
fn duid_options_opaque_including_empty() {
    let raw = Dhcpv6Option::ClientId(duid(&[1, 2, 3])).to_raw();
    assert_eq!((raw.code, raw.data), (1, vec![1, 2, 3]));
    let raw = Dhcpv6Option::ServerId(vec![]).to_raw();
    assert_eq!((raw.code, raw.data), (2, vec![]));
}

#[test]
fn iana_encodes_iaid_t1_t2_then_iaaddr_suboptions() {
    let raw = Dhcpv6Option::IaNa(IaNa {
        iaid: 0x01020304,
        t1: 100,
        t2: 200,
        addrs: vec![
            IaAddr { addr: v6([0xfd00, 0, 0, 0, 0, 0, 0, 1]), preferred: 300, valid: 400 },
            IaAddr { addr: v6([0xfd00, 0, 0, 0, 0, 0, 0, 2]), preferred: 301, valid: 401 },
        ],
    })
    .to_raw();
    assert_eq!(raw.code, 3);
    // 12-byte header + 2 sub-options of 28 data bytes each
    assert_eq!(raw.data.len(), 12 + 2 * 28);
    assert_eq!(&raw.data[..12], &[1, 2, 3, 4, 0, 0, 0, 100, 0, 0, 0, 200]);
    // first sub-option: code 5, len 24, addr, preferred, valid
    assert_eq!(&raw.data[12..16], &[0, 5, 0, 24]);
    assert_eq!(&raw.data[16..32], &v6([0xfd00, 0, 0, 0, 0, 0, 0, 1]).octets());
    assert_eq!(&raw.data[32..36], &300u32.to_be_bytes());
    assert_eq!(&raw.data[36..40], &400u32.to_be_bytes());
    // second sub-option header sits right after the first 24 data bytes
    assert_eq!(&raw.data[40..44], &[0, 5, 0, 24]);
    // empty IA_NA is just the 12-byte header
    let raw = Dhcpv6Option::IaNa(IaNa { iaid: 7, t1: 0, t2: 0, addrs: vec![] }).to_raw();
    assert_eq!(raw.data.len(), 12);
}

#[test]
fn dns_servers_concatenates_16_byte_addrs() {
    assert!(Dhcpv6Option::DnsServers(vec![]).to_raw().data.is_empty());
    let raw = Dhcpv6Option::DnsServers(vec![
        v6([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888]),
        v6([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844]),
    ])
    .to_raw();
    assert_eq!(raw.code, 23);
    assert_eq!(raw.data.len(), 32);
}

#[test]
fn status_code_is_be_code_plus_text() {
    let raw = Dhcpv6Option::StatusCode(2, "NoAddrsAvail".to_string()).to_raw();
    assert_eq!(raw.code, 13);
    assert_eq!(&raw.data[..2], &[0, 2]);
    assert_eq!(&raw.data[2..], b"NoAddrsAvail");
    let raw = Dhcpv6Option::StatusCode(0, String::new()).to_raw();
    assert_eq!(raw.code, 13);
    assert_eq!(raw.data, vec![0, 0]);
}

#[test]
fn unrecognized_round_trips_code_and_data() {
    let inner = RawDhcpv6Option { code: 60000, data: vec![9, 8, 7] };
    assert_eq!(Dhcpv6Option::Unrecognized(inner.clone()).to_raw(), inner);
}

#[test]
fn title_known_and_unknown() {
    assert_eq!(title(1), Some("Client Identifier"));
    assert_eq!(title(3), Some("Identity Association for Non-temporary Addresses"));
    assert_eq!(title(13), Some("Status Code"));
    assert_eq!(title(23), Some("DNS Recursive Name Server"));
    assert_eq!(title(0), None);
    assert_eq!(title(255), None);
    assert_eq!(title(60000), None);
}

// ---------------------------------------------------------------------------
// decode errors: strict, whole-packet rejection
// ---------------------------------------------------------------------------

#[test]
fn decode_rejects_truncated_header() {
    for len in 0..4 {
        let buf = vec![7u8; len];
        assert_eq!(Packet::from(&buf), Err(DecodeError::Truncated), "len {}", len);
    }
}

#[test]
fn decode_rejects_bad_msgtype() {
    assert_eq!(Packet::from(&[0, 0, 0, 1]), Err(DecodeError::BadMessageType(0)));
    assert_eq!(Packet::from(&[14, 0, 0, 1]), Err(DecodeError::BadMessageType(14)));
}

#[test]
fn decode_rejects_truncated_option_header_and_data() {
    // 3 trailing bytes: no full option header
    assert_eq!(
        Packet::from(&[1, 0, 0, 1, 53, 1, 2]),
        Err(DecodeError::Truncated)
    );
    // declared len overruns the datagram
    assert_eq!(
        Packet::from(&[1, 0, 0, 1, 0, 1, 0, 10, 1, 2]),
        Err(DecodeError::Truncated)
    );
    // direct: header needs 4 bytes
    assert_eq!(decode_option(&[1, 2, 3]), Err(DecodeError::Truncated));
    assert_eq!(decode_option(&[]), Err(DecodeError::Truncated));
}

#[test]
fn decode_malformed_iana_variants() {
    // shorter than IAID+T1+T2
    assert_eq!(decode_option(&[0, 3, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(DecodeError::Malformed));
    // trailing 1-3 bytes after header are not a sub-option
    let mut wire = vec![0, 3, 0, 13];
    wire.extend_from_slice(&[0u8; 12]);
    wire.push(0xAA);
    assert_eq!(decode_option(&wire), Err(DecodeError::Malformed));
    // sub-option length overruns
    let mut wire = vec![0, 3, 0, 14];
    wire.extend_from_slice(&[0u8; 12]);
    wire.extend_from_slice(&[0, 5, 0, 28, 1, 2]);
    assert_eq!(decode_option(&wire), Err(DecodeError::Malformed));
    // IAADDR body shorter than 24
    let mut wire = vec![0, 3, 0, 12 + 4 + 10];
    wire.extend_from_slice(&[0u8; 12]);
    wire.extend_from_slice(&[0, 5, 0, 10]);
    wire.extend_from_slice(&[0u8; 10]);
    assert_eq!(decode_option(&wire), Err(DecodeError::Malformed));
}

#[test]
fn decode_malformed_dns_and_status() {
    // DNS length not a multiple of 16
    assert_eq!(decode_option(&[0, 23, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(DecodeError::Malformed));
    // status shorter than 2-byte code
    assert_eq!(decode_option(&[0, 13, 0, 1, 0]), Err(DecodeError::Malformed));
    // status message not UTF-8
    assert_eq!(
        decode_option(&[0, 13, 0, 4, 0, 2, 0xFF, 0xFE]),
        Err(DecodeError::BadUtf8)
    );
    // empty status message is fine
    match decode_option(&[0, 13, 0, 2, 0, 0]) {
        Ok((_, Dhcpv6Option::StatusCode(0, m))) => assert_eq!(m, ""),
        _ => panic!("empty status message"),
    }
}

// ---------------------------------------------------------------------------
// packet round-trips (options run to end of datagram: no END byte)
// ---------------------------------------------------------------------------

#[test]
fn packet_empty_options_roundtrip() {
    let p = Packet { msg_type: MsgType::Solicit, transaction_id: 1, options: vec![] };
    let enc = p.encode().unwrap();
    assert_eq!(enc, vec![1, 0, 0, 1]);
    assert_eq!(Packet::from(&enc).unwrap(), p);
}

#[test]
fn packet_full_solicit_roundtrip_without_end_byte() {
    let p = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 0xABCDEF,
        options: vec![
            Dhcpv6Option::ClientId(duid(&[0, 3, 0, 1, 2, 0, 0x5e, 0xaa, 0xbb, 0xcc])),
            Dhcpv6Option::IaNa(IaNa {
                iaid: 0x0A0B0C0D,
                t1: 0,
                t2: 0,
                addrs: vec![],
            }),
            Dhcpv6Option::DnsServers(vec![v6([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888])]),
            Dhcpv6Option::Unrecognized(RawDhcpv6Option { code: 999, data: vec![1, 2] }),
        ],
    };
    let enc = p.encode().unwrap();
    // no END marker anywhere: last bytes are the final option's data
    assert_eq!(&enc[enc.len() - 2..], &[1, 2]);
    assert_eq!(Packet::from(&enc).unwrap(), p);
}

#[test]
fn packet_trailing_garbage_rejects_whole_packet() {
    // valid option followed by 2 undecodable bytes: strict Err (by design,
    // unlike the v4 swallow-and-desync behavior).
    let mut enc = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 1,
        options: vec![Dhcpv6Option::ClientId(duid(&[1]))],
    }
    .encode()
    .unwrap();
    enc.extend_from_slice(&[9, 9]);
    assert_eq!(Packet::from(&enc), Err(DecodeError::Truncated));
}

#[test]
fn packet_option_first_wins_and_iana_accessor() {
    let p = Packet {
        msg_type: MsgType::Request,
        transaction_id: 2,
        options: vec![
            Dhcpv6Option::IaNa(IaNa { iaid: 1, t1: 0, t2: 0, addrs: vec![] }),
            Dhcpv6Option::IaNa(IaNa { iaid: 2, t1: 0, t2: 0, addrs: vec![] }),
        ],
    };
    assert_eq!(p.first_iana().unwrap().iaid, 1);
    assert!(p.option(999).is_none());
    let bare = Packet { msg_type: MsgType::Solicit, transaction_id: 0, options: vec![] };
    assert!(bare.first_iana().is_none());
}

#[test]
fn encode_rejects_option_over_u16_max() {
    let p = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 1,
        options: vec![Dhcpv6Option::Unrecognized(RawDhcpv6Option {
            code: 200,
            data: vec![0u8; 65536],
        })],
    };
    assert_eq!(p.encode(), Err(EncodeError::OptionTooLarge));
}

#[test]
fn is_for_server_exact_duid_match_only() {
    let ours = duid(&[1, 2, 3]);
    let mk = |opts| Packet { msg_type: MsgType::Request, transaction_id: 1, options: opts };
    assert!(is_for_server(
        &ours,
        &mk(vec![Dhcpv6Option::ServerId(duid(&[1, 2, 3]))])
    ));
    assert!(!is_for_server(&ours, &mk(vec![Dhcpv6Option::ServerId(vec![])])));
    assert!(!is_for_server(
        &ours,
        &mk(vec![Dhcpv6Option::ServerId(duid(&[1, 2, 4]))])
    ));
    assert!(!is_for_server(&ours, &mk(vec![])), "missing ServerId");
    assert!(
        !is_for_server(
            &ours,
            &mk(vec![Dhcpv6Option::Unrecognized(RawDhcpv6Option {
                code: 2,
                data: duid(&[1, 2, 3])
            })])
        ),
        "Unrecognized(2) is not a ServerId"
    );
}

#[test]
fn default_t1_t2_halves_and_seven_eighths() {
    assert_eq!(default_t1_t2(86400), (43200, 75600));
    assert_eq!(default_t1_t2(3600), (1800, 3150));
    assert_eq!(default_t1_t2(0), (0, 0));
    assert_eq!(default_t1_t2(u32::MAX), (2147483647, 3758096384));
}

// ---------------------------------------------------------------------------
// V6Pool managed range
// ---------------------------------------------------------------------------

fn pool() -> V6Pool {
    V6Pool::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100),
        1000,
        Duration::from_secs(86400),
    )
}

fn ip(n: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, n)
}

#[test]
fn pool_accessors() {
    let p = pool();
    assert_eq!(p.start_addr(), ip(0x100));
    assert_eq!(p.count(), 1000);
    assert_eq!(p.len(), 0);
    assert!(p.is_empty());
}

#[test]
fn pool_boundaries_first_offer_and_last() {
    let mut p = pool();
    // round-robin starts at start+1 like the v4 example
    assert_eq!(p.discover(&duid(&[1])), Some(ip(0x101)));
    // last usable address is start+count-1
    assert!(p.available(&duid(&[2]), &ip(0x100 + 999)));
    assert!(!p.available(&duid(&[2]), &ip(0x100 + 1000)), "exclusive upper bound");
    assert!(!p.available(&duid(&[2]), &ip(0xFF)), "below pool");
    assert!(!p.available(&duid(&[2]), &v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])), "other prefix");
    // unleased in-pool address is available
    assert!(p.available(&duid(&[3]), &ip(0x200)));
}

#[test]
fn pool_exhaustion_returns_none_then_recovers() {
    let mut p = V6Pool::new(ip(0x100), 4, Duration::from_secs(60));
    for i in 0u8..4 {
        let d = duid(&[i]);
        let got = p.discover(&d).unwrap();
        p.request(&d, got).unwrap();
    }
    assert_eq!(p.len(), 4);
    assert_eq!(p.discover(&duid(&[9])), None, "pool exhausted");
    assert!(p.request(&duid(&[9]), ip(0x101)).is_err());
    assert!(p.release(&duid(&[0])));
    // freed .101 is first in scan order (round-robin resumes after last=0)
    assert_eq!(p.discover(&duid(&[9])), Some(ip(0x101)));
}

#[test]
fn pool_request_prefers_current_without_refresh_quirk() {
    let mut p = pool();
    let mac = duid(&[7]);
    assert_eq!(p.request(&mac, ip(0x110)), Ok(ip(0x110)));
    let before = p.get(&ip(0x110)).unwrap().1;
    // asking for someone else's IP still returns our own, untouched
    assert_eq!(p.request(&mac, ip(0x120)), Ok(ip(0x110)));
    assert_eq!(p.get(&ip(0x110)).unwrap().1, before, "no expiry refresh, like v4");
    assert!(p.get(&ip(0x120)).is_none());
}

#[test]
fn pool_infinite_leases_are_not_stealable() {
    // deliberate difference from the v4 available() quirk: None expiry here
    // means permanently reserved, and strangers get Err, not the address.
    let mut p = pool();
    let owner = duid(&[0xF4, 0x5C]);
    let stranger = duid(&[0xDE, 0xAD]);
    p.insert(ip(0x190), owner.clone(), None);
    assert!(!p.available(&stranger, &ip(0x190)));
    assert!(p.request(&stranger, ip(0x190)).is_err());
    assert_eq!(p.request(&owner, ip(0x190)), Ok(ip(0x190)));
    assert_eq!(p.discover(&owner), Some(ip(0x190)));
}

#[test]
fn pool_expired_leases_reusable() {
    let mut p = pool();
    p.insert(ip(0x1A0), duid(&[1]), Some(Instant::now() - Duration::from_secs(1)));
    assert!(p.available(&duid(&[2]), &ip(0x1A0)));
    assert_eq!(p.request(&duid(&[2]), ip(0x1A0)), Ok(ip(0x1A0)));
}

#[test]
fn pool_release_true_false() {
    let mut p = pool();
    assert!(!p.release(&duid(&[1])), "nothing held");
    assert_eq!(p.request(&duid(&[1]), ip(0x1B0)), Ok(ip(0x1B0)));
    assert!(p.release(&duid(&[1])));
    assert!(!p.release(&duid(&[1])), "already gone");
    assert!(p.is_empty());
}

#[test]
fn pool_duid_identity_is_exact_bytes() {
    let mut p = pool();
    assert_eq!(p.request(&duid(&[1, 2]), ip(0x1C0)), Ok(ip(0x1C0)));
    // prefix-extended DUID is a different client: blocked
    assert!(!p.available(&duid(&[1, 2, 3]), &ip(0x1C0)));
    assert_eq!(p.current_lease(&duid(&[1, 2, 3])), None);
    assert_eq!(p.current_lease(&duid(&[1, 2])), Some(ip(0x1C0)));
}

#[test]
fn pool_empty_count_never_panics() {
    let mut p = V6Pool::new(ip(0x100), 0, Duration::from_secs(60));
    assert_eq!(p.discover(&duid(&[1])), None);
    assert!(p.request(&duid(&[1]), ip(0x100)).is_err());
    assert!(!p.available(&duid(&[1]), &ip(0x100)));
}

#[test]
fn pool_max_start_never_panics() {
    // start near u128::MAX with a count reaching past it: the exclusive end
    // overflows, so every candidate is out of range — but small enough to
    // scan quickly (a huge count must never mean a huge loop).
    let near_max = Ipv6Addr::from(u128::MAX - 3);
    let mut p = V6Pool::new(near_max, 16, Duration::from_secs(60));
    assert_eq!(p.discover(&duid(&[1])), None, "overflowed candidates skipped");
    assert!(!p.available(&duid(&[1]), &near_max));
    assert!(p.request(&duid(&[1]), near_max).is_err());
    // sheer count size alone must not hang the scan either: an empty pool
    // returns None after scanning, and the loop is bounded by count — keep
    // counts under test small by construction (see pool_exhaustion test).
    let mut tiny = V6Pool::new(ip(0x100), 0, Duration::from_secs(60));
    assert_eq!(tiny.discover(&duid(&[1])), None);
}

// ---------------------------------------------------------------------------
// coverageg gaps: sub-option skipping, identity edges, pool corners
// ---------------------------------------------------------------------------

#[test]
fn iana_skips_unknown_suboptions_keeps_iaaddrs() {
    // unknown sub-option (code 99) interleaved between two IAADDRs: skipped
    // by length while both addresses still decode.
    let mut data = vec![0u8; 12]; // iaid/t1/t2 zeroes
    data[0..4].copy_from_slice(&9u32.to_be_bytes());
    let addr = |n: u16| {
        let mut sub = vec![0u8, 5, 0, 24];
        sub.extend_from_slice(&v6([0xfd00, 0, 0, 0, 0, 0, 0, n]).octets());
        sub.extend_from_slice(&100u32.to_be_bytes());
        sub.extend_from_slice(&200u32.to_be_bytes());
        sub
    };
    data.extend_from_slice(&addr(1));
    data.extend_from_slice(&[0, 99, 0, 2, 0xAA, 0xBB]); // unknown, skipped
    data.extend_from_slice(&addr(2));
    let mut wire = vec![0, 3, (data.len() >> 8) as u8, (data.len() & 0xFF) as u8];
    wire.extend_from_slice(&data);
    match decode_option(&wire) {
        Ok((_, Dhcpv6Option::IaNa(ia))) => {
            assert_eq!(ia.iaid, 9);
            assert_eq!(
                ia.addrs.iter().map(|a| a.addr).collect::<Vec<_>>(),
                vec![v6([0xfd00, 0, 0, 0, 0, 0, 0, 1]), v6([0xfd00, 0, 0, 0, 0, 0, 0, 2])]
            );
        }
        _ => panic!("unknown sub-options must be skipped"),
    }
}

#[test]
fn iaaddr_trailing_subsuboptions_ignored() {
    // IAADDR data longer than 24 bytes: first 24 parse, rest ignored.
    let mut body = vec![0u8; 0];
    body.extend_from_slice(&v6([0xfd00, 0, 0, 0, 0, 0, 0, 9]).octets());
    body.extend_from_slice(&300u32.to_be_bytes());
    body.extend_from_slice(&400u32.to_be_bytes());
    body.extend_from_slice(&[9, 9, 9, 9, 9, 9]); // sub-sub-options, ignored
    let mut data = vec![0u8; 12];
    let mut wire = vec![0, 3, 0, 0]; // len patched below
    let mut opt = vec![0, 5, 0, body.len() as u8];
    opt.extend_from_slice(&body);
    data.extend_from_slice(&opt);
    wire[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
    wire.extend_from_slice(&data);
    match decode_option(&wire) {
        Ok((_, Dhcpv6Option::IaNa(ia))) => {
            assert_eq!(ia.addrs.len(), 1);
            assert_eq!(ia.addrs[0].addr, v6([0xfd00, 0, 0, 0, 0, 0, 0, 9]));
            assert_eq!((ia.addrs[0].preferred, ia.addrs[0].valid), (300, 400));
        }
        _ => panic!("trailing sub-sub-option bytes must be ignored"),
    }
}

#[test]
fn is_for_server_first_identifier_wins() {
    let ours = duid(&[1, 2, 3]);
    let mk = |opts| Packet { msg_type: MsgType::Request, transaction_id: 1, options: opts };
    assert!(is_for_server(
        &ours,
        &mk(vec![
            Dhcpv6Option::ServerId(duid(&[1, 2, 3])),
            Dhcpv6Option::ServerId(duid(&[9, 9, 9])),
        ])
    ));
    assert!(!is_for_server(
        &ours,
        &mk(vec![
            Dhcpv6Option::ServerId(duid(&[9, 9, 9])),
            Dhcpv6Option::ServerId(duid(&[1, 2, 3])),
        ])
    ));
}

#[test]
fn empty_clientid_decodes() {
    match decode_option(&[0, 1, 0, 0]) {
        Ok((rest, Dhcpv6Option::ClientId(d))) => {
            assert!(d.is_empty());
            assert!(rest.is_empty());
        }
        _ => panic!("empty ClientId must decode"),
    }
    // and it round-trips through a packet
    let p = Packet {
        msg_type: MsgType::Solicit,
        transaction_id: 5,
        options: vec![Dhcpv6Option::ClientId(vec![])],
    };
    assert_eq!(Packet::from(&p.encode().unwrap()).unwrap(), p);
}

#[test]
fn opaque_messages_roundtrip() {
    // Confirm / Reconfigure / InformationRequest / RelayForward / RelayReply
    // carry no special-cased structure: header + opaque options round-trip.
    for mt in [
        MsgType::Confirm,
        MsgType::Reconfigure,
        MsgType::InformationRequest,
        MsgType::RelayForward,
        MsgType::RelayReply,
    ] {
        let p = Packet {
            msg_type: mt,
            transaction_id: 0x0A0B0C,
            options: vec![
                Dhcpv6Option::ClientId(duid(&[7])),
                Dhcpv6Option::Unrecognized(RawDhcpv6Option {
                    code: 65000,
                    data: vec![1, 2, 3],
                }),
            ],
        };
        let enc = p.encode().unwrap();
        assert_eq!(enc[0], mt as u8);
        assert_eq!(Packet::from(&enc).unwrap(), p);
    }
}

#[test]
fn transaction_id_zero_and_max_roundtrip() {
    for tid in [0u32, 0xFF_FF_FF] {
        let p = Packet { msg_type: MsgType::Solicit, transaction_id: tid, options: vec![] };
        let enc = p.encode().unwrap();
        assert_eq!(Packet::from(&enc).unwrap().transaction_id, tid);
    }
}

#[test]
fn pool_request_out_of_range_err_no_insert() {
    let mut p = pool();
    assert!(p.request(&duid(&[1]), v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])).is_err());
    assert!(p.is_empty(), "out-of-range request must not insert");
}

#[test]
fn pool_single_address_pool_cycles() {
    // count == 1: modulo-1 scan cannot divide by zero (loop runs once) and
    // the lone address is offered, committed, then reported current.
    let mut p = V6Pool::new(ip(0x100), 1, Duration::from_secs(60));
    assert_eq!(p.discover(&duid(&[1])), Some(ip(0x100)));
    assert_eq!(p.request(&duid(&[1]), ip(0x100)), Ok(ip(0x100)));
    assert_eq!(p.discover(&duid(&[1])), Some(ip(0x100)));
    assert_eq!(p.discover(&duid(&[2])), None, "taken single slot");
}
