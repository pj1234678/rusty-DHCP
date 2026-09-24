//! DHCP standards conformance regression suite.
//!
//! Locks behavior required by RFC 2131 (DHCP) and RFC 2132 (options) so that
//! refactors cannot silently break on-the-wire interoperability.
//!
//! Where the implementation intentionally deviates from (or is stricter than)
//! the RFC, the test name ends in `_quirk` / `_deviation` and the RFC
//! expectation is quoted in the doc comment. All such tests assert the
//! *current* behavior and pass against it.

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

#[allow(dead_code)]
fn opt_raw(code: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![code, data.len() as u8];
    v.extend_from_slice(data);
    v
}

/// RFC 2131 §2 / RFC 951 §3 fixed BOOTP header: 236 bytes before options.
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
    v[1] = 1; // htype = Ethernet per RFC 2131 §2 / RFC 1700
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
    v.extend_from_slice(&[99, 130, 83, 99]); // RFC 1533 magic cookie
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
        ciaddr: Ipv4Addr::new(0, 0, 0, 0),
        yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0),
        giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr,
        options: opts,
    }
}

#[allow(dead_code)]
fn recv(sock: &UdpSocket, buf: &mut [u8]) -> (usize, std::net::SocketAddr) {
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.recv_from(buf).expect("timeout waiting for reply")
}

// ===========================================================================
// RFC 2131 §2 — BOOTP/DHCP fixed header
// ===========================================================================

/// RFC 2131 §2: `op` 1 = BOOTREQUEST (client), 2 = BOOTREPLY (server).
#[test]
fn rfc2131_op_bootrequest_is_decode_request_encode_reply() {
    let req = unwrap_packet(Packet::from(&make_raw(
        1, 6, 0, 0x11111111, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6],
        vec![53, 1, 1, 255],
    )));
    assert!(!req.reply);

    let rep = unwrap_packet(Packet::from(&make_raw(
        2, 6, 0, 0x11111111, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6],
        vec![53, 1, 2, 255],
    )));
    assert!(rep.reply);

    // encode path mirrors the same mapping
    let mut buf = [0u8; 1500];
    assert_eq!(client_packet(1, [0; 6], vec![]).encode(&mut buf)[0], 1);
    let server_pkt = Packet {
        reply: true, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6], options: vec![],
    };
    assert_eq!(server_pkt.encode(&mut buf)[0], 2);
}

/// RFC 2131 §2: `htype` 1 = 10Mb Ethernet, `hlen` 6 for Ethernet.
/// Decoder enforces `hlen == 6`; `htype` is accepted as-is (relay/ethernet).
#[test]
fn rfc2131_htype_hlen_ethernet() {
    // hlen != 6 is rejected (Ethernet chaddr is 6 bytes)
    for bad in [0u8, 5, 7, 16, 255] {
        let raw = make_raw(
            1, bad, 0, 1, 0, [0, 0],
            [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
            [1, 2, 3, 4, 5, 6],
            vec![53, 1, 1, 255],
        );
        assert!(
            matches!(Packet::from(&raw), Err(CustomErr::InvalidHlen)),
            "hlen {} must be rejected",
            bad
        );
    }
    // encoder always emits htype=1, hlen=6
    let mut buf = [0u8; 1500];
    let enc = client_packet(1, [9; 6], vec![]).encode(&mut buf).to_vec();
    assert_eq!(enc[1], 1);
    assert_eq!(enc[2], 6);
}

/// RFC 2131 §2: fixed header is 236 bytes (op..file), then magic cookie.
/// `chaddr` is 16 bytes on the wire (6 used + 10 pad); sname/file are zero.
#[test]
fn rfc2131_fixed_header_layout_and_zero_padding() {
    let p = Packet {
        reply: false, hops: 0, xid: 0xAABBCCDD, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(1, 2, 3, 4), yiaddr: Ipv4Addr::new(5, 6, 7, 8),
        siaddr: Ipv4Addr::new(9, 10, 11, 12), giaddr: Ipv4Addr::new(13, 14, 15, 16),
        chaddr: [10, 20, 30, 40, 50, 60],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let mut buf = [0xFFu8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    // BOOTP fields at RFC offsets
    assert_eq!(&enc[4..8], &0xAABBCCDDu32.to_be_bytes()); // xid
    assert_eq!(&enc[12..16], &[1, 2, 3, 4]); // ciaddr
    assert_eq!(&enc[16..20], &[5, 6, 7, 8]); // yiaddr
    assert_eq!(&enc[20..24], &[9, 10, 11, 12]); // siaddr
    assert_eq!(&enc[24..28], &[13, 14, 15, 16]); // giaddr
    assert_eq!(&enc[28..34], &[10, 20, 30, 40, 50, 60]); // chaddr[0..6]
    assert!(enc[34..236].iter().all(|&b| b == 0)); // chaddr pad + sname + file
    assert_eq!(&enc[236..240], &[99, 130, 83, 99]); // cookie
    assert!(enc.len() >= 241 && enc.len() <= 300);
}

/// RFC 1533 §2 / RFC 2131 §3: magic cookie 99,130,83,99 selects DHCP options.
/// Anything else is not a DHCP packet.
#[test]
fn rfc1533_magic_cookie_required() {
    let mut raw = make_raw(
        1, 6, 0, 1, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6],
        vec![53, 1, 1, 255],
    );
    raw[236..240].copy_from_slice(&[99, 130, 83, 99]);
    assert!(Packet::from(&raw).is_ok(), "good cookie must decode");
    raw[236..240].copy_from_slice(&[0, 0, 0, 0]);
    assert!(
        matches!(Packet::from(&raw), Err(CustomErr::NomError(_))),
        "bad cookie must be rejected"
    );
}

/// RFC 2131 §2: minimum DHCP message handling. Implementation pads the send
/// buffer with zeros out to 300 bytes (BOOTP minimum on the wire).
#[test]
fn rfc2131_minimum_message_zero_padding() {
    let p = client_packet(1, [0; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Discover,
    )]);
    let mut buf = [0xFFu8; 1500];
    let len = p.encode(&mut buf).len();
    assert_eq!(len, 244);
    assert!(buf[len..300].iter().all(|&b| b == 0));
    // every encoded datagram fits in one 1500-byte Ethernet MTU datagram
    assert!(len <= 1500);
}

// ===========================================================================
// RFC 2132 §2 — option TLV wire format and lengths
// ===========================================================================

/// RFC 2132 §2: options are `code, len, data` except PAD (0) and END (255),
/// which carry neither length nor data. Every encoded option must appear as
/// exactly `2 + data.len()` bytes followed eventually by a single END byte.
#[test]
fn rfc2132_option_tlv_then_end() {
    let opts = vec![
        DhcpOption::DhcpMessageType(MessageType::Discover), // 53, len 1
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)), // 1, len 4
    ];
    let p = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6], options: opts,
    };
    let mut buf = [0u8; 1500];
    let enc = p.encode(&mut buf).to_vec();
    assert_eq!(&enc[240..243], &[53, 1, 1]);
    assert_eq!(&enc[243..249], &[1, 4, 255, 255, 255, 0]);
    assert_eq!(enc[249], 255); // END
    assert_eq!(enc.len(), 250);
}

/// RFC 2132 §9.6: DHCP Message Type (53) has length 1.
#[test]
fn rfc2132_opt53_message_type_len_1() {
    for mt in [
        MessageType::Discover, MessageType::Offer, MessageType::Request,
        MessageType::Decline, MessageType::Ack, MessageType::Nak,
        MessageType::Release, MessageType::Inform,
    ] {
        let raw = DhcpOption::DhcpMessageType(mt).to_raw();
        assert_eq!(raw.code, 53);
        assert_eq!(raw.data.len(), 1);
        assert_eq!(raw.data[0], mt as u8);
    }
    // len != 1 with trailing bytes: decoder uses first data byte (locked)
    match decode_option(&[53, 2, 1, 2]) {
        Ok((_, DhcpOption::DhcpMessageType(t))) => assert_eq!(t, MessageType::Discover),
        _ => panic!("53 len 2 should use first byte"),
    }
}

/// RFC 2132 §9.4/§9.7/§2.3/§2.4: IPv4 options carry 4 bytes per address.
/// Server Identifier (54), Requested IP (50), Subnet Mask (1) are exactly 4;
/// Lease Time (51) is a 4-byte unsigned seconds count, big-endian.
#[test]
fn rfc2132_ipv4_and_lease_time_lengths() {
    assert_eq!(DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 1)).to_raw().data.len(), 4);
    assert_eq!(DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 0, 0, 5)).to_raw().data.len(), 4);
    assert_eq!(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)).to_raw().data.len(), 4);
    // 86400 = one day; MAX = infinite per RFC 2132 §9.10 discussion
    assert_eq!(DhcpOption::IpAddressLeaseTime(86400).to_raw().data, vec![0, 1, 81, 128]);
    assert_eq!(DhcpOption::IpAddressLeaseTime(u32::MAX).to_raw().data, vec![255, 255, 255, 255]);
    assert_eq!(DhcpOption::IpAddressLeaseTime(0).to_raw().data, vec![0, 0, 0, 0]);
    // short address payloads are rejected
    assert!(matches!(decode_option(&[54, 3, 1, 2, 3]), Err(CustomErr::InvalidHlen)));
    assert!(matches!(decode_option(&[51, 2, 0, 1]), Err(CustomErr::InvalidHlen)));
}

/// RFC 2132 §9.2/§9.3: Router (3) and Domain Name Server (6) are sums of
/// 4-byte IPv4 addresses, so total data length is a multiple of 4.
/// The encoder preserves this invariant.
#[test]
fn rfc2132_router_dns_encoding_is_multiple_of_4() {
    assert!(DhcpOption::Router(vec![]).to_raw().data.is_empty());
    assert_eq!(DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]).to_raw().data.len(), 4);
    assert_eq!(
        DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1)])
            .to_raw().data.len(),
        8
    );
    assert_eq!(
        DhcpOption::DomainNameServer(vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)])
            .to_raw().data.len(),
        8
    );
}

/// RFC 2132 §9.8: Parameter Request List (55) is N bytes of option codes.
/// Empty list is legal.
#[test]
fn rfc2132_opt55_parameter_request_list() {
    match decode_option(&[55, 3, 1, 3, 6]) {
        Ok((_, DhcpOption::ParameterRequestList(v))) => assert_eq!(v, vec![1, 3, 6]),
        _ => panic!("PRL decode"),
    }
    match decode_option(&[55, 0]) {
        Ok((_, DhcpOption::ParameterRequestList(v))) => assert!(v.is_empty()),
        _ => panic!("empty PRL"),
    }
}

/// RFC 2132 §9.1/§7: Host Name (12) and Message (56) are variable-length text.
/// Decoder requires valid UTF-8 (stricter than RFC's opaque text).
#[test]
fn rfc2132_text_options_utf8() {
    match decode_option(&[12, 3, 65, 66, 67]) {
        Ok((_, DhcpOption::HostName(s))) => assert_eq!(s, "ABC"),
        _ => panic!("hostname"),
    }
    match decode_option(&[12, 0]) {
        Ok((_, DhcpOption::HostName(s))) => assert_eq!(s, ""),
        _ => panic!("empty hostname"),
    }
    assert!(matches!(decode_option(&[12, 2, 0xFF, 0xFE]), Err(CustomErr::NonUtf8String)));
    assert!(matches!(decode_option(&[56, 2, 0xFF, 0xFE]), Err(CustomErr::NonUtf8String)));
}

/// RFC 2132 §2: unknown codes must be preserved transparently (code + data).
#[test]
fn rfc2132_unrecognized_options_preserved() {
    match decode_option(&[99, 2, 1, 2]) {
        Ok((rest, DhcpOption::Unrecognized(r))) => {
            assert_eq!(r.code, 99);
            assert_eq!(r.data, vec![1, 2]);
            assert!(rest.is_empty());
        }
        _ => panic!("unrecognized"),
    }
    let inner = RawDhcpOption { code: 200, data: vec![1, 2, 3] };
    assert_eq!(DhcpOption::Unrecognized(inner.clone()).to_raw(), inner);
}

/// RFC 2132 §2 deviation: PAD (0) is defined as a single 0x00 byte with no
/// length, but this implementation parses it as a normal TLV code. Locked so
/// a future "fix" cannot silently change decoding of captures containing 0.
#[test]
fn rfc2132_pad_singleton_deviation_quirk() {
    match decode_option(&[0, 1, 2]) {
        Ok((_, DhcpOption::Unrecognized(r))) => {
            assert_eq!(r.code, 0);
            assert_eq!(r.data, vec![2]);
        }
        _ => panic!("PAD code 0 must decode as Unrecognized TLV"),
    }
}

// ===========================================================================
// RFC 2132 §9.6 + RFC 2131 Table 2 — message types and DORA roles
// ===========================================================================

/// RFC 2132 §9.6 numeric values 1..8.
#[test]
fn rfc2132_msgtype_values_1_to_8() {
    assert_eq!(MessageType::Discover as u8, 1);
    assert_eq!(MessageType::Offer as u8, 2);
    assert_eq!(MessageType::Request as u8, 3);
    assert_eq!(MessageType::Decline as u8, 4);
    assert_eq!(MessageType::Ack as u8, 5);
    assert_eq!(MessageType::Nak as u8, 6);
    assert_eq!(MessageType::Release as u8, 7);
    assert_eq!(MessageType::Inform as u8, 8);
    for v in 1u8..=8 {
        assert!(MessageType::from(v).is_ok());
    }
    for v in [0u8, 9, 255] {
        assert!(MessageType::from(v).is_err());
    }
}

/// RFC 2131 Table 2 roles: client sends Discover/Request/Decline/Release/
/// Inform; server sends Offer/Ack/Nak. Every packet carries option 53, and
/// `message_type()` reports it (or a precise error when absent/mistyped).
#[test]
fn rfc2131_table2_every_packet_carries_opt53() {
    for mt in [
        MessageType::Discover, MessageType::Offer, MessageType::Request,
        MessageType::Decline, MessageType::Ack, MessageType::Nak,
        MessageType::Release, MessageType::Inform,
    ] {
        let p = Packet {
            reply: matches!(mt, MessageType::Offer | MessageType::Ack | MessageType::Nak),
            hops: 0, xid: 0x42, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 6], options: vec![DhcpOption::DhcpMessageType(mt)],
        };
        assert_eq!(p.message_type(), Ok(mt));
        let mut buf = [0u8; 1500];
        let enc = p.encode(&mut buf).to_vec();
        assert_eq!(unwrap_packet(Packet::from(&enc)).message_type(), Ok(mt));
    }
    let bare = Packet {
        reply: false, hops: 0, xid: 1, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0; 6], options: vec![],
    };
    assert!(bare.message_type().is_err());
}

// ===========================================================================
// RFC 2131 §3.1 — client field rules per state
// ===========================================================================

/// RFC 2131 §3.1 Table 1 (DHCPDISCOVER): ciaddr MUST be 0, yiaddr/siaddr 0,
/// chaddr = client hardware address, xid = random transaction id.
#[test]
fn rfc2131_discover_zero_addresses_and_chaddr() {
    let xid = 0x39A12B4Cu32;
    let ch = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let raw = make_raw(
        1, 6, 0, xid, 0, [0, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], ch,
        vec![53, 1, 1, 255],
    );
    let p = unwrap_packet(Packet::from(&raw));
    assert_eq!(p.ciaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(p.yiaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(p.siaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(p.chaddr, ch);
    assert_eq!(p.xid, xid);
    assert_eq!(p.message_type(), Ok(MessageType::Discover));
}

/// RFC 2131 §3.1/§4.3.2: DHCPREQUEST address selection — INIT-REBOOT carries
/// Requested IP (50) and no ciaddr; RENEWING/REBINDING carries ciaddr.
/// Library rule (mirrored from src/main.rs): RequestedIp else ciaddr.
fn rfc2131_requested_or_ciaddr(p: &Packet) -> Ipv4Addr {
    match p.option(REQUESTED_IP_ADDRESS) {
        Some(DhcpOption::RequestedIpAddress(x)) => *x,
        _ => p.ciaddr,
    }
}

#[test]
fn rfc2131_request_address_selection() {
    // INIT-REBOOT: Requested IP wins over ciaddr
    let init = Packet {
        reply: false, hops: 0, xid: 2, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [1; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 100)),
        ],
    };
    assert_eq!(rfc2131_requested_or_ciaddr(&init), Ipv4Addr::new(192, 168, 1, 100));
    // RENEWING: no Requested IP, ciaddr identifies the lease
    let renew = Packet {
        reply: false, hops: 0, xid: 3, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 1, 50), yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [1; 6],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    assert_eq!(rfc2131_requested_or_ciaddr(&renew), Ipv4Addr::new(192, 168, 1, 50));
}

/// RFC 2131 §§3.1, 4.3.3, 4.4.4: DECLINE (address in use), RELEASE
/// (relinquish), INFORM (already-addressed client asks only for config).
#[test]
fn rfc2131_decline_release_inform_roles() {
    for mt in [MessageType::Decline, MessageType::Release, MessageType::Inform] {
        let p = Packet {
            reply: false, hops: 0, xid: 9, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::new(192, 168, 1, 10), yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [5; 6], options: vec![DhcpOption::DhcpMessageType(mt)],
        };
        assert_eq!(p.message_type(), Ok(mt));
        let mut buf = [0u8; 1500];
        let enc = p.encode(&mut buf).to_vec();
        let q = unwrap_packet(Packet::from(&enc));
        assert_eq!(q.message_type(), Ok(mt));
        assert_eq!(q.ciaddr, Ipv4Addr::new(192, 168, 1, 10));
    }
}

// ===========================================================================
// RFC 2131 §4.3 — server reply rules (via Server::reply over loopback)
// ===========================================================================

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

/// RFC 2131 §4.3: server replies are BOOTREPLY with echoed xid/chaddr/giaddr,
/// hops/secs reset to 0, yiaddr = offered address, Server Identifier present.
#[test]
fn rfc2131_server_reply_echo_and_fixed_fields() {
    let req = Packet {
        reply: false, hops: 4, xid: 0xDEADBEEF, secs: 55, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::new(9, 9, 9, 9), giaddr: Ipv4Addr::new(192, 168, 1, 254),
        chaddr: [7, 7, 7, 7, 7, 7],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let rep = reply_once(
        MessageType::Offer,
        vec![DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))],
        Ipv4Addr::new(192, 168, 1, 100),
        req,
    );
    assert!(rep.reply, "server must send BOOTREPLY");
    assert_eq!(rep.xid, 0xDEADBEEF, "xid MUST be echoed");
    assert_eq!(rep.chaddr, [7, 7, 7, 7, 7, 7], "chaddr MUST be echoed");
    assert_eq!(rep.giaddr, Ipv4Addr::new(192, 168, 1, 254), "giaddr MUST be echoed for relays");
    assert_eq!(rep.hops, 0, "server resets hops");
    assert_eq!(rep.secs, 0, "server resets secs");
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
    // siaddr 0.0.0.0 = "next server not specified" (standards-allowed)
    assert_eq!(rep.siaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    assert_eq!(
        rep.option(SERVER_IDENTIFIER),
        Some(&DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1))),
        "Offer MUST carry Server Identifier"
    );
}

/// RFC 2131 §4.3.1: DHCPNAK signals the client to restart; ciaddr MUST NOT
/// carry a stale client address (implementation zeroes it; yiaddr stays the
/// caller-supplied offer value).
#[test]
fn rfc2131_nak_clears_ciaddr() {
    let req = Packet {
        reply: false, hops: 0, xid: 0x77, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 1, 99), yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [1, 1, 1, 1, 1, 1],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    let rep = reply_once(MessageType::Nak, vec![], Ipv4Addr::UNSPECIFIED, req);
    assert_eq!(rep.message_type(), Ok(MessageType::Nak));
    assert_eq!(rep.ciaddr, Ipv4Addr::UNSPECIFIED);
}

/// RFC 2131 §4.3: non-NAK replies echo ciaddr (RENEWING client identity).
#[test]
fn rfc2131_non_nak_echoes_ciaddr() {
    for mt in [MessageType::Offer, MessageType::Ack] {
        let req = Packet {
            reply: false, hops: 0, xid: 0x78, secs: 0, broadcast: false,
            ciaddr: Ipv4Addr::new(192, 168, 1, 44), yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [2, 2, 2, 2, 2, 2],
            options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
        };
        let rep = reply_once(mt, vec![], Ipv4Addr::new(192, 168, 1, 45), req);
        assert_eq!(rep.ciaddr, Ipv4Addr::new(192, 168, 1, 44), "{:?}", mt);
    }
}

/// RFC 2131 §4.3.1 Table 3: DORA uses Discover→Offer→Request→Ack with the
/// same xid/chaddr throughout; the ACK commits yiaddr.
#[test]
fn rfc2131_dora_field_continuity() {
    let ch = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let xid = 0x1234ABCDu32;
    let mk_req = |mt: MessageType| Packet {
        reply: false, hops: 0, xid, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: ch,
        options: vec![
            DhcpOption::DhcpMessageType(mt),
            DhcpOption::ParameterRequestList(vec![SUBNET_MASK, ROUTER]),
        ],
    };
    let offer = reply_once(
        MessageType::Offer,
        vec![DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))],
        Ipv4Addr::new(192, 168, 1, 70),
        mk_req(MessageType::Discover),
    );
    assert_eq!(offer.message_type(), Ok(MessageType::Offer));
    let offered = offer.yiaddr;

    let ack = reply_once(
        MessageType::Ack,
        vec![DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))],
        offered,
        mk_req(MessageType::Request),
    );
    assert_eq!(ack.message_type(), Ok(MessageType::Ack));
    assert_eq!(ack.yiaddr, offered, "ACK MUST commit the offered address");
    assert_eq!(ack.xid, xid);
    assert_eq!(ack.chaddr, ch);
}

// ===========================================================================
// RFC 2131 §4.1 + §3.3 — broadcast, unicast, relays, server selection
// ===========================================================================

/// RFC 2131 §4.1: the BROADCAST flag is the high-order bit of `flags`
/// (0x8000). This implementation tests `flags & 128` (low-byte 0x80) instead;
/// `[0,128]` decodes broadcast while the on-the-wire RFC value `[128,0]`
/// decodes as unicast. Locked as a deviation so captures stay parseable.
#[test]
fn rfc2131_broadcast_flag_deviation_quirk() {
    let bcast = unwrap_packet(Packet::from(&make_raw(
        1, 6, 0, 1, 0, [0, 128],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6],
        vec![53, 1, 1, 255],
    )));
    assert!(bcast.broadcast);
    let rfc_wire = unwrap_packet(Packet::from(&make_raw(
        1, 6, 0, 1, 0, [128, 0],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6],
        vec![53, 1, 1, 255],
    )));
    assert!(!rfc_wire.broadcast, "RFC 0x8000 currently decodes as unicast");
}

/// RFC 2131 §4.1: server echoes the broadcast flag; relay `giaddr` is echoed
/// so the reply returns via the same relay.
///
/// NOTE: a `Packet { broadcast: true }` struct encodes to flags `[128,0]`,
/// which decodes back to `false` (see deviation test above). The server only
/// ever sees the decoded value, so this test sends the decodable `[0,128]`
/// wire form directly instead of round-tripping a struct.
#[test]
fn rfc2131_reply_echoes_broadcast_and_giaddr() {
    let raw_req = make_raw(
        1, 6, 0, 0x99, 0, [0, 128],
        [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [10, 0, 0, 254],
        [3, 3, 3, 3, 3, 3],
        vec![53, 1, 1, 255],
    );
    // sanity: the wire form the server will see decodes to broadcast=true
    assert!(unwrap_packet(Packet::from(&raw_req)).broadcast);

    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            assert!(p.broadcast, "server must see broadcast=true from [0,128]");
            let _ = s.reply(
                MessageType::Offer,
                vec![],
                Ipv4Addr::new(10, 0, 1, 5),
                p,
            );
        }
    }
    std::thread::spawn(move || {
        // broadcast_ip is loopback so the broadcast reply still reaches the
        // test client (same pattern as test_server.rs broadcast test).
        let _ = server::Server::serve(
            srv_sock, Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(127, 0, 0, 1), H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(&raw_req, srv_addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut rbuf = [0u8; 1500];
    let (n, _) = client.recv_from(&mut rbuf).expect("no reply");
    // server echoed broadcast=true, so the reply wire flags are [128,0]
    assert_eq!(&rbuf[10..12], &[128, 0], "reply wire must carry broadcast flag");
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    // decoding [128,0] yields false (see deviation test); the wire bytes are
    // authoritative, not the decoded struct field
    assert!(!rep.broadcast, "decoded [128,0] is false per flags & 128 quirk");
    assert_eq!(rep.giaddr, Ipv4Addr::new(10, 0, 0, 254));
}

/// RFC 2131 §3.3: relay agents bump `hops` and set `giaddr`; server replies
/// with `hops` reset to 0 (this implementation) while echoing `giaddr`.
#[test]
fn rfc2131_relay_hops_reset_giaddr_echoed() {
    let req = Packet {
        reply: false, hops: 3, xid: 0x55, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::new(10, 1, 1, 254),
        chaddr: [4, 4, 4, 4, 4, 4],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let rep = reply_once(MessageType::Offer, vec![], Ipv4Addr::new(10, 1, 2, 7), req);
    assert_eq!(rep.hops, 0);
    assert_eq!(rep.giaddr, Ipv4Addr::new(10, 1, 2, 7).with_octets([10, 1, 1, 254]));
}

/// RFC 2131 §4.3: clients select among offers via Server Identifier (54);
/// `for_this_server` is true only for an exact identifier match.
#[test]
fn rfc2131_server_identifier_selection() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(192, 168, 1, 1);
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    struct H {
        tx: std::sync::mpsc::Sender<bool>,
    }
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = self.tx.send(s.for_this_server(&p));
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(192, 168, 1, 255), H { tx });
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    for (id, expect) in [
        (Ipv4Addr::new(192, 168, 1, 1), true),
        (Ipv4Addr::new(192, 168, 1, 2), false),
    ] {
        let p = client_packet(0x60, [6; 6], vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(id),
        ]);
        client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), expect);
    }
    // no identifier at all: not for this server
    let p = client_packet(0x61, [6; 6], vec![DhcpOption::DhcpMessageType(MessageType::Request)]);
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert!(!rx.recv_timeout(Duration::from_secs(2)).unwrap());
}

// ===========================================================================
// RFC 2131 §3.6 / RFC 2132 §9.8 — Parameter Request List negotiation
// ===========================================================================

/// RFC 2131 §3.6: the client lists desired options in PRL (55); the server
/// MUST include DHCP Message Type (53) + Server Identifier (54) regardless,
/// then the requested subset of its configured options.
#[test]
fn rfc2131_prl_negotiation_keeps_required_plus_requested() {
    // server configured with Subnet + Lease + Message; client asks only [1]
    let req = Packet {
        reply: false, hops: 0, xid: 0x70, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED, yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED, giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [8; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)),
            DhcpOption::ParameterRequestList(vec![SUBNET_MASK]),
        ],
    };
    let rep = reply_once(
        MessageType::Ack,
        vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::IpAddressLeaseTime(3600),
            DhcpOption::Message("not requested".to_string()),
        ],
        Ipv4Addr::new(192, 168, 1, 80),
        req,
    );
    let got: Vec<u8> = rep.options.iter().map(|o| o.code()).collect();
    assert_eq!(got, vec![1, 53, 54, 51], "PRL [1] + required 53/54 + remaining default 51");
    assert!(rep.option(MESSAGE).is_none(), "unrequested Message MUST be filtered");
}

/// RFC 2131 §3.6: with no PRL the server returns its full configured set.
#[test]
fn rfc2131_no_prl_returns_full_configured_set() {
    let req = client_packet(0x71, [9; 6], vec![DhcpOption::DhcpMessageType(
        MessageType::Discover,
    )]);
    let rep = reply_once(
        MessageType::Offer,
        vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::IpAddressLeaseTime(7200),
        ],
        Ipv4Addr::new(192, 168, 1, 81),
        req,
    );
    let got: Vec<u8> = rep.options.iter().map(|o| o.code()).collect();
    assert_eq!(got, vec![53, 54, 1, 51]);
}

// ---------------------------------------------------------------------------
// small helper trait to build the relay-echo assertion without typos
// ---------------------------------------------------------------------------

trait WithOctets {
    fn with_octets(self, o: [u8; 4]) -> Ipv4Addr;
}
impl WithOctets for Ipv4Addr {
    fn with_octets(self, o: [u8; 4]) -> Ipv4Addr {
        let _ = self;
        Ipv4Addr::from(o)
    }
}
