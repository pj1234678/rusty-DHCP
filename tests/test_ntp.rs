//! Tests for NTP server advertisement (DHCP option 42).
//!
//! There is no typed NTP variant in `DhcpOption` by design, so the example
//! server builds option 42 as an `Unrecognized` option with the same N*4-byte
//! layout as DNS servers. These tests lock that wire shape, the
//! `enable_ntp` + `ntp_ips` config rule (mirroring `examples/server.rs`), and
//! the interplay with PRL filtering and the 300-byte wire cap.
//!
//! Conventions: option 42 is never in the filter defaults
//! `[53,54,1,51,6,3]`, so with a PRL present it survives only when requested.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

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

fn codes(opts: &[DhcpOption]) -> Vec<u8> {
    opts.iter().map(|o| o.code()).collect()
}

fn recv_with_timeout(sock: &UdpSocket, buf: &mut [u8]) -> (usize, std::net::SocketAddr) {
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.recv_from(buf).expect("timed out waiting for reply")
}

/// Mirrors the example `MyServer::offer_options` NTP rule: option 42 is
/// built only when enabled AND the list is non-empty, concatenated N*4.
fn ntp_option(enable_ntp: bool, ntp_ips: &[Ipv4Addr]) -> Option<DhcpOption> {
    if enable_ntp && !ntp_ips.is_empty() {
        let mut data = Vec::with_capacity(ntp_ips.len() * 4);
        for ip in ntp_ips {
            data.extend_from_slice(&ip.octets());
        }
        Some(DhcpOption::Unrecognized(RawDhcpOption {
            code: NETWORK_TIME_PROTOCOL_SERVERS,
            data,
        }))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// wire shape (unit)
// ---------------------------------------------------------------------------

#[test]
fn ntp_wire_format_is_code_42_len_4n() {
    assert_eq!(NETWORK_TIME_PROTOCOL_SERVERS, 42);
    let one = DhcpOption::Unrecognized(RawDhcpOption {
        code: 42,
        data: vec![192, 168, 2, 1],
    })
    .to_raw();
    assert_eq!(one.code, 42);
    assert_eq!(one.data, vec![192, 168, 2, 1]);
    // round-trips through decode intact (like any Unrecognized option)
    let p = test_packet(
        1,
        [0; 6],
        vec![
            DhcpOption::DhcpMessageType(MessageType::Ack),
            DhcpOption::Unrecognized(RawDhcpOption {
                code: 42,
                data: vec![10, 0, 0, 1, 10, 0, 0, 2],
            }),
        ],
    );
    let mut buf = [0u8; 1500];
    let q = unwrap_packet(Packet::from(&p.encode(&mut buf).to_vec()));
    assert_eq!(
        q.option(42),
        Some(&DhcpOption::Unrecognized(RawDhcpOption {
            code: 42,
            data: vec![10, 0, 0, 1, 10, 0, 0, 2],
        }))
    );
}

#[test]
fn ntp_decodes_as_unrecognized_not_typed() {
    // No typed variant exists: decode must fall through to Unrecognized,
    // which keeps the branch-matrix test's typed set unchanged.
    match decode_option(&[42, 4, 192, 168, 2, 1]) {
        Ok((_, DhcpOption::Unrecognized(r))) => {
            assert_eq!(r.code, 42);
            assert_eq!(r.data, vec![192, 168, 2, 1]);
        }
        _ => panic!("option 42 must decode as Unrecognized"),
    }
}

#[test]
fn ntp_multi_server_concatenation_order() {
    let ips = vec![
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 3),
    ];
    let opt = ntp_option(true, &ips).unwrap();
    let raw = opt.to_raw();
    assert_eq!(raw.code, 42);
    assert_eq!(raw.data.len(), 12);
    assert_eq!(&raw.data[0..4], &[10, 0, 0, 1]);
    assert_eq!(&raw.data[4..8], &[10, 0, 0, 2]);
    assert_eq!(&raw.data[8..12], &[10, 0, 0, 3]);
}

#[test]
fn ntp_rule_disabled_or_empty_yields_nothing() {
    assert!(ntp_option(false, &[Ipv4Addr::new(192, 168, 2, 1)]).is_none());
    assert!(ntp_option(true, &[]).is_none());
    assert!(ntp_option(false, &[]).is_none());
}

#[test]
fn ntp_rule_enabled_yields_concatenated() {
    let opt = ntp_option(true, &[Ipv4Addr::new(192, 168, 2, 1)]).unwrap();
    assert_eq!(opt.code(), 42);
    assert_eq!(
        opt.to_raw().data,
        vec![192, 168, 2, 1],
        "single server, 4 bytes"
    );
}

// ---------------------------------------------------------------------------
// reply behavior (live Server::reply over loopback, as in test_server.rs)
// ---------------------------------------------------------------------------

#[test]
fn ntp_offered_without_prl_live() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            let _ = s.reply(
                MessageType::Offer,
                vec![
                    DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                    DhcpOption::IpAddressLeaseTime(3600),
                    DhcpOption::Unrecognized(RawDhcpOption {
                        code: NETWORK_TIME_PROTOCOL_SERVERS,
                        data: vec![192, 168, 2, 1],
                    }),
                ],
                Ipv4Addr::new(10, 0, 0, 50),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(10, 0, 0, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // no PRL: everything kept in order after auto [53,54]
    let req = test_packet(
        0xA001,
        [1; 6],
        vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    );
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type(), Ok(MessageType::Offer));
    assert_eq!(codes(&rep.options), vec![53, 54, 1, 51, 42]);
    assert_eq!(
        rep.option(42),
        Some(&DhcpOption::Unrecognized(RawDhcpOption {
            code: 42,
            data: vec![192, 168, 2, 1],
        }))
    );
}

#[test]
fn ntp_filtered_without_prl_request_live() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            let _ = s.reply(
                MessageType::Ack,
                vec![
                    DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                    DhcpOption::Unrecognized(RawDhcpOption {
                        code: NETWORK_TIME_PROTOCOL_SERVERS,
                        data: vec![192, 168, 2, 1],
                    }),
                ],
                Ipv4Addr::new(10, 0, 0, 50),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(10, 0, 0, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // PRL asks only for Subnet(1): 42 is neither requested nor default.
    let req = Packet {
        reply: false, hops: 0, xid: 0xA002, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [2; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::ParameterRequestList(vec![1]),
        ],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(codes(&rep.options), vec![1, 53, 54]);
    assert!(rep.option(42).is_none(), "unrequested NTP must be filtered");
}

#[test]
fn ntp_kept_when_prl_requests_it_live() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            let _ = s.reply(
                MessageType::Ack,
                vec![
                    DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                    DhcpOption::Unrecognized(RawDhcpOption {
                        code: NETWORK_TIME_PROTOCOL_SERVERS,
                        data: vec![192, 168, 2, 1],
                    }),
                ],
                Ipv4Addr::new(10, 0, 0, 50),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(10, 0, 0, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    // PRL asks for 42 first: requested order, then defaults.
    let req = Packet {
        reply: false, hops: 0, xid: 0xA003, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [3; 6],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::ParameterRequestList(vec![42]),
        ],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(codes(&rep.options), vec![42, 53, 54, 1]);
    assert_eq!(
        rep.option(42),
        Some(&DhcpOption::Unrecognized(RawDhcpOption {
            code: 42,
            data: vec![192, 168, 2, 1],
        }))
    );
}

#[test]
fn ntp_two_servers_live() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            let _ = s.reply(
                MessageType::Offer,
                vec![DhcpOption::Unrecognized(RawDhcpOption {
                    code: NETWORK_TIME_PROTOCOL_SERVERS,
                    data: vec![10, 0, 0, 1, 10, 0, 0, 2],
                })],
                Ipv4Addr::new(10, 0, 0, 50),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(10, 0, 0, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = test_packet(
        0xA004,
        [4; 6],
        vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    );
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(codes(&rep.options), vec![53, 54, 42]);
    match rep.option(42) {
        Some(DhcpOption::Unrecognized(r)) => {
            assert_eq!(r.code, 42);
            assert_eq!(r.data, vec![10, 0, 0, 1, 10, 0, 0, 2]);
        }
        _ => panic!("two-server NTP list must survive"),
    }
}

#[test]
fn ntp_full_example_set_live() {
    // Mirrors the example reply order [lease, subnet, router, dns] + NTP:
    // 240+3+6 (auto) +6+6+6+6 (lease/subnet/router/dns) +8 (NTP) = 287,
    // which fits the 300-byte wire cap, so every TLV reaches the wire.
    // Decoded, Router still poisons the option loop (decoder quirk), leaving
    // [53,54,51,1] — the wire bytes are identical to before for that prefix.
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            let _ = s.reply(
                MessageType::Offer,
                vec![
                    DhcpOption::IpAddressLeaseTime(86400),
                    DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                    DhcpOption::Router(vec![Ipv4Addr::new(10, 0, 0, 1)]),
                    DhcpOption::DomainNameServer(vec![Ipv4Addr::new(8, 8, 8, 8)]),
                    DhcpOption::Unrecognized(RawDhcpOption {
                        code: NETWORK_TIME_PROTOCOL_SERVERS,
                        data: vec![10, 0, 0, 2],
                    }),
                ],
                Ipv4Addr::new(10, 0, 0, 50),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(10, 0, 0, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = test_packet(
        0xA005,
        [5; 6],
        vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    );
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    // every TLV fits the 300-byte cap now: router, DNS and NTP on the wire.
    assert!(
        rbuf[..n].windows(6).any(|w| w == [3, 4, 10, 0, 0, 1]),
        "router TLV on the wire"
    );
    assert!(
        rbuf[..n].windows(6).any(|w| w == [6, 4, 8, 8, 8, 8]),
        "DNS reaches the wire under the 300 cap"
    );
    assert!(
        rbuf[..n].windows(6).any(|w| w == [42, 4, 10, 0, 0, 2]),
        "NTP reaches the wire under the 300 cap"
    );
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(codes(&rep.options), vec![53, 54, 51, 1]);
    assert!(rep.option(42).is_none());
}
