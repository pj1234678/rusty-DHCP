//! Exact-functionality regression tests for `dhcp4r::server`.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::mpsc;
use std::time::Duration;

fn unwrap_packet(r: Result<Packet, CustomErr<&[u8]>>) -> Packet {
    match r {
        Ok(p) => p,
        Err(_) => panic!("expected Ok Packet"),
    }
}

fn test_packet(xid: u32, chaddr: [u8; 6], opts: Vec<DhcpOption>) -> Packet {
    Packet {
        reply: false, hops: 0, xid, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr, options: opts,
    }
}

fn codes(opts: &[DhcpOption]) -> Vec<u8> {
    opts.iter().map(|o| o.code()).collect()
}

// ---------------------------------------------------------------------------
// filter_options_by_req: pure function, exact ordering/truncation locked
// ---------------------------------------------------------------------------

#[test]
fn filter_empty_opts_stays_empty() {
    let mut opts: Vec<DhcpOption> = vec![];
    server::filter_options_by_req(&mut opts, &[1, 3, 6]);
    assert!(opts.is_empty());
    let mut opts: Vec<DhcpOption> = vec![];
    server::filter_options_by_req(&mut opts, &[]);
    assert!(opts.is_empty());
}

#[test]
fn filter_no_req_keeps_only_default_set_in_default_order() {
    // h = [53,54,1,51,6,3]
    let mut opts = vec![
        DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]), // 3
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)), // 1
        DhcpOption::Message("hi".to_string()),                   // 56 not in h
        DhcpOption::DhcpMessageType(MessageType::Offer),         // 53
    ];
    server::filter_options_by_req(&mut opts, &[]);
    // 56 dropped; rest ordered by h: 53,1,3 (54,51,6 absent)
    assert_eq!(codes(&opts), vec![53, 1, 3]);
}

#[test]
fn filter_req_order_comes_first_then_defaults() {
    let mut opts = vec![
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)), // 1
        DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]), // 3
        DhcpOption::DomainNameServer(vec![Ipv4Addr::new(8, 8, 8, 8)]), // 6
        DhcpOption::IpAddressLeaseTime(86400),                   // 51
        DhcpOption::DhcpMessageType(MessageType::Offer),         // 53
        DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)), // 54
    ];
    server::filter_options_by_req(&mut opts, &[6, 1]);
    // req [6,1] first, then remaining h in h-order [53,54,51,3]
    assert_eq!(codes(&opts), vec![6, 1, 53, 54, 51, 3]);
}

#[test]
fn filter_drops_options_not_in_req_or_defaults() {
    let mut opts = vec![
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
        DhcpOption::Message("extra".to_string()), // 56 never kept
        DhcpOption::HostName("h".to_string()),    // 12 never kept
        DhcpOption::ParameterRequestList(vec![1]), // 55 never kept (not in h)
    ];
    server::filter_options_by_req(&mut opts, &[]);
    assert_eq!(codes(&opts), vec![1]);

    let mut opts = vec![DhcpOption::Message("hi".to_string())];
    server::filter_options_by_req(&mut opts, &[1]);
    assert!(opts.is_empty(), "nothing matched -> truncated to 0");
}

#[test]
fn filter_unknown_req_codes_ignored() {
    let mut opts = vec![
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
        DhcpOption::DhcpMessageType(MessageType::Offer),
    ];
    server::filter_options_by_req(&mut opts, &[200, 201]);
    // unknown req adds nothing; defaults still apply: [53,1]
    // (order: req finds nothing, h finds 53 then 1)
    assert_eq!(codes(&opts), vec![53, 1]);
}

#[test]
fn filter_duplicate_req_does_not_duplicate() {
    let mut opts = vec![
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
        DhcpOption::DhcpMessageType(MessageType::Offer),
    ];
    server::filter_options_by_req(&mut opts, &[1, 1, 53, 53]);
    assert_eq!(codes(&opts), vec![1, 53]);
    assert_eq!(opts.len(), 2);
}

#[test]
fn filter_does_not_invent_missing_options() {
    let mut opts = vec![DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))];
    server::filter_options_by_req(&mut opts, &[1, 3, 6, 53, 54, 51]);
    // only 1 present
    assert_eq!(codes(&opts), vec![1]);
}

// ---------------------------------------------------------------------------
// integration helpers: real UDP loopback, Server via serve thread
// ---------------------------------------------------------------------------

fn recv_with_timeout(sock: &UdpSocket, buf: &mut [u8]) -> (usize, std::net::SocketAddr) {
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.recv_from(buf).expect("timed out waiting for reply")
}

#[test]
fn for_this_server_true_only_on_matching_id() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(10, 20, 30, 40);
    let (tx, rx) = mpsc::channel::<Vec<bool>>();

    struct H {
        tx: mpsc::Sender<Vec<bool>>,
    }
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            // For xid 4 we also check a manually-built packet holding
            // Unrecognized(54): wire code 54 ALWAYS decodes as ServerIdentifier,
            // so only a manual (non-decoded) Unrecognized hits the `_ => false` branch.
            if p.xid == 4 {
                let wire = s.for_this_server(&p);
                let manual = Packet {
                    reply: false, hops: 0, xid: 4, secs: 0, broadcast: false,
                    ciaddr: Ipv4Addr::new(0, 0, 0, 0),
                    yiaddr: Ipv4Addr::new(0, 0, 0, 0),
                    siaddr: Ipv4Addr::new(0, 0, 0, 0),
                    giaddr: Ipv4Addr::new(0, 0, 0, 0),
                    chaddr: [0; 6],
                    options: vec![DhcpOption::Unrecognized(RawDhcpOption {
                        code: 54,
                        data: Ipv4Addr::new(10, 20, 30, 40).octets().to_vec(),
                    })],
                };
                let manual_res = s.for_this_server(&manual);
                let _ = self.tx.send(vec![wire, manual_res]);
            } else {
                let _ = self.tx.send(vec![s.for_this_server(&p)]);
            }
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(10, 20, 30, 255), H { tx });
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];

    // matching
    let p = test_packet(1, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Request),
        DhcpOption::ServerIdentifier(server_ip),
    ]);
    let enc = p.encode(&mut buf).to_vec();
    client.send_to(&enc, srv_addr).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), vec![true]);

    // different IP
    let p = test_packet(2, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Request),
        DhcpOption::ServerIdentifier(Ipv4Addr::new(1, 1, 1, 1)),
    ]);
    let enc = p.encode(&mut buf).to_vec();
    client.send_to(&enc, srv_addr).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), vec![false]);

    // missing option
    let p = test_packet(3, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Request),
    ]);
    let enc = p.encode(&mut buf).to_vec();
    client.send_to(&enc, srv_addr).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), vec![false]);

    // Unrecognized with code 54 on the WIRE decodes as ServerIdentifier,
    // so for_this_server is true (quirk locked). A manual Unrecognized(54)
    // that never went through decode hits `_ => false`.
    let p = test_packet(4, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Request),
        DhcpOption::Unrecognized(RawDhcpOption { code: 54, data: server_ip.octets().to_vec() }),
    ]);
    let enc = p.encode(&mut buf).to_vec();
    client.send_to(&enc, srv_addr).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), vec![true, false]);
}

#[test]
fn reply_preserves_xid_chaddr_giaddr_and_sets_fixed_fields() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(192, 168, 2, 1);

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            // use only decodable options so client can verify all survive
            let _ = s.reply(
                MessageType::Offer,
                vec![
                    DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                    DhcpOption::IpAddressLeaseTime(86400),
                ],
                Ipv4Addr::new(192, 168, 2, 100),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(192, 168, 2, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];

    let req = Packet {
        reply: false, hops: 5, xid: 0xAABBCCDD, secs: 77, broadcast: false,
        ciaddr: Ipv4Addr::new(192, 168, 2, 50), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(192, 168, 2, 254),
        chaddr: [9, 8, 7, 6, 5, 4],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    let enc = req.encode(&mut buf).to_vec();
    client.send_to(&enc, srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));

    assert!(rep.reply, "reply flag must be true");
    assert_eq!(rep.hops, 0, "reply hops forced to 0");
    assert_eq!(rep.xid, 0xAABBCCDD, "xid echoed");
    assert_eq!(rep.secs, 0, "reply secs forced to 0");
    assert_eq!(rep.chaddr, [9, 8, 7, 6, 5, 4]);
    assert_eq!(rep.giaddr, Ipv4Addr::new(192, 168, 2, 254), "giaddr echoed");
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 2, 100));
    assert_eq!(rep.siaddr, Ipv4Addr::new(0, 0, 0, 0), "siaddr forced to 0.0.0.0");
    assert_eq!(rep.ciaddr, Ipv4Addr::new(192, 168, 2, 50), "ciaddr echoed for non-Nak");
    assert_eq!(rep.message_type().unwrap(), MessageType::Offer);
    // auto-added MsgType + ServerId first, then additional in order
    assert_eq!(codes(&rep.options), vec![53, 54, 1, 51]);
    assert_eq!(rep.options[1], DhcpOption::ServerIdentifier(server_ip));
}

#[test]
fn reply_nak_zeroes_ciaddr_and_yiaddr_is_offer_ip() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            let _ = s.reply(
                MessageType::Nak,
                vec![DhcpOption::Message("no".to_string())],
                Ipv4Addr::new(0, 0, 0, 0),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 255),
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = Packet {
        reply: false, hops: 0, xid: 0x2222, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(10, 0, 0, 99), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [1, 1, 1, 1, 1, 1],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.message_type().unwrap(), MessageType::Nak);
    assert_eq!(rep.ciaddr, Ipv4Addr::new(0, 0, 0, 0), "Nak forces ciaddr 0");
    assert_eq!(rep.yiaddr, Ipv4Addr::new(0, 0, 0, 0));
}

#[test]
fn reply_filters_by_prl_shows_exact_order() {
    // PRL [6,1] with additional [Subnet, Lease] plus auto [Msg,Server]:
    // filter keeps req order then h-order. Raw bytes must show
    // DNS? No DNS in additional here, so result is [1,53,54,51] filtered?
    // Use additional with Subnet+Lease+Message: req [1] -> [1,53,54,51], Message dropped.
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
                    DhcpOption::IpAddressLeaseTime(3600),
                    DhcpOption::Message("should be dropped when PRL present".to_string()),
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

    // Request asks only for Subnet(1). Message(56) not in req nor h -> dropped.
    let req = Packet {
        reply: false, hops: 0, xid: 0x9999, secs: 0, broadcast: false,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0), yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [5, 5, 5, 5, 5, 5],
        options: vec![
            DhcpOption::DhcpMessageType(MessageType::Request),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::ParameterRequestList(vec![1]),
        ],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    // req [1] first, then h remainder [53,54,51] (6,3 absent). Message dropped.
    assert_eq!(codes(&rep.options), vec![1, 53, 54, 51]);
}

#[test]
fn reply_without_prl_keeps_all_additional_in_order() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            // NOTE: Message must be short to fit the packet.
            // 240 + 3(Msg) + 6(Server) + 6(Subnet) + (2+len) + 1(END) < 300
            // => len < 43. "hi" fits; longer strings trigger truncation.
            let _ = s.reply(
                MessageType::Ack,
                vec![
                    DhcpOption::SubnetMask(Ipv4Addr::new(255, 0, 0, 0)),
                    DhcpOption::Message("hi".to_string()),
                ],
                Ipv4Addr::new(10, 0, 0, 60),
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
    let req = test_packet(0x7777, [6, 6, 6, 6, 6, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Request),
    ]);
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(codes(&rep.options), vec![53, 54, 1, 56]);
}

#[test]
fn send_unicast_goes_to_request_source() {
    // broadcast=false + real src IP -> reply sent to src (client receives).
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            let _ = s.reply(
                MessageType::Offer,
                vec![DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))],
                Ipv4Addr::new(192, 168, 1, 10),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 255),
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = test_packet(0x5555, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Discover),
    ]);
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, src) = recv_with_timeout(&client, &mut rbuf);
    assert!(n > 240);
    // src must be the server socket (reply came from server)
    assert_eq!(src.ip(), srv_addr.ip());
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 1, 10));
}

#[test]
fn send_broadcast_flag_routes_to_broadcast_ip() {
    // To set broadcast=true on the server side, the REQUEST must decode
    // with broadcast=true, which requires low-byte 0x80 ([0,128]) due to
    // the `flags & 128` quirk. [128,0] (correct RFC 0x8000) decodes false.
    // Server is configured with broadcast_ip=127.0.0.1 so the reply still
    // reaches this test client (same port, loopback IP).
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            assert!(in_packet.broadcast, "test precondition: req must decode broadcast=true");
            let _ = s.reply(
                MessageType::Offer,
                vec![DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))],
                Ipv4Addr::new(192, 168, 1, 11),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(127, 0, 0, 1), // loopback so test can receive
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut rbuf = [0u8; 1500];

    // hand-crafted raw with flags [0,128] -> decodes broadcast=true
    let mut raw = vec![0u8; 236];
    raw[0] = 1; raw[1] = 1; raw[2] = 6; raw[3] = 0;
    raw[4..8].copy_from_slice(&0xBEEFu32.to_be_bytes());
    raw[10] = 0; raw[11] = 128;
    raw[28..34].copy_from_slice(&[7, 7, 7, 7, 7, 7]);
    raw.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1, 255]);
    client.send_to(&raw, srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 1, 11));
}

#[test]
fn serve_ignores_malformed_and_handles_valid() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<u32>();

    struct H {
        tx: mpsc::Sender<u32>,
    }
    impl server::Handler for H {
        fn handle_request(&mut self, _s: &server::Server, p: Packet) {
            let _ = self.tx.send(p.xid);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(
            srv_sock,
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 255),
            H { tx },
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];

    // malformed: bad cookie -> must be ignored (no handler call)
    let mut bad = vec![0u8; 236];
    bad[0] = 1; bad[1] = 1; bad[2] = 6;
    bad.extend_from_slice(&[0, 0, 0, 0, 53, 1, 1, 255]);
    client.send_to(&bad, srv_addr).unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "bad packet must be ignored");

    // truncated header -> ignored
    client.send_to(&[1u8; 10], srv_addr).unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "short packet must be ignored");

    // valid -> handled
    let p = test_packet(0xABCD, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Discover),
    ]);
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 0xABCD);
}

#[test]
fn serve_with_broadcasts_fans_out_to_each_address() {
    // Broadcast-routed replies go to EVERY listed address (unicast still
    // goes once to the peer). Two loopback clients on 127.0.0.1 and
    // 127.0.0.2 must each receive the same Offer.
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            assert!(in_packet.broadcast, "test precondition: req must decode broadcast=true");
            let _ = s.reply(
                MessageType::Offer,
                vec![DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))],
                Ipv4Addr::new(192, 168, 1, 12),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve_with_broadcasts(
            srv_sock,
            Ipv4Addr::new(192, 168, 1, 1),
            vec![Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2)],
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client_a = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Same port number on the second loopback IP: the server fans out to
    // <each-broadcast-ip>:<sender-port>, so B must listen on A's port.
    let port_a = client_a.local_addr().unwrap().port();
    let client_b = UdpSocket::bind(("127.0.0.2", port_a)).unwrap();
    let mut rbuf = [0u8; 1500];

    // hand-crafted raw with flags [0,128] -> decodes broadcast=true
    let mut raw = vec![0u8; 236];
    raw[0] = 1; raw[1] = 1; raw[2] = 6; raw[3] = 0;
    raw[4..8].copy_from_slice(&0xF00Du32.to_be_bytes());
    raw[10] = 0; raw[11] = 128;
    raw[28..34].copy_from_slice(&[8, 8, 8, 8, 8, 8]);
    raw.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1, 255]);
    client_a.send_to(&raw, srv_addr).unwrap();

    let (n_a, _) = recv_with_timeout(&client_a, &mut rbuf);
    let rep_a = unwrap_packet(Packet::from(&rbuf[..n_a]));
    assert_eq!(rep_a.yiaddr, Ipv4Addr::new(192, 168, 1, 12));
    let (n_b, _) = recv_with_timeout(&client_b, &mut rbuf);
    let rep_b = unwrap_packet(Packet::from(&rbuf[..n_b]));
    assert_eq!(rep_b.yiaddr, Ipv4Addr::new(192, 168, 1, 12));
    assert_eq!(rep_a.xid, rep_b.xid, "both copies are the same reply");
}

#[test]
fn serve_with_broadcasts_empty_list_falls_back_without_panic() {
    // Empty list falls back to the limited broadcast address and must not
    // panic; the server must stay alive for later unicast requests. (No
    // delivery assertion: limited broadcast is not loopback-reliable, and
    // the test socket lacks SO_BROADCAST so the send itself errors out.)
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();

    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, in_packet: Packet) {
            let _ = s.reply(
                MessageType::Offer,
                vec![],
                Ipv4Addr::new(192, 168, 1, 13),
                in_packet,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve_with_broadcasts(
            srv_sock,
            Ipv4Addr::new(192, 168, 1, 1),
            vec![],
            H,
        );
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];

    // broadcast-flagged Discover: routed to 255.255.255.255, must not panic.
    let mut raw = vec![0u8; 236];
    raw[0] = 1; raw[1] = 1; raw[2] = 6; raw[3] = 0;
    raw[4..8].copy_from_slice(&0xBEEFu32.to_be_bytes());
    raw[10] = 0; raw[11] = 128;
    raw[28..34].copy_from_slice(&[9, 9, 9, 9, 9, 9]);
    raw.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1, 255]);
    client.send_to(&raw, srv_addr).unwrap();
    let _ = client.recv_from(&mut rbuf); // delivered or not; must not hang the server

    // server still alive: plain unicast Discover gets its Offer.
    let req = test_packet(0x7777, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Discover),
    ]);
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv_with_timeout(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(192, 168, 1, 13));
}

// ---------------------------------------------------------------------------
// route_dests: RFC 2131 s4.1 delivery plan (pure, no sockets)
// ---------------------------------------------------------------------------

fn peer(ip: Ipv4Addr) -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 68)
}

#[test]
fn route_sourced_peer_unicasts_once() {
    // Renewing client with a real source address: unicast back, even with
    // yiaddr set and broadcasts configured (no fan-out, no unicast copy).
    let dsts = server::Server::route_dests(
        peer(Ipv4Addr::new(192, 168, 2, 50)),
        false,
        Ipv4Addr::new(192, 168, 2, 50),
        &[Ipv4Addr::new(192, 168, 2, 255), Ipv4Addr::BROADCAST],
    );
    assert_eq!(dsts, vec![peer(Ipv4Addr::new(192, 168, 2, 50))]);
}

#[test]
fn route_broadcast_flag_fans_out_without_unicast_copy() {
    // Flag set means broadcast-only, even with a usable yiaddr: the client
    // announced it cannot take unicast.
    let dsts = server::Server::route_dests(
        peer(Ipv4Addr::UNSPECIFIED),
        true,
        Ipv4Addr::new(192, 168, 2, 3),
        &[Ipv4Addr::new(192, 168, 2, 255), Ipv4Addr::BROADCAST],
    );
    assert_eq!(
        dsts,
        vec![
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 2, 255)),
                68
            ),
            std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), 68),
        ]
    );
}

#[test]
fn route_unspecified_no_flag_adds_unicast_yiaddr_copy() {
    // The dnsmasq case: flag clear, source 0.0.0.0, offered address present.
    // Broadcast copies go out AND a unicast copy to yiaddr:port.
    let dsts = server::Server::route_dests(
        peer(Ipv4Addr::UNSPECIFIED),
        false,
        Ipv4Addr::new(192, 168, 2, 71),
        &[Ipv4Addr::new(192, 168, 2, 255), Ipv4Addr::BROADCAST],
    );
    assert_eq!(
        dsts,
        vec![
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 2, 255)),
                68
            ),
            std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), 68),
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 2, 71)),
                68
            ),
        ]
    );
}

#[test]
fn route_nak_has_no_unicast_target() {
    // yiaddr 0.0.0.0 (NAK): broadcast fan-out only, no 0.0.0.0 copy.
    let dsts = server::Server::route_dests(
        peer(Ipv4Addr::UNSPECIFIED),
        false,
        Ipv4Addr::UNSPECIFIED,
        &[Ipv4Addr::new(192, 168, 2, 255)],
    );
    assert_eq!(
        dsts,
        vec![std::net::SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 2, 255)),
            68
        )]
    );
}
