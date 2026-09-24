//! Extra server coverage: filter value preservation and non-default codes,
//! reply variants beyond Offer/Ack/Nak, duplicate auto-options, port routing,
//! sequential packets and the panic-packet server-kill quirk.

use dhcp4r::options::*;
use dhcp4r::packet::*;
use dhcp4r::server;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

fn unwrap_packet(r: Result<Packet, CustomErr<&[u8]>>) -> Packet {
    match r {
        Ok(p) => p,
        Err(_) => panic!("expected Ok"),
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
fn codes(o: &[DhcpOption]) -> Vec<u8> {
    o.iter().map(|x| x.code()).collect()
}
fn recv(sock: &UdpSocket, buf: &mut [u8]) -> (usize, std::net::SocketAddr) {
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.recv_from(buf).expect("timeout")
}

// ---------------------------------------------------------------------------
// filter: values and non-default requested codes
// ---------------------------------------------------------------------------

#[test]
fn filter_requesting_message_keeps_it_first() {
    let mut opts = vec![
        DhcpOption::Message("m".to_string()),
        DhcpOption::HostName("h".to_string()),
        DhcpOption::ParameterRequestList(vec![1]),
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
        DhcpOption::DhcpMessageType(MessageType::Offer),
    ];
    server::filter_options_by_req(&mut opts, &[56]);
    assert_eq!(codes(&opts), vec![56, 53, 1]);
    assert_eq!(opts[0], DhcpOption::Message("m".to_string()));
}

#[test]
fn filter_requesting_hostname_keeps_it_first() {
    let mut opts = vec![
        DhcpOption::Message("m".to_string()),
        DhcpOption::HostName("h".to_string()),
        DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
        DhcpOption::DhcpMessageType(MessageType::Offer),
    ];
    server::filter_options_by_req(&mut opts, &[12]);
    assert_eq!(codes(&opts), vec![12, 53, 1]);
}

#[test]
fn filter_full_default_set_orders_as_h() {
    let mut opts = vec![
        DhcpOption::Router(vec![Ipv4Addr::new(1, 1, 1, 1)]),
        DhcpOption::DomainNameServer(vec![Ipv4Addr::new(2, 2, 2, 2)]),
        DhcpOption::IpAddressLeaseTime(1),
        DhcpOption::SubnetMask(Ipv4Addr::new(3, 3, 3, 3)),
        DhcpOption::ServerIdentifier(Ipv4Addr::new(4, 4, 4, 4)),
        DhcpOption::DhcpMessageType(MessageType::Offer),
    ];
    server::filter_options_by_req(&mut opts, &[]);
    assert_eq!(codes(&opts), vec![53, 54, 1, 51, 6, 3]);
}

#[test]
fn filter_duplicate_subnet_keeps_second_value_quirk() {
    // Two Subnets: first is swapped away and truncated, second survives.
    let mut opts = vec![
        DhcpOption::SubnetMask(Ipv4Addr::new(1, 1, 1, 1)),
        DhcpOption::SubnetMask(Ipv4Addr::new(2, 2, 2, 2)),
        DhcpOption::DhcpMessageType(MessageType::Offer),
    ];
    server::filter_options_by_req(&mut opts, &[]);
    assert_eq!(codes(&opts), vec![53, 1]);
    assert_eq!(opts[1], DhcpOption::SubnetMask(Ipv4Addr::new(2, 2, 2, 2)));
}

#[test]
fn filter_preserves_values_not_just_codes() {
    let mut opts = vec![
        DhcpOption::SubnetMask(Ipv4Addr::new(10, 20, 30, 40)),
        DhcpOption::IpAddressLeaseTime(12345),
        DhcpOption::DhcpMessageType(MessageType::Ack),
        DhcpOption::ServerIdentifier(Ipv4Addr::new(9, 9, 9, 9)),
    ];
    server::filter_options_by_req(&mut opts, &[]);
    assert_eq!(
        opts,
        vec![
            DhcpOption::DhcpMessageType(MessageType::Ack),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(9, 9, 9, 9)),
            DhcpOption::SubnetMask(Ipv4Addr::new(10, 20, 30, 40)),
            DhcpOption::IpAddressLeaseTime(12345),
        ]
    );
}

// ---------------------------------------------------------------------------
// for_this_server: first ServerIdentifier wins
// ---------------------------------------------------------------------------

#[test]
fn for_this_server_uses_first_identifier_when_duplicated() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);
    let other = Ipv4Addr::new(10, 0, 0, 2);
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
        let _ = server::Server::serve(srv_sock, server_ip, Ipv4Addr::new(10, 0, 0, 255), H { tx });
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    // first matches -> true even though second differs. Note: two ServerIds
    // both survive encode (small packet) and decode preserves order.
    let p = test_packet(1, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Request),
        DhcpOption::ServerIdentifier(server_ip),
        DhcpOption::ServerIdentifier(other),
    ]);
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());

    // first differs -> false even though second matches.
    let p = test_packet(2, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Request),
        DhcpOption::ServerIdentifier(other),
        DhcpOption::ServerIdentifier(server_ip),
    ]);
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert!(!rx.recv_timeout(Duration::from_secs(2)).unwrap());
}

// ---------------------------------------------------------------------------
// reply: non-Offer/Ack/Nak types preserve ciaddr; Nak with non-zero offer
// ---------------------------------------------------------------------------

fn reply_once(
    msg: MessageType,
    additional: Vec<DhcpOption>,
    offer: Ipv4Addr,
    req_xid: u32,
    req_ci: Ipv4Addr,
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
        let _ = server::Server::serve(srv_sock, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 255), h);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = Packet {
        reply: false, hops: 0, xid: req_xid, secs: 0, broadcast: false,
        ciaddr: req_ci, yiaddr: Ipv4Addr::new(0, 0, 0, 0),
        siaddr: Ipv4Addr::new(0, 0, 0, 0), giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: [1, 1, 1, 1, 1, 1],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Request)],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv(&client, &mut rbuf);
    unwrap_packet(Packet::from(&rbuf[..n]))
}

#[test]
fn reply_non_nak_types_preserve_ciaddr() {
    for mt in [MessageType::Decline, MessageType::Release, MessageType::Inform, MessageType::Discover, MessageType::Request] {
        let rep = reply_once(mt, vec![], Ipv4Addr::new(1, 2, 3, 4), 0x100, Ipv4Addr::new(7, 7, 7, 7));
        assert_eq!(rep.message_type().unwrap(), mt);
        assert_eq!(rep.ciaddr, Ipv4Addr::new(7, 7, 7, 7), "ciaddr for {:?}", mt);
        assert_eq!(rep.yiaddr, Ipv4Addr::new(1, 2, 3, 4));
    }
}

#[test]
fn reply_nak_yiaddr_is_offer_ip_not_forced_zero() {
    let rep = reply_once(MessageType::Nak, vec![], Ipv4Addr::new(9, 9, 9, 9), 0x101, Ipv4Addr::new(7, 7, 7, 7));
    assert_eq!(rep.ciaddr, Ipv4Addr::new(0, 0, 0, 0));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(9, 9, 9, 9), "Nak only zeroes ciaddr");
}

#[test]
fn reply_ignores_incoming_siaddr_yiaddr_hops_secs() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = s.reply(MessageType::Offer, vec![], Ipv4Addr::new(5, 5, 5, 5), p);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = Packet {
        reply: false, hops: 9, xid: 0x102, secs: 99, broadcast: false,
        ciaddr: Ipv4Addr::new(1, 1, 1, 1), yiaddr: Ipv4Addr::new(2, 2, 2, 2),
        siaddr: Ipv4Addr::new(3, 3, 3, 3), giaddr: Ipv4Addr::new(4, 4, 4, 4),
        chaddr: [2, 2, 2, 2, 2, 2],
        options: vec![DhcpOption::DhcpMessageType(MessageType::Discover)],
    };
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    assert_eq!(rep.hops, 0);
    assert_eq!(rep.secs, 0);
    assert_eq!(rep.siaddr, Ipv4Addr::new(0, 0, 0, 0));
    assert_eq!(rep.yiaddr, Ipv4Addr::new(5, 5, 5, 5));
    assert_eq!(rep.giaddr, Ipv4Addr::new(4, 4, 4, 4));
}

#[test]
fn reply_with_duplicate_auto_options_keeps_both_when_no_prl() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = s.reply(
                MessageType::Offer,
                vec![
                    DhcpOption::DhcpMessageType(MessageType::Inform),
                    DhcpOption::SubnetMask(Ipv4Addr::new(1, 1, 1, 1)),
                ],
                Ipv4Addr::new(5, 5, 5, 5),
                p,
            );
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = test_packet(0x103, [3, 3, 3, 3, 3, 3], vec![
        DhcpOption::DhcpMessageType(MessageType::Discover),
    ]);
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (n, _) = recv(&client, &mut rbuf);
    let rep = unwrap_packet(Packet::from(&rbuf[..n]));
    // auto Offer + ServerId, then duplicate Inform + Subnet (no PRL => no filter)
    assert_eq!(codes(&rep.options), vec![53, 54, 53, 1]);
    assert_eq!(rep.message_type().unwrap(), MessageType::Offer, "first MsgType wins");
}

// ---------------------------------------------------------------------------
// send: port preserved; sequential packets; panic-packet kills server
// ---------------------------------------------------------------------------

#[test]
fn send_preserves_client_port() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    struct H;
    impl server::Handler for H {
        fn handle_request(&mut self, s: &server::Server, p: Packet) {
            let _ = s.reply(MessageType::Offer, vec![], Ipv4Addr::new(1, 1, 1, 1), p);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 1, 255), H);
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client_port = client.local_addr().unwrap().port();
    let mut buf = [0u8; 1500];
    let mut rbuf = [0u8; 1500];
    let req = test_packet(0x200, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Discover),
    ]);
    client.send_to(&req.encode(&mut buf).to_vec(), srv_addr).unwrap();
    let (_, src) = recv(&client, &mut rbuf);
    assert_eq!(src.ip(), srv_addr.ip());
    // reply destination was client port; implicit by receipt, but also check
    // server did not send to a different port by verifying we got it at all.
    assert_ne!(client_port, 0);
}

#[test]
fn serve_handles_sequential_valid_packets() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<u32>();
    struct H {
        tx: std::sync::mpsc::Sender<u32>,
    }
    impl server::Handler for H {
        fn handle_request(&mut self, _s: &server::Server, p: Packet) {
            let _ = self.tx.send(p.xid);
        }
    }
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 1, 255), H { tx });
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    for xid in [0xA1u32, 0xA2, 0xA3] {
        let p = test_packet(xid, [1, 2, 3, 4, 5, 6], vec![
            DhcpOption::DhcpMessageType(MessageType::Discover),
        ]);
        client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), xid);
    }
}

#[test]
fn serve_panic_packet_kills_server_thread_quirk() {
    // END-first (and missing-END exact) cause Packet::from to PANIC, not Err.
    // serve uses `if let Ok`, so the panic unwinds and kills the server loop
    // (DoS quirk locked). Subsequent valid packets are never handled.
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<u32>();
    struct H {
        tx: std::sync::mpsc::Sender<u32>,
    }
    impl server::Handler for H {
        fn handle_request(&mut self, _s: &server::Server, p: Packet) {
            let _ = self.tx.send(p.xid);
        }
    }
    let handle = std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 1, 255), H { tx });
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; 1500];
    let p = test_packet(0xAAAA, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Discover),
    ]);
    client.send_to(&p.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 0xAAAA);

    // panic packet: valid header + cookie + END first
    let mut panic_raw = vec![0u8; 236];
    panic_raw[0] = 1;
    panic_raw[1] = 1;
    panic_raw[2] = 6;
    panic_raw.extend_from_slice(&[99, 130, 83, 99, 255, 0, 0]);
    client.send_to(&panic_raw, srv_addr).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(handle.is_finished(), "server thread must have panicked");

    // server dead: further valid packet gets no handler call (sender disconnected)
    let p2 = test_packet(0xBBBB, [1, 2, 3, 4, 5, 6], vec![
        DhcpOption::DhcpMessageType(MessageType::Discover),
    ]);
    client.send_to(&p2.encode(&mut buf).to_vec(), srv_addr).unwrap();
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "dead server must not handle packets"
    );
}

#[test]
fn serve_missing_end_exact_packet_also_panics_quirk() {
    let srv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv_sock.local_addr().unwrap();
    let (tx, _rx) = std::sync::mpsc::channel::<u32>();
    struct H {
        tx: std::sync::mpsc::Sender<u32>,
    }
    impl server::Handler for H {
        fn handle_request(&mut self, _s: &server::Server, p: Packet) {
            let _ = self.tx.send(p.xid);
        }
    }
    let handle = std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 1, 255), H { tx });
    });
    std::thread::sleep(Duration::from_millis(100));
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    // one valid option, no END, exact consumption -> split_at panic
    let mut raw = vec![0u8; 236];
    raw[0] = 1;
    raw[1] = 1;
    raw[2] = 6;
    raw.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1]);
    client.send_to(&raw, srv_addr).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(handle.is_finished(), "missing-END exact packet must panic server");
}
