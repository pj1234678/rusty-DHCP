//! Zero-dependency throughput benchmarks (std only, no criterion).
//!
//! Run: `cargo run --release --example bench`
//! Reports req/s (higher is better) for decode/encode/filter/pools + UDP loopback.
//! Old-vs-new: record numbers before optimization, re-run after; same machine,
//! same build flags, median of 3 runs.

use dhcp4r::{dhcpv6, options, packet, server};
use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::{Duration, Instant};

fn bench_fn(name: &str, iters: u64, mut f: impl FnMut()) -> f64 {
    // warmup (not timed)
    for _ in 0..5_000 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let el = t.elapsed();
    let rps = iters as f64 / el.as_secs_f64();
    println!(
        "{:<28} {:>12.0} req/s  ({:.1} ns/req)",
        name,
        rps,
        el.as_nanos() as f64 / iters as f64
    );
    rps
}

fn discover_packet() -> packet::Packet {
    packet::Packet {
        reply: false,
        hops: 0,
        xid: 0x1234_5678,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [1, 2, 3, 4, 5, 6],
        options: vec![
            options::DhcpOption::DhcpMessageType(options::MessageType::Discover),
            options::DhcpOption::ParameterRequestList(vec![1, 3, 6, 15]),
            options::DhcpOption::HostName("bench-host".to_string()),
        ],
    }
}

fn request_packet() -> packet::Packet {
    packet::Packet {
        reply: false,
        hops: 0,
        xid: 0x9abc_def0,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        options: vec![
            options::DhcpOption::DhcpMessageType(options::MessageType::Request),
            options::DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 2, 10)),
            options::DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 2, 1)),
            options::DhcpOption::ParameterRequestList(vec![1, 3, 6, 51]),
            options::DhcpOption::HostName("bench-request-host".to_string()),
            options::DhcpOption::IpAddressLeaseTime(3600),
        ],
    }
}

fn offer_options() -> Vec<options::DhcpOption> {
    vec![
        options::DhcpOption::IpAddressLeaseTime(86400),
        options::DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
        options::DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 2, 1)]),
        options::DhcpOption::DomainNameServer(vec![
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(8, 8, 4, 4),
        ]),
    ]
}

/// reply assembly without sockets: mirrors Server::reply's Vec build
/// (auto [Msg,SrvId] + extend + conditional PRL filter). Isolates the
/// ~80-150ns assembly cost from the ~15µs UDP number.
fn reply_assembly(offer: &[options::DhcpOption], prl: Option<&[u8]>) -> Vec<options::DhcpOption> {
    let mut opts = Vec::with_capacity(offer.len() + 2);
    opts.push(options::DhcpOption::DhcpMessageType(
        options::MessageType::Offer,
    ));
    opts.push(options::DhcpOption::ServerIdentifier(
        Ipv4Addr::new(192, 168, 2, 1),
    ));
    opts.extend(offer.iter().cloned());
    if let Some(p) = prl {
        server::filter_options_by_req(&mut opts, p);
    }
    opts
}

fn bench_udp_roundtrip() -> f64 {
    // Minimal Offer handler over real loopback UDP, exercising
    // Server::reply -> filter_options_by_req -> Packet::encode -> send_to.
    // Offer options are cached once (like the real server) so the bench
    // measures reply/filter/encode/send, not option rebuilds.
    struct BenchHandler {
        server_ip: Ipv4Addr,
        offer: Vec<options::DhcpOption>,
    }
    impl server::Handler for BenchHandler {
        fn handle_request(&mut self, s: &server::Server, p: packet::Packet) {
            let _ = s.reply(
                options::MessageType::Offer,
                self.offer.clone(),
                Ipv4Addr::new(192, 168, 2, 10),
                p,
            );
        }
    }

    let srv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind srv");
    let srv_addr = srv_sock.local_addr().unwrap();
    srv_sock
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .ok();
    let server_ip = Ipv4Addr::new(127, 0, 0, 1);
    let broadcast_ip = Ipv4Addr::new(127, 0, 0, 1);
    let offer = offer_options();
    std::thread::spawn(move || {
        let _ = server::Server::serve(srv_sock, server_ip, broadcast_ip, BenchHandler { server_ip, offer });
    });
    // Give server a moment to bind.
    std::thread::sleep(Duration::from_millis(100));

    let cli = UdpSocket::bind("127.0.0.1:0").expect("bind cli");
    cli.connect(srv_addr).expect("connect");
    cli.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = [0u8; dhcp4r::packet::WIRE_MAX];
    let wire = {
        let mut tmp = [0u8; dhcp4r::packet::WIRE_MAX];
        discover_packet().encode(&mut tmp).to_vec()
    };
    // warmup
    let mut rx = [0u8; 1500];
    for _ in 0..200 {
        cli.send(black_box(&wire)).unwrap();
        let _ = cli.recv(&mut rx);
    }
    const N: u64 = 5_000;
    let t = Instant::now();
    let mut ok = 0u64;
    for _ in 0..N {
        cli.send(black_box(&wire)).unwrap();
        match cli.recv(&mut rx) {
            Ok(l) => {
                black_box(l);
                ok += 1;
            }
            Err(_) => break,
        }
    }
    let el = t.elapsed();
    // Silence unused warning for buf
    black_box(&mut buf);
    let rps = ok as f64 / el.as_secs_f64();
    println!(
        "{:<28} {:>12.0} req/s  ({:.1} ns/req, {}/{{}} ok)",
        "udp/offer-roundtrip",
        rps,
        el.as_nanos() as f64 / (ok.max(1) as f64),
        ok,
    );
    // Server thread is detached; process exit kills it.
    rps
}

fn main() {
    println!("=== dhcp4r bench (release, std Instant, black_box) ===");
    println!(
        "sizeof Packet={} DhcpOption={} RawDhcpOption={} Server={}",
        std::mem::size_of::<packet::Packet>(),
        std::mem::size_of::<options::DhcpOption>(),
        std::mem::size_of::<options::RawDhcpOption>(),
        std::mem::size_of::<server::Server>(),
    );
    // Wire ceiling is WIRE_MAX = 300 (BOOTP minimum: 240 header+cookie,
    // up to 59 bytes options + END, PAD to 300); the shipped
    // send path already uses [u8; WIRE_MAX], so the bench does too.
    let mut encode_buf = [0u8; dhcp4r::packet::WIRE_MAX];
    let d = discover_packet();
    let r = request_packet();
    let d_wire = d.encode(&mut encode_buf).to_vec();
    let r_wire = r.encode(&mut encode_buf).to_vec();
    // sanity: roundtrip preserves options
    assert_eq!(
        packet::Packet::from(&d_wire).ok().expect("decode").options,
        d.options
    );

    const N: u64 = 200_000;
    bench_fn("decode/discover", N, || {
        black_box(packet::Packet::from(black_box(&d_wire)).ok().expect("decode"));
    });
    bench_fn("decode/request", N, || {
        black_box(packet::Packet::from(black_box(&r_wire)).ok().expect("decode"));
    });
    bench_fn("encode/discover", N, || {
        let n = black_box(&d).encode(black_box(&mut encode_buf)).len();
        black_box(n);
    });
    bench_fn("encode/request", N, || {
        let n = black_box(&r).encode(black_box(&mut encode_buf)).len();
        black_box(n);
    });

    // filter_options_by_req: typical Offer(4 opts) filtered by PRL[1,3,6]
    bench_fn("filter/prl-3", N, || {
        let mut o = offer_options();
        // prepend auto opts like Server::reply does
        o.insert(0, options::DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 2, 1)));
        o.insert(
            0,
            options::DhcpOption::DhcpMessageType(options::MessageType::Offer),
        );
        server::filter_options_by_req(black_box(&mut o), black_box(&[1u8, 3, 6]));
        black_box(o);
    });

    // options::to_raw throughput (Router x2) for old-vs-new comparison
    let router2 = options::DhcpOption::Router(vec![
        Ipv4Addr::new(192, 168, 2, 1),
        Ipv4Addr::new(192, 168, 2, 2),
    ]);
    bench_fn("options/to_raw-router2", N, || {
        black_box(black_box(&router2).to_raw());
    });

    // DHCPv6 codec
    let v6_solicit = dhcpv6::Packet {
        msg_type: dhcpv6::MsgType::Solicit,
        transaction_id: 0x112233,
        options: vec![
            dhcpv6::Dhcpv6Option::ClientId(vec![0, 3, 0, 1, 2, 0, 0x5e, 0xaa, 0xbb, 0xcc]),
            dhcpv6::Dhcpv6Option::IaNa(dhcpv6::IaNa {
                iaid: 1,
                t1: 0,
                t2: 0,
                addrs: vec![],
            }),
        ],
    };
    let v6_wire = v6_solicit.encode().unwrap();
    bench_fn("v6/decode-solicit", N, || {
        black_box(dhcpv6::Packet::from(black_box(&v6_wire)).expect("v6 decode"));
    });
    bench_fn("v6/encode-solicit", N, || {
        black_box(black_box(&v6_solicit).encode().unwrap());
    });
    let v6_reply = dhcpv6::Packet {
        msg_type: dhcpv6::MsgType::Reply,
        transaction_id: 0x445566,
        options: vec![
            dhcpv6::Dhcpv6Option::ServerId(vec![0, 3, 0, 1, 2, 0, 0x5e, 0xaa, 0xbb, 0xcc]),
            dhcpv6::Dhcpv6Option::ClientId(vec![0, 3, 0, 1, 9, 9, 9, 9, 9, 9]),
            dhcpv6::Dhcpv6Option::IaNa(dhcpv6::IaNa {
                iaid: 7,
                t1: 43200,
                t2: 75600,
                addrs: vec![dhcpv6::IaAddr {
                    addr: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100),
                    preferred: 86400,
                    valid: 86400,
                }],
            }),
            dhcpv6::Dhcpv6Option::DnsServers(vec![Ipv6Addr::new(
                0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
            )]),
        ],
    };
    bench_fn("v6/encode-reply-1addr", N, || {
        black_box(black_box(&v6_reply).encode().unwrap());
    });

    // V6Pool: 1000-entry pool, hit vs miss
    {
        let mut pool = dhcpv6::V6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100),
            1000,
            Duration::from_secs(86400),
        );
        // prefill 1000 leases with distinct DUIDs
        for i in 0..1000u32 {
            let mut duid = vec![0, 3, 0, 1];
            duid.extend_from_slice(&i.to_be_bytes());
            let ip = Ipv6Addr::from(u128::from(pool.start_addr()) + i as u128);
            pool.insert(ip, duid, Some(Instant::now() + Duration::from_secs(3600)));
        }
        let owner_duid = {
            let mut d = vec![0, 3, 0, 1];
            d.extend_from_slice(&42u32.to_be_bytes());
            d
        };
        bench_fn("v6pool/discover-hit-1000", N, || {
            black_box(pool.discover(black_box(&owner_duid)));
        });
        let stranger: Vec<u8> = vec![9, 9, 9, 9, 9, 9, 9, 9];
        // exhausted pool: stranger always misses after full scan
        bench_fn("v6pool/discover-miss-full", 5_000, || {
            black_box(pool.discover(black_box(&stranger)));
        });
    }
    {
        // v4-style pool simulation via V6Pool with small count for comparison
        let mut pool = dhcpv6::V6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x200),
            252,
            Duration::from_secs(86400),
        );
        bench_fn("v6pool/discover-miss-empty-252", 20_000, || {
            let mut duid = vec![1, 2, 3, 4];
            duid.extend_from_slice(&black_box(12345u32).to_be_bytes());
            black_box(pool.discover(black_box(&duid)));
        });
    }

    // ---- Round-2 additions: Nak, hostname-63, large PRL, DNS4, combined ----
    {
        let nak = packet::Packet {
            reply: true,
            hops: 0,
            xid: 0x1234_5678,
            secs: 0,
            broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [1, 2, 3, 4, 5, 6],
            options: vec![
                options::DhcpOption::DhcpMessageType(options::MessageType::Nak),
                options::DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 2, 1)),
                options::DhcpOption::Message("Requested IP not available".to_string()),
            ],
        };
        bench_fn("encode/nak", N, || {
            let n = black_box(&nak).encode(black_box(&mut encode_buf)).len();
            black_box(n);
        });
        let mut h63 = discover_packet();
        h63.options
            .push(options::DhcpOption::HostName("h".repeat(63)));
        let h63_wire = h63.encode(&mut encode_buf).to_vec();
        bench_fn("decode/hostname-63", 100_000, || {
            black_box(
                packet::Packet::from(black_box(&h63_wire))
                    .ok()
                    .expect("decode"),
            );
        });
        bench_fn("encode/hostname-63", 100_000, || {
            let n = black_box(&h63).encode(black_box(&mut encode_buf)).len();
            black_box(n);
        });
        bench_fn("decode+msgtype/request", N, || {
            let p = packet::Packet::from(black_box(&r_wire))
                .ok()
                .expect("decode");
            black_box(p.message_type().ok());
            black_box(p.option(50).is_some());
            black_box(p.option(12).is_some());
        });
    }
    {
        const PRL10: &[u8] = &[1, 3, 6, 15, 51, 54, 58, 59, 42, 12];
        bench_fn("filter/prl-10", N, || {
            let mut o = offer_options();
            o.insert(
                0,
                options::DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 2, 1)),
            );
            o.insert(
                0,
                options::DhcpOption::DhcpMessageType(options::MessageType::Offer),
            );
            server::filter_options_by_req(black_box(&mut o), black_box(PRL10));
            black_box(o);
        });
        let dns4 = options::DhcpOption::DomainNameServer(vec![
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(8, 8, 4, 4),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(9, 9, 9, 9),
        ]);
        bench_fn("options/to_raw-dns4", N, || {
            black_box(black_box(&dns4).to_raw());
        });
        bench_fn("reply/asm-no-prl", N, || {
            let o = offer_options();
            black_box(reply_assembly(black_box(&o), None));
        });
        bench_fn("reply/asm-prl-4", N, || {
            let o = offer_options();
            black_box(reply_assembly(black_box(&o), Some(black_box(&[1u8, 3, 6, 51]))));
        });
    }
    {
        let v6_big = dhcpv6::Packet {
            msg_type: dhcpv6::MsgType::Solicit,
            transaction_id: 0x112233,
            options: vec![
                dhcpv6::Dhcpv6Option::ClientId(vec![
                    0, 3, 0, 1, 2, 0, 0x5e, 0xaa, 0xbb, 0xcc,
                ]),
                dhcpv6::Dhcpv6Option::IaNa(dhcpv6::IaNa {
                    iaid: 9,
                    t1: 0,
                    t2: 0,
                    addrs: vec![
                        dhcpv6::IaAddr {
                            addr: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x101),
                            preferred: 100,
                            valid: 200,
                        },
                        dhcpv6::IaAddr {
                            addr: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x102),
                            preferred: 100,
                            valid: 200,
                        },
                        dhcpv6::IaAddr {
                            addr: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x103),
                            preferred: 100,
                            valid: 200,
                        },
                        dhcpv6::IaAddr {
                            addr: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x104),
                            preferred: 100,
                            valid: 200,
                        },
                    ],
                }),
            ],
        };
        let big_wire = v6_big.encode().unwrap();
        bench_fn("v6/decode-iana-4addr", N, || {
            black_box(dhcpv6::Packet::from(black_box(&big_wire)).expect("v6 decode"));
        });
        bench_fn("v6/encode-iana-4addr", N, || {
            black_box(black_box(&v6_big).encode().unwrap());
        });
        let mut pool = dhcpv6::V6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x300),
            252,
            Duration::from_secs(86400),
        );
        bench_fn("v6pool/release-hit", 20_000, || {
            let mut d = vec![8, 8, 8, 8];
            d.extend_from_slice(&black_box(pool.len() as u32).to_be_bytes());
            d.extend_from_slice(&black_box(999u32).to_be_bytes());
            if let Some(ip) = pool.discover(&d) {
                let _ = pool.request(&d, ip);
            }
            black_box(pool.release(black_box(&d)));
        });
    }

    // ---- Final-round diagnostics: hostile wire + v6 mix (not headlines) ----
    {
        // 4096B / 1285-option bomb: proves Vec growth stays linear/bounded.
        let mut opts = vec![53u8, 1, 1];
        for _ in 0..1284 {
            opts.extend_from_slice(&[200, 1, 7]);
        }
        opts.push(255);
        let mut raw = vec![0u8; 236];
        raw[0] = 1;
        raw[1] = 1;
        raw[2] = 6;
        raw.extend_from_slice(&[99, 130, 83, 99]);
        raw.extend_from_slice(&opts);
        assert_eq!(raw.len(), 4096);
        bench_fn("diag/decode-4096b", 5_000, || {
            let p = packet::Packet::from(black_box(&raw)).ok().expect("decode");
            black_box(p.options.len());
        });
        // Mixed reject rate: truncated, bad type, short, bad cookie,
        // non-UTF8 hostname, Router fast-fail. No-cliff proof only.
        let mut bad_cookie = vec![0u8; 236];
        bad_cookie[0] = 1;
        bad_cookie[1] = 1;
        bad_cookie[2] = 6;
        bad_cookie.extend_from_slice(&[9, 9, 9, 9, 53, 1, 1, 255]);
        let cases: Vec<Vec<u8>> = vec![
            {
                let mut v = vec![0u8; 236];
                v[0] = 1;
                v[1] = 1;
                v[2] = 6;
                v.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1, 200, 255, 7]);
                v
            },
            {
                let mut v = vec![0u8; 236];
                v[0] = 1;
                v[1] = 1;
                v[2] = 6;
                v.extend_from_slice(&[99, 130, 83, 99, 53, 1, 9]);
                v
            },
            vec![0u8; 10],
            bad_cookie,
        ];
        bench_fn("diag/reject-mixed", 20_000, || {
            for c in &cases {
                black_box(packet::Packet::from(black_box(c)).is_err());
            }
        });
    }
    {
        // v6 traffic mix: solicit-fresh / renew-hit / release, half-full pool.
        let mut pool = dhcpv6::V6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x400),
            252,
            Duration::from_secs(86400),
        );
        for i in 0..126u32 {
            let mut duid = vec![0, 3, 0, 1];
            duid.extend_from_slice(&i.to_be_bytes());
            let ip = Ipv6Addr::from(u128::from(pool.start_addr()) + i as u128);
            pool.insert(ip, duid, Some(Instant::now() + Duration::from_secs(3600)));
        }
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next_rand = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        bench_fn("mix/v6-solicit-renew-release", 50_000, || {
            let r = next_rand();
            let mut duid = vec![0, 3, 0, 1];
            duid.extend_from_slice(&((r & 0xFFFF) as u32).to_be_bytes());
            match r % 3 {
                0 => {
                    black_box(pool.discover(black_box(&duid)));
                }
                1 => {
                    if let Some(ip) = pool.discover(&duid) {
                        black_box(pool.request(black_box(&duid), black_box(ip)).ok());
                    }
                }
                _ => {
                    black_box(pool.release(black_box(&duid)));
                }
            }
        });
    }

    // Full UDP loopback (dominant for "requests per second it can do").
    bench_udp_roundtrip();
    if std::env::var("BENCH_SUSTAINED").is_ok() {
        bench_udp_sustained();
    }
    println!("=== done (median of 3 runs; higher req/s is better) ===");
}

fn bench_udp_sustained() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    struct CountHandler {
        n: Arc<AtomicU64>,
        offer: Vec<options::DhcpOption>,
    }
    impl server::Handler for CountHandler {
        fn handle_request(&mut self, s: &server::Server, p: packet::Packet) {
            self.n.fetch_add(1, Ordering::Relaxed);
            let _ = s.reply(
                options::MessageType::Offer,
                self.offer.clone(),
                Ipv4Addr::new(192, 168, 2, 10),
                p,
            );
        }
    }
    let mut medians = vec![];
    for _ in 0..1 {
        let srv = UdpSocket::bind("127.0.0.1:0").expect("bind srv");
        let sa = srv.local_addr().unwrap();
        let handled = Arc::new(AtomicU64::new(0));
        let h = handled.clone();
        let offer = offer_options();
        std::thread::spawn(move || {
            let _ = server::Server::serve(
                srv,
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(127, 0, 0, 1),
                CountHandler { n: h, offer },
            );
        });
        std::thread::sleep(Duration::from_millis(100));
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind tx");
        tx.connect(sa).unwrap();
        let rx = tx.try_clone().unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(500))).ok();
        let wire = {
            let mut t = [0u8; dhcp4r::packet::WIRE_MAX];
            discover_packet().encode(&mut t).to_vec()
        };
        let lats = Arc::new(Mutex::new(Vec::with_capacity(1 << 20)));
        let run = Arc::new(AtomicBool::new(true));
        let rx_lats = lats.clone();
        let rx_flag = run.clone();
        let rxh = std::thread::spawn(move || {
            let mut b = [0u8; 1500];
            let mut n = 0u64;
            while rx_flag.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                if rx.recv(&mut b).is_ok() {
                    n += 1;
                    rx_lats.lock().unwrap().push(t0.elapsed());
                }
            }
            n
        });
        let dur = Duration::from_secs(10);
        let t0 = Instant::now();
        let mut sent = 0u64;
        while t0.elapsed() < dur {
            tx.send(black_box(&wire)).unwrap();
            sent += 1;
        }
        std::thread::sleep(Duration::from_millis(500));
        run.store(false, Ordering::Relaxed);
        let got = rxh.join().unwrap();
        let hv = handled.load(Ordering::Relaxed);
        let mut v = lats.lock().unwrap().clone();
        v.sort_unstable();
        let pct = |q: f64| v.get((v.len() as f64 * q) as usize).copied().unwrap_or_default();
        let loss = 100.0 * (sent.saturating_sub(got) as f64) / (sent.max(1) as f64);
        let rps = hv as f64 / dur.as_secs_f64();
        println!(
            "{:<28} {:>12.0} req/s  (sent={} handled={} rx={} loss={:.1}% p50={:?} p99={:?})",
            "udp/sustained-10s",
            rps,
            sent,
            hv,
            got,
            loss,
            pct(0.5),
            pct(0.99)
        );
        medians.push(rps);
    }
    medians.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "{:<28} {:>12.0} req/s  (median)",
        "udp/sustained-median",
        medians[medians.len() / 2]
    );
}
