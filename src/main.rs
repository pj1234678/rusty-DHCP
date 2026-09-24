//! RustyDHCP server binary: DHCPv4 + DHCPv6 service with request monitor.
//!
//! Single binary, no arguments: configuration always comes from `./dhcp.conf`
//! (built-in defaults when unreadable). Every DHCP Request is both served
//! (leases, Offer/Ack/Nak) and logged monitor-style:
//! `timestamp\tmac\tip\thostname\tOnline` (UTC, `-` when no host name).

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use dhcp4r::{config, dhcpv6, options, packet, server};

// Special value for infinite (permanent file-reserved) leases.
const INFINITE_LEASE: Option<Instant> = None;

fn main() {
    // Fixed configuration path (no arguments). Without a readable file the
    // server falls back to the built-in defaults, which match the old
    // hard-coded constants exactly.
    let cfg_path = "dhcp.conf".to_string();
    let config = match config::Config::load(&cfg_path) {
        Ok(c) => {
            println!("Loaded {} ({} v4 leases, dhcpv6 {})", cfg_path, c.lease_num, if c.enable_dhcpv6 {
                "on"
            } else {
                "off"
            });
            c
        }
        Err(e) => {
            eprintln!("{}; using built-in defaults", e);
            config::Config::defaults()
        }
    };
    {
        // u64 math: validation guarantees ip_start + lease_num <= u32::MAX + 1,
        // so ip_start + (lease_num - 1) always fits u32 here.
        let v4_last = if config.lease_num == 0 {
            "(empty pool)".to_string()
        } else {
            Ipv4Addr::from(
                (config.ip_start_num() as u64 + config.lease_num as u64 - 1) as u32,
            )
            .to_string()
        };
        println!(
            "IPv4 pool {} .. {} (server {}, broadcast {}; rapid_commit {}, ntp {})",
            config.ip_start,
            v4_last,
            config.server_ip,
            config
                .broadcasts()
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(","),
            onoff(config.enable_rapid_commit),
            onoff(config.enable_ntp),
        );
        if config.enable_dhcpv6 {
            println!(
                "IPv6 pool {} +{} (server DUID {})",
                config.ipv6_start,
                config.ipv6_lease_num,
                config
                    .server_duid
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":"),
            );
        }
        println!("listening on {}", config.listen_addr);
    }

    if config.enable_dhcpv6 {
        let v6 = config.clone();
        std::thread::spawn(move || {
            let _ = serve_v6(&v6);
        });
    }

    let socket = UdpSocket::bind(config.listen_addr).unwrap();
    socket.set_broadcast(true).unwrap();

    // Ipv4Addr -> (MAC address, lease expiry, client host name) mapping.
    // The host name comes from DHCP option 12 of the client's packets and
    // is `None` until the client announces one (leases-file entries start
    // unnamed too; the file format stays `mac,ip`).
    // In-range leases live in a dense slot array (O(1) indexed probes, no
    // hashing on the miss scan); out-of-range file entries spill to overflow.
    let use_slots = config.lease_num <= 100_000;
    let mut slots: Vec<Option<([u8; 6], Option<Instant>, Option<String>)>> = if use_slots {
        let mut s = Vec::new();
        s.resize_with(config.lease_num as usize, || None);
        s
    } else {
        Vec::new()
    };
    let mut filled: usize = 0;
    let mut overflow: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>, Option<String>)> =
        HashMap::new();
    let mut by_mac: HashMap<[u8; 6], Ipv4Addr> =
        HashMap::with_capacity(config.lease_num.min(1024) as usize);
    let slot_idx = |ip: &Ipv4Addr, start: u32, num: u32| -> Option<usize> {
        if !use_slots {
            return None;
        }
        let off = u32::from(*ip).checked_sub(start)?;
        if (off as u64) < num as u64 {
            Some(off as usize)
        } else {
            None
        }
    };
    // Read and populate leases from the file
    if let Ok(file) = File::open(&config.leases_file) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() == 2 {
                    let mac_parts: Vec<u8> = parts[0]
                        .split(':')
                        .filter_map(|part| u8::from_str_radix(part, 16).ok())
                        .collect();

                    if mac_parts.len() == 6 {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&mac_parts);

                        let ip = parts[1].trim().parse::<Ipv4Addr>().unwrap();
                        // Duplicate IPs last-wins (locked); duplicate MACs
                        // preserved with `by_mac` as O(1) hint.
                        if let Some(i) = slot_idx(&ip, config.ip_start_num(), config.lease_num) {
                            if let Some((old_mac, _, _)) = &slots[i] {
                                if *old_mac != mac && by_mac.get(old_mac) == Some(&ip) {
                                    let old = *old_mac;
                                    by_mac.remove(&old);
                                }
                            }
                            if slots[i].is_none() {
                                filled += 1;
                            }
                            slots[i] = Some((mac, INFINITE_LEASE, None));
                            by_mac.insert(mac, ip);
                        } else {
                            if let Some((old_mac, _, _)) = overflow.get(&ip) {
                                if *old_mac != mac && by_mac.get(old_mac) == Some(&ip) {
                                    let old = *old_mac;
                                    by_mac.remove(&old);
                                }
                            }
                            // Huge hash-only pools keep in-range entries here too.
                            if !use_slots {
                                let start = config.ip_start_num();
                                let num = config.lease_num;
                                let pos: u32 = ip.into();
                                let in_range = pos
                                    .checked_sub(start)
                                    .map_or(false, |d| (d as u64) < num as u64);
                                if !in_range {
                                    overflow.insert(ip, (mac, INFINITE_LEASE, None));
                                    by_mac.insert(mac, ip);
                                    continue;
                                }
                            }
                            overflow.insert(ip, (mac, INFINITE_LEASE, None));
                            by_mac.insert(mac, ip);
                        }
                    }
                }
            }
        }
    } else {
        eprintln!("Failed to open leases file. Continuing...");
        //return;
    }

    let cached_offer = build_offer_options(
        config.subnet_mask,
        config.router_ip,
        &config.dns_ips,
        &config.ntp_ips,
        config.enable_ntp,
        config.lease_duration_secs,
    );
    let ms = MyServer {
        use_slots,
        slots,
        filled,
        overflow,
        by_mac,
        last_lease: 0,
        lease_duration: Duration::new(config.lease_duration_secs as u64, 0),
        ip_start_num: config.ip_start_num(),
        lease_num: config.lease_num,
        enable_rapid_commit: config.enable_rapid_commit,
        broadcasts: config.broadcasts(),
        cached_offer,
    };

    server::Server::serve_with_broadcasts(
        socket,
        config.server_ip,
        config.broadcasts(),
        ms,
    );
}

/// Option list for Offer/Ack replies, mirroring the documented order:
/// lease time, subnet, router, DNS, then NTP (option 42) if enabled.
/// Built once at startup and cloned per reply (instead of rebuilt).
fn build_offer_options(
    subnet_mask: Ipv4Addr,
    router_ip: Ipv4Addr,
    dns_ips: &[Ipv4Addr],
    ntp_ips: &[Ipv4Addr],
    enable_ntp: bool,
    lease_secs: u32,
) -> Vec<options::DhcpOption> {
    let mut opts = Vec::with_capacity(4 + (enable_ntp && !ntp_ips.is_empty()) as usize);
    opts.push(options::DhcpOption::IpAddressLeaseTime(lease_secs));
    opts.push(options::DhcpOption::SubnetMask(subnet_mask));
    opts.push(options::DhcpOption::Router(vec![router_ip]));
    opts.push(options::DhcpOption::DomainNameServer(dns_ips.to_vec()));
    if enable_ntp && !ntp_ips.is_empty() {
        let mut data = Vec::with_capacity(ntp_ips.len() * 4);
        for ip in ntp_ips {
            data.extend_from_slice(&ip.octets());
        }
        opts.push(options::DhcpOption::Unrecognized(
            options::RawDhcpOption {
                code: options::NETWORK_TIME_PROTOCOL_SERVERS,
                data,
            },
        ));
    }
    opts
}

struct MyServer {
    // In-range leases: dense slot array indexed by `ip - ip_start_num`.
    // Out-of-range file reservations spill to `overflow`. `by_mac` is an
    // O(1) hint with fallback scan (duplicate MACs preserved).
    use_slots: bool,
    slots: Vec<Option<([u8; 6], Option<Instant>, Option<String>)>>,
    filled: usize,
    overflow: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>, Option<String>)>,
    // Reverse index MAC -> IP for O(1) current_lease (1:1 invariant).
    by_mac: HashMap<[u8; 6], Ipv4Addr>,
    last_lease: u32,
    lease_duration: Duration,
    ip_start_num: u32,
    lease_num: u32,
    enable_rapid_commit: bool,
    /// Broadcast destinations, primary first (mirrors `Server` fan-out).
    broadcasts: Vec<Ipv4Addr>,
    cached_offer: Vec<options::DhcpOption>,
}

/// Client-announced host name (DHCP option 12), if the packet carries one.
/// Borrowed: clone only on insert/remember write paths.
fn hostname_of(in_packet: &packet::Packet) -> Option<&str> {
    match in_packet.option(options::HOST_NAME) {
        Some(options::DhcpOption::HostName(name)) => Some(name.as_str()),
        _ => None,
    }
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SS` (std only, no timezone database).
fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = ymd_from_days((secs / 86400) as i64);
    let t = secs % 86400;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        y,
        m,
        d,
        t / 3600,
        (t % 3600) / 60,
        t % 60
    )
}

/// Days since 1970-01-01 -> (year, month, day), Howard Hinnant's algorithm.
fn ymd_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Formats byte array machine address into hex pairs separated by colons.
/// Array must be at least one byte long.
fn chaddr(a: &[u8]) -> String {
    a[1..].iter().fold(format!("{:02x}", a[0]), |acc, &b| {
        format!("{}:{:02x}", acc, &b)
    })
}

/// "on"/"off" flag rendering for startup diagnostics.
fn onoff(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

impl server::Handler for MyServer {
    fn handle_request(&mut self, server: &server::Server, in_packet: packet::Packet) {
        let hostname = hostname_of(&in_packet);
        match in_packet.message_type() {
            Ok(options::MessageType::Discover) => {
                // Rapid Commit (RFC 4039, option 80): when enabled and asked
                // for, commit immediately with an Ack (2-message exchange)
                // instead of offering. Selection is Discover-style (current
                // lease, else round-robin); Requested IP / ciaddr do NOT
                // steer it. Pool exhausted behaves like Discover: silence.
                let mac_s = chaddr(&in_packet.chaddr);
                let rapid = self.enable_rapid_commit
                    && in_packet.option(options::RAPID_COMMIT).is_some();
                let opt_s = in_packet
                    .options
                    .iter()
                    .map(|o| o.code().to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let prl_s = match in_packet.option(options::PARAMETER_REQUEST_LIST) {
                    Some(options::DhcpOption::ParameterRequestList(p)) => p
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    _ => "-".to_string(),
                };
                println!(
                    "v4 DISCOVER mac={} xid={} rapid={} bcast={} src={} opts=[{}] prl=[{}]",
                    mac_s,
                    in_packet.xid,
                    rapid,
                    in_packet.broadcast,
                    server.peer(),
                    opt_s,
                    prl_s
                );
                if rapid {
                    if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                        self.remember_hostname(&ip, &hostname);
                        println!(
                            "v4 DISCOVER mac={} xid={} -> ACK {} to {} (rapid commit, existing lease)",
                            mac_s,
                            in_packet.xid,
                            ip,
                            self.dsts_s(server, in_packet.broadcast, ip)
                        );
                        self.reply(server, options::MessageType::Ack, in_packet, &ip);
                        return;
                    }
                    let now = Instant::now();
                    let mut committed: Option<Ipv4Addr> = None;
                    for _ in 0..self.lease_num {
                        self.last_lease = (self.last_lease + 1) % self.lease_num;
                        let cand: Ipv4Addr =
                            (self.ip_start_num + self.last_lease).into();
                        if self.available_at(&in_packet.chaddr, &cand, now) {
                            let expiry = now + self.lease_duration;
                            self.insert_lease(cand, in_packet.chaddr, Some(expiry), hostname);
                            committed = Some(cand);
                            break;
                        }
                    }
                    match committed {
                        Some(ip) => {
                            println!(
                                "v4 DISCOVER mac={} xid={} -> ACK {} to {} (rapid commit, new lease)",
                                mac_s,
                                in_packet.xid,
                                ip,
                                self.dsts_s(server, in_packet.broadcast, ip)
                            );
                            self.reply(server, options::MessageType::Ack, in_packet, &ip);
                        }
                        None => println!(
                            "v4 DISCOVER mac={} xid={} -> no reply (rapid commit, pool exhausted {}/{} used)",
                            mac_s,
                            in_packet.xid,
                            self.filled + self.overflow.len(),
                            self.lease_num
                        ),
                    }
                    return;
                }
                // Otherwise prefer existing (including expired if available)
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    self.remember_hostname(&ip, &hostname);
                    println!(
                        "v4 DISCOVER mac={} xid={} -> OFFER {} to {} (existing lease)",
                        mac_s,
                        in_packet.xid,
                        ip,
                        self.dsts_s(server, in_packet.broadcast, ip)
                    );
                    self.reply(server, options::MessageType::Offer, in_packet, &ip);
                    return;
                }
                // Otherwise choose a free ip if available
                let now = Instant::now();
                let mut offered: Option<Ipv4Addr> = None;
                for _ in 0..self.lease_num {
                    self.last_lease = (self.last_lease + 1) % self.lease_num;
                    let cand: Ipv4Addr = (self.ip_start_num + self.last_lease).into();
                    if self.available_at(&in_packet.chaddr, &cand, now) {
                        offered = Some(cand);
                        break;
                    }
                }
                match offered {
                    Some(ip) => {
                        println!(
                            "v4 DISCOVER mac={} xid={} -> OFFER {} to {} (new lease)",
                            mac_s,
                            in_packet.xid,
                            ip,
                            self.dsts_s(server, in_packet.broadcast, ip)
                        );
                        self.reply(
                            server,
                            options::MessageType::Offer,
                            in_packet,
                            &ip,
                        );
                    }
                    None => println!(
                        "v4 DISCOVER mac={} xid={} -> no reply (pool exhausted {}/{} used)",
                        mac_s,
                        in_packet.xid,
                        self.filled + self.overflow.len(),
                        self.lease_num
                    ),
                }
            }

            Ok(options::MessageType::Request) => {
                // Ignore requests to alternative DHCP server
                let for_us = server.for_this_server(&in_packet);
                // fall through when false (preserves old behavior)

                let req_ip = match in_packet.option(options::REQUESTED_IP_ADDRESS) {
                    Some(options::DhcpOption::RequestedIpAddress(x)) => *x,
                    _ => in_packet.ciaddr,
                };
                let sid = match in_packet.option(options::SERVER_IDENTIFIER) {
                    Some(options::DhcpOption::ServerIdentifier(ip)) => ip.to_string(),
                    _ => "-".to_string(),
                };
                let mac_s = chaddr(&in_packet.chaddr);
                let opt_s = in_packet
                    .options
                    .iter()
                    .map(|o| o.code().to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "v4 REQUEST mac={} xid={} req_ip={} ciaddr={} server_id={} bcast={} src={} opts=[{}]",
                    mac_s,
                    in_packet.xid,
                    req_ip,
                    in_packet.ciaddr,
                    sid,
                    in_packet.broadcast,
                    server.peer(),
                    opt_s
                );
                if !for_us {
                    println!(
                        "v4 REQUEST mac={} xid={} note: server_id mismatch, serving anyway",
                        mac_s, in_packet.xid
                    );
                }
                // Monitor log (old monitor binary behavior): every Request.
                println!(
                    "{}\t{}\t{}\t{}\tOnline",
                    utc_now_iso(),
                    mac_s,
                    req_ip,
                    hostname.unwrap_or("-")
                );
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    self.remember_hostname(&ip, &hostname);
                    println!(
                        "v4 REQUEST mac={} xid={} -> ACK {} to {} (existing lease)",
                        mac_s,
                        in_packet.xid,
                        ip,
                        self.dsts_s(server, in_packet.broadcast, ip)
                    );
                    self.reply(server, options::MessageType::Ack, in_packet, &ip);
                    return;
                }
                let now = Instant::now();
                if !self.available_at(&in_packet.chaddr, &req_ip, now) {
                    let in_pool = u32::from(req_ip)
                        .checked_sub(self.ip_start_num)
                        .map_or(false, |d| (d as u64) < self.lease_num as u64);
                    println!(
                        "v4 REQUEST mac={} xid={} -> NAK {} to {} ({})",
                        mac_s,
                        in_packet.xid,
                        req_ip,
                        self.dsts_s(server, in_packet.broadcast, Ipv4Addr::UNSPECIFIED),
                        if in_pool {
                            "requested IP in use by another client"
                        } else {
                            "requested IP outside pool range"
                        }
                    );
                    self.nak(server, in_packet, "Requested IP not available");
                    return;
                }
                let expiry = now + self.lease_duration;
                self.insert_lease(req_ip, in_packet.chaddr, Some(expiry), hostname);
                println!(
                    "v4 REQUEST mac={} xid={} -> ACK {} to {} (new lease)",
                    mac_s,
                    in_packet.xid,
                    req_ip,
                    self.dsts_s(server, in_packet.broadcast, req_ip)
                );
                self.reply(server, options::MessageType::Ack, in_packet, &req_ip);
            }

            Ok(options::MessageType::Release) | Ok(options::MessageType::Decline) => {
                let kind =
                    match in_packet.message_type() {
                        Ok(options::MessageType::Release) => "RELEASE",
                        _ => "DECLINE",
                    };
                let mac_s = chaddr(&in_packet.chaddr);
                // Ignore requests to alternative DHCP server
                if !server.for_this_server(&in_packet) {
                    println!(
                        "v4 {} mac={} xid={} src={} ignored (server_id mismatch)",
                        kind,
                        mac_s,
                        in_packet.xid,
                        server.peer()
                    );
                    return;
                }
                match self.current_lease(&in_packet.chaddr) {
                    Some(ip) => {
                        self.remove_lease(&in_packet.chaddr);
                        println!(
                            "v4 {} mac={} xid={} src={} freed {}",
                            kind,
                            mac_s,
                            in_packet.xid,
                            server.peer(),
                            ip
                        );
                    }
                    None => println!(
                        "v4 {} mac={} xid={} src={} no lease held",
                        kind,
                        mac_s,
                        in_packet.xid,
                        server.peer()
                    ),
                }
            }

            // Anything else (e.g. INFORM, which this server does not implement)
            // is ignored — but logged, so silent clients can be diagnosed.
            other => match other {
                Ok(t) => println!(
                    "v4 {:?} mac={} xid={} src={} ignored (unsupported message type)",
                    t,
                    chaddr(&in_packet.chaddr),
                    in_packet.xid,
                    server.peer()
                ),
                Err(e) => println!(
                    "v4 ? mac={} xid={} src={} ignored ({})",
                    chaddr(&in_packet.chaddr),
                    in_packet.xid,
                    server.peer(),
                    e
                ),
            },
        }
    }
}

impl MyServer {
    /// Where [`server::Server::send`] would deliver a reply (mirrors its
    /// routing exactly, for diagnostics).
    fn dsts_for(
        &self,
        server: &server::Server,
        broadcast: bool,
        yiaddr: Ipv4Addr,
    ) -> Vec<SocketAddr> {
        server::Server::route_dests(server.peer(), broadcast, yiaddr, &self.broadcasts)
    }

    /// `dsts_for` rendered for one-line logs.
    fn dsts_s(&self, server: &server::Server, broadcast: bool, yiaddr: Ipv4Addr) -> String {
        self.dsts_for(server, broadcast, yiaddr)
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    #[inline]
    fn idx(&self, addr: &Ipv4Addr) -> Option<usize> {
        if !self.use_slots {
            return None;
        }
        let off = u32::from(*addr).checked_sub(self.ip_start_num)?;
        if (off as u64) < self.lease_num as u64 {
            Some(off as usize)
        } else {
            None
        }
    }

    #[inline]
    fn lookup(&self, addr: &Ipv4Addr) -> Option<&([u8; 6], Option<Instant>, Option<String>)> {
        match self.idx(addr) {
            Some(i) => self.slots[i].as_ref(),
            None => self.overflow.get(addr),
        }
    }

    fn is_empty(&self) -> bool {
        self.filled == 0 && self.overflow.is_empty()
    }

    fn available_at(&self, chaddr: &[u8; 6], addr: &Ipv4Addr, now: Instant) -> bool {
        if let Some(i) = self.idx(addr) {
            return match &self.slots[i] {
                Some((mac, expiry, _)) => {
                    *mac == *chaddr || expiry.map_or(true, |exp| now > exp)
                }
                None => true,
            };
        }
        if !self.use_slots {
            let pos: u32 = (*addr).into();
            let in_range = pos
                .checked_sub(self.ip_start_num)
                .map_or(false, |d| (d as u64) < self.lease_num as u64);
            if in_range {
                return match self.overflow.get(addr) {
                    Some((mac, expiry, _)) => {
                        *mac == *chaddr || expiry.map_or(true, |exp| now > exp)
                    }
                    None => true,
                };
            }
        }
        false
    }
    #[inline]
    fn current_lease(&self, chaddr: &[u8; 6]) -> Option<Ipv4Addr> {
        if self.is_empty() {
            return None;
        }
        if let Some(ip) = self.by_mac.get(chaddr).copied() {
            if let Some((m, _, _)) = self.lookup(&ip) {
                if *m == *chaddr {
                    return Some(ip);
                }
            }
        }
        if self.use_slots {
            for (i, s) in self.slots.iter().enumerate() {
                if let Some((m, _, _)) = s {
                    if *m == *chaddr {
                        return Some(Ipv4Addr::from(self.ip_start_num + i as u32));
                    }
                }
            }
        }
        for (ip, (m, _, _)) in &self.overflow {
            if *m == *chaddr {
                return Some(*ip);
            }
        }
        None
    }
    /// Insert (or steal) a lease. Duplicate MACs for different IPs are
    /// preserved (like the original); `by_mac` is an O(1) hint for the
    /// common 1:1 case. Duplicate IPs last-wins.
    fn insert_lease(
        &mut self,
        ip: Ipv4Addr,
        mac: [u8; 6],
        expiry: Option<Instant>,
        hostname: Option<&str>,
    ) {
        let entry = (mac, expiry, hostname.map(|s| s.to_owned()));
        if let Some(i) = self.idx(&ip) {
            if let Some((old_mac, _, _)) = &self.slots[i] {
                if *old_mac != mac && self.by_mac.get(old_mac) == Some(&ip) {
                    let old = *old_mac;
                    self.by_mac.remove(&old);
                }
            }
            if self.slots[i].is_none() {
                self.filled += 1;
            }
            self.slots[i] = Some(entry);
            self.by_mac.insert(mac, ip);
        } else {
            if let Some((old_mac, _, _)) = self.overflow.get(&ip) {
                if *old_mac != mac && self.by_mac.get(old_mac) == Some(&ip) {
                    let old = *old_mac;
                    self.by_mac.remove(&old);
                }
            }
            self.overflow.insert(ip, entry);
            self.by_mac.insert(mac, ip);
        }
    }
    fn remove_lease(&mut self, chaddr: &[u8; 6]) {
        if let Some(ip) = self.current_lease(chaddr) {
            if let Some(i) = self.idx(&ip) {
                self.slots[i] = None;
                self.filled -= 1;
            } else {
                self.overflow.remove(&ip);
            }
            if self.by_mac.get(chaddr) == Some(&ip) {
                self.by_mac.remove(chaddr);
                let mut repaired = false;
                if self.use_slots {
                    for (j, s) in self.slots.iter().enumerate() {
                        if let Some((m, _, _)) = s {
                            if *m == *chaddr {
                                self.by_mac.insert(
                                    *chaddr,
                                    Ipv4Addr::from(self.ip_start_num + j as u32),
                                );
                                repaired = true;
                                break;
                            }
                        }
                    }
                }
                if !repaired {
                    for (other_ip, (m, _, _)) in &self.overflow {
                        if *m == *chaddr {
                            self.by_mac.insert(*chaddr, *other_ip);
                            break;
                        }
                    }
                }
            }
        }
    }
    /// Refresh the stored host name when the client announces one. A packet
    /// without option 12 leaves the stored name untouched, so renewals that
    /// omit it don't flap the recorded name.
    fn remember_hostname(&mut self, ip: &Ipv4Addr, hostname: &Option<&str>) {
        let entry = match self.idx(ip) {
            Some(i) => self.slots[i].as_mut().map(|e| &mut e.2),
            None => self.overflow.get_mut(ip).map(|e| &mut e.2),
        };
        if let (Some(name), Some(slot)) = (hostname, entry) {
            *slot = Some((*name).to_owned());
        }
    }

    /// Option list for Offer/Ack replies, mirroring the documented order:
    /// lease time, subnet, router, DNS, then NTP (option 42) if enabled.
    /// Cloned from the startup-built cache (no per-reply rebuild).
    fn offer_options(&self) -> Vec<options::DhcpOption> {
        self.cached_offer.clone()
    }

    fn reply(
        &self,
        s: &server::Server,
        msg_type: options::MessageType,
        req_packet: packet::Packet,
        offer_ip: &Ipv4Addr,
    ) {
        let opts = self.offer_options();
        // Log delivery failures (e.g. unroutable renewing client): they are
        // otherwise silent because the handshake simply stalls.
        if let Err(e) = s.reply(msg_type, opts, *offer_ip, req_packet) {
            eprintln!("reply {:?} to {} failed: {}", msg_type, offer_ip, e);
        }
    }

    fn nak(&self, s: &server::Server, req_packet: packet::Packet, message: &str) {
        if let Err(e) = s.reply(
            options::MessageType::Nak,
            vec![options::DhcpOption::Message(message.to_string())],
            Ipv4Addr::new(0, 0, 0, 0),
            req_packet,
        ) {
            eprintln!("reply Nak failed: {}", e);
        }
    }
}

// ---------------------------------------------------------------------------
// DHCPv6 managed range (RFC 8415), driven by the same dhcp.conf
// ---------------------------------------------------------------------------

/// Run the DHCPv6 service: Solicit->Advertise, Request/Renew/Rebind->Reply,
/// Release/Decline frees. With `enable_rapid_commit`, Solicit carrying
/// option 14 commits immediately with a Reply instead. Packets without a
/// Client ID or IA_NA, and unknown message types, are ignored. Returns only
/// on socket error like `serve`.
fn serve_v6(config: &config::Config) -> std::io::Error {
    let socket = UdpSocket::bind(config.listen_addr_v6).unwrap();

    let mut pool = dhcpv6::V6Pool::new(
        config.ipv6_start,
        config.ipv6_lease_num,
        Duration::new(config.ipv6_lease_duration_secs as u64, 0),
    );
    // v6 reservations file: `duid-hex,ipv6` per line; malformed lines are
    // skipped (unlike the v4 loader, a bad line never panics the daemon).
    if let Ok(file) = File::open(&config.leases_file_v6) {
        for line in BufReader::new(file).lines().flatten() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() == 2 {
                if let (Ok(duid), Ok(ip)) = (
                    config::parse_duid_hex(parts[0].trim()),
                    parts[1].trim().parse::<Ipv6Addr>(),
                ) {
                    if !duid.is_empty() {
                        pool.insert(ip, duid, None);
                    }
                }
            }
        }
    } else {
        eprintln!("Failed to open v6 leases file. Continuing...");
    }

    let mut in_buf: [u8; 1500] = [0; 1500];
    loop {
        let (len, src) = match socket.recv_from(&mut in_buf) {
            Err(e) => return e,
            Ok((l, src)) => (l, src),
        };
        let in_packet = match dhcpv6::Packet::from(&in_buf[..len]) {
            Ok(p) => p,
            // Malformed datagrams never reach the handler, so log why here.
            Err(_) => {
                eprintln!("v6 ignoring malformed datagram ({} bytes)", len);
                continue;
            }
        };
        // Every message below needs the client DUID; without it there is no
        // identity to lease to. Borrowed (no per-packet clone; the reply
        // path clones once when building ClientId).
        let duid: &[u8] = match in_packet.option(dhcpv6::OPT_CLIENTID) {
            Some(dhcpv6::Dhcpv6Option::ClientId(d)) => d.as_slice(),
            _ => {
                println!(
                    "v6 ? tid={:06x} ignored (no client ID)",
                    in_packet.transaction_id
                );
                continue;
            }
        };
        let duid_s = if duid.is_empty() {
            // Empty ClientIds decode fine but carry no identity; never panic.
            "-".to_string()
        } else {
            chaddr(duid)
        };
        let iaid = in_packet.first_iana().map(|ia| ia.iaid).unwrap_or(0);
        match in_packet.msg_type {
            dhcpv6::MsgType::Solicit => {
                let rapid = config.enable_rapid_commit
                    && in_packet.option(dhcpv6::OPT_RAPID_COMMIT).is_some();
                println!(
                    "v6 SOLICIT duid={} tid={:06x} iaid={} rapid={}",
                    duid_s, in_packet.transaction_id, iaid, rapid
                );
                // Rapid Commit (RFC 8415 option 14): when enabled and asked
                // for, commit immediately with a Reply (2-message exchange)
                // instead of advertising. Exhaustion replies NoAddrsAvail,
                // like the Request path below.
                if rapid {
                    match pool.discover(&duid) {
                        Some(offered) => match pool.request(&duid, offered) {
                            Ok(ip) => {
                                println!(
                                    "v6 SOLICIT duid={} tid={:06x} -> REPLY {} (rapid commit)",
                                    duid_s, in_packet.transaction_id, ip
                                );
                                let _ = send_v6(
                                    &socket,
                                    src,
                                    &config.server_duid,
                                    &duid,
                                    &in_packet,
                                    dhcpv6::MsgType::Reply,
                                    ip,
                                    &config.ipv6_dns,
                                    config.ipv6_lease_duration_secs,
                                );
                            }
                            Err(_) => {
                                println!(
                                    "v6 SOLICIT duid={} tid={:06x} -> REPLY nodata (NoAddrsAvail, pool {}/{} used)",
                                    duid_s,
                                    in_packet.transaction_id,
                                    pool.len(),
                                    pool.count()
                                );
                                let _ = send_v6_nodata(
                                    &socket,
                                    src,
                                    &config.server_duid,
                                    &duid,
                                    &in_packet,
                                    dhcpv6::MsgType::Reply,
                                );
                            }
                        },
                        None => {
                            println!(
                                "v6 SOLICIT duid={} tid={:06x} -> REPLY nodata (NoAddrsAvail, pool {}/{} used)",
                                duid_s,
                                in_packet.transaction_id,
                                pool.len(),
                                pool.count()
                            );
                            let _ = send_v6_nodata(
                                &socket,
                                src,
                                &config.server_duid,
                                &duid,
                                &in_packet,
                                dhcpv6::MsgType::Reply,
                            );
                        }
                    }
                    continue;
                }
                if let Some(ip) = pool.discover(&duid) {
                    println!(
                        "v6 SOLICIT duid={} tid={:06x} -> ADVERTISE {}",
                        duid_s, in_packet.transaction_id, ip
                    );
                    let _ = send_v6(
                        &socket,
                        src,
                        &config.server_duid,
                        &duid,
                        &in_packet,
                        dhcpv6::MsgType::Advertise,
                        ip,
                        &config.ipv6_dns,
                        config.ipv6_lease_duration_secs,
                    );
                } else {
                    println!(
                        "v6 SOLICIT duid={} tid={:06x} -> ADVERTISE nodata (NoAddrsAvail, pool {}/{} used)",
                        duid_s,
                        in_packet.transaction_id,
                        pool.len(),
                        pool.count()
                    );
                    let _ = send_v6_nodata(
                        &socket,
                        src,
                        &config.server_duid,
                        &duid,
                        &in_packet,
                        dhcpv6::MsgType::Advertise,
                    );
                }
            }
            dhcpv6::MsgType::Request
            | dhcpv6::MsgType::Renew
            | dhcpv6::MsgType::Rebind => {
                let name = format!("{:?}", in_packet.msg_type);
                let wanted = in_packet
                    .first_iana()
                    .and_then(|ia| ia.addrs.first().map(|a| a.addr));
                match wanted {
                    None => println!(
                        "v6 {} duid={} tid={:06x} ignored (no IA_NA)",
                        name.to_uppercase(),
                        duid_s,
                        in_packet.transaction_id
                    ),
                    Some(addr) => match pool.request(&duid, addr) {
                        Ok(ip) => {
                            println!(
                                "v6 {} duid={} tid={:06x} want={} -> REPLY {}",
                                name.to_uppercase(),
                                duid_s,
                                in_packet.transaction_id,
                                addr,
                                ip
                            );
                            let _ = send_v6(
                                &socket,
                                src,
                                &config.server_duid,
                                &duid,
                                &in_packet,
                                dhcpv6::MsgType::Reply,
                                ip,
                                &config.ipv6_dns,
                                config.ipv6_lease_duration_secs,
                            );
                        }
                        Err(_) => {
                            println!(
                                "v6 {} duid={} tid={:06x} want={} -> REPLY nodata (requested address not available)",
                                name.to_uppercase(),
                                duid_s,
                                in_packet.transaction_id,
                                addr
                            );
                            let _ = send_v6_nodata(
                                &socket,
                                src,
                                &config.server_duid,
                                &duid,
                                &in_packet,
                                dhcpv6::MsgType::Reply,
                            );
                        }
                    },
                }
            }
            dhcpv6::MsgType::Release | dhcpv6::MsgType::Decline => {
                let name = format!("{:?}", in_packet.msg_type);
                if dhcpv6::is_for_server(&config.server_duid, &in_packet) {
                    if pool.release(&duid) {
                        println!(
                            "v6 {} duid={} tid={:06x} freed lease",
                            name.to_uppercase(),
                            duid_s,
                            in_packet.transaction_id
                        );
                    } else {
                        println!(
                            "v6 {} duid={} tid={:06x} no lease held",
                            name.to_uppercase(),
                            duid_s,
                            in_packet.transaction_id
                        );
                    }
                } else {
                    println!(
                        "v6 {} duid={} tid={:06x} ignored (server_id mismatch)",
                        name.to_uppercase(),
                        duid_s,
                        in_packet.transaction_id
                    );
                }
            }
            other => {
                println!(
                    "v6 {:?} tid={:06x} ignored (unsupported message type)",
                    other, in_packet.transaction_id
                );
            }
        }
    }
}

/// Successful Advertise/Reply for `ip`, echoing the request IAID and lease
/// lifetimes.
#[allow(clippy::too_many_arguments)]
fn send_v6(
    socket: &UdpSocket,
    dst: std::net::SocketAddr,
    server_duid: &[u8],
    client_duid: &[u8],
    req: &dhcpv6::Packet,
    msg_type: dhcpv6::MsgType,
    ip: Ipv6Addr,
    dns: &[Ipv6Addr],
    lease_secs: u32,
) -> std::io::Result<usize> {
    let iaid = req.first_iana().map(|ia| ia.iaid).unwrap_or(0);
    let (t1, t2) = dhcpv6::default_t1_t2(lease_secs);
    let mut options = vec![
        dhcpv6::Dhcpv6Option::ServerId(server_duid.to_vec()),
        dhcpv6::Dhcpv6Option::ClientId(client_duid.to_vec()),
        dhcpv6::Dhcpv6Option::IaNa(dhcpv6::IaNa {
            iaid,
            t1,
            t2,
            addrs: vec![dhcpv6::IaAddr {
                addr: ip,
                preferred: lease_secs,
                valid: lease_secs,
            }],
        }),
    ];
    if !dns.is_empty() {
        options.push(dhcpv6::Dhcpv6Option::DnsServers(dns.to_vec()));
    }
    let out = dhcpv6::Packet {
        msg_type,
        transaction_id: req.transaction_id,
        options,
    }
    .encode()
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;
    socket.send_to(&out, dst)
}

/// Failure Advertise/Reply: no addresses, top-level NoAddrsAvail status.
/// (Minimal simplification: RFC 8415 places the status inside the IA_NA.)
fn send_v6_nodata(
    socket: &UdpSocket,
    dst: std::net::SocketAddr,
    server_duid: &[u8],
    client_duid: &[u8],
    req: &dhcpv6::Packet,
    msg_type: dhcpv6::MsgType,
) -> std::io::Result<usize> {
    let iaid = req.first_iana().map(|ia| ia.iaid).unwrap_or(0);
    let out = dhcpv6::Packet {
        msg_type,
        transaction_id: req.transaction_id,
        options: vec![
            dhcpv6::Dhcpv6Option::ServerId(server_duid.to_vec()),
            dhcpv6::Dhcpv6Option::ClientId(client_duid.to_vec()),
            dhcpv6::Dhcpv6Option::IaNa(dhcpv6::IaNa {
                iaid,
                t1: 0,
                t2: 0,
                addrs: vec![],
            }),
            dhcpv6::Dhcpv6Option::StatusCode(
                dhcpv6::STATUS_NO_ADDRS_AVAIL,
                "NoAddrsAvail".to_string(),
            ),
        ],
    }
    .encode()
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;
    socket.send_to(&out, dst)
}
