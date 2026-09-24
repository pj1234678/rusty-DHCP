//! `dhcp.conf` configuration file support (zero dependencies).
//!
//! All server settings — previously hard-coded constants in
//! `examples/server.rs` — now live in a single `dhcp.conf` file using a
//! minimal `key = value` format:
//!
//! ```text
//! # lines starting with '#' or ';' are comments; blank lines are ignored
//! server_ip = 192.168.2.1
//! dns_ips   = 8.8.8.8, 8.8.4.4
//! ```
//!
//! Rules (locked by `tests/test_config.rs`):
//! - keys are case-insensitive; surrounding whitespace is trimmed;
//! - a trailing ` # comment` (whitespace + `#`) is stripped from values;
//! - duplicate keys: last occurrence wins;
//! - unknown keys are ignored (forward compatibility);
//! - a line without `=` (that is not blank/comment) is an error;
//! - empty keys and empty values are errors;
//! - every value is validated; failures name the key and line number.
//!
//! [`Config::defaults`] exactly matches the historical hard-coded constants,
//! so running without a `dhcp.conf` behaves exactly as before.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// All tunable server settings. See [`Config::defaults`] for the values the
/// server historically used when everything was hard-coded.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    // -- IPv4 (DHCPv4, RFC 2131) --
    pub server_ip: Ipv4Addr,
    pub ip_start: Ipv4Addr,
    pub lease_num: u32,
    pub subnet_mask: Ipv4Addr,
    pub router_ip: Ipv4Addr,
    pub dns_ips: Vec<Ipv4Addr>,
    /// Master switch for advertising NTP servers (DHCP option 42). Off by
    /// default so a missing config file preserves old behavior exactly
    /// (the old server never sent option 42).
    pub enable_ntp: bool,
    /// NTP servers advertised to clients (option 42), comma-separated.
    /// Only sent when `enable_ntp` is true and the list is non-empty.
    pub ntp_ips: Vec<Ipv4Addr>,
    /// Master switch for DHCP Rapid Commit (RFC 4039 option 80 for IPv4,
    /// RFC 8415 option 14 for IPv6): when true, a Solicit/Discover carrying
    /// the rapid-commit option is answered immediately (Reply/Ack) instead
    /// of Advertise/Offer. Off by default so a missing config file preserves
    /// old behavior exactly.
    pub enable_rapid_commit: bool,
    pub broadcast_ip: Ipv4Addr,
    /// Extra broadcast destinations for replies (comma-separated). Every
    /// broadcast-routed reply is sent to each address in
    /// [`Config::broadcasts`]: some clients/APs only accept the limited
    /// broadcast `255.255.255.255`, others only the subnet directed
    /// broadcast — listing both reaches both populations. Unicast replies
    /// are unaffected (sent once to the peer).
    pub extra_broadcast_ips: Vec<Ipv4Addr>,
    pub lease_duration_secs: u32,
    pub leases_file: String,
    pub listen_addr: SocketAddr,
    // -- IPv6 managed range (DHCPv6, RFC 8415) --
    pub enable_dhcpv6: bool,
    /// Server DUID served in SERVERID options (opaque bytes, 1..=128).
    pub server_duid: Vec<u8>,
    /// First address of the managed IPv6 pool.
    pub ipv6_start: Ipv6Addr,
    /// Number of addresses in the managed IPv6 pool.
    pub ipv6_lease_num: u64,
    pub ipv6_dns: Vec<Ipv6Addr>,
    pub ipv6_lease_duration_secs: u32,
    pub leases_file_v6: String,
    pub listen_addr_v6: SocketAddr,
}

impl Config {
    /// Defaults identical to the historical hard-coded constants
    /// (`examples/server.rs` before `dhcp.conf` existed). DHCPv6 is off by
    /// default so a missing config file preserves old behavior exactly.
    pub fn defaults() -> Config {
        Config {
            server_ip: Ipv4Addr::new(192, 168, 2, 1),
            ip_start: Ipv4Addr::new(192, 168, 2, 2),
            lease_num: 252,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router_ip: Ipv4Addr::new(192, 168, 2, 1),
            dns_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            enable_ntp: false,
            ntp_ips: vec![],
            enable_rapid_commit: false,
            broadcast_ip: Ipv4Addr::new(192, 168, 2, 255),
            extra_broadcast_ips: vec![],
            lease_duration_secs: 86400,
            leases_file: "leases".to_string(),
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 67)),
            enable_dhcpv6: false,
            server_duid: vec![
                0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0xaa, 0xbb, 0xcc,
            ],
            ipv6_start: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100),
            ipv6_lease_num: 1000,
            ipv6_dns: vec![Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)],
            ipv6_lease_duration_secs: 86400,
            leases_file_v6: "leases6".to_string(),
            listen_addr_v6: SocketAddr::from((
                Ipv6Addr::UNSPECIFIED,
                547,
            )),
        }
    }

    /// First usable IPv4 address as a number (pool is
    /// `[ip_start_num, ip_start_num + lease_num)`).
    pub fn ip_start_num(&self) -> u32 {
        u32::from_be_bytes(self.ip_start.octets())
    }

    /// First usable IPv6 address as a number (pool is
    /// `[ipv6_start_num, ipv6_start_num + ipv6_lease_num)`).
    pub fn ipv6_start_num(&self) -> u128 {
        u128::from(self.ipv6_start)
    }

    /// All broadcast destinations for replies, primary first,
    /// de-duplicated. Never empty (falls back to the primary alone).
    pub fn broadcasts(&self) -> Vec<Ipv4Addr> {
        let mut out = Vec::with_capacity(1 + self.extra_broadcast_ips.len());
        out.push(self.broadcast_ip);
        for ip in &self.extra_broadcast_ips {
            if !out.contains(ip) {
                out.push(*ip);
            }
        }
        out
    }

    /// Load and parse the file at `path`.
    pub fn load(path: &str) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {}", path, e))?;
        Config::parse(&text)
    }

    /// Parse `dhcp.conf` text; starts from [`Config::defaults`] and applies
    /// each key in order.
    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg = Config::defaults();
        for (idx, raw_line) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let eq = line.find('=').ok_or_else(|| {
                format!("{}: expected `key = value`, got {:?}", line_no, raw_line.trim())
            })?;
            let key = line[..eq].trim().to_lowercase();
            let mut value = line[eq + 1..].trim().to_string();
            // strip trailing " # comment" (whitespace + '#'); a '#' glued to
            // the value is kept verbatim.
            if let Some(pos) = value.find(" #").or_else(|| value.find('\t').and_then(|p| {
                if value[p + 1..].starts_with('#') {
                    Some(p)
                } else {
                    None
                }
            })) {
                value.truncate(pos);
                value = value.trim_end().to_string();
            }
            if key.is_empty() {
                return Err(format!("{}: empty key", line_no));
            }
            if value.is_empty() {
                return Err(format!("{}: empty value for key {:?}", line_no, key));
            }
            cfg.apply(&key, &value, line_no)?;
        }
        cfg.validate()
    }

    fn apply(&mut self, key: &str, value: &str, line: usize) -> Result<(), String> {
        let bad = |what: &str| format!("{}: invalid {} for key {:?}: {:?}", line, what, key, value);
        match key {
            "server_ip" => self.server_ip = value.parse().map_err(|_| bad("IPv4 address"))?,
            "ip_start" => self.ip_start = value.parse().map_err(|_| bad("IPv4 address"))?,
            "lease_num" => self.lease_num = value.parse().map_err(|_| bad("u32"))?,
            "subnet_mask" => self.subnet_mask = value.parse().map_err(|_| bad("IPv4 address"))?,
            "router_ip" => self.router_ip = value.parse().map_err(|_| bad("IPv4 address"))?,
            "dns_ips" => self.dns_ips = parse_ipv4_list(value).map_err(|_| bad("IPv4 list"))?,
            "enable_ntp" => self.enable_ntp = parse_bool(value).ok_or_else(|| bad("bool"))?,
            "ntp_ips" => self.ntp_ips = parse_ipv4_list(value).map_err(|_| bad("IPv4 list"))?,
            "enable_rapid_commit" => {
                self.enable_rapid_commit = parse_bool(value).ok_or_else(|| bad("bool"))?
            }
            "broadcast_ip" => {
                // Accepts a comma-separated list: the first address stays the
                // primary `broadcast_ip`, the rest extend
                // `extra_broadcast_ips` (de-duplicated by `broadcasts()`).
                let mut parts = value.split(',');
                let first = parts.next().ok_or_else(|| bad("IPv4 address"))?;
                self.broadcast_ip = first
                    .trim()
                    .parse()
                    .map_err(|_| bad("IPv4 address"))?;
                for part in parts {
                    self.extra_broadcast_ips.push(
                        part.trim().parse().map_err(|_| bad("IPv4 address"))?,
                    );
                }
            }
            "extra_broadcast_ips" => {
                let mut list =
                    parse_ipv4_list(value).map_err(|_| bad("IPv4 list"))?;
                self.extra_broadcast_ips.append(&mut list);
            }
            "lease_duration_secs" => {
                self.lease_duration_secs = value.parse().map_err(|_| bad("u32"))?
            }
            "leases_file" => self.leases_file = value.to_string(),
            "listen_addr" => {
                self.listen_addr = value.parse().map_err(|_| bad("socket address"))?
            }
            "enable_dhcpv6" => self.enable_dhcpv6 = parse_bool(value).ok_or_else(|| bad("bool"))?,
            "server_duid" => self.server_duid = parse_duid_hex(value).map_err(|_| bad("DUID hex"))?,
            "ipv6_start" => self.ipv6_start = value.parse().map_err(|_| bad("IPv6 address"))?,
            "ipv6_lease_num" => self.ipv6_lease_num = value.parse().map_err(|_| bad("u64"))?,
            "ipv6_dns" => self.ipv6_dns = parse_ipv6_list(value).map_err(|_| bad("IPv6 list"))?,
            "ipv6_lease_duration_secs" => {
                self.ipv6_lease_duration_secs = value.parse().map_err(|_| bad("u32"))?
            }
            "leases_file_v6" => self.leases_file_v6 = value.to_string(),
            "listen_addr_v6" => {
                self.listen_addr_v6 = value.parse().map_err(|_| bad("socket address"))?
            }
            // unknown keys are ignored for forward compatibility
            _ => {}
        }
        Ok(())
    }

    /// Cross-field validation: pool ranges must not overflow the address
    /// space, and the DUID must fit RFC 8415 limits (1..=128 bytes).
    fn validate(self) -> Result<Config, String> {
        if self.server_duid.is_empty() || self.server_duid.len() > 128 {
            return Err("server_duid must be 1..=128 bytes".to_string());
        }
        let v4_end = u64::from(self.ip_start_num()) + u64::from(self.lease_num);
        if v4_end > u64::from(u32::MAX) + 1 {
            return Err("ip_start + lease_num overflows IPv4 space".to_string());
        }
        if (self.ipv6_start_num())
            .checked_add(self.ipv6_lease_num as u128)
            .is_none()
        {
            return Err("ipv6_start + ipv6_lease_num overflows IPv6 space".to_string());
        }
        Ok(self)
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn parse_ipv4_list(s: &str) -> Result<Vec<Ipv4Addr>, String> {
    s.split(',')
        .map(|part| {
            part.trim()
                .parse::<Ipv4Addr>()
                .map_err(|e| format!("{:?}: {}", part.trim(), e))
        })
        .collect()
}

fn parse_ipv6_list(s: &str) -> Result<Vec<Ipv6Addr>, String> {
    s.split(',')
        .map(|part| {
            part.trim()
                .parse::<Ipv6Addr>()
                .map_err(|e| format!("{:?}: {}", part.trim(), e))
        })
        .collect()
}

/// Parse opaque hex bytes (a DUID), accepting `00:03:00:01...`, `00-03-...`
/// or plain `00030001...` (whitespace between bytes is also tolerated).
///
/// Used for `server_duid` values and the DUID field of `leases6` lines.
pub fn parse_duid_hex(s: &str) -> Result<Vec<u8>, String> {
    #[inline]
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut hi: Option<u8> = None;
    for &c in bytes {
        if c == b':' || c == b'-' || c == b' ' || c == b'\t' {
            continue;
        }
        let v = hex_val(c).ok_or_else(|| format!("invalid hex {:?}: {:?}", s, c as char))?;
        if let Some(h) = hi {
            out.push((h << 4) | v);
            hi = None;
        } else {
            hi = Some(v);
        }
    }
    if hi.is_some() || out.is_empty() {
        return Err(format!("odd-length hex: {:?}", s));
    }
    Ok(out)
}
