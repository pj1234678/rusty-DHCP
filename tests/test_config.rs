//! Tests for `dhcp.conf` parsing (`dhcp4r::config`).
//!
//! Locks that every setting is specifiable in the file, that the shipped
//! `dhcp.conf` parses to the documented values, and that malformed input
//! fails loudly (key + line info) instead of silently misconfiguring the
//! server. Also locks that `Config::defaults()` is byte-for-byte the old
//! hard-coded constants, so a missing file preserves legacy behavior.

use dhcp4r::config::{parse_duid_hex, Config};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

fn defaults() -> Config {
    Config::defaults()
}

#[test]
fn defaults_match_legacy_hardcoded_values() {
    let c = defaults();
    assert_eq!(c.server_ip, Ipv4Addr::new(192, 168, 2, 1));
    assert_eq!(c.ip_start, Ipv4Addr::new(192, 168, 2, 2));
    assert_eq!(c.lease_num, 252);
    assert_eq!(c.subnet_mask, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(c.router_ip, Ipv4Addr::new(192, 168, 2, 1));
    assert_eq!(c.dns_ips, vec![Ipv4Addr::new(8, 8, 8, 8)]);
    assert_eq!(c.broadcast_ip, Ipv4Addr::new(192, 168, 2, 255));
    assert_eq!(c.lease_duration_secs, 86400);
    assert_eq!(c.leases_file, "leases");
    assert_eq!(c.listen_addr, SocketAddr::from(([0, 0, 0, 0], 67)));
    // v6 off by default: missing file behaves exactly like the old server
    assert!(!c.enable_dhcpv6);
    // rapid commit off by default: legacy 4-message behavior preserved
    assert!(!c.enable_rapid_commit);
    assert_eq!(
        c.server_duid,
        vec![0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0xaa, 0xbb, 0xcc]
    );
    assert_eq!(c.ipv6_start, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100));
    assert_eq!(c.ipv6_lease_num, 1000);
    assert_eq!(
        c.ipv6_dns,
        vec![Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)]
    );
    assert_eq!(c.ipv6_lease_duration_secs, 86400);
    assert_eq!(c.leases_file_v6, "leases6");
    assert_eq!(
        c.listen_addr_v6,
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 547))
    );
}

#[test]
fn start_num_helpers() {
    let c = defaults();
    assert_eq!(c.ip_start_num(), 0xC0A8_0202);
    assert_eq!(c.ip_start_num(), 3232236034);
    assert_eq!(
        c.ipv6_start_num(),
        u128::from(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x100))
    );
}

#[test]
fn parse_full_sample_sets_every_field() {
    let text = "\
server_ip = 10.0.0.1
ip_start = 10.0.1.10
lease_num = 100
subnet_mask = 255.255.0.0
router_ip = 10.0.0.254
dns_ips = 1.1.1.1, 1.0.0.1
broadcast_ip = 10.0.255.255
lease_duration_secs = 3600
leases_file = custom.leases
listen_addr = 127.0.0.1:6767
enable_dhcpv6 = yes
server_duid = 00:01:00:01:02:03:04:05:06:07
ipv6_start = 2001:db8::100
ipv6_lease_num = 500
ipv6_dns = 2001:db8::53, 2001:db8::54
ipv6_lease_duration_secs = 7200
leases_file_v6 = custom6.leases
listen_addr_v6 = [::1]:5547
";
    let c = Config::parse(text).unwrap();
    assert_eq!(c.server_ip, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(c.ip_start, Ipv4Addr::new(10, 0, 1, 10));
    assert_eq!(c.lease_num, 100);
    assert_eq!(c.subnet_mask, Ipv4Addr::new(255, 255, 0, 0));
    assert_eq!(c.router_ip, Ipv4Addr::new(10, 0, 0, 254));
    assert_eq!(c.dns_ips, vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)]);
    assert_eq!(c.broadcast_ip, Ipv4Addr::new(10, 0, 255, 255));
    assert_eq!(c.lease_duration_secs, 3600);
    assert_eq!(c.leases_file, "custom.leases");
    assert_eq!(c.listen_addr, "127.0.0.1:6767".parse::<SocketAddr>().unwrap());
    assert!(c.enable_dhcpv6);
    assert_eq!(
        c.server_duid,
        vec![0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
    );
    assert_eq!(c.ipv6_start, "2001:db8::100".parse::<Ipv6Addr>().unwrap());
    assert_eq!(c.ipv6_lease_num, 500);
    assert_eq!(
        c.ipv6_dns,
        vec![
            "2001:db8::53".parse::<Ipv6Addr>().unwrap(),
            "2001:db8::54".parse::<Ipv6Addr>().unwrap(),
        ]
    );
    assert_eq!(c.ipv6_lease_duration_secs, 7200);
    assert_eq!(c.leases_file_v6, "custom6.leases");
    assert_eq!(c.listen_addr_v6, "[::1]:5547".parse::<SocketAddr>().unwrap());
}

#[test]
fn comments_blanks_and_whitespace_tolerated() {
    let text = "# leading comment\n; semicolon comment\n\n   \nserver_ip=10.1.2.3\n\tlease_num\t=\t7\n";
    let c = Config::parse(text).unwrap();
    assert_eq!(c.server_ip, Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(c.lease_num, 7);
    // everything else stayed default
    assert_eq!(c.subnet_mask, defaults().subnet_mask);
}

#[test]
fn keys_case_insensitive_and_duplicate_last_wins() {
    let c = Config::parse("SERVER_IP = 10.0.0.9\nServer_Ip = 10.0.0.10\n").unwrap();
    assert_eq!(c.server_ip, Ipv4Addr::new(10, 0, 0, 10));
}

#[test]
fn unknown_keys_ignored_for_forward_compat() {
    let c = Config::parse("future_knob = 123\nserver_ip = 10.9.9.9\n").unwrap();
    assert_eq!(c.server_ip, Ipv4Addr::new(10, 9, 9, 9));
}

#[test]
fn trailing_hash_comment_stripped_glued_hash_kept() {
    let c = Config::parse("lease_num = 5 # five leases\n").unwrap();
    assert_eq!(c.lease_num, 5);
    // no whitespace before '#': kept verbatim -> invalid IPv4 -> error naming key
    let err = Config::parse("server_ip = 1.2.3.4#x\n").unwrap_err();
    assert!(err.contains("server_ip"), "unexpected: {}", err);
}

#[test]
fn bool_variants_accepted() {
    for truthy in ["true", "True", "TRUE", "yes", "YES", "on", "ON", "1"] {
        let c = Config::parse(&format!("enable_dhcpv6 = {}\n", truthy)).unwrap();
        assert!(c.enable_dhcpv6, "{}", truthy);
    }
    for falsy in ["false", "False", "FALSE", "no", "NO", "off", "OFF", "0"] {
        let c = Config::parse(&format!("enable_dhcpv6 = {}\n", falsy)).unwrap();
        assert!(!c.enable_dhcpv6, "{}", falsy);
    }
    for bad in ["2", "maybe", "onoff", ""] {
        let text = if bad.is_empty() {
            "enable_dhcpv6 =\n".to_string()
        } else {
            format!("enable_dhcpv6 = {}\n", bad)
        };
        let err = Config::parse(&text).unwrap_err();
        assert!(err.contains("enable_dhcpv6"), "unexpected: {}", err);
    }
}

#[test]
fn malformed_lines_error_with_line_numbers() {
    let err = Config::parse("server_ip 10.0.0.1\n").unwrap_err();
    assert!(err.contains('1'), "unexpected: {}", err);
    let err = Config::parse("server_ip = 10.0.0.1\n=oops\n").unwrap_err();
    assert!(err.contains('2'), "unexpected: {}", err);
    let err = Config::parse("   = 10.0.0.1\n").unwrap_err();
    assert!(err.contains("empty key"), "unexpected: {}", err);
    let err = Config::parse("lease_num =\n").unwrap_err();
    assert!(err.contains("empty value"), "unexpected: {}", err);
}

#[test]
fn invalid_values_name_the_key() {
    let cases = [
        ("lease_num = abc\n", "lease_num"),
        ("lease_num = 4294967296\n", "lease_num"), // 2^32
        ("server_ip = 999.1.1.1\n", "server_ip"),
        ("dns_ips = 8.8.8.8, bogus\n", "dns_ips"),
        ("dns_ips = 8.8.8.8,\n", "dns_ips"), // trailing comma
        ("ipv6_start = not-an-ip\n", "ipv6_start"),
        ("ipv6_dns = ::1, nope\n", "ipv6_dns"),
        ("ipv6_lease_num = -5\n", "ipv6_lease_num"),
        ("listen_addr = 0.0.0.0:notaport\n", "listen_addr"),
        ("listen_addr_v6 = [::]:99999\n", "listen_addr_v6"),
        ("server_duid = 00:03:0\n", "server_duid"), // odd digits
        ("server_duid = 00:zz\n", "server_duid"),   // non-hex
        ("lease_duration_secs = 1.5\n", "lease_duration_secs"),
    ];
    for (text, key) in cases {
        let err = Config::parse(text).unwrap_err();
        assert!(err.contains(key), "{} should name {:?}: {}", text.trim(), key, err);
    }
}

#[test]
fn duid_length_limits() {
    // empty and >128 bytes rejected
    assert!(Config::parse("server_duid = \n").is_err());
    let too_long = "aa:".repeat(129) + "bb";
    assert!(Config::parse(&format!("server_duid = {}\n", too_long)).is_err());
    // exactly 128 bytes accepted
    let max = vec!["aa"; 128].join(":");
    let c = Config::parse(&format!("server_duid = {}\n", max)).unwrap();
    assert_eq!(c.server_duid.len(), 128);
    // single byte accepted
    let c = Config::parse("server_duid = ff\n").unwrap();
    assert_eq!(c.server_duid, vec![0xff]);
}

#[test]
fn pool_overflow_rejected() {
    // 255.255.255.255 + 2 as an exclusive end exceeds u32 space
    let err = Config::parse("ip_start = 255.255.255.255\nlease_num = 2\n").unwrap_err();
    assert!(err.contains("overflows"), "unexpected: {}", err);
    // 255.255.255.255 + 1 is exactly the end (exclusive) — allowed
    assert!(Config::parse("ip_start = 255.255.255.255\nlease_num = 1\n").is_ok());
    // 255.255.255.255 + 0 is exactly the end (exclusive) — allowed
    assert!(Config::parse("ip_start = 255.255.255.255\nlease_num = 0\n").is_ok());
    // v6: max addr + 1 overflows u128
    let err = Config::parse(
        "ipv6_start = ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\nipv6_lease_num = 1\n",
    )
    .unwrap_err();
    assert!(err.contains("overflows"), "unexpected: {}", err);
}

#[test]
fn zero_lease_num_allowed() {
    let c = Config::parse("lease_num = 0\nipv6_lease_num = 0\n").unwrap();
    assert_eq!(c.lease_num, 0);
    assert_eq!(c.ipv6_lease_num, 0);
}

#[test]
fn load_missing_file_errors() {
    let err = Config::load("definitely-not-a-real-dhcp-conf-12345.conf").unwrap_err();
    assert!(err.contains("cannot read"), "unexpected: {}", err);
}

#[test]
fn shipped_dhcp_conf_parses_to_documented_values() {
    // Runs with CWD = package root under `cargo test`, where dhcp.conf ships.
    let c = Config::load("dhcp.conf").unwrap();
    let d = defaults();
    // v4 section mirrors the legacy constants
    assert_eq!(c.server_ip, d.server_ip);
    assert_eq!(c.ip_start, d.ip_start);
    assert_eq!(c.lease_num, d.lease_num);
    assert_eq!(c.subnet_mask, d.subnet_mask);
    assert_eq!(c.router_ip, d.router_ip);
    assert_eq!(c.dns_ips, d.dns_ips);
    // NTP section is enabled in the shipped file (differs from defaults)
    assert!(c.enable_ntp);
    assert_eq!(c.ntp_ips, vec![Ipv4Addr::new(192, 168, 2, 1)]);
    assert_eq!(c.broadcast_ip, d.broadcast_ip);
    assert_eq!(c.lease_duration_secs, d.lease_duration_secs);
    assert_eq!(c.leases_file, "leases");
    assert_eq!(c.listen_addr, d.listen_addr);
    // v6 section is the managed range from the README table
    assert!(c.enable_dhcpv6);
    assert_eq!(c.server_duid, d.server_duid);
    assert_eq!(c.ipv6_start, d.ipv6_start);
    assert_eq!(c.ipv6_lease_num, d.ipv6_lease_num);
    assert_eq!(c.ipv6_dns, d.ipv6_dns);
    assert_eq!(c.ipv6_lease_duration_secs, d.ipv6_lease_duration_secs);
    assert_eq!(c.leases_file_v6, "leases6");
    assert_eq!(c.listen_addr_v6, d.listen_addr_v6);
    // Rapid Commit section is enabled in the shipped file too.
    assert!(c.enable_rapid_commit);
    // Rapid Commit section is enabled in the shipped file too.
    assert!(c.enable_rapid_commit);
    // full-struct equality: file must not drift from any default silently
    let mut expected = d;
    expected.enable_dhcpv6 = true;
    expected.enable_ntp = true;
    expected.ntp_ips = vec![Ipv4Addr::new(192, 168, 2, 1)];
    expected.enable_rapid_commit = true;
    assert_eq!(c, expected);
}

#[test]
fn parse_duid_hex_forms() {
    assert_eq!(
        parse_duid_hex("00:03:00:01:02:00:5e:aa:bb:cc").unwrap(),
        vec![0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0xaa, 0xbb, 0xcc]
    );
    assert_eq!(
        parse_duid_hex("00-03-00-01").unwrap(),
        vec![0x00, 0x03, 0x00, 0x01]
    );
    assert_eq!(parse_duid_hex("00030001").unwrap(), vec![0x00, 0x03, 0x00, 0x01]);
    assert_eq!(parse_duid_hex("AA BB").unwrap(), vec![0xaa, 0xbb]);
    assert!(parse_duid_hex("").is_err());
    assert!(parse_duid_hex("0").is_err());
    assert!(parse_duid_hex("zz").is_err());
}

// ---------------------------------------------------------------------------
// coverage gaps: socket forms, line endings, values with spaces, negatives
// ---------------------------------------------------------------------------

#[test]
fn ipv6_bracketless_socket_fails() {
    // SocketAddr requires brackets around IPv6 hosts with ports.
    let err = Config::parse("listen_addr_v6 = ::1:547\n").unwrap_err();
    assert!(err.contains("listen_addr_v6"), "unexpected: {}", err);
}

#[test]
fn crlf_line_endings_ok() {
    let c = Config::parse("server_ip = 10.0.0.1\r\nlease_num = 7\r\n").unwrap();
    assert_eq!(c.server_ip, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(c.lease_num, 7);
}

#[test]
fn values_with_spaces_preserved() {
    let c = Config::parse("leases_file = my leases.conf\nleases_file_v6 = v6 leases.conf\n").unwrap();
    assert_eq!(c.leases_file, "my leases.conf");
    assert_eq!(c.leases_file_v6, "v6 leases.conf");
}

#[test]
fn negative_numbers_rejected() {
    for (text, key) in [
        ("lease_num = -1\n", "lease_num"),
        ("lease_duration_secs = -60\n", "lease_duration_secs"),
        ("ipv6_lease_num = -1\n", "ipv6_lease_num"),
    ] {
        let err = Config::parse(text).unwrap_err();
        assert!(err.contains(key), "{} should name {:?}: {}", text.trim(), key, err);
    }
}

#[test]
fn rapid_commit_defaults_disabled() {
    assert!(!defaults().enable_rapid_commit);
}

#[test]
fn rapid_commit_parses_flag() {
    for truthy in ["true", "yes", "on", "1", "True"] {
        let c = Config::parse(&format!("enable_rapid_commit = {}\n", truthy)).unwrap();
        assert!(c.enable_rapid_commit, "{}", truthy);
    }
    for falsy in ["false", "no", "off", "0", "False"] {
        let c = Config::parse(&format!("enable_rapid_commit = {}\n", falsy)).unwrap();
        assert!(!c.enable_rapid_commit, "{}", falsy);
    }
    let err = Config::parse("enable_rapid_commit = eventually\n").unwrap_err();
    assert!(err.contains("enable_rapid_commit"), "unexpected: {}", err);
    assert_eq!(
        Config::parse("ENABLE_RAPID_COMMIT = YES\n").map(|c| c.enable_rapid_commit),
        Ok(true),
        "keys are case-insensitive"
    );
}

// ---------------------------------------------------------------------------
// NTP settings (option 42)
// ---------------------------------------------------------------------------

#[test]
fn ntp_defaults_disabled_with_empty_list() {
    // Legacy behavior: the old hardcoded server never sent option 42.
    let c = defaults();
    assert!(!c.enable_ntp);
    assert!(c.ntp_ips.is_empty());
}

#[test]
fn ntp_parses_flag_and_server_list() {
    let c = Config::parse("enable_ntp = true\nntp_ips = 192.168.2.1, 192.168.2.2\n").unwrap();
    assert!(c.enable_ntp);
    assert_eq!(c.ntp_ips, vec![Ipv4Addr::new(192, 168, 2, 1), Ipv4Addr::new(192, 168, 2, 2)]);
    let c = Config::parse("ENABLE_NTP = Yes\nNTP_IPS = 10.0.0.5\n").unwrap();
    assert!(c.enable_ntp);
    assert_eq!(c.ntp_ips, vec![Ipv4Addr::new(10, 0, 0, 5)]);
    let c = Config::parse("enable_ntp = off\n").unwrap();
    assert!(!c.enable_ntp);
}

#[test]
fn ntp_invalid_values_name_the_key() {
    let err = Config::parse("enable_ntp = sometimes\n").unwrap_err();
    assert!(err.contains("enable_ntp"), "unexpected: {}", err);
    let err = Config::parse("ntp_ips = 8.8.8.8, bogus\n").unwrap_err();
    assert!(err.contains("ntp_ips"), "unexpected: {}", err);
    let err = Config::parse("ntp_ips = 8.8.8.8,\n").unwrap_err();
    assert!(err.contains("ntp_ips"), "unexpected: {}", err);
}

#[test]
fn broadcast_ip_comma_list_and_extra_key() {
    // Single value keeps legacy shape: primary set, no extras.
    let c = Config::parse("broadcast_ip = 10.0.255.255\n").unwrap();
    assert_eq!(c.broadcast_ip, Ipv4Addr::new(10, 0, 255, 255));
    assert!(c.extra_broadcast_ips.is_empty());
    assert_eq!(c.broadcasts(), vec![Ipv4Addr::new(10, 0, 255, 255)]);
    // Comma form from the issue: first stays primary, rest are extras.
    let c =
        Config::parse("broadcast_ip = 192.168.2.255, 255.255.255.255\n").unwrap();
    assert_eq!(c.broadcast_ip, Ipv4Addr::new(192, 168, 2, 255));
    assert_eq!(
        c.extra_broadcast_ips,
        vec![Ipv4Addr::new(255, 255, 255, 255)]
    );
    assert_eq!(
        c.broadcasts(),
        vec![
            Ipv4Addr::new(192, 168, 2, 255),
            Ipv4Addr::new(255, 255, 255, 255)
        ]
    );
    // Dedicated key appends; duplicates collapse in broadcasts().
    let c = Config::parse(
        "broadcast_ip = 192.168.2.255\nextra_broadcast_ips = 255.255.255.255, 192.168.2.255\n",
    )
    .unwrap();
    assert_eq!(
        c.broadcasts(),
        vec![
            Ipv4Addr::new(192, 168, 2, 255),
            Ipv4Addr::new(255, 255, 255, 255)
        ]
    );
    // Invalid entries fail loudly naming the key (no silent misroute).
    // (Note: 255.255.255.0 is a *valid* address and parses fine.)
    let err = Config::parse("broadcast_ip = 192.168.2.255, bogus\n").unwrap_err();
    assert!(err.contains("broadcast_ip"), "unexpected: {}", err);
    let err = Config::parse("extra_broadcast_ips = bogus\n").unwrap_err();
    assert!(err.contains("extra_broadcast_ips"), "unexpected: {}", err);
    // Defaults carry no extras (legacy single-destination behavior).
    assert!(defaults().extra_broadcast_ips.is_empty());
    assert_eq!(
        defaults().broadcasts(),
        vec![Ipv4Addr::new(192, 168, 2, 255)]
    );
}


