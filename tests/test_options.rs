//! Exact-functionality regression tests for `dhcp4r::options`.

use dhcp4r::options::*;
use std::net::Ipv4Addr;

#[test]
fn constants_have_exact_wire_values() {
    assert_eq!(SUBNET_MASK, 1);
    assert_eq!(TIME_OFFSET, 2);
    assert_eq!(ROUTER, 3);
    assert_eq!(TIME_SERVER, 4);
    assert_eq!(NAME_SERVER, 5);
    assert_eq!(DOMAIN_NAME_SERVER, 6);
    assert_eq!(LOG_SERVER, 7);
    assert_eq!(COOKIE_SERVER, 8);
    assert_eq!(LPR_SERVER, 9);
    assert_eq!(IMPRESS_SERVER, 10);
    assert_eq!(RESOURCE_LOCATION_SERVER, 11);
    assert_eq!(HOST_NAME, 12);
    assert_eq!(BOOT_FILE_SIZE, 13);
    assert_eq!(MERIT_DUMP_FILE, 14);
    assert_eq!(DOMAIN_NAME, 15);
    assert_eq!(SWAP_SERVER, 16);
    assert_eq!(ROOT_PATH, 17);
    assert_eq!(EXTENSIONS_PATH, 18);
    assert_eq!(IP_FORWARDING_ENABLE_DISABLE, 19);
    assert_eq!(NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE, 20);
    assert_eq!(POLICY_FILTER, 21);
    assert_eq!(MAXIMUM_DATAGRAM_REASSEMBLY_SIZE, 22);
    assert_eq!(DEFAULT_IP_TIME_TO_LIVE, 23);
    assert_eq!(PATH_MTU_AGING_TIMEOUT, 24);
    assert_eq!(PATH_MTU_PLATEAU_TABLE, 25);
    assert_eq!(INTERFACE_MTU, 26);
    assert_eq!(ALL_SUBNETS_ARE_LOCAL, 27);
    assert_eq!(BROADCAST_ADDRESS, 28);
    assert_eq!(PERFORM_MASK_DISCOVERY, 29);
    assert_eq!(MASK_SUPPLIER, 30);
    assert_eq!(PERFORM_ROUTER_DISCOVERY, 31);
    assert_eq!(ROUTER_SOLICITATION_ADDRESS, 32);
    assert_eq!(STATIC_ROUTE, 33);
    assert_eq!(TRAILER_ENCAPSULATION, 34);
    assert_eq!(ARP_CACHE_TIMEOUT, 35);
    assert_eq!(ETHERNET_ENCAPSULATION, 36);
    assert_eq!(TCP_DEFAULT_TTL, 37);
    assert_eq!(TCP_KEEPALIVE_INTERVAL, 38);
    assert_eq!(TCP_KEEPALIVE_GARBAGE, 39);
    assert_eq!(NETWORK_INFORMATION_SERVICE_DOMAIN, 40);
    assert_eq!(NETWORK_INFORMATION_SERVERS, 41);
    assert_eq!(NETWORK_TIME_PROTOCOL_SERVERS, 42);
    assert_eq!(VENDOR_SPECIFIC_INFORMATION, 43);
    assert_eq!(NETBIOS_OVER_TCPIP_NAME_SERVER, 44);
    assert_eq!(NETBIOS_OVER_TCPIP_DATAGRAM_DISTRIBUTION_SERVER, 45);
    assert_eq!(NETBIOS_OVER_TCPIP_NODE_TYPE, 46);
    assert_eq!(NETBIOS_OVER_TCPIP_SCOPE, 47);
    assert_eq!(XWINDOW_SYSTEM_FONT_SERVER, 48);
    assert_eq!(XWINDOW_SYSTEM_DISPLAY_MANAGER, 49);
    assert_eq!(REQUESTED_IP_ADDRESS, 50);
    assert_eq!(IP_ADDRESS_LEASE_TIME, 51);
    assert_eq!(OVERLOAD, 52);
    assert_eq!(DHCP_MESSAGE_TYPE, 53);
    assert_eq!(SERVER_IDENTIFIER, 54);
    assert_eq!(PARAMETER_REQUEST_LIST, 55);
    assert_eq!(MESSAGE, 56);
    assert_eq!(MAXIMUM_DHCP_MESSAGE_SIZE, 57);
    assert_eq!(RENEWAL_TIME_VALUE, 58);
    assert_eq!(REBINDING_TIME_VALUE, 59);
    assert_eq!(VENDOR_CLASS_IDENTIFIER, 60);
    assert_eq!(CLIENT_IDENTIFIER, 61);
    assert_eq!(NETWORK_INFORMATION_SERVICEPLUS_DOMAIN, 64);
    assert_eq!(NETWORK_INFORMATION_SERVICEPLUS_SERVERS, 65);
    assert_eq!(TFTP_SERVER_NAME, 66);
    assert_eq!(BOOTFILE_NAME, 67);
    assert_eq!(MOBILE_IP_HOME_AGENT, 68);
    assert_eq!(SIMPLE_MAIL_TRANSPORT_PROTOCOL, 69);
    assert_eq!(POST_OFFICE_PROTOCOL_SERVER, 70);
    assert_eq!(NETWORK_NEWS_TRANSPORT_PROTOCOL, 71);
    assert_eq!(DEFAULT_WORLD_WIDE_WEB_SERVER, 72);
    assert_eq!(DEFAULT_FINGER_SERVER, 73);
    assert_eq!(DEFAULT_INTERNET_RELAY_CHAT_SERVER, 74);
    assert_eq!(STREETTALK_SERVER, 75);
    assert_eq!(STREETTALK_DIRECTORY_ASSISTANCE, 76);
    assert_eq!(USER_CLASS, 77);
    assert_eq!(RAPID_COMMIT, 80);
    assert_eq!(RELAY_AGENT_INFORMATION, 82);
    assert_eq!(CLIENT_ARCHITECTURE, 93);
    assert_eq!(TZ_POSIX_STRING, 100);
    assert_eq!(TZ_DATABASE_STRING, 101);
    assert_eq!(CLASSLESS_ROUTE_FORMAT, 121);
}

#[test]
fn title_returns_exact_strings_for_known_codes() {
    let cases: &[(u8, &str)] = &[
        (1, "Subnet Mask"),
        (2, "Time Offset"),
        (3, "Router"),
        (4, "Time Server"),
        (5, "Name Server"),
        (6, "Domain Name Server"),
        (7, "Log Server"),
        (8, "Cookie Server"),
        (9, "LPR Server"),
        (10, "Impress Server"),
        (11, "Resource Location Server"),
        (12, "Host Name"),
        (13, "Boot File Size"),
        (14, "Merit Dump File"),
        (15, "Domain Name"),
        (16, "Swap Server"),
        (17, "Root Path"),
        (18, "Extensions Path"),
        (19, "IP Forwarding Enable/Disable"),
        (20, "Non-Local Source Routing Enable/Disable"),
        (21, "Policy Filter"),
        (22, "Maximum Datagram Reassembly Size"),
        (23, "Default IP Time-to-live"),
        (24, "Path MTU Aging Timeout"),
        (25, "Path MTU Plateau Table"),
        (26, "Interface MTU"),
        (27, "All Subnets are Local"),
        (28, "Broadcast Address"),
        (29, "Perform Mask Discovery"),
        (30, "Mask Supplier"),
        (31, "Perform Router Discovery"),
        (32, "Router Solicitation Address"),
        (33, "Static Route"),
        (34, "Trailer Encapsulation"),
        (35, "ARP Cache Timeout"),
        (36, "Ethernet Encapsulation"),
        (37, "TCP Default TTL"),
        (38, "TCP Keepalive Interval"),
        (39, "TCP Keepalive Garbage"),
        (40, "Network Information Service Domain"),
        (41, "Network Information Servers"),
        (42, "Network Time Protocol Servers"),
        (43, "Vendor Specific Information"),
        (44, "NetBIOS over TCP/IP Name Server"),
        (45, "NetBIOS over TCP/IP Datagram Distribution Server"),
        (46, "NetBIOS over TCP/IP Node Type"),
        (47, "NetBIOS over TCP/IP Scope"),
        (48, "X Window System Font Server"),
        (49, "X Window System Display Manager"),
        (50, "Requested IP Address"),
        (51, "IP Address Lease Time"),
        (52, "Overload"),
        (53, "DHCP Message Type"),
        (54, "Server Identifier"),
        (55, "Parameter Request List"),
        (56, "Message"),
        (57, "Maximum DHCP Message Size"),
        (58, "Renewal (T1) Time Value"),
        (59, "Rebinding (T2) Time Value"),
        (60, "Vendor class identifier"),
        (61, "Client-identifier"),
        (64, "Network Information Service+ Domain"),
        (65, "Network Information Service+ Servers"),
        (66, "TFTP server name"),
        (67, "Bootfile name"),
        (68, "Mobile IP Home Agent"),
        (69, "Simple Mail Transport Protocol (SMTP) Server"),
        (70, "Post Office Protocol (POP3) Server"),
        (71, "Network News Transport Protocol (NNTP) Server"),
        (72, "Default World Wide Web (WWW) Server"),
        (73, "Default Finger Server"),
        (74, "Default Internet Relay Chat (IRC) Server"),
        (75, "StreetTalk Server"),
        (76, "StreetTalk Directory Assistance (STDA) Server"),
        (77, "User Class"),
        (80, "Rapid Commit"),
        (82, "Relay Agent Information"),
        (93, "Client Architecture"),
        (100, "TZ-POSIX String"),
        (101, "TZ-Database String"),
        (121, "Classless Route Format"),
    ];
    for (code, expected) in cases {
        assert_eq!(title(*code), Some(*expected), "title({})", code);
    }
}

#[test]
fn title_returns_none_for_unknown_codes() {
    for code in [0u8, 62, 63, 78, 79, 81, 83, 99, 122, 200, 254, 255] {
        assert_eq!(title(code), None, "title({}) should be None", code);
    }
}

#[test]
fn message_type_from_valid_values() {
    assert_eq!(MessageType::from(1), Ok(MessageType::Discover));
    assert_eq!(MessageType::from(2), Ok(MessageType::Offer));
    assert_eq!(MessageType::from(3), Ok(MessageType::Request));
    assert_eq!(MessageType::from(4), Ok(MessageType::Decline));
    assert_eq!(MessageType::from(5), Ok(MessageType::Ack));
    assert_eq!(MessageType::from(6), Ok(MessageType::Nak));
    assert_eq!(MessageType::from(7), Ok(MessageType::Release));
    assert_eq!(MessageType::from(8), Ok(MessageType::Inform));
}

#[test]
fn message_type_discriminants_match_wire() {
    assert_eq!(MessageType::Discover as u8, 1);
    assert_eq!(MessageType::Offer as u8, 2);
    assert_eq!(MessageType::Request as u8, 3);
    assert_eq!(MessageType::Decline as u8, 4);
    assert_eq!(MessageType::Ack as u8, 5);
    assert_eq!(MessageType::Nak as u8, 6);
    assert_eq!(MessageType::Release as u8, 7);
    assert_eq!(MessageType::Inform as u8, 8);
}

#[test]
fn message_type_from_invalid_returns_err() {
    for v in [0u8, 9, 10, 100, 255] {
        let r = MessageType::from(v);
        assert!(r.is_err(), "from({}) should err", v);
        let msg = r.unwrap_err();
        assert!(msg.contains("Invalid DHCP Message Type"), "msg: {}", msg);
        assert!(msg.contains(&v.to_string()), "msg should contain value: {}", msg);
    }
}

#[test]
fn dhcp_option_code_matches_wire() {
    assert_eq!(DhcpOption::DhcpMessageType(MessageType::Discover).code(), 53);
    assert_eq!(DhcpOption::ServerIdentifier(Ipv4Addr::new(1, 2, 3, 4)).code(), 54);
    assert_eq!(DhcpOption::ParameterRequestList(vec![1]).code(), 55);
    assert_eq!(DhcpOption::RequestedIpAddress(Ipv4Addr::new(1, 2, 3, 4)).code(), 50);
    assert_eq!(DhcpOption::HostName("h".to_string()).code(), 12);
    assert_eq!(DhcpOption::Router(vec![]).code(), 3);
    assert_eq!(DhcpOption::DomainNameServer(vec![]).code(), 6);
    assert_eq!(DhcpOption::IpAddressLeaseTime(1).code(), 51);
    assert_eq!(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)).code(), 1);
    assert_eq!(DhcpOption::Message("m".to_string()).code(), 56);
    assert_eq!(
        DhcpOption::Unrecognized(RawDhcpOption { code: 99, data: vec![1] }).code(),
        99
    );
}

#[test]
fn dhcp_option_to_raw_message_type() {
    for (t, v) in [
        (MessageType::Discover, 1),
        (MessageType::Offer, 2),
        (MessageType::Request, 3),
        (MessageType::Decline, 4),
        (MessageType::Ack, 5),
        (MessageType::Nak, 6),
        (MessageType::Release, 7),
        (MessageType::Inform, 8),
    ] {
        let raw = DhcpOption::DhcpMessageType(t).to_raw();
        assert_eq!(raw.code, 53);
        assert_eq!(raw.data, vec![v]);
    }
}

#[test]
fn dhcp_option_to_raw_ipv4_single() {
    let raw = DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)).to_raw();
    assert_eq!(raw.code, 54);
    assert_eq!(raw.data, vec![192, 168, 1, 1]);

    let raw = DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 0, 0, 5)).to_raw();
    assert_eq!(raw.code, 50);
    assert_eq!(raw.data, vec![10, 0, 0, 5]);

    let raw = DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)).to_raw();
    assert_eq!(raw.code, 1);
    assert_eq!(raw.data, vec![255, 255, 255, 0]);
}

#[test]
fn dhcp_option_to_raw_prl_clones() {
    let prl = vec![1u8, 3, 6, 51];
    let raw = DhcpOption::ParameterRequestList(prl.clone()).to_raw();
    assert_eq!(raw.code, 55);
    assert_eq!(raw.data, prl);
}

#[test]
fn dhcp_option_to_raw_hostname_and_message() {
    let raw = DhcpOption::HostName("foo".to_string()).to_raw();
    assert_eq!(raw.code, 12);
    assert_eq!(raw.data, b"foo".to_vec());

    let raw = DhcpOption::HostName(String::new()).to_raw();
    assert_eq!(raw.code, 12);
    assert!(raw.data.is_empty());

    let raw = DhcpOption::Message("hello".to_string()).to_raw();
    assert_eq!(raw.code, 56);
    assert_eq!(raw.data, b"hello".to_vec());
}

#[test]
fn dhcp_option_to_raw_router_concatenates() {
    let raw = DhcpOption::Router(vec![]).to_raw();
    assert_eq!(raw.code, 3);
    assert!(raw.data.is_empty());

    let raw = DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]).to_raw();
    assert_eq!(raw.code, 3);
    assert_eq!(raw.data, vec![192, 168, 1, 1]);

    let raw = DhcpOption::Router(vec![
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(10, 0, 0, 1),
    ])
    .to_raw();
    assert_eq!(raw.code, 3);
    assert_eq!(raw.data, vec![192, 168, 1, 1, 10, 0, 0, 1]);
}

#[test]
fn dhcp_option_to_raw_dns_concatenates() {
    let raw = DhcpOption::DomainNameServer(vec![]).to_raw();
    assert_eq!(raw.code, 6);
    assert!(raw.data.is_empty());

    let raw = DhcpOption::DomainNameServer(vec![Ipv4Addr::new(8, 8, 8, 8)]).to_raw();
    assert_eq!(raw.code, 6);
    assert_eq!(raw.data, vec![8, 8, 8, 8]);

    let raw = DhcpOption::DomainNameServer(vec![
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(8, 8, 4, 4),
    ])
    .to_raw();
    assert_eq!(raw.code, 6);
    assert_eq!(raw.data, vec![8, 8, 8, 8, 8, 8, 4, 4]);
}

#[test]
fn dhcp_option_to_raw_lease_time_is_big_endian() {
    let raw = DhcpOption::IpAddressLeaseTime(86400).to_raw();
    assert_eq!(raw.code, 51);
    assert_eq!(raw.data, 86400u32.to_be_bytes().to_vec());
    assert_eq!(raw.data, vec![0, 1, 81, 128]);

    let raw = DhcpOption::IpAddressLeaseTime(0).to_raw();
    assert_eq!(raw.data, vec![0, 0, 0, 0]);

    let raw = DhcpOption::IpAddressLeaseTime(u32::MAX).to_raw();
    assert_eq!(raw.data, vec![255, 255, 255, 255]);
}

#[test]
fn dhcp_option_to_raw_unrecognized_clones() {
    let inner = RawDhcpOption { code: 200, data: vec![1, 2, 3] };
    let raw = DhcpOption::Unrecognized(inner.clone()).to_raw();
    assert_eq!(raw, inner);
}
