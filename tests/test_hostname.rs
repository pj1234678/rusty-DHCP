//! Tests for DHCP option 12 (Host Name) tracking in `examples/server.rs`.
//!
//! The library codec for option 12 already round-trips (see `test_packet.rs`);
//! what was missing was any *server-side* use: leases stored only
//! `(mac, expiry)`, and neither the server logs nor the monitor showed the
//! name. The example now stores the announced name per lease, refreshes it
//! whenever a packet carries one, and the monitor prints it.
//!
//! Following this repo's convention, `HostnameServer` below mirrors the
//! example's arms body-for-body (Discover incl. rapid-commit insert,
//! Request, Release) but returns values instead of sending on a socket.
//! Naming rule locked throughout: a packet *with* option 12 sets the stored
//! name (even to empty); a packet *without* it leaves the stored name
//! untouched, so renewals that omit it don't flap the recorded name.

use dhcp4r::{options, packet};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::time::{Duration, Instant};

const IP_START: [u8; 4] = [192, 168, 2, 2];
const IP_START_NUM: u32 = u32::from_be_bytes(IP_START);
const LEASE_NUM: u32 = 252;
const LEASE_SECS: u32 = 86400;

/// Same body as the `hostname_of` helper in `examples/server.rs`.
fn hostname_of(in_packet: &packet::Packet) -> Option<String> {
    match in_packet.option(options::HOST_NAME) {
        Some(options::DhcpOption::HostName(name)) => Some(name.clone()),
        _ => None,
    }
}

/// Same display rule as `examples/monitor.rs`: "-" when absent.
fn display_name(name: &Option<String>) -> String {
    match name {
        Some(n) => n.clone(),
        _ => "-".to_string(),
    }
}

struct HostnameServer {
    leases: HashMap<Ipv4Addr, ([u8; 6], Option<Instant>, Option<String>)>,
    last_lease: u32,
    lease_duration: Duration,
    enable_rapid_commit: bool,
}

impl HostnameServer {
    fn new(rapid: bool) -> Self {
        Self {
            leases: HashMap::new(),
            last_lease: 0,
            lease_duration: Duration::from_secs(LEASE_SECS as u64),
            enable_rapid_commit: rapid,
        }
    }
    fn available(&self, chaddr: &[u8; 6], addr: &Ipv4Addr) -> bool {
        let pos: u32 = (*addr).into();
        pos >= IP_START_NUM
            && pos < IP_START_NUM + LEASE_NUM
            && match self.leases.get(addr) {
                Some((mac, expiry, _)) => {
                    *mac == *chaddr || expiry.map_or(true, |exp| Instant::now().gt(&exp))
                }
                None => true,
            }
    }
    fn current_lease(&self, chaddr: &[u8; 6]) -> Option<Ipv4Addr> {
        for (i, v) in &self.leases {
            if v.0 == *chaddr {
                return Some(*i);
            }
        }
        None
    }
    fn remember_hostname(&mut self, ip: &Ipv4Addr, hostname: &Option<String>) {
        if let (Some(name), Some(entry)) = (hostname, self.leases.get_mut(ip)) {
            entry.2 = Some(name.clone());
        }
    }
    fn name_of(&self, ip: &Ipv4Addr) -> Option<Option<String>> {
        self.leases.get(ip).map(|(_, _, name)| name.clone())
    }
    // Mirrors the Discover arm (rapid branch + legacy path), pure return.
    fn discover(&mut self, p: &packet::Packet) -> Option<Ipv4Addr> {
        let hostname = hostname_of(p);
        if self.enable_rapid_commit && p.option(options::RAPID_COMMIT).is_some() {
            if let Some(ip) = self.current_lease(&p.chaddr) {
                self.remember_hostname(&ip, &hostname);
                return Some(ip);
            }
            for _ in 0..LEASE_NUM {
                self.last_lease = (self.last_lease + 1) % LEASE_NUM;
                let cand: Ipv4Addr = (IP_START_NUM + self.last_lease).into();
                if self.available(&p.chaddr, &cand) {
                    self.leases.insert(
                        cand,
                        (
                            p.chaddr,
                            Some(Instant::now().add(self.lease_duration)),
                            hostname.clone(),
                        ),
                    );
                    return Some(cand);
                }
            }
            return None;
        }
        if let Some(ip) = self.current_lease(&p.chaddr) {
            self.remember_hostname(&ip, &hostname);
            return Some(ip);
        }
        for _ in 0..LEASE_NUM {
            self.last_lease = (self.last_lease + 1) % LEASE_NUM;
            let cand: Ipv4Addr = (IP_START_NUM + self.last_lease).into();
            if self.available(&p.chaddr, &cand) {
                return Some(cand);
            }
        }
        None
    }
    // Mirrors the Request arm (RequestedIp else ciaddr; current wins with
    // refresh; unavailable NAKs; else insert). for_this gate omitted like the
    // example (commented out upstream).
    fn request(
        &mut self,
        p: &packet::Packet,
        requested: Option<Ipv4Addr>,
    ) -> Result<Ipv4Addr, &'static str> {
        let hostname = hostname_of(p);
        let req_ip = requested.unwrap_or(p.ciaddr);
        if let Some(ip) = self.current_lease(&p.chaddr) {
            self.remember_hostname(&ip, &hostname);
            return Ok(ip);
        }
        if !self.available(&p.chaddr, &req_ip) {
            return Err("Requested IP not available");
        }
        self.leases.insert(
            req_ip,
            (
                p.chaddr,
                Some(Instant::now().add(self.lease_duration)),
                hostname.clone(),
            ),
        );
        Ok(req_ip)
    }
    fn release(&mut self, chaddr: &[u8; 6], for_this: bool) -> bool {
        if !for_this {
            return false;
        }
        if let Some(ip) = self.current_lease(chaddr) {
            self.leases.remove(&ip);
            return true;
        }
        false
    }
}

fn discover_pkt(chaddr: [u8; 6], hostname: Option<&str>) -> packet::Packet {
    let mut options = vec![options::DhcpOption::DhcpMessageType(
        options::MessageType::Discover,
    )];
    if let Some(name) = hostname {
        options.push(options::DhcpOption::HostName(name.to_string()));
    }
    packet::Packet {
        reply: false,
        hops: 0,
        xid: 1,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr,
        options,
    }
}

fn request_pkt(
    chaddr: [u8; 6],
    requested: Option<Ipv4Addr>,
    hostname: Option<&str>,
) -> packet::Packet {
    let mut options = vec![options::DhcpOption::DhcpMessageType(
        options::MessageType::Request,
    )];
    if let Some(ip) = requested {
        options.push(options::DhcpOption::RequestedIpAddress(ip));
    }
    if let Some(name) = hostname {
        options.push(options::DhcpOption::HostName(name.to_string()));
    }
    packet::Packet {
        reply: false,
        hops: 0,
        xid: 2,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr,
        options,
    }
}

/// Build a raw DHCP packet: 236-byte BOOTP header + cookie + options bytes.
fn make_raw(chaddr: [u8; 6], opts_after_cookie: Vec<u8>) -> Vec<u8> {
    let mut v = vec![0u8; 236];
    v[0] = 1;
    v[1] = 1;
    v[2] = 6;
    v[28..34].copy_from_slice(&chaddr);
    v.extend_from_slice(&[99, 130, 83, 99]);
    v.extend_from_slice(&opts_after_cookie);
    v
}

fn unwrap_packet(r: Result<packet::Packet, packet::CustomErr<&[u8]>>) -> packet::Packet {
    match r {
        Ok(p) => p,
        Err(_) => panic!("expected Ok Packet"),
    }
}

// ---------------------------------------------------------------------------
// insert + refresh semantics
// ---------------------------------------------------------------------------

#[test]
fn request_inserts_hostname() {
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 10);
    let p = request_pkt([1; 6], Some(ip), Some("laptop"));
    assert_eq!(s.request(&p, Some(ip)), Ok(ip));
    assert_eq!(s.name_of(&ip), Some(Some("laptop".to_string())));
}

#[test]
fn request_without_hostname_stores_none() {
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 11);
    let p = request_pkt([2; 6], Some(ip), None);
    assert_eq!(s.request(&p, Some(ip)), Ok(ip));
    assert_eq!(s.name_of(&ip), Some(None));
}

#[test]
fn request_empty_hostname_stored_verbatim() {
    // Empty string decodes fine, so it is stored as-is (no normalization).
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 12);
    let p = request_pkt([3; 6], Some(ip), Some(""));
    assert_eq!(s.request(&p, Some(ip)), Ok(ip));
    assert_eq!(s.name_of(&ip), Some(Some("".to_string())));
}

#[test]
fn discover_refreshes_hostname_on_existing_lease() {
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 13);
    assert_eq!(s.request(&request_pkt([4; 6], Some(ip), None), Some(ip)), Ok(ip));
    assert_eq!(s.name_of(&ip), Some(None));
    assert_eq!(s.leases.len(), 1);
    // later Discover announces a name: same IP, name recorded, no new entry
    assert_eq!(s.discover(&discover_pkt([4; 6], Some("laptop"))), Some(ip));
    assert_eq!(s.name_of(&ip), Some(Some("laptop".to_string())));
    assert_eq!(s.leases.len(), 1, "refresh must not duplicate the lease");
}

#[test]
fn discover_without_hostname_preserves_stored_name() {
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 14);
    assert_eq!(
        s.request(&request_pkt([5; 6], Some(ip), Some("kept")), Some(ip)),
        Ok(ip)
    );
    // renewals that omit option 12 must not clear the recorded name
    assert_eq!(s.discover(&discover_pkt([5; 6], None)), Some(ip));
    assert_eq!(s.name_of(&ip), Some(Some("kept".to_string())));
}

#[test]
fn request_renew_refreshes_hostname() {
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 15);
    assert_eq!(s.request(&request_pkt([6; 6], Some(ip), Some("old")), Some(ip)), Ok(ip));
    // renew path (current lease hit) with a new name updates it in place
    assert_eq!(
        s.request(&request_pkt([6; 6], Some(ip), Some("new")), Some(ip)),
        Ok(ip)
    );
    assert_eq!(s.name_of(&ip), Some(Some("new".to_string())));
    assert_eq!(s.leases.len(), 1);
}

#[test]
fn request_renew_without_hostname_preserves_name() {
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 16);
    assert_eq!(s.request(&request_pkt([7; 6], Some(ip), Some("kept")), Some(ip)), Ok(ip));
    assert_eq!(s.request(&request_pkt([7; 6], Some(ip), None), Some(ip)), Ok(ip));
    assert_eq!(s.name_of(&ip), Some(Some("kept".to_string())));
}

// ---------------------------------------------------------------------------
// lifecycle: release removes the name with the lease
// ---------------------------------------------------------------------------

#[test]
fn release_removes_hostname_with_lease() {
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 17);
    assert_eq!(s.request(&request_pkt([8; 6], Some(ip), Some("gone")), Some(ip)), Ok(ip));
    assert!(s.release(&[8; 6], true));
    assert_eq!(s.name_of(&ip), None, "name goes away with the lease");
    assert!(s.leases.is_empty());
    // the freed address is reusable and takes the next name cleanly
    assert_eq!(
        s.request(&request_pkt([9; 6], Some(ip), Some("next")), Some(ip)),
        Ok(ip)
    );
    assert_eq!(s.name_of(&ip), Some(Some("next".to_string())));
}

// ---------------------------------------------------------------------------
// rapid commit + misc
// ---------------------------------------------------------------------------

#[test]
fn rapid_commit_insert_stores_hostname() {
    let mut s = HostnameServer::new(true);
    let mut p = discover_pkt([10; 6], Some("quick"));
    p.options.push(options::DhcpOption::Unrecognized(
        options::RawDhcpOption { code: options::RAPID_COMMIT, data: vec![] },
    ));
    let ip = s.discover(&p).expect("rapid commit must offer");
    assert_eq!(s.name_of(&ip), Some(Some("quick".to_string())));
}

#[test]
fn rapid_existing_lease_refreshes_hostname() {
    let mut s = HostnameServer::new(true);
    let ip = Ipv4Addr::new(192, 168, 2, 18);
    assert_eq!(s.request(&request_pkt([11; 6], Some(ip), None), Some(ip)), Ok(ip));
    let mut p = discover_pkt([11; 6], Some("renamed"));
    p.options.push(options::DhcpOption::Unrecognized(
        options::RawDhcpOption { code: options::RAPID_COMMIT, data: vec![] },
    ));
    assert_eq!(s.discover(&p), Some(ip));
    assert_eq!(s.name_of(&ip), Some(Some("renamed".to_string())));
}

#[test]
fn hostname_255b_and_unicode_store_exactly() {
    let mut s = HostnameServer::new(false);
    let long = "x".repeat(255);
    let ip = Ipv4Addr::new(192, 168, 2, 19);
    assert_eq!(
        s.request(&request_pkt([12; 6], Some(ip), Some(&long)), Some(ip)),
        Ok(ip)
    );
    assert_eq!(s.name_of(&ip), Some(Some(long)));
    let ip2 = Ipv4Addr::new(192, 168, 2, 20);
    assert_eq!(
        s.request(&request_pkt([13; 6], Some(ip2), Some("büro-01")), Some(ip2)),
        Ok(ip2)
    );
    assert_eq!(s.name_of(&ip2), Some(Some("büro-01".to_string())));
}

#[test]
fn malformed_hostname_treated_as_absent() {
    // Invalid UTF-8 in option 12 is rejected by the decoder, so the packet
    // arrives with no HostName at all: existing names are preserved and no
    // garbage is ever stored.
    let raw = make_raw([14; 6], vec![53, 1, 1, 12, 2, 0xFF, 0xFE, 255]);
    let p = unwrap_packet(packet::Packet::from(&raw));
    assert_eq!(hostname_of(&p), None);
    // ...while a valid name on the wire extracts exactly
    let raw2 = make_raw([14; 6], vec![53, 1, 1, 12, 3, b'f', b'o', b'o', 255]);
    let q = unwrap_packet(packet::Packet::from(&raw2));
    assert_eq!(hostname_of(&q), Some("foo".to_string()));
    // ...and a nameless packet never clears a stored name
    let mut s = HostnameServer::new(false);
    let ip = Ipv4Addr::new(192, 168, 2, 21);
    assert_eq!(s.request(&request_pkt([14; 6], Some(ip), Some("kept")), Some(ip)), Ok(ip));
    let bare = discover_pkt([14; 6], None);
    assert_eq!(s.discover(&bare), Some(ip));
    assert_eq!(s.name_of(&ip), Some(Some("kept".to_string())));
}

#[test]
fn two_clients_hostnames_isolated() {
    let mut s = HostnameServer::new(false);
    let a = Ipv4Addr::new(192, 168, 2, 22);
    let b = Ipv4Addr::new(192, 168, 2, 23);
    assert_eq!(s.request(&request_pkt([0xA0; 6], Some(a), Some("alpha")), Some(a)), Ok(a));
    assert_eq!(s.request(&request_pkt([0xB0; 6], Some(b), Some("beta")), Some(b)), Ok(b));
    assert_eq!(s.name_of(&a), Some(Some("alpha".to_string())));
    assert_eq!(s.name_of(&b), Some(Some("beta".to_string())));
    // refreshing one never touches the other
    assert_eq!(s.discover(&discover_pkt([0xA0; 6], Some("alpha2"))), Some(a));
    assert_eq!(s.name_of(&a), Some(Some("alpha2".to_string())));
    assert_eq!(s.name_of(&b), Some(Some("beta".to_string())));
}

#[test]
fn monitor_display_fallback() {
    assert_eq!(display_name(&None), "-");
    assert_eq!(display_name(&Some("laptop".to_string())), "laptop");
    assert_eq!(display_name(&Some("".to_string())), "");
}
