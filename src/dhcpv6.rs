//! Minimal DHCPv6 (RFC 8415) packet codec plus a managed-range allocator.
//!
//! Wire format (RFC 8415 §7): `msg-type` (1 octet) + `transaction-id`
//! (3 octets) followed by options to the end of the datagram. Unlike DHCPv4
//! there is **no END byte and no PAD**: options are `code` (u16 BE) +
//! `len` (u16 BE) + `data`, parsed strictly — any truncation or malformed
//! option rejects the whole datagram with [`DecodeError`] (there is no
//! v4-style swallow-and-desync quirk here by design).
//!
//! Identity is the client DUID (opaque bytes, option 1); address state is
//! tracked per IA_NA (option 3, IAID + IA Address sub-options). [`V6Pool`]
//! manages one contiguous range `[start, start + count)` with round-robin
//! allocation mirroring the v4 example, except infinite (`None` expiry)
//! leases are **not** stealable (this intentionally differs from the v4
//! `available()` quirk — see its docs).

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Message types (RFC 8415 §7.3)
// ---------------------------------------------------------------------------

/// DHCPv6 message types with their RFC 8415 §7.3 numeric values.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MsgType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForward = 12,
    RelayReply = 13,
}

impl MsgType {
    pub fn from(val: u8) -> Result<MsgType, DecodeError> {
        match val {
            1 => Ok(MsgType::Solicit),
            2 => Ok(MsgType::Advertise),
            3 => Ok(MsgType::Request),
            4 => Ok(MsgType::Confirm),
            5 => Ok(MsgType::Renew),
            6 => Ok(MsgType::Rebind),
            7 => Ok(MsgType::Reply),
            8 => Ok(MsgType::Release),
            9 => Ok(MsgType::Decline),
            10 => Ok(MsgType::Reconfigure),
            11 => Ok(MsgType::InformationRequest),
            12 => Ok(MsgType::RelayForward),
            13 => Ok(MsgType::RelayReply),
            _ => Err(DecodeError::BadMessageType(val)),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Reasons a DHCPv6 datagram (or option) cannot be decoded.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodeError {
    /// Fewer bytes than the header / declared length requires.
    Truncated,
    /// Unknown message type byte.
    BadMessageType(u8),
    /// Text option is not valid UTF-8.
    BadUtf8,
    /// Well-framed but internally inconsistent (short IA_NA, short IAADDR,
    /// DNS length not a multiple of 16, short status, trailing < 4 bytes).
    Malformed,
}

/// Reasons a [`Packet`] cannot be encoded.
#[derive(Debug, Clone, PartialEq)]
pub enum EncodeError {
    /// A single option payload exceeds the 16-bit length field (65535).
    OptionTooLarge,
}

// ---------------------------------------------------------------------------
// Options (RFC 8415 §24 and friends)
// ---------------------------------------------------------------------------

pub const OPT_CLIENTID: u16 = 1;
pub const OPT_SERVERID: u16 = 2;
pub const OPT_IA_NA: u16 = 3;
pub const OPT_IA_TA: u16 = 4;
pub const OPT_IAADDR: u16 = 5;
pub const OPT_ORO: u16 = 6;
pub const OPT_PREFERENCE: u16 = 7;
pub const OPT_ELAPSED_TIME: u16 = 8;
pub const OPT_RELAY_MSG: u16 = 9;
pub const OPT_AUTH: u16 = 11;
pub const OPT_UNICAST: u16 = 12;
pub const OPT_STATUS_CODE: u16 = 13;
pub const OPT_RAPID_COMMIT: u16 = 14;
pub const OPT_USER_CLASS: u16 = 15;
pub const OPT_VENDOR_CLASS: u16 = 16;
pub const OPT_VENDOR_OPTS: u16 = 17;
pub const OPT_INTERFACE_ID: u16 = 18;
pub const OPT_RECONF_MSG: u16 = 19;
pub const OPT_RECONF_ACCEPT: u16 = 20;
pub const OPT_DNS_SERVERS: u16 = 23;
pub const OPT_DOMAIN_LIST: u16 = 24;
pub const OPT_IA_PD: u16 = 25;
pub const OPT_IAPREFIX: u16 = 26;

/// RFC 8415 status codes (§21.13): 0 Success, 1 UnspecFail, 2 NoAddrsAvail,
/// 3 NoBinding, 4 UseMulticast, 5 NoPrefixAvail.
pub const STATUS_SUCCESS: u16 = 0;
pub const STATUS_NO_ADDRS_AVAIL: u16 = 2;

/// An IA Address sub-option body (RFC 8415 §21.6): address plus its
/// preferred and valid lifetimes in seconds.
#[derive(Debug, Clone, PartialEq)]
pub struct IaAddr {
    pub addr: Ipv6Addr,
    pub preferred: u32,
    pub valid: u32,
}

/// An IA_NA option body (RFC 8415 §21.4): IAID + T1/T2 plus address bindings.
#[derive(Debug, Clone, PartialEq)]
pub struct IaNa {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub addrs: Vec<IaAddr>,
}

/// Raw form of any option that has no typed variant here.
#[derive(Debug, Clone, PartialEq)]
pub struct RawDhcpv6Option {
    pub code: u16,
    pub data: Vec<u8>,
}

/// A decoded DHCPv6 option. Anything without a typed variant is preserved
/// transparently as [`Dhcpv6Option::Unrecognized`].
#[derive(Debug, Clone, PartialEq)]
pub enum Dhcpv6Option {
    /// Option 1: client DUID (opaque bytes).
    ClientId(Vec<u8>),
    /// Option 2: server DUID (opaque bytes).
    ServerId(Vec<u8>),
    /// Option 3: identity association for non-temporary addresses.
    IaNa(IaNa),
    /// Option 23 (RFC 3646): recursive name servers.
    DnsServers(Vec<Ipv6Addr>),
    /// Option 13: status code + human-readable message.
    StatusCode(u16, String),
    Unrecognized(RawDhcpv6Option),
}

impl Dhcpv6Option {
    #[inline]
    pub fn wire_len(&self) -> usize {
        4 + match self {
            Self::ClientId(d) | Self::ServerId(d) => d.len(),
            Self::Unrecognized(r) => r.data.len(),
            Self::DnsServers(a) => a.len() * 16,
            Self::StatusCode(_, m) => 2 + m.len(),
            Self::IaNa(ia) => 12 + ia.addrs.len() * 28,
        }
    }

    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let payload = self.wire_len() - 4;
        if payload > 0xFFFF {
            return Err(EncodeError::OptionTooLarge);
        }
        out.extend_from_slice(&self.code().to_be_bytes());
        out.extend_from_slice(&(payload as u16).to_be_bytes());
        match self {
            Self::ClientId(d) | Self::ServerId(d) => out.extend_from_slice(d),
            Self::Unrecognized(r) => out.extend_from_slice(&r.data),
            Self::DnsServers(a) => {
                for ip in a {
                    out.extend_from_slice(&ip.octets());
                }
            }
            Self::StatusCode(c, m) => {
                out.extend_from_slice(&c.to_be_bytes());
                out.extend_from_slice(m.as_bytes());
            }
            Self::IaNa(ia) => {
                out.extend_from_slice(&ia.iaid.to_be_bytes());
                out.extend_from_slice(&ia.t1.to_be_bytes());
                out.extend_from_slice(&ia.t2.to_be_bytes());
                for a in &ia.addrs {
                    let mut sub = [0u8; 28];
                    sub[0..2].copy_from_slice(&OPT_IAADDR.to_be_bytes());
                    sub[2..4].copy_from_slice(&24u16.to_be_bytes());
                    sub[4..20].copy_from_slice(&a.addr.octets());
                    sub[20..24].copy_from_slice(&a.preferred.to_be_bytes());
                    sub[24..28].copy_from_slice(&a.valid.to_be_bytes());
                    out.extend_from_slice(&sub);
                }
            }
        }
        Ok(())
    }

    pub fn to_raw(&self) -> RawDhcpv6Option {
        match self {
            Self::ClientId(duid) => RawDhcpv6Option {
                code: OPT_CLIENTID,
                data: duid.clone(),
            },
            Self::ServerId(duid) => RawDhcpv6Option {
                code: OPT_SERVERID,
                data: duid.clone(),
            },
            Self::IaNa(ia) => {
                let mut data = Vec::with_capacity(12 + ia.addrs.len() * 28);
                data.extend_from_slice(&ia.iaid.to_be_bytes());
                data.extend_from_slice(&ia.t1.to_be_bytes());
                data.extend_from_slice(&ia.t2.to_be_bytes());
                for a in &ia.addrs {
                    // Fixed 24-byte IAADDR body written directly (no per-addr
                    // sub-Vec alloc); trailing sub-sub-options are never
                    // emitted here by construction.
                    data.extend_from_slice(&OPT_IAADDR.to_be_bytes());
                    data.extend_from_slice(&24u16.to_be_bytes());
                    data.extend_from_slice(&a.addr.octets());
                    data.extend_from_slice(&a.preferred.to_be_bytes());
                    data.extend_from_slice(&a.valid.to_be_bytes());
                }
                RawDhcpv6Option {
                    code: OPT_IA_NA,
                    data,
                }
            }
            Self::DnsServers(addrs) => {
                let mut data = Vec::with_capacity(addrs.len() * 16);
                for a in addrs {
                    data.extend_from_slice(&a.octets());
                }
                RawDhcpv6Option {
                    code: OPT_DNS_SERVERS,
                    data,
                }
            }
            Self::StatusCode(code, msg) => {
                let mut data = Vec::with_capacity(2 + msg.len());
                data.extend_from_slice(&code.to_be_bytes());
                data.extend_from_slice(msg.as_bytes());
                RawDhcpv6Option {
                    code: OPT_STATUS_CODE,
                    data,
                }
            }
            Self::Unrecognized(raw) => raw.clone(),
        }
    }

    #[inline]
    pub fn code(&self) -> u16 {
        match self {
            Self::ClientId(_) => OPT_CLIENTID,
            Self::ServerId(_) => OPT_SERVERID,
            Self::IaNa(_) => OPT_IA_NA,
            Self::DnsServers(_) => OPT_DNS_SERVERS,
            Self::StatusCode(_, _) => OPT_STATUS_CODE,
            Self::Unrecognized(x) => x.code,
        }
    }
}

/// Human-readable title for known option codes, if any.
pub fn title(code: u16) -> Option<&'static str> {
    Some(match code {
        OPT_CLIENTID => "Client Identifier",
        OPT_SERVERID => "Server Identifier",
        OPT_IA_NA => "Identity Association for Non-temporary Addresses",
        OPT_IA_TA => "Identity Association for Temporary Addresses",
        OPT_IAADDR => "IA Address",
        OPT_ORO => "Option Request",
        OPT_PREFERENCE => "Preference",
        OPT_ELAPSED_TIME => "Elapsed Time",
        OPT_RELAY_MSG => "Relay Message",
        OPT_AUTH => "Authentication",
        OPT_UNICAST => "Server Unicast",
        OPT_STATUS_CODE => "Status Code",
        OPT_RAPID_COMMIT => "Rapid Commit",
        OPT_USER_CLASS => "User Class",
        OPT_VENDOR_CLASS => "Vendor Class",
        OPT_VENDOR_OPTS => "Vendor-specific Information",
        OPT_INTERFACE_ID => "Interface-Id",
        OPT_RECONF_MSG => "Reconfigure Message",
        OPT_RECONF_ACCEPT => "Reconfigure Accept",
        OPT_DNS_SERVERS => "DNS Recursive Name Server",
        OPT_DOMAIN_LIST => "Domain Search List",
        OPT_IA_PD => "Identity Association for Prefix Delegation",
        OPT_IAPREFIX => "IA Prefix",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// decode helpers
// ---------------------------------------------------------------------------

#[inline]
fn be_u16(input: &[u8]) -> Result<(&[u8], u16), DecodeError> {
    if input.len() < 2 {
        return Err(DecodeError::Truncated);
    }
    Ok((
        &input[2..],
        u16::from_be_bytes([input[0], input[1]]),
    ))
}

#[inline]
fn be_u32(input: &[u8]) -> Result<(&[u8], u32), DecodeError> {
    if input.len() < 4 {
        return Err(DecodeError::Truncated);
    }
    Ok((
        &input[4..],
        u32::from_be_bytes([input[0], input[1], input[2], input[3]]),
    ))
}

#[inline]
fn take<'a>(input: &'a [u8], n: usize) -> Result<(&'a [u8], &'a [u8]), DecodeError> {
    if input.len() < n {
        return Err(DecodeError::Truncated);
    }
    Ok((&input[n..], &input[..n]))
}

#[inline]
fn decode_iana(data: &[u8]) -> Result<IaNa, DecodeError> {
    if data.len() < 12 {
        return Err(DecodeError::Malformed);
    }
    let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let t1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let t2 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let mut rest = &data[12..];
    let mut addrs = Vec::with_capacity(rest.len() / 28);
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(DecodeError::Malformed);
        }
        let slen = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() - 4 < slen {
            return Err(DecodeError::Malformed);
        }
        let code = u16::from_be_bytes([rest[0], rest[1]]);
        let body = &rest[4..4 + slen];
        rest = &rest[4 + slen..];
        if code == OPT_IAADDR {
            if body.len() < 24 {
                return Err(DecodeError::Malformed);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[..16]);
            addrs.push(IaAddr {
                addr: Ipv6Addr::from(octets),
                preferred: u32::from_be_bytes([body[16], body[17], body[18], body[19]]),
                valid: u32::from_be_bytes([body[20], body[21], body[22], body[23]]),
            });
            // any sub-sub-options past byte 24 are ignored
        }
        // unknown sub-options are skipped by length
    }
    Ok(IaNa { iaid, t1, t2, addrs })
}

/// Decode one option; returns the remainder plus the option.
#[inline]
pub fn decode_option(input: &[u8]) -> Result<(&[u8], Dhcpv6Option), DecodeError> {
    if input.len() < 4 {
        return Err(DecodeError::Truncated);
    }
    let code = u16::from_be_bytes([input[0], input[1]]);
    let len = u16::from_be_bytes([input[2], input[3]]) as usize;
    if input.len() - 4 < len {
        return Err(DecodeError::Truncated);
    }
    let data = &input[4..4 + len];
    let input = &input[4 + len..];
    let option = match code {
        OPT_CLIENTID => Dhcpv6Option::ClientId(data.to_vec()),
        OPT_SERVERID => Dhcpv6Option::ServerId(data.to_vec()),
        OPT_IA_NA => Dhcpv6Option::IaNa(decode_iana(data)?),
        OPT_DNS_SERVERS => {
            if data.len() % 16 != 0 {
                return Err(DecodeError::Malformed);
            }
            let mut addrs = Vec::with_capacity(data.len() / 16);
            for chunk in data.chunks_exact(16) {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(chunk);
                addrs.push(Ipv6Addr::from(octets));
            }
            Dhcpv6Option::DnsServers(addrs)
        }
        OPT_STATUS_CODE => {
            if data.len() < 2 {
                return Err(DecodeError::Malformed);
            }
            let code = u16::from_be_bytes([data[0], data[1]]);
            let msg = std::str::from_utf8(&data[2..]).map_err(|_| DecodeError::BadUtf8)?;
            Dhcpv6Option::StatusCode(code, msg.to_string())
        }
        _ => Dhcpv6Option::Unrecognized(RawDhcpv6Option {
            code,
            data: data.to_vec(),
        }),
    };
    Ok((input, option))
}

// ---------------------------------------------------------------------------
// Packet
// ---------------------------------------------------------------------------

/// A DHCPv6 datagram: message type + 24-bit transaction id + options.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub msg_type: MsgType,
    pub transaction_id: u32,
    pub options: Vec<Dhcpv6Option>,
}

impl Packet {
    pub fn from(input: &[u8]) -> Result<Packet, DecodeError> {
        if input.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let msg_type = MsgType::from(input[0])?;
        let transaction_id =
            ((input[1] as u32) << 16) | ((input[2] as u32) << 8) | (input[3] as u32);
        let mut options = Vec::with_capacity(input.len().saturating_sub(4) / 8);
        let mut rest = &input[4..];
        while !rest.is_empty() {
            let (new_rest, option) = decode_option(rest)?;
            rest = new_rest;
            options.push(option);
        }
        Ok(Packet {
            msg_type,
            transaction_id,
            options,
        })
    }

    /// First option with the given code, if any.
    #[inline]
    pub fn option(&self, code: u16) -> Option<&Dhcpv6Option> {
        for o in &self.options {
            if o.code() == code {
                return Some(o);
            }
        }
        None
    }

    /// First IA_NA option, if any (handlers key address state off this).
    #[inline]
    pub fn first_iana(&self) -> Option<&IaNa> {
        for o in &self.options {
            if let Dhcpv6Option::IaNa(ia) = o {
                return Some(ia);
            }
        }
        None
    }

    /// Single-pass ClientId + IA_NA harvest (first-wins each); saves the
    /// 2-3 linear scans handlers otherwise do per packet.
    #[inline]
    pub fn client_iana(&self) -> (Option<&[u8]>, Option<&IaNa>) {
        let (mut c, mut ia) = (None, None);
        for o in &self.options {
            match o {
                Dhcpv6Option::ClientId(d) if c.is_none() => c = Some(d.as_slice()),
                Dhcpv6Option::IaNa(a) if ia.is_none() => ia = Some(a),
                _ => {}
            }
            if c.is_some() && ia.is_some() {
                break;
            }
        }
        (c, ia)
    }

    /// Encode to wire bytes. Only the low 24 bits of `transaction_id` are
    /// emitted (the field is 3 octets); a single option payload over 65535
    /// bytes is rejected with [`EncodeError::OptionTooLarge`].
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(4 + self.options.iter().map(|o| o.wire_len()).sum::<usize>());
        out.push(self.msg_type as u8);
        let tid = self.transaction_id & 0xFF_FF_FF;
        out.push(((tid >> 16) & 0xFF) as u8);
        out.push(((tid >> 8) & 0xFF) as u8);
        out.push((tid & 0xFF) as u8);
        for option in &self.options {
            option.encode_into(&mut out)?;
        }
        Ok(out)
    }
}

/// True when the packet carries OUR Server ID (exact DUID byte match), i.e.
/// the client selected this server. Anything else (missing, wrong type,
/// different bytes) is false.
#[inline]
pub fn is_for_server(our_duid: &[u8], pkt: &Packet) -> bool {
    match pkt.option(OPT_SERVERID) {
        Some(Dhcpv6Option::ServerId(d)) => d.as_slice() == our_duid,
        _ => false,
    }
}

/// Renewal/rebinding defaults for a lease of `lease_secs` seconds, mirroring
/// the RFC 2131 client-side rule the v4 tests use (T1 = 1/2, T2 = 7/8):
/// T1 = secs/2, T2 = secs - secs/8 (overflow-free).
#[inline]
pub fn default_t1_t2(lease_secs: u32) -> (u32, u32) {
    (lease_secs / 2, lease_secs - lease_secs / 8)
}

// ---------------------------------------------------------------------------
// Managed range allocator ("managed dhcpv6 range")
// ---------------------------------------------------------------------------

/// Allocator for one contiguous managed IPv6 range
/// `[start, start + count)`, keyed by client DUID bytes.
///
/// Semantics mirror the v4 example (`discover` prefers the current lease,
/// otherwise first-free round-robin; `request` prefers current, else inserts
/// a timed lease; `release` drops it) with one deliberate difference:
/// infinite (`None` expiry) leases are **not** stealable here — unlike the
/// v4 `available()` quirk, `None` means permanently reserved.
///
/// In-range addresses live in a dense slot array indexed by `addr - start`
/// (O(1) loads, no hashing on the miss scan); out-of-range reservations
/// (e.g. `leases6` entries outside the pool) spill to `overflow`. Huge pools
/// (over `MAX_SLOTS`) fall back to hash-only storage.
///
/// Discovery scans linearly like the v4 example, so keep `count` modest
/// (tens of thousands at most); absurd counts make each Solicitation walk
/// the whole range.
pub struct V6Pool {
    start: u128,
    end: Option<u128>,
    count: u64,
    last: u64,
    lease_duration: Duration,
    use_slots: bool,
    slots: Vec<Option<(Vec<u8>, Option<Instant>)>>,
    filled: usize,
    overflow: HashMap<Ipv6Addr, (Vec<u8>, Option<Instant>)>,
    by_duid: HashMap<Vec<u8>, Ipv6Addr>,
}

/// Upper bound for slot-array allocation (100k slots ≈ 5MB); larger pools
/// use hash-only storage with identical semantics.
const MAX_SLOTS: u64 = 100_000;

impl V6Pool {
    pub fn new(start: Ipv6Addr, count: u64, lease_duration: Duration) -> V6Pool {
        let start_num = u128::from(start);
        let use_slots = count <= MAX_SLOTS && count <= usize::MAX as u64;
        let slots = if use_slots {
            let mut s = Vec::new();
            s.resize_with(count as usize, || None);
            s
        } else {
            Vec::new()
        };
        V6Pool {
            start: start_num,
            end: start_num.checked_add(count as u128),
            count,
            last: 0,
            lease_duration,
            use_slots,
            slots,
            filled: 0,
            overflow: HashMap::new(),
            by_duid: HashMap::with_capacity(count.min(4096) as usize),
        }
    }

    pub fn start_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.start)
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Number of leases currently held.
    pub fn len(&self) -> usize {
        self.filled + self.overflow.len()
    }

    pub fn is_empty(&self) -> bool {
        self.filled == 0 && self.overflow.is_empty()
    }

    fn end(&self) -> Option<u128> {
        self.end
    }

    fn in_range(&self, addr: &Ipv6Addr) -> bool {
        let pos: u128 = (*addr).into();
        pos >= self.start && self.end.map_or(false, |end| pos < end)
    }

    /// Slot index for in-range addresses. `None` for out-of-range,
    /// overflowed pools (`end` is `None`), and hash-only huge pools.
    #[inline]
    fn idx(&self, addr: &Ipv6Addr) -> Option<usize> {
        if !self.use_slots || self.end.is_none() {
            return None;
        }
        let off = u128::from(*addr).checked_sub(self.start)?;
        if off < self.count as u128 {
            Some(off as usize)
        } else {
            None
        }
    }

    /// Unified lookup (slot or overflow) for verification/`get` paths.
    #[inline]
    fn lookup(&self, addr: &Ipv6Addr) -> Option<&(Vec<u8>, Option<Instant>)> {
        match self.idx(addr) {
            Some(i) => self.slots[i].as_ref(),
            None => self.overflow.get(addr),
        }
    }

    #[inline]
    fn slot_available(&self, i: usize, duid: &[u8], now: Instant) -> bool {
        match &self.slots[i] {
            Some((d, expiry)) => {
                d.as_slice() == duid || expiry.map_or(false, |exp| now > exp)
            }
            None => true,
        }
    }

    /// Insert a reservation directly (used for `leases6` file entries).
    /// `None` expiry means a permanent (infinite) reservation.
    /// Duplicate DUIDs for different IPs are preserved (like the original:
    /// one DUID may hold several IPs; `current_lease` returns one of them),
    /// while `by_duid` stays as an O(1) hint for the common 1:1 case.
    /// Duplicate IPs last-wins.
    pub fn insert(&mut self, addr: Ipv6Addr, duid: Vec<u8>, expiry: Option<Instant>) {
        if let Some(i) = self.idx(&addr) {
            if let Some((old_duid, _)) = &self.slots[i] {
                if *old_duid != duid && self.by_duid.get(old_duid) == Some(&addr) {
                    self.by_duid.remove(old_duid);
                }
            }
            if self.slots[i].is_none() {
                self.filled += 1;
            }
            self.slots[i] = Some((duid.clone(), expiry));
            self.by_duid.insert(duid, addr);
        } else if !self.use_slots && self.in_range(&addr) {
            // Huge hash-only pool: in-range entries live in overflow.
            if let Some((old_duid, _)) = self.overflow.get(&addr) {
                if *old_duid != duid && self.by_duid.get(old_duid) == Some(&addr) {
                    let old = old_duid.clone();
                    self.by_duid.remove(&old);
                }
            }
            self.by_duid.insert(duid.clone(), addr);
            self.overflow.insert(addr, (duid, expiry));
        } else {
            // Out-of-range reservation spillover.
            if let Some((old_duid, _)) = self.overflow.get(&addr) {
                if *old_duid != duid && self.by_duid.get(old_duid) == Some(&addr) {
                    let old = old_duid.clone();
                    self.by_duid.remove(&old);
                }
            }
            self.by_duid.insert(duid.clone(), addr);
            self.overflow.insert(addr, (duid, expiry));
        }
    }

    pub fn get(&self, addr: &Ipv6Addr) -> Option<&(Vec<u8>, Option<Instant>)> {
        self.lookup(addr)
    }

    #[inline]
    fn available_at(&self, duid: &[u8], addr: &Ipv6Addr, now: Instant) -> bool {
        if let Some(i) = self.idx(addr) {
            return self.slot_available(i, duid, now);
        }
        if !self.use_slots && self.in_range(addr) {
            // Huge hash-only pool: consult overflow with the range gate.
            return match self.overflow.get(addr) {
                Some((d, expiry)) => {
                    d.as_slice() == duid || expiry.map_or(false, |exp| now > exp)
                }
                None => true,
            };
        }
        // Out-of-range is never available (verbatim).
        false
    }

    pub fn available(&self, duid: &[u8], addr: &Ipv6Addr) -> bool {
        self.available_at(duid, addr, Instant::now())
    }

    #[inline]
    pub fn current_lease(&self, duid: &[u8]) -> Option<Ipv6Addr> {
        if self.is_empty() {
            return None;
        }
        // Fast O(1) hint; verified because duplicate-DUID inserts and
        // IP-takeover inserts can leave it stale. Falls back to a full scan
        // (slots + overflow) so semantics stay identical.
        if let Some(ip) = self.by_duid.get(duid).copied() {
            if let Some((d, _)) = self.lookup(&ip) {
                if d.as_slice() == duid {
                    return Some(ip);
                }
            }
        }
        if self.use_slots {
            for (i, s) in self.slots.iter().enumerate() {
                if let Some((d, _)) = s {
                    if d.as_slice() == duid {
                        return Some(Ipv6Addr::from(self.start + i as u128));
                    }
                }
            }
        }
        for (ip, (d, _)) in &self.overflow {
            if d.as_slice() == duid {
                return Some(*ip);
            }
        }
        // Huge hash-only pools keep in-range entries in overflow (scanned
        // above); nothing else to scan.
        None
    }

    fn candidate(&self, offset: u64) -> Option<Ipv6Addr> {
        self.start.checked_add(offset as u128).map(Ipv6Addr::from)
    }

    /// Offer an address: current lease first, else first-free round-robin.
    /// Returns `None` when the pool is exhausted (or empty); never panics,
    /// even if `start + count` overflows (candidates past the end are
    /// skipped as unavailable).
    pub fn discover(&mut self, duid: &[u8]) -> Option<Ipv6Addr> {
        if let Some(ip) = self.current_lease(duid) {
            return Some(ip);
        }
        if self.count == 0 {
            return None;
        }
        if !self.use_slots {
            // Huge hash-only pool: original candidate path.
            let now = Instant::now();
            let end = self.end;
            for _ in 0..self.count {
                self.last = (self.last + 1) % self.count;
                if let Some(pos) = self.start.checked_add(self.last as u128) {
                    if end.map_or(false, |e| pos < e) {
                        let cand = Ipv6Addr::from(pos);
                        if self.available_at(duid, &cand, now) {
                            return Some(cand);
                        }
                    }
                }
            }
            return None;
        }
        let now = Instant::now();
        let end = self.end;
        for _ in 0..self.count {
            self.last = (self.last + 1) % self.count;
            let i = self.last as usize;
            // Overflowed candidates are skipped (never panics), mirroring
            // the old `candidate()` semantics.
            if let Some(pos) = self.start.checked_add(self.last as u128) {
                if end.map_or(false, |e| pos < e) {
                    if self.slot_available(i, duid, now) {
                        return Some(Ipv6Addr::from(pos));
                    }
                }
            }
        }
        None
    }

    /// Commit a lease: current lease wins unchanged (no
    /// expiry refresh, mirroring v4); otherwise insert a timed lease if free.
    pub fn request(&mut self, duid: &[u8], addr: Ipv6Addr) -> Result<Ipv6Addr, &'static str> {
        if let Some(ip) = self.current_lease(duid) {
            return Ok(ip);
        }
        let now = Instant::now();
        if !self.available_at(duid, &addr, now) {
            return Err("Requested address not available");
        }
        let expiry = now + self.lease_duration;
        if let Some(i) = self.idx(&addr) {
            if self.slots[i].is_none() {
                self.filled += 1;
            }
            self.slots[i] = Some((duid.to_vec(), Some(expiry)));
            self.by_duid.insert(duid.to_vec(), addr);
        } else {
            self.by_duid.insert(duid.to_vec(), addr);
            self.overflow.insert(addr, (duid.to_vec(), Some(expiry)));
        }
        Ok(addr)
    }

    /// Drop the caller's current lease, if any.
    pub fn release(&mut self, duid: &[u8]) -> bool {
        if let Some(ip) = self.current_lease(duid) {
            if let Some(i) = self.idx(&ip) {
                self.slots[i] = None;
                self.filled -= 1;
            } else {
                self.overflow.remove(&ip);
            }
            if self.by_duid.get(duid) == Some(&ip) {
                self.by_duid.remove(duid);
                // Re-point the hint at a surviving duplicate, if any.
                if self.use_slots {
                    for (j, s) in self.slots.iter().enumerate() {
                        if let Some((d, _)) = s {
                            if d.as_slice() == duid {
                                self.by_duid.insert(
                                    duid.to_vec(),
                                    Ipv6Addr::from(self.start + j as u128),
                                );
                                break;
                            }
                        }
                    }
                }
                if self.by_duid.get(duid).is_none() {
                    for (other_ip, (d, _)) in &self.overflow {
                        if d.as_slice() == duid {
                            self.by_duid.insert(duid.to_vec(), *other_ip);
                            break;
                        }
                    }
                }
            }
            true
        } else {
            false
        }
    }
}
