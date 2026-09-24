use crate::options::*;

use std::net::Ipv4Addr;

pub enum CustomErr<I> {
    NomError((I, ErrorKind)),
    NonUtf8String,
    UnrecognizedMessageType,
    InvalidHlen,
}

pub enum ErrorKind {
    Tag,
    MapRes,
    ManyTill,
    Eof,
    Custom(u32),
}

type IResult<I, O> = Result<(I, O), CustomErr<I>>;

/// DHCP Packet Structure
#[derive(Debug)]
pub struct Packet {
    pub reply: bool, // false = request, true = reply
    pub hops: u8,
    pub xid: u32, // Random identifier
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    pub options: Vec<DhcpOption>,
}

#[inline(always)]
fn ipv4_of(data: &[u8]) -> Result<Ipv4Addr, CustomErr<&[u8]>> {
    if data.len() < 4 {
        return Err(CustomErr::InvalidHlen);
    }
    Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

pub fn decode_option(input: &[u8]) -> IResult<&[u8], DhcpOption> {
    if input.is_empty() {
        return Err(CustomErr::InvalidHlen);
    }
    let code = input[0];
    assert!(code != END);
    let len = *input.get(1).ok_or(CustomErr::InvalidHlen)? as usize;
    if input.len() - 2 < len {
        return Err(CustomErr::InvalidHlen);
    }
    let data = &input[2..2 + len];
    let input = &input[2 + len..];
    let option = match code {
        // Frequency-ordered: 53 on every packet, 55 on ~90%, then 54/50.
        DHCP_MESSAGE_TYPE => {
            // Preserve quirk: empty data -> InvalidHlen, bad value ->
            // UnrecognizedMessageType, trailing bytes ignored.
            if data.is_empty() {
                return Err(CustomErr::InvalidHlen);
            }
            match MessageType::from_option(data[0]) {
                Some(x) => DhcpOption::DhcpMessageType(x),
                None => return Err(CustomErr::UnrecognizedMessageType),
            }
        }
        PARAMETER_REQUEST_LIST => DhcpOption::ParameterRequestList(data.to_vec()),
        SERVER_IDENTIFIER => DhcpOption::ServerIdentifier(ipv4_of(data)?),
        REQUESTED_IP_ADDRESS => DhcpOption::RequestedIpAddress(ipv4_of(data)?),
        HOST_NAME => DhcpOption::HostName(match std::str::from_utf8(data) {
            Ok(s) => s.to_string(),
            Err(_) => return Err(CustomErr::NonUtf8String),
        }),
        // Locked quirk: Router/DNS ALWAYS fail with InvalidHlen because the
        // old custom_many0(decode_ipv4) expected NomError termination but
        // decode_ipv4 yields InvalidHlen. Preserve without the overhead.
        ROUTER | DOMAIN_NAME_SERVER => return Err(CustomErr::InvalidHlen),
        IP_ADDRESS_LEASE_TIME => {
            if data.len() < 4 {
                return Err(CustomErr::InvalidHlen);
            }
            DhcpOption::IpAddressLeaseTime(u32::from_be_bytes([
                data[0], data[1], data[2], data[3],
            ]))
        }
        SUBNET_MASK => DhcpOption::SubnetMask(ipv4_of(data)?),
        MESSAGE => DhcpOption::Message(match std::str::from_utf8(data) {
            Ok(s) => s.to_string(),
            Err(_) => return Err(CustomErr::NonUtf8String),
        }),
        _ => DhcpOption::Unrecognized(RawDhcpOption {
            code,
            data: data.to_vec(),
        }),
    };
    Ok((input, option))
}

/// Parses Packet from byte array
fn decode(input: &[u8]) -> IResult<&[u8], Packet> {
    if input.len() < 236 {
        return Err(CustomErr::InvalidHlen);
    }
    let (hdr, mut rest) = input.split_at(236);
    // Header fields at fixed offsets (mirrors the closure version exactly).
    let reply = match hdr[0] {
        BOOT_REPLY => true,
        BOOT_REQUEST => false,
        _ => false,
    };
    let hlen = hdr[2];
    if hlen != 6 {
        return Err(CustomErr::InvalidHlen);
    }
    let hops = hdr[3];
    let xid = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let secs = u16::from_be_bytes([hdr[8], hdr[9]]);
    let flags = u16::from_be_bytes([hdr[10], hdr[11]]);
    let ciaddr = Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15]);
    let yiaddr = Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19]);
    let siaddr = Ipv4Addr::new(hdr[20], hdr[21], hdr[22], hdr[23]);
    let giaddr = Ipv4Addr::new(hdr[24], hdr[25], hdr[26], hdr[27]);

    let chaddr = [hdr[28], hdr[29], hdr[30], hdr[31], hdr[32], hdr[33]];

    // Cookie check preserves NomError(Tag) kind.
    if rest.len() < 4 || rest[0..4] != COOKIE {
        return Err(CustomErr::NomError((rest, ErrorKind::Tag)));
    }
    rest = &rest[4..];

    // Live traffic carries 3-6 options (Discover 3, Request 6); 7-8-opt
    // packets pay one cheap 6->12 growth instead of every decode wasting
    // two slots (~64B) of malloc+memset.
    let mut options = Vec::with_capacity(6);
    while let Ok((new_rest, option)) = decode_option(rest) {
        rest = new_rest;
        options.push(option);
        if rest.first().copied() == Some(END) {
            break;
        }
    }

    let input = rest.split_at(1).1; // Skip the END tag byte

    Ok((
        input,
        Packet {
            reply,
            hops,
            secs,
            broadcast: flags & 128 == 128,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            options,
            chaddr,
            xid,
        },
    ))
}

impl Packet {
    pub fn from(input: &[u8]) -> Result<Packet, CustomErr<&[u8]>> {
        Ok(decode(input)?.1)
    }

    /// Extracts requested option payload from packet if available
    #[inline]
    pub fn option(&self, code: u8) -> Option<&DhcpOption> {
        for o in &self.options {
            if o.code() == code {
                return Some(o);
            }
        }
        None
    }

    /// Convenience function for extracting a packet's message type.
    /// Single pass (no second scan via option()), preserving the
    /// Unrecognized(53) wrong-enum quirk.
    #[inline]
    pub fn message_type(&self) -> Result<MessageType, String> {
        for o in &self.options {
            match o {
                DhcpOption::DhcpMessageType(m) => return Ok(*m),
                DhcpOption::Unrecognized(r) if r.code == DHCP_MESSAGE_TYPE => {
                    return Err(format![
                        "Got wrong enum code {} for DHCP_MESSAGE_TYPE",
                        r.code
                    ])
                }
                _ => continue,
            }
        }
        Err("Packet does not have MessageType option".to_string())
    }
    pub fn encode<'a>(&'a self, p: &'a mut [u8]) -> &[u8] {
        let broadcast_flag = if self.broadcast { 128 } else { 0 };
        let mut length = 240;

        p[..12].copy_from_slice(&[
            if self.reply { BOOT_REPLY } else { BOOT_REQUEST },
            1,
            6,
            self.hops,
            ((self.xid >> 24) & 0xFF) as u8,
            ((self.xid >> 16) & 0xFF) as u8,
            ((self.xid >> 8) & 0xFF) as u8,
            (self.xid & 0xFF) as u8,
            (self.secs >> 8) as u8,
            (self.secs & 255) as u8,
            broadcast_flag,
            0,
        ]);

        p[12..16].copy_from_slice(&self.ciaddr.octets());
        p[16..20].copy_from_slice(&self.yiaddr.octets());
        p[20..24].copy_from_slice(&self.siaddr.octets());
        p[24..28].copy_from_slice(&self.giaddr.octets());
        p[28..34].copy_from_slice(&self.chaddr);
        p[34..236].fill(0);
        p[236..240].copy_from_slice(&COOKIE);

        for option in &self.options {
            let option_len = option.data_len();
            if length + 2 + option_len >= WIRE_MAX {
                break;
            }
            if let Some(dest) = p.get_mut(length..length + 2 + option_len) {
                dest[0] = option.code();
                dest[1] = option_len as u8;
                option.write_data(&mut dest[2..]);
            }
            length += 2 + option_len;
        }

        if let Some(end_segment) = p.get_mut(length..length + 1) {
            end_segment[0] = END;
        }
        length += 1;

        if let Some(pad_segment) = p.get_mut(length..WIRE_MAX) {
            pad_segment.fill(PAD);
        }

        &p[..length]
    }
}

/// Maximum encoded packet size: the BOOTP minimum (RFC 951). The fixed
/// header + cookie occupy 240 bytes, leaving 59 bytes for options + END —
/// enough for a complete standard Offer (message type, server id, lease,
/// mask, router, DNS, NTP ≈ 43 bytes). Smaller ceilings amputate mandatory
/// options (e.g. Server Identifier) off real replies.
/// Callers must supply a buffer of at least this size.
pub const WIRE_MAX: usize = 300;

const COOKIE: [u8; 4] = [99, 130, 83, 99];

const BOOT_REQUEST: u8 = 1; // From Client;
const BOOT_REPLY: u8 = 2; // From Server;

const END: u8 = 255;
const PAD: u8 = 0;
