//! This is a convenience module that simplifies the writing of a DHCP server service.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use crate::options;
use crate::options::{DhcpOption, MessageType};
use crate::packet::*;

pub struct Server {
    socket: UdpSocket,
    src: SocketAddr,
    server_ip: Ipv4Addr,
    /// Broadcast destinations, primary first. Unicast replies always go
    /// once to the peer; broadcast-routed replies go to each address.
    broadcasts: Vec<Ipv4Addr>,
}

pub trait Handler {
    fn handle_request(&mut self, server: &Server, in_packet: Packet);
}

/// Short reason for a rejected datagram (diagnostics; no allocation).
fn describe_decode_error(e: &CustomErr<&[u8]>) -> &'static str {
    match e {
        CustomErr::NomError(_) => "bad magic cookie",
        CustomErr::NonUtf8String => "non-UTF8 string option",
        CustomErr::UnrecognizedMessageType => "unrecognized message type",
        CustomErr::InvalidHlen => "truncated header or option",
    }
}

pub fn filter_options_by_req(opts: &mut Vec<DhcpOption>, req_params: &[u8]) {
    let n = opts.len();
    if n == 0 {
        return;
    }
    // Fast path: cache option codes once so the O(n*m) scan compares u8s
    // instead of re-running the `code()` match per probe. Swap sequence and
    // truncation are bit-identical to the original (including duplicate-code
    // quirks) because `codes` is kept in lockstep with `opts`.
    if n > 64 {
        return filter_options_by_req_slow(opts, req_params);
    }
    let mut codes = [0u8; 64];
    for (i, o) in opts.iter().enumerate() {
        codes[i] = o.code();
    }
    let mut pos = 0usize;
    for r in req_params.iter() {
        let mut found = None;
        for i in pos..n {
            if codes[i] == *r {
                found = Some(i);
                break;
            }
        }
        if let Some(i) = found {
            if i != pos {
                opts.swap(i, pos);
                codes.swap(i, pos);
            }
            pos += 1;
        }
    }
    const H: [u8; 6] = [
        options::DHCP_MESSAGE_TYPE,
        options::SERVER_IDENTIFIER,
        options::SUBNET_MASK,
        options::IP_ADDRESS_LEASE_TIME,
        options::DOMAIN_NAME_SERVER,
        options::ROUTER,
    ];
    for r in H.iter() {
        let mut found = None;
        for i in pos..n {
            if codes[i] == *r {
                found = Some(i);
                break;
            }
        }
        if let Some(i) = found {
            if i != pos {
                opts.swap(i, pos);
                codes.swap(i, pos);
            }
            pos += 1;
        }
    }
    opts.truncate(pos);
}

fn filter_options_by_req_slow(opts: &mut Vec<DhcpOption>, req_params: &[u8]) {
    let mut pos = 0;
    let h = &[
        options::DHCP_MESSAGE_TYPE,
        options::SERVER_IDENTIFIER,
        options::SUBNET_MASK,
        options::IP_ADDRESS_LEASE_TIME,
        options::DOMAIN_NAME_SERVER,
        options::ROUTER,
    ] as &[u8];

    // Process options from req_params
    for r in req_params.iter() {
        let mut found = false;
        for (i, o) in opts[pos..].iter().enumerate() {
            if o.code() == *r {
                found = true;
                if pos + i != pos {
                    opts.swap(pos + i, pos);
                }
                pos += 1;
                break;
            }
        }
        if !found {
            // Option not found, continue searching
        }
    }

    // Process options from h
    for r in h.iter() {
        let mut found = false;
        for (i, o) in opts[pos..].iter().enumerate() {
            if o.code() == *r {
                found = true;
                if pos + i != pos {
                    opts.swap(pos + i, pos);
                }
                pos += 1;
                break;
            }
        }
        if !found {
            // Option not found, continue searching
        }
    }

    // Truncate the options list if necessary
    opts.truncate(pos);
}

impl Server {
    pub fn serve<H: Handler>(
        udp_soc: UdpSocket,
        server_ip: Ipv4Addr,
        broadcast_ip: Ipv4Addr,
        handler: H,
    ) -> std::io::Error {
        Self::serve_with_broadcasts(udp_soc, server_ip, vec![broadcast_ip], handler)
    }

    /// Serve with several broadcast destinations: broadcast-routed replies
    /// are sent to each address (unicast replies still go once to the peer).
    /// An empty list falls back to the limited broadcast address.
    pub fn serve_with_broadcasts<H: Handler>(
        udp_soc: UdpSocket,
        server_ip: Ipv4Addr,
        broadcast_ips: Vec<Ipv4Addr>,
        mut handler: H,
    ) -> std::io::Error {
        let broadcasts = if broadcast_ips.is_empty() {
            vec![Ipv4Addr::BROADCAST]
        } else {
            broadcast_ips
        };
        let mut in_buf: [u8; 1500] = [0; 1500];
        let mut s = Server {
            socket: udp_soc,
            server_ip,
            broadcasts,
            src: SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        };
        loop {
            match s.socket.recv_from(&mut in_buf) {
                Err(e) => return e,
                Ok((l, src)) => match Packet::from(&in_buf[..l]) {
                    Ok(p) => {
                        s.src = src;

                        handler.handle_request(&s, p);
                    }
                    Err(e) => {
                        // Diagnose silent handshake failures: undecodable
                        // datagrams never reach the handler, so log why here.
                        eprintln!(
                            "ignoring malformed DHCP packet ({} bytes): {}",
                            l,
                            describe_decode_error(&e)
                        );
                    }
                },
            }
        }
    }

    /// Constructs and sends a reply packet back to the client.
    /// additional_options should not include DHCP_MESSAGE_TYPE nor SERVER_IDENTIFIER as these
    /// are added automatically.
    pub fn reply(
        &self,
        msg_type: MessageType,
        additional_options: Vec<DhcpOption>,
        offer_ip: Ipv4Addr,
        req_packet: Packet,
    ) -> std::io::Result<usize> {
        let ciaddr = match msg_type {
            MessageType::Nak => Ipv4Addr::new(0, 0, 0, 0),
            _ => req_packet.ciaddr,
        };

        let mut opts: Vec<DhcpOption> = Vec::with_capacity(additional_options.len() + 2);
        opts.push(DhcpOption::DhcpMessageType(msg_type));
        opts.push(DhcpOption::ServerIdentifier(self.server_ip));
        opts.extend(additional_options);

        if let Some(DhcpOption::ParameterRequestList(prl)) =
            req_packet.option(options::PARAMETER_REQUEST_LIST)
        {
            filter_options_by_req(&mut opts, prl);
        }

        self.send(Packet {
            reply: true,
            hops: 0,
            xid: req_packet.xid,
            secs: 0,
            broadcast: req_packet.broadcast,
            ciaddr,
            yiaddr: offer_ip,
            siaddr: Ipv4Addr::new(0, 0, 0, 0),
            giaddr: req_packet.giaddr,
            chaddr: req_packet.chaddr,
            options: opts,
        })
    }

    /// Checks the packet see if it was intended for this DHCP server (as opposed to some other also on the network).
    pub fn for_this_server(&self, packet: &Packet) -> bool {
        match packet.option(options::SERVER_IDENTIFIER) {
            Some(DhcpOption::ServerIdentifier(x)) => x.to_bits() == self.server_ip.to_bits(),
            _ => false,
        }
    }

    /// Peer address of the last-received datagram (diagnostics: combined
    /// with the packet's broadcast flag this determines reply routing).
    pub fn peer(&self) -> SocketAddr {
        self.src
    }

    /// Reply delivery plan (pure, unit-testable).
    ///
    /// Unicast back to the peer when it has a usable source address.
    /// Otherwise broadcast — plus, with the broadcast flag clear and a
    /// committed/offered address present, a unicast copy to `yiaddr`
    /// (RFC 2131 §4.1: a clear flag advertises unicast capability).
    /// That copy is what sleeping broadcast-deaf clients accept, and what
    /// dnsmasq-style servers send; broadcast copies still go out alongside.
    pub fn route_dests(
        peer: SocketAddr,
        broadcast: bool,
        yiaddr: Ipv4Addr,
        broadcasts: &[Ipv4Addr],
    ) -> Vec<SocketAddr> {
        if broadcast || peer.ip().is_unspecified() {
            let mut out = Vec::with_capacity(broadcasts.len() + 1);
            for b in broadcasts {
                let mut dst = peer;
                dst.set_ip(std::net::IpAddr::V4(*b));
                out.push(dst);
            }
            if !broadcast && peer.ip().is_unspecified() && !yiaddr.is_unspecified() {
                out.push(SocketAddr::new(std::net::IpAddr::V4(yiaddr), peer.port()));
            }
            out
        } else {
            vec![peer]
        }
    }

    /// Encodes and sends a DHCP packet back to the client. Delivery follows
    /// [`Server::route_dests`]: unicast replies go once to the peer (zero
    /// extra allocation, as before); broadcast-routed replies are encoded
    /// once and fanned out. Returns the last send's byte count.
    pub fn send(&self, p: Packet) -> std::io::Result<usize> {
        let addr = self.src;
        if !p.broadcast && !addr.ip().is_unspecified() {
            // Fast path: sourced peer, no broadcast — byte-identical to the
            // historical behavior (bench-sensitive: no allocation here).
            let mut out_buf = [0u8; crate::packet::WIRE_MAX];
            return self.socket.send_to(p.encode(&mut out_buf), addr);
        }
        // WIRE_MAX is the DHCP wire ceiling (see packet::Packet::encode):
        // 240-byte header+cookie, options, END, PAD-to-WIRE_MAX. Bytes
        // beyond are never read. Encoded once, fanned out to each address.
        let mut out_buf = [0u8; crate::packet::WIRE_MAX];
        let wire = p.encode(&mut out_buf);
        let mut sent = 0;
        for dst in Self::route_dests(addr, p.broadcast, p.yiaddr, &self.broadcasts) {
            sent = self.socket.send_to(wire, dst)?;
        }
        Ok(sent)
    }
}
