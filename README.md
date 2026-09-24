# RustyDHCP V2



V2 HAS BEEN RELEASED 
ipv6 and ntp and fast dhcp option is supported, hostnames are supported,
Fixes for Nest thermostats
Benchmarks added, significant performance uplifts in how many requests per second.


![Rust](https://img.shields.io/badge/Language-Rust-orange)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)
![Crossplatform](https://img.shields.io/badge/Crossplatform-Yes-brightgreen)
![Cross Compilation](https://img.shields.io/badge/Cross%20Compilation-Supported-brightgreen)

A simple and zero-dependency DHCP server written in Rust, with credit to Richard Warburton for contributions to parts of the code.

## Features

- IPV6 support
- NTP support
- Highly performant. tested over 60k/s in DHCP requests
- Fast negotiation DHCP option
- Lightweight and minimalistic DHCP server.
- Zero external dependencies; just Rust!
- Easy to use and configure.
- Based on reliable networking libraries.
- Fast and efficient.
- Cross-platform support and cross-compilation.
- Customizable Leases File: Support for a "leases" file that allows you to define permanent leases, ensuring clients always receive the same IP address.
- Managed DHCPv6 range: stateful DHCPv6 (RFC 8415) address allocation from a configured IPv6 pool, with DUID-based leases.
- Single `dhcp.conf` file: every IPv4 and IPv6 setting in one place, no recompiling to reconfigure.
  
## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributions](#contributions)
- [License](#license)

## Installation

1. Make sure you have Rust installed. If not, install it from [https://www.rust-lang.org/](https://www.rust-lang.org/).

2. Clone this repository:

   ```bash
   git clone https://github.com/pj1234678/RustyDHCP.git
   ```

 3. Build the server:

    ```bash
    cd RustyDHCP
    cargo build --release
    ```

## Usage

1. Start the DHCP server (no arguments; it always reads `./dhcp.conf`):

    ```bash
    sudo ./target/release/dhcp4r
    ```

    The server will listen on the configured DHCP ports (67 for IPv4, 547 for IPv6 when enabled) and start serving DHCP requests. Every DHCP Request is also printed monitor-style (`timestamp\tmac\tip\thostname\tOnline`).

2. Make DHCP requests from clients, and the server will respond with IP addresses and other configuration details.

### Diagnosing clients

Every handshake step is logged: `DISCOVER -> OFFER/ACK`, `REQUEST -> ACK/NAK (reason)`, `RELEASE -> freed`, pool-exhaustion (`no reply ... used`), ignored packets (`unsupported message type`, `no client ID`, `server_id mismatch`), and malformed datagrams (`ignoring malformed ...: reason`). If a client (e.g. an IoT thermostat) won't connect while dnsmasq works, watch for:
- `INFORM ... ignored` — this server does not answer DHCPINFORM; dnsmasq does.
- `-> NAK ... outside pool range` — the client asks for an address outside `ip_start + lease_num`.
- `no reply (pool exhausted ...)` — all leases are handed out.
- `ignoring malformed ...` — the client's packet fails to decode at all.
- `-> OFFER ... to [192.168.2.255:68, 255.255.255.255:68]` but the client
never sends Request — check for a unicast copy in the list. With the
broadcast flag clear the server unicasts a copy to the offered address
(`..., 192.168.2.x:68`, RFC 2131 §4.1, like dnsmasq) alongside the
broadcasts, for clients/APs that drop every broadcast flavor. If even the
unicast copy never arrives, suspect AP broadcast handling or firewall, and
compare a dnsmasq capture (`tcpdump -i <lan> -e -vvv`).

## Configuration

All settings live in a single `dhcp.conf` file using a minimal `key = value` format (no dependencies to parse it). Blank lines and lines starting with `#` or `;` are ignored, keys are case-insensitive, a trailing ` # comment` is stripped, duplicate keys use the last value, and unknown keys are ignored. Any malformed line or invalid value fails loudly with the key and line number. If the file is missing, the server warns and uses the built-in defaults below.

| Key | Default | Description |
| --- | ------- | ----------- |
| `server_ip` | `192.168.2.1` | This server's address (DHCP option 54) |
| `ip_start` | `192.168.2.2` | First address of the managed IPv4 pool |
| `lease_num` | `252` | IPv4 pool size (covers `.2` .. `.253`) |
| `subnet_mask` | `255.255.255.0` | Advertised subnet mask (option 1) |
| `router_ip` | `192.168.2.1` | Advertised gateway (option 3) |
| `dns_ips` | `8.8.8.8` | Advertised DNS servers, comma-separated (option 6) |
| `enable_ntp` | `false` | Master switch for advertising NTP servers (option 42) |
| `ntp_ips` | _(empty)_ | Advertised NTP servers, comma-separated (option 42); sent only when `enable_ntp` is true and the list is non-empty |
| `enable_rapid_commit` | `false` | Master switch for DHCP Rapid Commit (option 80 for IPv4, option 14 for IPv6) |
| `broadcast_ip` | `192.168.2.255` | Where broadcast replies are sent; comma-separated list fans each reply out to every address (e.g. `192.168.2.255, 255.255.255.255`) |
| `extra_broadcast_ips` | _(empty)_ | Additional broadcast destinations, comma-separated; appended to `broadcast_ip` |
| `lease_duration_secs` | `86400` | IPv4 lease lifetime (option 51) |
| `leases_file` | `leases` | Permanent `mac,ip` reservations |
| `listen_addr` | `0.0.0.0:67` | Address to bind for DHCPv4 |
| `enable_dhcpv6` | `false` | Master switch for the DHCPv6 service |
| `server_duid` | `00:03:00:01:02:00:5e:aa:bb:cc` | Server DUID for SERVERID (1..=128 hex bytes) |
| `ipv6_start` | `fd00::100` | First address of the managed IPv6 pool |
| `ipv6_lease_num` | `1000` | IPv6 pool size |
| `ipv6_dns` | `2001:4860:4860::8888` | Advertised DNS servers, comma-separated (option 23) |
| `ipv6_lease_duration_secs` | `86400` | IPv6 preferred + valid lifetimes (IAADDR) |
| `leases_file_v6` | `leases6` | Permanent `duid-hex,ipv6` reservations |
| `listen_addr_v6` | `[::]:547` | Address to bind for DHCPv6 |

See the shipped `dhcp.conf` for a fully commented example. Boolean values accept `true/false`, `yes/no`, `on/off`, `1/0` (any case).

### DHCPv6 managed range (RFC 8415)

Set `enable_dhcpv6 = true` and configure `ipv6_start` / `ipv6_lease_num` to serve stateful DHCPv6 on port 547 alongside DHCPv4:

- **Solicit → Advertise**: offers the client's current address, else the first free address of the managed range (round-robin).
- **Request / Renew / Rebind → Reply**: commits the requested IA_NA address; T1/T2 are set to half / seven-eighths of the lease lifetime.
- **Release / Decline → frees** the client's lease (only when the Server ID matches this server).
- Pool exhaustion (or any failure) gets a Reply with Status Code `NoAddrsAvail` (2).

Clients are identified by their exact DUID bytes and leases work like the IPv4 side, with one deliberate difference: infinite (file-reserved) IPv6 leases are never stealable. Malformed lines in `leases6` are skipped without killing the server.

To create a "leases" file with the example permanent lease, you can manually create a file named "leases" in the same directory as the compiled program with the following content:

f4:5c:19:af:96:8d,192.168.2.90

This lease format specifies the MAC address and the corresponding IP address for the client. The DHCP server will read this file to assign permanent leases based on its contents.

### Client host names (DHCP option 12)

When a client announces a host name (option 12, RFC 2132 §3.14), the server records it against the lease: it is stored when the lease is created, refreshed whenever a later Discover or Request carries a name, and left untouched by packets that omit it (so renewals without the option don't flap the recorded name). Releasing the lease drops the name with it. Malformed (non-UTF-8) names never reach the server logic — the decoder already rejects them. The monitor prints the recorded name per Request (`-` when the client sent none):

```text
2026-01-01T12:00:00	f4:5c:19:af:96:8d	192.168.2.90	laptop	Online
```

The IPv6 equivalent is a "leases6" file with `duid-hex,ipv6` lines, for example:

00:03:00:01:02:00:5e:aa:bb:cc,fd00::100

### DHCP Rapid Commit

Set `enable_rapid_commit = true` to allow the 2-message exchange: a Discover (IPv4, RFC 4039 option 80) or Solicit (IPv6, RFC 8415 option 14) carrying the rapid-commit option is answered immediately with an Ack/Reply that commits the lease, skipping Offer/Advertise. Without both the flag and the option on the wire, the server uses the legacy 4-message flow. Rapid-commit selection is Discover-style (current lease, else round-robin); pool exhaustion behaves like the unanswered Discover/Advertise path.


## Contributions

This DHCP server has been made possible with contributions from the open-source community, including valuable code from Richard Warburton. Feel free to contribute to this project and make it even better!

If you find a bug or have a feature request, please open an issue on the GitHub repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note:** Remember to use this DHCP server responsibly and comply with local network regulations and security practices.
