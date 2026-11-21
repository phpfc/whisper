use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Public STUN servers - free, reliable, always available
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// The two servers (from different operators) used to tell whether the NAT
/// reuses the same external mapping regardless of destination.
const PROBE_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

/// How long `probe_nat` waits for each server.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How the NAT maps our local port when talking to different destinations.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatMapping {
    /// Same external ip:port for every destination (hole punching works).
    EndpointIndependent,
    /// A new external ip:port per destination (symmetric NAT).
    EndpointDependent,
    /// Not enough STUN answers to tell.
    Unknown,
}

/// Discovers our public IP:port as seen from the internet.
/// Uses STUN protocol to query public servers.
///
/// Note: This creates a temporary socket for STUN queries to avoid
/// issues with the main socket binding.
pub fn discover_public_endpoint() -> Result<(UdpSocket, SocketAddr)> {
    // Create a fresh socket for STUN
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    let mut last_error = None;
    for server in STUN_SERVERS {
        match query_stun_server(&socket, server) {
            Ok(addr) => return Ok((socket, addr)),
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!(
        "Failed to discover public address. Check your internet connection."
    )))
}

/// Builds a STUN Binding Request (no attributes) for the given transaction id.
/// https://datatracker.ietf.org/doc/html/rfc5389
pub fn build_binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut request = [0u8; 20];
    // Message Type: Binding Request (0x0001)
    request[0..2].copy_from_slice(&[0x00, 0x01]);
    // Message Length: 0 (no attributes)
    request[2..4].copy_from_slice(&[0x00, 0x00]);
    // Magic Cookie (fixed value)
    request[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    // Transaction ID (96 bits)
    request[8..20].copy_from_slice(txid);
    request
}

/// Parses a STUN Binding Response and returns the IPv4 address the server saw
/// us at. Fails if the datagram is not a Binding Response for `txid`.
pub fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddr> {
    let len = buf.len();
    if len < 20 {
        return Err(anyhow!("STUN response too short"));
    }

    // Verify it's a Binding Response (0x0101)
    if buf[0] != 0x01 || buf[1] != 0x01 {
        return Err(anyhow!("Not a STUN Binding Response"));
    }

    // Verify transaction ID matches
    if buf[8..20] != txid[..] {
        return Err(anyhow!("Transaction ID mismatch"));
    }

    // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut offset = 20;

    while offset + 4 <= 20 + msg_len && offset + 4 <= len {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > len {
            break;
        }

        match attr_type {
            0x0020 => {
                // XOR-MAPPED-ADDRESS
                if attr_len >= 8 {
                    let family = buf[offset + 1];
                    if family == 0x01 {
                        // IPv4
                        let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) ^ 0x2112;
                        let ip = [
                            buf[offset + 4] ^ 0x21,
                            buf[offset + 5] ^ 0x12,
                            buf[offset + 6] ^ 0xA4,
                            buf[offset + 7] ^ 0x42,
                        ];
                        let addr = SocketAddr::from((ip, port));
                        return Ok(addr);
                    }
                }
            }
            0x0001 => {
                // MAPPED-ADDRESS (fallback)
                if attr_len >= 8 {
                    let family = buf[offset + 1];
                    if family == 0x01 {
                        // IPv4
                        let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                        let ip = [buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]];
                        let addr = SocketAddr::from((ip, port));
                        return Ok(addr);
                    }
                }
            }
            _ => {}
        }

        // Move to next attribute (aligned to 4 bytes)
        offset += (attr_len + 3) & !3;
    }

    Err(anyhow!("No address found in STUN response"))
}

fn query_stun_server(socket: &UdpSocket, server: &str) -> Result<SocketAddr> {
    // Get IPv4 address only (filter out IPv6)
    let server_addr = server
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| anyhow!("Failed to resolve STUN server to IPv4"))?;

    // Set timeout for this query
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;

    let transaction_id: [u8; 12] = rand::random();
    socket.send_to(&build_binding_request(&transaction_id), server_addr)?;

    let mut buf = [0u8; 256];
    let (len, _) = socket.recv_from(&mut buf)?;

    parse_binding_response(&buf[..len], &transaction_id)
}

/// Compares the external address two different STUN servers saw for the same
/// local socket: identical means the NAT reuses the mapping per local port.
pub fn classify_mapping(a: SocketAddr, b: SocketAddr) -> NatMapping {
    if a == b {
        NatMapping::EndpointIndependent
    } else {
        NatMapping::EndpointDependent
    }
}

/// Asks `server` which address it sees us at, using `socket` (so the result is
/// the NAT mapping of that socket's local port). Datagrams that are not a
/// matching Binding Response are ignored until `timeout` expires.
pub async fn query(
    socket: &tokio::net::UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr> {
    let txid: [u8; 12] = rand::random();
    socket.send_to(&build_binding_request(&txid), server).await?;

    let wait_for_response = async {
        let mut buf = [0u8; 512];
        loop {
            let (len, _) = socket.recv_from(&mut buf).await?;
            if let Ok(addr) = parse_binding_response(&buf[..len], &txid) {
                return Ok::<SocketAddr, anyhow::Error>(addr);
            }
        }
    };

    tokio::time::timeout(timeout, wait_for_response)
        .await
        .map_err(|_| anyhow!("STUN query to {} timed out", server))?
}

/// Resolves a "host:port" STUN server to its first IPv4 address.
async fn resolve_ipv4(server: &str) -> Option<SocketAddr> {
    tokio::net::lookup_host(server)
        .await
        .ok()?
        .find(|addr| addr.is_ipv4())
}

/// Queries one STUN server by name; `None` if it does not resolve or answer.
async fn query_by_name(socket: &tokio::net::UdpSocket, server: &str) -> Option<SocketAddr> {
    let server_addr = resolve_ipv4(server).await?;
    query(socket, server_addr, PROBE_TIMEOUT).await.ok()
}

/// Discovers our public address through `socket` and whether the NAT keeps the
/// same mapping across destinations, by asking two independent STUN servers
/// in sequence.
///
/// - Both answered: `(Some(first), classify_mapping(first, second))`.
/// - Only one answered: `(Some(it), Unknown)`.
/// - Neither answered: the remaining `STUN_SERVERS` are tried just to learn
///   our address (`(Some(addr), Unknown)`), else `(None, Unknown)`.
pub async fn probe_nat(socket: &tokio::net::UdpSocket) -> (Option<SocketAddr>, NatMapping) {
    let first = query_by_name(socket, PROBE_SERVERS[0]).await;
    let second = query_by_name(socket, PROBE_SERVERS[1]).await;

    match (first, second) {
        (Some(a), Some(b)) => (Some(a), classify_mapping(a, b)),
        (Some(addr), None) | (None, Some(addr)) => (Some(addr), NatMapping::Unknown),
        (None, None) => {
            for server in STUN_SERVERS.iter().filter(|s| !PROBE_SERVERS.contains(s)) {
                if let Some(addr) = query_by_name(socket, server).await {
                    return (Some(addr), NatMapping::Unknown);
                }
            }
            (None, NatMapping::Unknown)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    /// Builds a Binding Response (0x0101) carrying one XOR-MAPPED-ADDRESS
    /// attribute (0x0020) for `addr` and the given transaction id.
    fn response_for(txid: &[u8; 12], addr: SocketAddrV4) -> Vec<u8> {
        let mut r = Vec::with_capacity(32);
        r.extend_from_slice(&[0x01, 0x01]);
        // Message length: one attribute = 4-byte header + 8-byte value
        r.extend_from_slice(&[0x00, 12]);
        r.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        r.extend_from_slice(txid);
        r.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
        let cookie = [0x21, 0x12, 0xA4, 0x42];
        for (octet, key) in addr.ip().octets().iter().zip(cookie) {
            r.push(octet ^ key);
        }
        r
    }

    #[test]
    fn request_has_header_cookie_and_txid() {
        let r = build_binding_request(&[1; 12]);
        assert_eq!(&r[0..4], &[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(&r[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(&r[8..20], &[1; 12]);
    }

    #[test]
    fn parses_xor_mapped_address() {
        let txid = [7; 12];
        let addr: SocketAddrV4 = "203.0.113.5:54321".parse().unwrap();
        assert_eq!(
            parse_binding_response(&response_for(&txid, addr), &txid).unwrap(),
            SocketAddr::V4(addr)
        );
    }

    #[test]
    fn rejects_wrong_txid_and_short_buffers() {
        let resp = response_for(&[7; 12], "203.0.113.5:1".parse().unwrap());
        assert!(parse_binding_response(&resp, &[8; 12]).is_err());
        assert!(parse_binding_response(&[0u8; 10], &[0; 12]).is_err());
    }

    #[test]
    fn same_mapping_is_endpoint_independent() {
        let a: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let b: SocketAddr = "203.0.113.5:4001".parse().unwrap();
        assert_eq!(classify_mapping(a, a), NatMapping::EndpointIndependent);
        assert_eq!(classify_mapping(a, b), NatMapping::EndpointDependent);
    }

    #[tokio::test]
    async fn query_skips_unrelated_datagrams_until_matching_response() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let mapped: SocketAddrV4 = "203.0.113.5:54321".parse().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(len, 20);
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            // Garbage and a response for another transaction come first.
            server.send_to(b"not stun", from).await.unwrap();
            let other = response_for(&[0xEE; 12], "198.51.100.9:1".parse().unwrap());
            server.send_to(&other, from).await.unwrap();
            server.send_to(&response_for(&txid, mapped), from).await.unwrap();
        });

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = query(&client, server_addr, Duration::from_secs(2)).await.unwrap();
        assert_eq!(addr, SocketAddr::V4(mapped));
    }

    #[tokio::test]
    async fn query_times_out_when_nobody_answers() {
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = query(&client, silent.local_addr().unwrap(), Duration::from_millis(100)).await;
        assert!(result.is_err());
    }

    #[test]
    #[ignore] // Requires network
    fn test_stun_discovery() {
        let result = discover_public_endpoint();
        assert!(result.is_ok());
        let (_, addr) = result.unwrap();
        println!("Public endpoint: {}", addr);
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn probe_nat_against_public_servers() {
        let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let (addr, _) = probe_nat(&s).await;
        assert!(addr.is_some());
    }
}
