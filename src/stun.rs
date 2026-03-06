use anyhow::{anyhow, Result};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Public STUN servers - free, reliable, always available
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
];

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

fn query_stun_server(socket: &UdpSocket, server: &str) -> Result<SocketAddr> {
    // Get IPv4 address only (filter out IPv6)
    let server_addr = server
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| anyhow!("Failed to resolve STUN server to IPv4"))?;

    // Set timeout for this query
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Build STUN Binding Request
    // https://datatracker.ietf.org/doc/html/rfc5389
    let transaction_id: [u8; 12] = rand::random();
    let mut request = Vec::with_capacity(20);

    // Message Type: Binding Request (0x0001)
    request.extend_from_slice(&[0x00, 0x01]);
    // Message Length: 0 (no attributes)
    request.extend_from_slice(&[0x00, 0x00]);
    // Magic Cookie (fixed value)
    request.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    // Transaction ID (96 bits)
    request.extend_from_slice(&transaction_id);

    socket.send_to(&request, server_addr)?;

    let mut buf = [0u8; 256];
    let (len, _) = socket.recv_from(&mut buf)?;

    if len < 20 {
        return Err(anyhow!("STUN response too short"));
    }

    // Verify it's a Binding Response (0x0101)
    if buf[0] != 0x01 || buf[1] != 0x01 {
        return Err(anyhow!("Not a STUN Binding Response"));
    }

    // Verify transaction ID matches
    if buf[8..20] != transaction_id {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires network
    fn test_stun_discovery() {
        let result = discover_public_endpoint();
        assert!(result.is_ok());
        let (_, addr) = result.unwrap();
        println!("Public endpoint: {}", addr);
    }
}
