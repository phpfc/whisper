use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::crypto::KeyExchange;

/// Messages used during hole punching and connection establishment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PunchMessage {
    /// Initial punch packet - sent repeatedly to establish NAT mapping
    Punch {
        session_id: String,
    },
    /// Acknowledgment with public key for key exchange
    PunchAck {
        session_id: String,
        public_key: Vec<u8>,
        username: String,
    },
    /// Key exchange response
    KeyExchangeResponse {
        public_key: Vec<u8>,
        username: String,
    },
}

/// Result of successful hole punch
pub struct PunchResult {
    pub peer_addr: SocketAddr,
    pub peer_public_key: [u8; 32],
    pub peer_username: String,
}

/// Waits for incoming connection (for session creator)
pub fn wait_for_peer(
    socket: &UdpSocket,
    session_id: &str,
    key_exchange: &KeyExchange,
    our_username: &str,
    timeout: Duration,
) -> Result<PunchResult> {
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let start = Instant::now();
    let mut buf = [0u8; 2048];
    let our_public_key = key_exchange.public_key().as_bytes().to_vec();

    println!("Waiting for peer to connect...");

    while start.elapsed() < timeout {
        match socket.recv_from(&mut buf) {
            Ok((len, peer_addr)) => {
                if let Ok(msg) = serde_json::from_slice::<PunchMessage>(&buf[..len]) {
                    match msg {
                        PunchMessage::Punch { session_id: sid } if sid == session_id => {
                            // Received punch, send ack with our public key
                            let ack = PunchMessage::PunchAck {
                                session_id: session_id.to_string(),
                                public_key: our_public_key.clone(),
                                username: our_username.to_string(),
                            };
                            let ack_bytes = serde_json::to_vec(&ack)?;

                            // Send multiple times for reliability
                            for _ in 0..3 {
                                socket.send_to(&ack_bytes, peer_addr)?;
                                std::thread::sleep(Duration::from_millis(50));
                            }
                        }
                        PunchMessage::KeyExchangeResponse { public_key, username } => {
                            // Peer responded with their key
                            if public_key.len() == 32 {
                                let mut peer_key = [0u8; 32];
                                peer_key.copy_from_slice(&public_key);
                                return Ok(PunchResult {
                                    peer_addr,
                                    peer_public_key: peer_key,
                                    peer_username: username,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout, continue waiting
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                return Err(anyhow!("Socket error: {}", e));
            }
        }
    }

    Err(anyhow!("Timeout waiting for peer connection"))
}

/// Connects to peer (for session joiner)
pub fn connect_to_peer(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    session_id: &str,
    key_exchange: &KeyExchange,
    our_username: &str,
    timeout: Duration,
) -> Result<PunchResult> {
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let start = Instant::now();
    let mut buf = [0u8; 2048];
    let our_public_key = key_exchange.public_key().as_bytes().to_vec();

    let punch = PunchMessage::Punch {
        session_id: session_id.to_string(),
    };
    let punch_bytes = serde_json::to_vec(&punch)?;

    println!("Connecting to peer at {}...", peer_addr);

    let mut last_punch = Instant::now() - Duration::from_secs(1);

    while start.elapsed() < timeout {
        // Send punch packets every 500ms
        if last_punch.elapsed() > Duration::from_millis(500) {
            socket.send_to(&punch_bytes, peer_addr)?;
            last_punch = Instant::now();
        }

        match socket.recv_from(&mut buf) {
            Ok((len, from_addr)) => {
                if from_addr != peer_addr {
                    continue;
                }

                if let Ok(msg) = serde_json::from_slice::<PunchMessage>(&buf[..len]) {
                    match msg {
                        PunchMessage::PunchAck { session_id: sid, public_key, username }
                            if sid == session_id =>
                        {
                            // Received ack, send our key exchange response
                            let response = PunchMessage::KeyExchangeResponse {
                                public_key: our_public_key.clone(),
                                username: our_username.to_string(),
                            };
                            let response_bytes = serde_json::to_vec(&response)?;

                            // Send multiple times for reliability
                            for _ in 0..3 {
                                socket.send_to(&response_bytes, peer_addr)?;
                                std::thread::sleep(Duration::from_millis(50));
                            }

                            if public_key.len() == 32 {
                                let mut peer_key = [0u8; 32];
                                peer_key.copy_from_slice(&public_key);
                                return Ok(PunchResult {
                                    peer_addr,
                                    peer_public_key: peer_key,
                                    peer_username: username,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                return Err(anyhow!("Socket error: {}", e));
            }
        }
    }

    Err(anyhow!(
        "Could not connect to peer. Possible causes:\n\
         - Peer is offline\n\
         - Symmetric NAT (corporate/carrier network) blocking connection\n\
         - Firewall blocking UDP traffic"
    ))
}
