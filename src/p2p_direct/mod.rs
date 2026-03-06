use crate::crypto::CryptoSession;
use crate::invite::Invite;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Serialize, Deserialize)]
pub enum P2PMessage {
    Ping,
    Pong,
    HandshakeInit {
        public_key: Vec<u8>,
        username: String,
    },
    HandshakeAck,
    ChatMessage {
        sender: String,
        encrypted_content: Vec<u8>,
    },
    Goodbye,
}

pub struct P2PConnection {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    crypto: Arc<RwLock<Option<CryptoSession>>>,
    username: String,
    peer_username: Arc<RwLock<Option<String>>>,
}

impl P2PConnection {
    pub async fn create_host(local_port: u16, username: String) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?;

        Ok(Self {
            socket: Arc::new(socket),
            peer_addr: "0.0.0.0:0".parse()?,
            crypto: Arc::new(RwLock::new(None)),
            username,
            peer_username: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn connect_to_peer(invite: Invite, username: String, shared_secret: [u8; 32]) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        let mut conn = Self {
            socket: Arc::new(socket),
            peer_addr: invite.public_addr,
            crypto: Arc::new(RwLock::new(Some(CryptoSession::new(shared_secret)))),
            username: username.clone(),
            peer_username: Arc::new(RwLock::new(Some(invite.username))),
        };

        conn.initiate_handshake().await?;
        Ok(conn)
    }

    async fn initiate_handshake(&mut self) -> Result<()> {
        for _ in 0..5 {
            self.send_message(&P2PMessage::Ping).await?;
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
        Ok(())
    }

    pub async fn send_message(&self, msg: &P2PMessage) -> Result<()> {
        let json = serde_json::to_vec(msg)?;
        self.socket.send_to(&json, self.peer_addr).await?;
        Ok(())
    }

    pub async fn receive_message(&self) -> Result<(P2PMessage, SocketAddr)> {
        let mut buf = vec![0u8; 65507];
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        let msg = serde_json::from_slice(&buf[..len])?;
        Ok((msg, addr))
    }

    pub async fn send_chat(&self, text: String) -> Result<()> {
        let crypto_guard = self.crypto.read().await;
        if let Some(crypto) = crypto_guard.as_ref() {
            let encrypted = crypto.encrypt(text.as_bytes())?;
            self.send_message(&P2PMessage::ChatMessage {
                sender: self.username.clone(),
                encrypted_content: encrypted,
            })
            .await?;
        }
        Ok(())
    }

    pub async fn run(
        &mut self,
        mut rx: mpsc::UnboundedReceiver<String>,
        tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let socket = self.socket.clone();
        let crypto = self.crypto.clone();
        let peer_username = self.peer_username.clone();

        let receive_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65507];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        if let Ok(msg) = serde_json::from_slice::<P2PMessage>(&buf[..len]) {
                            match msg {
                                P2PMessage::Ping => {
                                    let pong = serde_json::to_vec(&P2PMessage::Pong).unwrap();
                                    socket.send_to(&pong, addr).await.ok();
                                }
                                P2PMessage::Pong => {}
                                P2PMessage::HandshakeInit { username, .. } => {
                                    *peer_username.write().await = Some(username.clone());
                                    let ack = serde_json::to_vec(&P2PMessage::HandshakeAck).unwrap();
                                    socket.send_to(&ack, addr).await.ok();
                                }
                                P2PMessage::ChatMessage {
                                    sender,
                                    encrypted_content,
                                } => {
                                    let crypto_guard = crypto.read().await;
                                    if let Some(crypto_session) = crypto_guard.as_ref() {
                                        if let Ok(plaintext) = crypto_session.decrypt(&encrypted_content) {
                                            if let Ok(text) = String::from_utf8(plaintext) {
                                                tx.send(format!("{}: {}", sender, text)).ok();
                                            }
                                        }
                                    }
                                }
                                P2PMessage::Goodbye => {
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        while let Some(text) = rx.recv().await {
            self.send_chat(text).await?;
        }

        receive_task.abort();
        Ok(())
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}
