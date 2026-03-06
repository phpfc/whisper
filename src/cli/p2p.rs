use crate::crypto::CryptoSession;
use crate::invite::Invite;
use crate::session::SessionId;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Serialize, Deserialize)]
enum P2PMessage {
    Ping,
    Pong,
    Handshake { username: String },
    Chat { sender: String, content: Vec<u8> },
}

pub struct P2PChatClient {
    username: String,
    session_id: SessionId,
    messages: Vec<String>,
    input: String,
    socket: Arc<UdpSocket>,
    peer_addr: Arc<RwLock<Option<SocketAddr>>>,
    crypto: Arc<RwLock<Option<CryptoSession>>>,
}

impl P2PChatClient {
    pub async fn create_host(
        username: String,
        session_id: SessionId,
        port: u16,
        crypto: CryptoSession,
    ) -> Result<Self> {
        let addr = format!("0.0.0.0:{}", if port == 0 { 8080 } else { port });
        let socket = UdpSocket::bind(&addr).await?;

        Ok(Self {
            username,
            session_id,
            messages: vec![
                format!("Listening on {}...", socket.local_addr()?),
                "Waiting for peer to send handshake...".to_string(),
            ],
            input: String::new(),
            socket: Arc::new(socket),
            peer_addr: Arc::new(RwLock::new(None)),
            crypto: Arc::new(RwLock::new(Some(crypto))),
        })
    }

    pub async fn connect_to_peer(
        username: String,
        invite: Invite,
        crypto: CryptoSession,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        let mut client = Self {
            username: username.clone(),
            session_id: invite.session_id,
            messages: vec![
                format!("Connecting to {}...", invite.public_addr),
                "Sending handshake packets...".to_string(),
            ],
            input: String::new(),
            socket: Arc::new(socket),
            peer_addr: Arc::new(RwLock::new(Some(invite.public_addr))),
            crypto: Arc::new(RwLock::new(Some(crypto))),
        };

        client.send_handshake().await?;
        Ok(client)
    }

    async fn send_handshake(&self) -> Result<()> {
        let peer_addr = self.peer_addr.read().await;
        if let Some(peer) = *peer_addr {
            let msg = P2PMessage::Handshake {
                username: self.username.clone(),
            };
            let json = serde_json::to_vec(&msg)?;
            for _ in 0..5 {
                self.socket.send_to(&json, peer).await?;
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
        }
        Ok(())
    }

    pub async fn run(mut self) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(Clear(ClearType::All))?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                if event::poll(std::time::Duration::from_millis(100)).unwrap_or(false) {
                    if let Ok(evt) = event::read() {
                        if event_tx.send(evt).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let socket = self.socket.clone();
        let crypto = self.crypto.clone();
        let peer_addr_lock = self.peer_addr.clone();
        let (net_tx, mut net_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        if let Ok(msg) = serde_json::from_slice::<P2PMessage>(&buf[..len]) {
                            net_tx.send((msg, addr)).ok();
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let result = loop {
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(3)].as_ref())
                    .split(f.area());

                let messages: Vec<ListItem> = self
                    .messages
                    .iter()
                    .map(|m| {
                        ListItem::new(Line::from(m.clone()))
                            .style(Style::default().fg(Color::White))
                    })
                    .collect();

                let messages_list = List::new(messages).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(
                            "P2P Session: {} | User: {}",
                            self.session_id, self.username
                        )),
                );

                f.render_widget(messages_list, chunks[0]);

                let input = Paragraph::new(self.input.as_str())
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title("Message"));

                f.render_widget(input, chunks[1]);
            })?;

            tokio::select! {
                Some(evt) = event_rx.recv() => {
                    if let Event::Key(key) = evt {
                        match key.code {
                            KeyCode::Char(c) => {
                                self.input.push(c);
                            }
                            KeyCode::Backspace => {
                                self.input.pop();
                            }
                            KeyCode::Enter => {
                                if !self.input.is_empty() {
                                    let peer_lock = self.peer_addr.read().await;
                                    if let Some(peer) = *peer_lock {
                                        let message = self.input.clone();
                                        self.messages.push(format!("{}: {}", self.username, message));

                                        let crypto_lock = self.crypto.read().await;
                                        if let Some(crypto) = crypto_lock.as_ref() {
                                            if let Ok(encrypted) = crypto.encrypt(message.as_bytes()) {
                                                let msg = P2PMessage::Chat {
                                                    sender: self.username.clone(),
                                                    content: encrypted,
                                                };
                                                if let Ok(json) = serde_json::to_vec(&msg) {
                                                    self.socket.send_to(&json, peer).await.ok();
                                                }
                                            }
                                        }

                                        self.input.clear();
                                    }
                                }
                            }
                            KeyCode::Esc => {
                                break Ok(());
                            }
                            _ => {}
                        }
                    }
                }
                Some((msg, addr)) = net_rx.recv() => {
                    match msg {
                        P2PMessage::Ping => {
                            self.messages.push(format!("Received Ping from {}", addr));
                            let pong = serde_json::to_vec(&P2PMessage::Pong).unwrap();
                            self.socket.send_to(&pong, addr).await.ok();
                        }
                        P2PMessage::Pong => {
                            self.messages.push(format!("Received Pong from {}", addr));
                        }
                        P2PMessage::Handshake { username } => {
                            self.messages.push(format!("Received Handshake from {} ({})", username, addr));
                            let mut peer_lock = self.peer_addr.write().await;
                            let was_none = peer_lock.is_none();
                            *peer_lock = Some(addr);
                            drop(peer_lock);

                            if was_none {
                                self.messages.push(format!("{} connected from {}", username, addr));
                            }

                            let reply = P2PMessage::Handshake {
                                username: self.username.clone(),
                            };
                            let json = serde_json::to_vec(&reply).unwrap();
                            self.socket.send_to(&json, addr).await.ok();
                        }
                        P2PMessage::Chat { sender, content } => {
                            let crypto_lock = self.crypto.read().await;
                            if let Some(crypto) = crypto_lock.as_ref() {
                                if let Ok(plaintext) = crypto.decrypt(&content) {
                                    if let Ok(text) = String::from_utf8(plaintext) {
                                        self.messages.push(format!("{}: {}", sender, text));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        disable_raw_mode()?;
        terminal.show_cursor()?;
        result
    }
}
