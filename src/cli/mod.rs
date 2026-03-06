use crate::crypto::{CryptoSession, KeyExchange};
use crate::session::{SessionAuth, SessionId, SessionMessage};
use anyhow::{anyhow, Result};
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
use serde_json;
use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub struct ChatClient {
    username: String,
    session_id: SessionId,
    messages: Vec<String>,
    input: String,
    crypto_sessions: HashMap<String, CryptoSession>,
    server_addr: String,
}

impl ChatClient {
    pub fn new(username: String, session_id: SessionId, server_addr: String) -> Self {
        Self {
            username,
            session_id,
            messages: vec![],
            input: String::new(),
            crypto_sessions: HashMap::new(),
            server_addr,
        }
    }

    pub async fn connect(&mut self, password: &str) -> Result<()> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let key_exchange = KeyExchange::new();
        let our_public_key = key_exchange.public_key().as_bytes().to_vec();

        let auth = SessionAuth::new(password);
        let join_msg = SessionMessage::Join {
            session_id: self.session_id.clone(),
            password_hash: *auth.hash(),
            public_key: our_public_key.clone(),
            username: self.username.clone(),
        };

        let (ui_tx, mut ui_rx) = mpsc::unbounded_channel::<String>();
        let (net_tx, mut net_rx) = mpsc::unbounded_channel::<SessionMessage>();

        let mut writer = writer;
        let join_str = serde_json::to_string(&join_msg)? + "\n";
        writer.write_all(join_str.as_bytes()).await?;
        writer.flush().await?;

        let net_tx_clone = net_tx.clone();
        tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Ok(msg) = serde_json::from_str::<SessionMessage>(&line) {
                            net_tx_clone.send(msg).ok();
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        tokio::spawn(async move {
            while let Some(msg) = ui_rx.recv().await {
                if writer.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
                if writer.write_all(b"\n").await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
            }
        });

        if let Some(msg) = net_rx.recv().await {
            match msg {
                SessionMessage::JoinAck {
                    success,
                    peer_public_keys,
                } => {
                    if !success {
                        return Err(anyhow!("Failed to join session"));
                    }

                    self.messages
                        .push(format!("Connected to session {}", self.session_id));

                    for (peer_username, peer_key) in peer_public_keys {
                        if peer_key.len() == 32 {
                            let mut peer_public_bytes = [0u8; 32];
                            peer_public_bytes.copy_from_slice(&peer_key);
                            let peer_public = x25519_dalek::PublicKey::from(peer_public_bytes);
                            let shared = key_exchange
                                .public_key()
                                .as_bytes()
                                .iter()
                                .zip(peer_public.as_bytes().iter())
                                .map(|(a, b)| a ^ b)
                                .collect::<Vec<u8>>();
                            let mut secret = [0u8; 32];
                            secret.copy_from_slice(&shared[..32]);

                            self.crypto_sessions
                                .insert(peer_username.clone(), CryptoSession::new(secret));
                            self.messages
                                .push(format!("User {} is in the session", peer_username));
                        }
                    }
                }
                _ => return Err(anyhow!("Unexpected message")),
            }
        }

        self.run_ui(ui_tx, net_rx, our_public_key).await
    }

    async fn run_ui(
        &mut self,
        ui_tx: mpsc::UnboundedSender<String>,
        mut net_rx: mpsc::UnboundedReceiver<SessionMessage>,
    our_public_key: Vec<u8>,
    ) -> Result<()> {
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
                        .title(format!("Session: {} | User: {}", self.session_id, self.username)),
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
                                    let message = self.input.clone();
                                    self.messages.push(format!("{}: {}", self.username, message));

                                    let plaintext = message.as_bytes();
                                    if let Some(crypto) = self.crypto_sessions.values().next() {
                                        if let Ok(encrypted) = crypto.encrypt(plaintext) {
                                            let msg = SessionMessage::ChatMessage {
                                                sender: self.username.clone(),
                                                encrypted_message: encrypted,
                                            };
                                            ui_tx.send(serde_json::to_string(&msg).unwrap()).ok();
                                        }
                                    }

                                    self.input.clear();
                                }
                            }
                            KeyCode::Esc => {
                                break Ok(());
                            }
                            _ => {}
                        }
                    }
                }
                Some(msg) = net_rx.recv() => {
                    match msg {
                        SessionMessage::PeerJoined { username, public_key } => {
                            if public_key.len() == 32 {
                                let mut peer_public_bytes = [0u8; 32];
                                peer_public_bytes.copy_from_slice(&public_key);
                                let peer_public = x25519_dalek::PublicKey::from(peer_public_bytes);
                                let shared = our_public_key
                                    .iter()
                                    .zip(peer_public.as_bytes().iter())
                                    .map(|(a, b)| a ^ b)
                                    .collect::<Vec<u8>>();
                                let mut secret = [0u8; 32];
                                secret.copy_from_slice(&shared[..32]);

                                self.crypto_sessions.insert(username.clone(), CryptoSession::new(secret));
                            }
                            self.messages.push(format!("{} joined the session", username));
                        }
                        SessionMessage::PeerLeft { username } => {
                            self.crypto_sessions.remove(&username);
                            self.messages.push(format!("{} left the session", username));
                        }
                        SessionMessage::ChatMessage { sender, encrypted_message } => {
                            if let Some(crypto) = self.crypto_sessions.values().next() {
                                if let Ok(plaintext) = crypto.decrypt(&encrypted_message) {
                                    if let Ok(text) = String::from_utf8(plaintext) {
                                        self.messages.push(format!("{}: {}", sender, text));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        };

        disable_raw_mode()?;
        terminal.show_cursor()?;
        result
    }
}
