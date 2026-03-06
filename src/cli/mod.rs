use crate::crypto::CryptoSession;
use crate::session::{ChatMessage, MAX_MESSAGE_LEN};
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
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_MESSAGES: usize = 1000;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

pub struct P2PChat {
    username: String,
    peer_username: String,
    messages: VecDeque<String>,
    input: String,
    crypto: CryptoSession,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
}

impl P2PChat {
    pub fn new(
        username: String,
        peer_username: String,
        socket: UdpSocket,
        peer_addr: SocketAddr,
        shared_secret: [u8; 32],
    ) -> Self {
        Self {
            username,
            peer_username,
            messages: VecDeque::with_capacity(MAX_MESSAGES),
            input: String::new(),
            crypto: CryptoSession::new(shared_secret),
            socket: Arc::new(socket),
            peer_addr,
        }
    }

    fn add_message(&mut self, msg: String) {
        if self.messages.len() >= MAX_MESSAGES {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
    }

    pub fn run(&mut self) -> Result<()> {
        // Set socket to non-blocking for UI thread
        self.socket.set_nonblocking(true)?;

        // Channel for incoming messages
        let (msg_tx, msg_rx): (Sender<ChatMessage>, Receiver<ChatMessage>) = mpsc::channel();

        // Spawn receiver thread
        let socket_clone = Arc::clone(&self.socket);
        let peer_addr = self.peer_addr;
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match socket_clone.recv_from(&mut buf) {
                    Ok((len, from)) => {
                        if from == peer_addr {
                            if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&buf[..len]) {
                                if msg_tx.send(msg).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });

        // Spawn keepalive thread
        let socket_keepalive = Arc::clone(&self.socket);
        let peer_addr_keepalive = self.peer_addr;
        thread::spawn(move || {
            let ping = serde_json::to_vec(&ChatMessage::Ping).unwrap();
            loop {
                thread::sleep(KEEPALIVE_INTERVAL);
                let _ = socket_keepalive.send_to(&ping, peer_addr_keepalive);
            }
        });

        self.add_message(format!("Connected to {}", self.peer_username));
        self.add_message(format!(
            "Your messages are end-to-end encrypted."
        ));
        self.add_message(String::new());

        self.run_ui(msg_rx)
    }

    fn run_ui(&mut self, msg_rx: Receiver<ChatMessage>) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(Clear(ClearType::All))?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = loop {
            // Process incoming messages
            while let Ok(msg) = msg_rx.try_recv() {
                match msg {
                    ChatMessage::Text { ciphertext } => {
                        if let Ok(plaintext) = self.crypto.decrypt(&ciphertext) {
                            if let Ok(text) = String::from_utf8(plaintext) {
                                self.add_message(format!("{}: {}", self.peer_username, text));
                            }
                        }
                    }
                    ChatMessage::Ping => {
                        let pong = serde_json::to_vec(&ChatMessage::Pong).unwrap();
                        let _ = self.socket.send_to(&pong, self.peer_addr);
                    }
                    ChatMessage::Pong => {
                        // Keepalive acknowledged
                    }
                }
            }

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

                let title = format!(
                    "Chat with {} | You: {} | Press ESC to exit",
                    self.peer_username, self.username
                );
                let messages_list = List::new(messages)
                    .block(Block::default().borders(Borders::ALL).title(title));

                f.render_widget(messages_list, chunks[0]);

                let input = Paragraph::new(self.input.as_str())
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title("Message"));

                f.render_widget(input, chunks[1]);
            })?;

            // Handle keyboard input
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char(c) => {
                            if self.input.len() < MAX_MESSAGE_LEN {
                                self.input.push(c);
                            }
                        }
                        KeyCode::Backspace => {
                            self.input.pop();
                        }
                        KeyCode::Enter => {
                            if !self.input.is_empty() {
                                let message = self.input.clone();
                                self.add_message(format!("{}: {}", self.username, message));

                                if let Ok(ciphertext) = self.crypto.encrypt(message.as_bytes()) {
                                    let chat_msg = ChatMessage::Text { ciphertext };
                                    if let Ok(bytes) = serde_json::to_vec(&chat_msg) {
                                        let _ = self.socket.send_to(&bytes, self.peer_addr);
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
        };

        disable_raw_mode()?;
        terminal.show_cursor()?;
        result
    }
}
