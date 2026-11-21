use crate::connect::Connection;
use crate::crypto::Transport;
use crate::session::MAX_MESSAGE_LEN;
use crate::wire::{ChatPayload, Packet};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_MESSAGES: usize = 1000;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Nothing authenticated from the peer for this long means the connection is
/// gone (three keepalives missed).
const LOST_AFTER: Duration = Duration::from_secs(45);

/// Receive buffer, larger than any datagram we send; a bigger one is junk.
const RECV_BUF: usize = 2048;

/// What a key press means for the chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Quit,
    Send,
    Backspace,
    Char(char),
    Ignore,
}

/// Maps a key event to a chat action.
///
/// Releases are ignored: Windows reports them too, and reacting would type
/// every letter twice. Ctrl-C quits like Esc, because in raw mode it arrives
/// as a key and not as a signal.
pub fn key_action(key: KeyEvent) -> KeyAction {
    if key.kind == KeyEventKind::Release {
        return KeyAction::Ignore;
    }
    // Windows reports AltGr as Ctrl+Alt, and AltGr types ordinary characters.
    let ctrl =
        key.modifiers.contains(KeyModifiers::CONTROL) && !key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Esc => KeyAction::Quit,
        KeyCode::Enter => KeyAction::Send,
        KeyCode::Backspace => KeyAction::Backspace,
        KeyCode::Char('c' | 'C') if ctrl => KeyAction::Quit,
        KeyCode::Char(_) if ctrl => KeyAction::Ignore,
        KeyCode::Char(c) => KeyAction::Char(c),
        _ => KeyAction::Ignore,
    }
}

/// Appends `c` unless the input would pass `MAX_MESSAGE_LEN` bytes.
fn push_capped(input: &mut String, c: char) {
    if input.len() + c.len_utf8() <= MAX_MESSAGE_LEN {
        input.push(c);
    }
}

/// Cuts text from the peer down to `MAX_MESSAGE_LEN` bytes (on a character
/// boundary), so a peer cannot flood the screen with one giant message.
fn clamp_text(mut text: String) -> String {
    if text.len() > MAX_MESSAGE_LEN {
        let mut end = MAX_MESSAGE_LEN;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// Turns a datagram into what the peer said: only an authentic, fresh `Data`
/// packet holding a well-formed payload counts.
fn open_payload(transport: &Transport, datagram: &[u8]) -> Option<ChatPayload> {
    let Packet::Data { nonce, ciphertext } = Packet::decode(datagram)? else {
        return None;
    };
    let plaintext = transport.open(nonce, ciphertext).ok()?;
    ChatPayload::decode(&plaintext)
}

/// Seals `payload` and sends it to `peer`. Failures are ignored: UDP gives no
/// guarantee anyway and the keepalive tells us when the peer is gone.
fn send_payload(
    socket: &UdpSocket,
    transport: &Transport,
    peer: SocketAddr,
    payload: &ChatPayload,
) {
    if let Ok((nonce, ciphertext)) = transport.seal(&payload.encode()) {
        let datagram = Packet::Data {
            nonce,
            ciphertext: &ciphertext,
        }
        .encode();
        let _ = socket.send_to(&datagram, peer);
    }
}

/// Raw mode for as long as the guard lives, so every way out of the chat
/// (including an error or a panic) gives the terminal back.
struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

pub struct P2PChat {
    username: String,
    peer_username: String,
    messages: VecDeque<String>,
    input: String,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    transport: Arc<Transport>,
    fingerprint: String,
    /// When something authentic last arrived from the peer.
    last_heard: Instant,
    /// The "connection lost" notice is on screen.
    lost_shown: bool,
    /// The peer said goodbye, so silence from it is expected.
    peer_left: bool,
}

impl P2PChat {
    pub fn new(username: String, conn: Connection) -> Self {
        let Connection {
            socket,
            peer,
            transport,
            peer_username,
            fingerprint,
            ..
        } = conn;
        Self {
            username,
            peer_username,
            messages: VecDeque::with_capacity(MAX_MESSAGES),
            input: String::new(),
            socket: Arc::new(socket),
            peer_addr: peer,
            transport,
            fingerprint,
            last_heard: Instant::now(),
            lost_shown: false,
            peer_left: false,
        }
    }

    fn add_message(&mut self, msg: String) {
        if self.messages.len() >= MAX_MESSAGES {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
    }

    fn send(&self, payload: &ChatPayload) {
        send_payload(&self.socket, &self.transport, self.peer_addr, payload);
    }

    pub fn run(&mut self) -> Result<()> {
        // Set socket to non-blocking for UI thread
        self.socket.set_nonblocking(true)?;

        // Tells the helper threads to stop once the chat is over.
        let stop = Arc::new(AtomicBool::new(false));

        // Channel for incoming messages
        let (msg_tx, msg_rx): (mpsc::Sender<ChatPayload>, Receiver<ChatPayload>) = mpsc::channel();

        // Spawn receiver thread
        let socket_clone = Arc::clone(&self.socket);
        let transport_clone = Arc::clone(&self.transport);
        let stop_clone = Arc::clone(&stop);
        let peer_addr = self.peer_addr;
        thread::spawn(move || {
            let mut buf = [0u8; RECV_BUF];
            while !stop_clone.load(Ordering::Relaxed) {
                match socket_clone.recv_from(&mut buf) {
                    // Only the peer's address is listened to; anything else is junk.
                    Ok((len, from)) if from == peer_addr => {
                        if let Some(payload) = open_payload(&transport_clone, &buf[..len]) {
                            if msg_tx.send(payload).is_err() {
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
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
        let transport_keepalive = Arc::clone(&self.transport);
        let stop_keepalive = Arc::clone(&stop);
        let peer_addr_keepalive = self.peer_addr;
        thread::spawn(move || loop {
            thread::sleep(KEEPALIVE_INTERVAL);
            if stop_keepalive.load(Ordering::Relaxed) {
                break;
            }
            send_payload(
                &socket_keepalive,
                &transport_keepalive,
                peer_addr_keepalive,
                &ChatPayload::Ping,
            );
        });

        self.add_message(format!("Connected to {}", self.peer_username));
        self.add_message("Your messages are end-to-end encrypted.".to_string());
        // The chat clears the screen, so the line printed before it is gone.
        self.add_message(format!(
            "Session fingerprint: {} (should match your peer's)",
            self.fingerprint
        ));
        self.add_message(String::new());

        self.last_heard = Instant::now();
        let result = self.run_ui(msg_rx);
        stop.store(true, Ordering::Relaxed);
        result
    }

    fn run_ui(&mut self, msg_rx: Receiver<ChatPayload>) -> Result<()> {
        // Dropped on every way out of this function, errors included.
        let _raw_mode = RawModeGuard::enable()?;
        let mut stdout = io::stdout();
        stdout.execute(Clear(ClearType::All))?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = self.ui_loop(&mut terminal, &msg_rx);

        let _ = terminal.show_cursor();
        result
    }

    fn ui_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        msg_rx: &Receiver<ChatPayload>,
    ) -> Result<()> {
        loop {
            // Process incoming messages
            while let Ok(payload) = msg_rx.try_recv() {
                self.on_payload(payload);
            }
            self.check_lost();

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
                let messages_list =
                    List::new(messages).block(Block::default().borders(Borders::ALL).title(title));

                f.render_widget(messages_list, chunks[0]);

                let input = Paragraph::new(self.input.as_str())
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title("Message"));

                f.render_widget(input, chunks[1]);
            })?;

            // Handle keyboard input
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    match key_action(key) {
                        KeyAction::Quit => {
                            // Sent twice: a lost datagram should not leave the
                            // peer waiting for a timeout.
                            self.send(&ChatPayload::Bye);
                            self.send(&ChatPayload::Bye);
                            return Ok(());
                        }
                        KeyAction::Send => self.send_input(),
                        KeyAction::Backspace => {
                            self.input.pop();
                        }
                        KeyAction::Char(c) => push_capped(&mut self.input, c),
                        KeyAction::Ignore => {}
                    }
                }
            }
        }
    }

    /// Sends what was typed, if anything.
    fn send_input(&mut self) {
        if self.input.is_empty() {
            return;
        }
        let message = std::mem::take(&mut self.input);
        self.add_message(format!("{}: {}", self.username, message));
        self.send(&ChatPayload::Text(message));
    }

    fn on_payload(&mut self, payload: ChatPayload) {
        self.last_heard = Instant::now();
        self.lost_shown = false;
        match payload {
            ChatPayload::Text(text) => {
                let text = clamp_text(text);
                self.add_message(format!("{}: {}", self.peer_username, text));
            }
            ChatPayload::Ping => self.send(&ChatPayload::Pong),
            ChatPayload::Pong => {
                // Keepalive acknowledged
            }
            ChatPayload::Bye => {
                // `Bye` is sent twice; announce it once.
                if !self.peer_left {
                    self.peer_left = true;
                    self.add_message(format!("{} left the chat.", self.peer_username));
                }
            }
        }
    }

    /// Announces once that the peer went silent.
    fn check_lost(&mut self) {
        if !self.lost_shown && !self.peer_left && self.last_heard.elapsed() >= LOST_AFTER {
            self.lost_shown = true;
            self.add_message(format!("Connection to {} lost.", self.peer_username));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn ev(code: KeyCode, mods: KeyModifiers, kind: KeyEventKind) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: mods,
            kind,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn key_action_ignores_release_events() {
        assert!(matches!(
            key_action(ev(
                KeyCode::Char('a'),
                KeyModifiers::NONE,
                KeyEventKind::Release
            )),
            KeyAction::Ignore
        ));
        assert!(matches!(
            key_action(ev(
                KeyCode::Char('a'),
                KeyModifiers::NONE,
                KeyEventKind::Press
            )),
            KeyAction::Char('a')
        ));
    }

    #[test]
    fn key_action_ctrl_c_and_esc_quit() {
        assert!(matches!(
            key_action(ev(
                KeyCode::Char('c'),
                KeyModifiers::CONTROL,
                KeyEventKind::Press
            )),
            KeyAction::Quit
        ));
        assert!(matches!(
            key_action(ev(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Press)),
            KeyAction::Quit
        ));
        assert!(matches!(
            key_action(ev(
                KeyCode::Char('c'),
                KeyModifiers::NONE,
                KeyEventKind::Press
            )),
            KeyAction::Char('c')
        ));
    }

    use crate::crypto::{initiator, responder};
    use crate::wire::MAX_DATAGRAM;

    /// A connected pair of transports (joiner side, creator side).
    fn transports() -> (Transport, Transport) {
        let psk = [7u8; 32];
        let mut init = initiator(&psk).unwrap();
        let mut resp = responder(&psk).unwrap();
        let mut msg = [0u8; 1024];
        let mut out = [0u8; 1024];
        let n = init.write_message(b"", &mut msg).unwrap();
        resp.read_message(&msg[..n], &mut out).unwrap();
        let n = resp.write_message(b"", &mut msg).unwrap();
        init.read_message(&msg[..n], &mut out).unwrap();
        (
            Transport::from_handshake(init).unwrap().0,
            Transport::from_handshake(resp).unwrap().0,
        )
    }

    fn data_datagram(transport: &Transport, payload: &ChatPayload) -> Vec<u8> {
        let (nonce, ciphertext) = transport.seal(&payload.encode()).unwrap();
        Packet::Data {
            nonce,
            ciphertext: &ciphertext,
        }
        .encode()
    }

    #[test]
    fn key_action_maps_editing_keys() {
        let press = |code, mods| key_action(ev(code, mods, KeyEventKind::Press));
        assert_eq!(press(KeyCode::Enter, KeyModifiers::NONE), KeyAction::Send);
        assert_eq!(
            press(KeyCode::Backspace, KeyModifiers::NONE),
            KeyAction::Backspace
        );
        assert_eq!(
            press(KeyCode::Char('A'), KeyModifiers::SHIFT),
            KeyAction::Char('A')
        );
        assert_eq!(press(KeyCode::Up, KeyModifiers::NONE), KeyAction::Ignore);
        // Other Ctrl shortcuts type nothing; AltGr (Ctrl+Alt) types the character.
        assert_eq!(
            press(KeyCode::Char('d'), KeyModifiers::CONTROL),
            KeyAction::Ignore
        );
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        assert_eq!(press(KeyCode::Char('@'), altgr), KeyAction::Char('@'));
        // Holding a key down repeats it.
        assert_eq!(
            key_action(ev(
                KeyCode::Char('x'),
                KeyModifiers::NONE,
                KeyEventKind::Repeat
            )),
            KeyAction::Char('x')
        );
    }

    #[test]
    fn text_from_the_peer_is_capped_on_a_char_boundary() {
        assert_eq!(clamp_text("oi".to_string()), "oi");
        let exact = "a".repeat(MAX_MESSAGE_LEN);
        assert_eq!(clamp_text(exact.clone()), exact);
        assert_eq!(clamp_text("a".repeat(5000)).len(), MAX_MESSAGE_LEN);
        // 3-byte characters: 1000 is not a boundary, so the cut backs off to 999.
        let euros = clamp_text("€".repeat(400));
        assert_eq!(euros.len(), 999);
        assert!(euros.chars().all(|c| c == '€'));
    }

    #[test]
    fn typing_stops_at_the_message_cap() {
        let mut input = "a".repeat(MAX_MESSAGE_LEN - 1);
        push_capped(&mut input, 'é'); // 2 bytes: does not fit
        assert_eq!(input.len(), MAX_MESSAGE_LEN - 1);
        push_capped(&mut input, 'b');
        assert_eq!(input.len(), MAX_MESSAGE_LEN);
        push_capped(&mut input, 'c');
        assert_eq!(input.len(), MAX_MESSAGE_LEN);
    }

    #[test]
    fn open_payload_accepts_only_fresh_authentic_data() {
        let (joiner, creator) = transports();

        let hello = data_datagram(&joiner, &ChatPayload::Text("oi".into()));
        assert_eq!(
            open_payload(&creator, &hello),
            Some(ChatPayload::Text("oi".into()))
        );
        // The same datagram again is a replay.
        assert_eq!(open_payload(&creator, &hello), None);

        let mut forged = data_datagram(&joiner, &ChatPayload::Ping);
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(open_payload(&creator, &forged), None);

        // Not `Data`, or not a packet at all.
        assert_eq!(open_payload(&creator, &Packet::Hs1(b"x").encode()), None);
        assert_eq!(open_payload(&creator, b"junk"), None);
        assert_eq!(open_payload(&creator, &[]), None);

        // Authentic bytes that are not a chat payload.
        let (nonce, ciphertext) = joiner.seal(&[9, 9]).unwrap();
        let odd = Packet::Data {
            nonce,
            ciphertext: &ciphertext,
        }
        .encode();
        assert_eq!(open_payload(&creator, &odd), None);

        // The forged and odd packets did not spoil the session.
        let pong = data_datagram(&joiner, &ChatPayload::Pong);
        assert_eq!(open_payload(&creator, &pong), Some(ChatPayload::Pong));
    }

    #[test]
    fn longest_message_fits_in_one_datagram() {
        let (joiner, _) = transports();
        let datagram = data_datagram(&joiner, &ChatPayload::Text("a".repeat(MAX_MESSAGE_LEN)));
        assert!(datagram.len() <= MAX_DATAGRAM);
    }
}
