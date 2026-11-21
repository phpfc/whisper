//! Connectivity checks and the authenticated handshake.
//!
//! Both peers probe every remote candidate at the same time (this is the UDP
//! hole punching) and answer each valid `Probe` with a `ProbeAck` to its
//! source address. The joiner waits `tiebreak` after the first confirmed
//! address, takes the confirmed one with the highest priority and runs Noise
//! NNpsk0 on it:
//!
//! ```text
//! joiner                               creator
//!   Probe / ProbeAck  <------------->  Probe / ProbeAck   (every candidate)
//!   Hs1 (payload: own name)  ------->                     (resent every hs_retry)
//!                     <-------------  Hs2 (payload: own name)
//!   3 x Data(Ping)    ------------->                      (done on the first it opens)
//! ```
//!
//! Anything that does not parse, fails `verify` or fails Noise is dropped
//! without a reply, so junk hitting the session port never triggers traffic.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant, MissedTickBehavior};

use crate::candidates::{Candidate, CandidateKind};
use crate::crypto::{initiator, responder, Transport};
use crate::gather::{NetSummary, Sockets};
use crate::keys::SessionKeys;
use crate::session::validate_username;
use crate::wire::{probe, probe_ack, verify, ChatPayload, Packet, MAX_DATAGRAM};

/// Probe transaction ids still waiting for a `ProbeAck` are forgotten after this.
const TXID_TTL: Duration = Duration::from_secs(5);

/// Receive buffer size, above anything we send: a bigger datagram is junk.
const RECV_BUF: usize = 2048;

/// `Ping`s the joiner sends to finish. The creator completes on the first one
/// it can open, so the others cover for loss.
const FINAL_PINGS: usize = 3;

/// Windows fails a receive with WSAEMSGSIZE when the datagram is larger than
/// the buffer (other systems truncate it), and with WSAENETRESET when an ICMP
/// "TTL expired" arrives for an earlier send.
const WSAEMSGSIZE: i32 = 10040;
const WSAENETRESET: i32 = 10052;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Creator,
    Joiner,
}

/// What a peer publishes about itself through the DHT.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PeerInfo {
    pub candidates: Vec<Candidate>,
    pub summary: NetSummary,
    /// Unix time of publication, in milliseconds.
    pub published_ms: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// Time between two probe rounds.
    pub probe_interval: Duration,
    /// How long the joiner keeps collecting confirmations after the first one.
    pub tiebreak: Duration,
    /// Time between two sends of the same `Hs1`.
    pub hs_retry: Duration,
    /// The joiner gives up with `WrongPassword` this long after its first `Hs1`.
    pub wrong_password_after: Duration,
    /// The creator gives up with `NoOneJoined` after this long.
    pub creator_wait: Duration,
    /// Either side gives up with `NoPath` this long after the first `PeerInfo`.
    pub joiner_with_remote: Duration,
    /// The joiner gives up with `NoPath` after this long without any `PeerInfo`.
    pub joiner_without_remote: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_millis(200),
            tiebreak: Duration::from_millis(300),
            hs_retry: Duration::from_millis(500),
            wrong_password_after: Duration::from_secs(5),
            creator_wait: Duration::from_secs(600),
            joiner_with_remote: Duration::from_secs(45),
            joiner_without_remote: Duration::from_secs(60),
        }
    }
}

pub struct ConnectArgs<'a> {
    pub role: Role,
    pub keys: &'a SessionKeys,
    pub psk: [u8; 32],
    pub username: &'a str,
    pub initial_remote: Vec<Candidate>,
    pub timeouts: Timeouts,
}

/// An established session over the chosen path.
pub struct Connection {
    /// The socket of the chosen path, as `into_std()` leaves it (non-blocking).
    pub socket: std::net::UdpSocket,
    pub peer: SocketAddr,
    pub path: CandidateKind,
    pub transport: Arc<Transport>,
    pub peer_username: String,
    pub fingerprint: String,
}

#[derive(Debug)]
pub enum ConnectError {
    NoOneJoined,
    WrongPassword,
    NoPath { remote: Option<NetSummary> },
    Io(io::Error),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::NoOneJoined => {
                f.write_str("No one joined within 10 minutes. Create a new session to try again.")
            }
            ConnectError::WrongPassword => f.write_str("wrong password or invalid code"),
            ConnectError::NoPath { .. } => f.write_str("No direct path to the other peer."),
            ConnectError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<io::Error> for ConnectError {
    fn from(e: io::Error) -> Self {
        ConnectError::Io(e)
    }
}

/// Probes the remote candidates from `sockets`, picks a path (joiner) and runs
/// the handshake on it. More remote candidates may arrive on `remote_rx`.
pub async fn connect(
    sockets: Sockets,
    args: ConnectArgs<'_>,
    mut remote_rx: mpsc::Receiver<PeerInfo>,
) -> Result<Connection, ConnectError> {
    let mut checks = Checks::new(&args, sockets.v6.is_some(), Instant::now());
    let mut probes =
        tokio::time::interval(args.timeouts.probe_interval.max(Duration::from_millis(1)));
    probes.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut rx_open = true;
    let (mut buf4, mut buf6) = (vec![0u8; RECV_BUF], vec![0u8; RECV_BUF]);

    let session = loop {
        let step = tokio::select! {
            r = sockets.v4.recv_from(&mut buf4) => checks.on_recv(r, &buf4),
            r = recv_opt(sockets.v6.as_ref(), &mut buf6) => checks.on_recv(r, &buf6),
            _ = probes.tick() => {
                checks.send_probes(Instant::now());
                Ok(None)
            }
            info = remote_rx.recv(), if rx_open => {
                match info {
                    Some(info) => checks.add_peer_info(info, Instant::now()),
                    // Closed for good: stop polling it.
                    None => rx_open = false,
                }
                Ok(None)
            }
            _ = sleep_opt(checks.tiebreak_at) => checks.choose_path(Instant::now()).map(|()| None),
            _ = sleep_opt(checks.resend_at()) => {
                checks.resend_hs1(Instant::now());
                Ok(None)
            }
            _ = sleep_opt(checks.wrong_password_at()) => Err(ConnectError::WrongPassword),
            _ = sleep_until(checks.deadline) => Err(checks.deadline_error()),
        };
        for (to, bytes) in checks.outbox.drain(..) {
            if let Some(socket) = socket_for(&sockets, to) {
                // A candidate we cannot send to (no route, ...) must not stop
                // the others; it is simply skipped this time.
                let _ = socket.send_to(&bytes, to).await;
            }
        }
        if let Some(session) = step? {
            break session;
        }
    };

    let path = checks.kind_of(session.peer);
    let Sockets { v4, v6 } = sockets;
    // IPv6 peers are only ever reached through the IPv6 socket.
    let socket = match (session.peer, v6) {
        (SocketAddr::V6(_), Some(v6)) => v6,
        _ => v4,
    };
    Ok(Connection {
        socket: socket.into_std()?,
        peer: session.peer,
        path,
        transport: Arc::new(session.transport),
        peer_username: session.peer_username,
        fingerprint: session.fingerprint,
    })
}

/// A completed handshake with `peer`.
struct Session {
    peer: SocketAddr,
    transport: Transport,
    peer_username: String,
    fingerprint: String,
}

/// Joiner: the handshake started on the chosen path.
struct Dialing {
    peer: SocketAddr,
    hs: snow::HandshakeState,
    /// The encoded `Hs1` packet, resent as is.
    hs1: Vec<u8>,
    first_sent: Instant,
    next_resend: Instant,
}

/// Creator: an `Hs1` that authenticated, waiting for the first `Data`.
struct Answered {
    /// The `Hs1` body as received, to recognise resends.
    hs1: Vec<u8>,
    /// The encoded `Hs2` packet sent back.
    hs2: Vec<u8>,
    session: Session,
}

/// State of the connectivity checks. Handlers queue datagrams in `outbox`;
/// `connect` sends them.
struct Checks<'a> {
    role: Role,
    probe_key: [u8; 32],
    psk: [u8; 32],
    username: &'a str,
    t: Timeouts,
    has_v6: bool,
    remote: Vec<Candidate>,
    /// Probes sent: txid -> (destination, when).
    pending: HashMap<[u8; 12], (SocketAddr, Instant)>,
    /// Addresses that answered a probe of ours, in order of confirmation.
    confirmed: Vec<SocketAddr>,
    remote_summary: Option<NetSummary>,
    deadline: Instant,
    tiebreak_at: Option<Instant>,
    dialing: Option<Dialing>,
    answered: Option<Answered>,
    warned: bool,
    outbox: Vec<(SocketAddr, Vec<u8>)>,
}

impl<'a> Checks<'a> {
    fn new(args: &ConnectArgs<'a>, has_v6: bool, now: Instant) -> Self {
        let mut remote = Vec::new();
        for c in &args.initial_remote {
            add_candidate(&mut remote, *c);
        }
        let wait = match args.role {
            Role::Creator => args.timeouts.creator_wait,
            Role::Joiner => args.timeouts.joiner_without_remote,
        };
        Self {
            role: args.role,
            probe_key: args.keys.probe_key,
            psk: args.psk,
            username: args.username,
            t: args.timeouts,
            has_v6,
            remote,
            pending: HashMap::new(),
            confirmed: Vec::new(),
            remote_summary: None,
            deadline: now + wait,
            tiebreak_at: None,
            dialing: None,
            answered: None,
            warned: false,
            outbox: Vec::new(),
        }
    }

    fn send_probes(&mut self, now: Instant) {
        self.pending
            .retain(|_, (_, sent)| now.duration_since(*sent) < TXID_TTL);
        for c in &self.remote {
            if c.addr.is_ipv6() && !self.has_v6 {
                continue;
            }
            let txid: [u8; 12] = rand::random();
            self.pending.insert(txid, (c.addr, now));
            self.outbox
                .push((c.addr, probe(&self.probe_key, txid).encode()));
        }
    }

    fn add_peer_info(&mut self, info: PeerInfo, now: Instant) {
        if self.remote_summary.is_none() {
            self.deadline = now + self.t.joiner_with_remote;
        }
        self.remote_summary = Some(info.summary);
        for c in info.candidates {
            add_candidate(&mut self.remote, c);
        }
    }

    fn deadline_error(&self) -> ConnectError {
        match (self.role, &self.remote_summary) {
            (Role::Creator, None) => ConnectError::NoOneJoined,
            (_, remote) => ConnectError::NoPath {
                remote: remote.clone(),
            },
        }
    }

    fn kind_of(&self, addr: SocketAddr) -> CandidateKind {
        self.remote
            .iter()
            .find(|c| c.addr == addr)
            .map_or(CandidateKind::PeerReflexive, |c| c.kind)
    }

    fn on_recv(
        &mut self,
        r: io::Result<(usize, SocketAddr)>,
        buf: &[u8],
    ) -> Result<Option<Session>, ConnectError> {
        match r {
            Ok((n, src)) => self.on_datagram(src, &buf[..n], Instant::now()),
            Err(e) if is_transient(&e) => Ok(None),
            Err(e) => Err(ConnectError::Io(e)),
        }
    }

    fn on_datagram(
        &mut self,
        src: SocketAddr,
        buf: &[u8],
        now: Instant,
    ) -> Result<Option<Session>, ConnectError> {
        let Some(packet) = Packet::decode(buf) else {
            return Ok(None);
        };
        match packet {
            Packet::Probe { txid, .. } if verify(&self.probe_key, &packet) => {
                self.outbox
                    .push((src, probe_ack(&self.probe_key, txid).encode()));
                self.learn(src);
            }
            Packet::ProbeAck { txid, .. } if verify(&self.probe_key, &packet) => {
                if self.pending.remove(&txid).is_some() {
                    self.confirm(src, now);
                }
            }
            Packet::Hs1(body) if self.role == Role::Creator => self.answer(src, body)?,
            Packet::Hs2(body) if self.role == Role::Joiner => return self.finish(src, body),
            Packet::Data { nonce, ciphertext } if self.role == Role::Creator => {
                return Ok(self.first_data(src, nonce, ciphertext));
            }
            _ => {}
        }
        Ok(None)
    }

    /// A source we did not know about becomes a peer-reflexive candidate.
    fn learn(&mut self, src: SocketAddr) {
        add_candidate(
            &mut self.remote,
            Candidate {
                kind: CandidateKind::PeerReflexive,
                addr: src,
            },
        );
    }

    fn confirm(&mut self, src: SocketAddr, now: Instant) {
        self.learn(src);
        if self.confirmed.contains(&src) {
            return;
        }
        self.confirmed.push(src);
        let undecided = self.dialing.is_none() && self.tiebreak_at.is_none();
        if self.role == Role::Joiner && undecided {
            self.tiebreak_at = Some(now + self.t.tiebreak);
        }
    }

    /// Joiner, after the tie-break window: start the handshake on the best path.
    fn choose_path(&mut self, now: Instant) -> Result<(), ConnectError> {
        self.tiebreak_at = None;
        let Some(best) = best_path(&self.confirmed, &self.remote) else {
            return Ok(());
        };
        let mut hs = initiator(&self.psk).map_err(local_fault)?;
        let mut msg = vec![0u8; MAX_DATAGRAM];
        let len = hs
            .write_message(self.username.as_bytes(), &mut msg)
            .map_err(local_fault)?;
        let hs1 = Packet::Hs1(&msg[..len]).encode();
        self.outbox.push((best.addr, hs1.clone()));
        self.dialing = Some(Dialing {
            peer: best.addr,
            hs,
            hs1,
            first_sent: now,
            next_resend: now + self.t.hs_retry,
        });
        Ok(())
    }

    fn resend_at(&self) -> Option<Instant> {
        self.dialing.as_ref().map(|d| d.next_resend)
    }

    fn wrong_password_at(&self) -> Option<Instant> {
        self.dialing
            .as_ref()
            .map(|d| d.first_sent + self.t.wrong_password_after)
    }

    fn resend_hs1(&mut self, now: Instant) {
        if let Some(d) = &mut self.dialing {
            self.outbox.push((d.peer, d.hs1.clone()));
            d.next_resend = now + self.t.hs_retry;
        }
    }

    /// Joiner: an `Hs2`. Garbage or a forgery is ignored (snow restores its
    /// state on a failed read), so the real answer can still complete it.
    fn finish(&mut self, src: SocketAddr, body: &[u8]) -> Result<Option<Session>, ConnectError> {
        let Some(mut d) = self.dialing.take_if(|d| d.peer == src) else {
            return Ok(None);
        };
        let mut payload = vec![0u8; body.len()];
        let n = match d.hs.read_message(body, &mut payload) {
            Ok(n) => n,
            Err(_) => {
                self.dialing = Some(d);
                return Ok(None);
            }
        };
        let peer_username = valid_username(&payload[..n]).ok_or(ConnectError::WrongPassword)?;
        let (transport, fingerprint) = Transport::from_handshake(d.hs).map_err(local_fault)?;
        for _ in 0..FINAL_PINGS {
            let (nonce, ciphertext) = transport
                .seal(&ChatPayload::Ping.encode())
                .map_err(local_fault)?;
            self.outbox.push((
                src,
                Packet::Data {
                    nonce,
                    ciphertext: &ciphertext,
                }
                .encode(),
            ));
        }
        Ok(Some(Session {
            peer: src,
            transport,
            peer_username,
            fingerprint,
        }))
    }

    /// Creator: an `Hs1`.
    fn answer(&mut self, src: SocketAddr, body: &[u8]) -> Result<(), ConnectError> {
        if let Some(a) = self.answered.as_ref().filter(|a| a.hs1 == body) {
            self.outbox.push((src, a.hs2.clone()));
            return Ok(());
        }
        match respond(&self.psk, body, self.username, src)? {
            Some(a) => {
                self.outbox.push((src, a.hs2.clone()));
                self.answered = Some(a);
            }
            None if !self.warned => {
                self.warned = true;
                println!("Someone tried to join with the wrong password.");
            }
            None => {}
        }
        Ok(())
    }

    /// Creator: the first `Data` from the answered peer that opens completes it.
    fn first_data(&mut self, src: SocketAddr, nonce: u64, ciphertext: &[u8]) -> Option<Session> {
        self.answered
            .take_if(|a| {
                a.session.peer == src && a.session.transport.open(nonce, ciphertext).is_ok()
            })
            .map(|a| a.session)
    }
}

/// Creator's half of the handshake. `None` when `hs1` does not authenticate
/// (wrong password, junk) or carries an invalid username.
fn respond(
    psk: &[u8; 32],
    hs1: &[u8],
    username: &str,
    peer: SocketAddr,
) -> Result<Option<Answered>, ConnectError> {
    let mut hs = responder(psk).map_err(local_fault)?;
    let mut payload = vec![0u8; hs1.len()];
    let Ok(n) = hs.read_message(hs1, &mut payload) else {
        return Ok(None);
    };
    let Some(peer_username) = valid_username(&payload[..n]) else {
        return Ok(None);
    };
    let mut msg = vec![0u8; MAX_DATAGRAM];
    let len = hs
        .write_message(username.as_bytes(), &mut msg)
        .map_err(local_fault)?;
    let (transport, fingerprint) = Transport::from_handshake(hs).map_err(local_fault)?;
    Ok(Some(Answered {
        hs1: hs1.to_vec(),
        hs2: Packet::Hs2(&msg[..len]).encode(),
        session: Session {
            peer,
            transport,
            peer_username,
            fingerprint,
        },
    }))
}

fn valid_username(bytes: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(bytes).ok()?;
    validate_username(name).ok()?;
    Some(name.to_owned())
}

/// Noise failing on our own side (building the state, writing a message) is
/// a local fault, not the peer's.
fn local_fault<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> ConnectError {
    ConnectError::Io(io::Error::other(e))
}

/// An address that can be a peer: a port, and not unspecified, broadcast or
/// multicast.
fn usable(addr: SocketAddr) -> bool {
    let ip = addr.ip().to_canonical();
    let broadcast = matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
    addr.port() != 0 && !ip.is_unspecified() && !ip.is_multicast() && !broadcast
}

/// Adds `c` unless unusable; a known address keeps the higher-priority kind.
fn add_candidate(list: &mut Vec<Candidate>, c: Candidate) {
    if !usable(c.addr) {
        return;
    }
    match list.iter_mut().find(|known| known.addr == c.addr) {
        Some(known) if c.kind.priority() > known.kind.priority() => known.kind = c.kind,
        Some(_) => {}
        None => list.push(c),
    }
}

/// The confirmed candidate with the highest priority; the earliest confirmed
/// among equals.
fn best_path(confirmed: &[SocketAddr], remote: &[Candidate]) -> Option<Candidate> {
    confirmed
        .iter()
        .filter_map(|addr| remote.iter().find(|c| c.addr == *addr))
        .fold(None, |best: Option<&Candidate>, c| match best {
            Some(b) if b.kind.priority() >= c.kind.priority() => Some(b),
            _ => Some(c),
        })
        .copied()
}

/// Receive errors about a single datagram or an ICMP report for an earlier
/// send, not about the socket. Windows reports the port-unreachable caused by
/// probing a dead candidate as `ConnectionReset` on the next `recv_from`.
fn is_transient(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionReset
            | ConnectionRefused
            | HostUnreachable
            | NetworkUnreachable
            | Interrupted
            | WouldBlock
    ) || (cfg!(windows) && matches!(e.raw_os_error(), Some(WSAEMSGSIZE | WSAENETRESET)))
}

fn socket_for(sockets: &Sockets, to: SocketAddr) -> Option<&UdpSocket> {
    match to {
        SocketAddr::V4(_) => Some(&sockets.v4),
        SocketAddr::V6(_) => sockets.v6.as_ref(),
    }
}

async fn recv_opt(socket: Option<&UdpSocket>, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    match socket {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn sleep_opt(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{derive_psk, SessionSecret};
    use crate::stun::NatMapping;
    use crate::wire::{T_DATA, T_HS1, T_HS2};
    use rand::Rng;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    async fn loopback_sockets() -> (Sockets, SocketAddr) {
        let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = v4.local_addr().unwrap();
        (Sockets { v4, v6: None }, addr)
    }

    /// A receiver whose sender is already gone.
    fn closed_rx() -> mpsc::Receiver<PeerInfo> {
        mpsc::channel(1).1
    }

    fn args<'a>(
        role: Role,
        keys: &'a SessionKeys,
        psk: [u8; 32],
        name: &'a str,
        initial_remote: Vec<Candidate>,
    ) -> ConnectArgs<'a> {
        let timeouts = Timeouts {
            probe_interval: ms(50),
            tiebreak: ms(50),
            hs_retry: ms(100),
            wrong_password_after: ms(1000),
            creator_wait: ms(3000),
            joiner_with_remote: ms(2000),
            joiner_without_remote: ms(2000),
        };
        ConnectArgs {
            role,
            keys,
            psk,
            username: name,
            initial_remote,
            timeouts,
        }
    }

    fn lan(addr: SocketAddr) -> Candidate {
        Candidate {
            kind: CandidateKind::Lan,
            addr,
        }
    }

    fn info(candidates: Vec<Candidate>) -> PeerInfo {
        let summary = NetSummary {
            ipv6: false,
            mapped: false,
            cgnat: None,
            nat: NatMapping::Unknown,
        };
        PeerInfo {
            candidates,
            summary,
            published_ms: 0,
        }
    }

    fn err(r: Result<Connection, ConnectError>) -> ConnectError {
        match r {
            Ok(c) => panic!("unexpectedly connected to {}", c.peer),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn connects_over_loopback() {
        let keys = SessionKeys::derive(&SessionSecret([1; 16]));
        let psk = derive_psk(&keys, "");
        let (cs, caddr) = loopback_sockets().await;
        let (js, jaddr) = loopback_sockets().await;
        let creator = connect(
            cs,
            args(Role::Creator, &keys, psk, "alice", vec![]),
            closed_rx(),
        );
        let joiner = connect(
            js,
            args(Role::Joiner, &keys, psk, "bob", vec![lan(caddr)]),
            closed_rx(),
        );
        let (c, j) = tokio::join!(creator, joiner);
        let (c, j) = (c.unwrap(), j.unwrap());
        assert_eq!(
            (c.peer_username.as_str(), j.peer_username.as_str()),
            ("bob", "alice")
        );
        assert_eq!(c.fingerprint, j.fingerprint);
        assert_eq!(j.path, CandidateKind::Lan);
        assert_eq!((c.peer, j.peer), (jaddr, caddr));
        assert_eq!(c.socket.local_addr().unwrap(), caddr);

        // The transports are each other's counterpart.
        let (n, ct) = j.transport.seal(b"oi").unwrap();
        assert_eq!(c.transport.open(n, &ct).unwrap(), b"oi");
        let (n, ct) = c.transport.seal(b"tchau").unwrap();
        assert_eq!(j.transport.open(n, &ct).unwrap(), b"tchau");
    }

    #[tokio::test]
    async fn wrong_password_is_reported() {
        let keys = SessionKeys::derive(&SessionSecret([2; 16]));
        let (psk_a, psk_b) = (derive_psk(&keys, "a"), derive_psk(&keys, "b"));
        let (cs, caddr) = loopback_sockets().await;
        let (js, _) = loopback_sockets().await;
        let started = Instant::now();
        let creator = connect(
            cs,
            args(Role::Creator, &keys, psk_a, "alice", vec![]),
            closed_rx(),
        );
        let joiner = connect(
            js,
            args(Role::Joiner, &keys, psk_b, "bob", vec![lan(caddr)]),
            closed_rx(),
        );
        tokio::pin!(creator);
        let j = tokio::select! {
            c = &mut creator => panic!("creator stopped waiting: {:?}", c.err()),
            j = joiner => j,
        };
        let e = err(j);
        assert!(matches!(e, ConnectError::WrongPassword), "{e:?}");
        assert!(started.elapsed() < ms(2000), "{:?}", started.elapsed());
        // The creator keeps waiting for someone with the right password.
        assert!(tokio::time::timeout(ms(300), &mut creator).await.is_err());
    }

    #[tokio::test]
    async fn remote_candidates_arrive_via_channel() {
        let keys = SessionKeys::derive(&SessionSecret([3; 16]));
        let psk = derive_psk(&keys, "");
        let (cs, caddr) = loopback_sockets().await;
        let (js, _) = loopback_sockets().await;
        let (tx, rx) = mpsc::channel(1);
        let started = Instant::now();
        let creator = connect(
            cs,
            args(Role::Creator, &keys, psk, "alice", vec![]),
            closed_rx(),
        );
        let joiner = connect(js, args(Role::Joiner, &keys, psk, "bob", vec![]), rx);
        let feed = async {
            tokio::time::sleep(ms(300)).await;
            tx.send(info(vec![lan(caddr)])).await.unwrap();
        };
        let (c, j, ()) = tokio::join!(creator, joiner, feed);
        let (c, j) = (c.unwrap(), j.unwrap());
        assert!(started.elapsed() >= ms(300));
        assert_eq!(j.peer, caddr);
        assert_eq!(j.path, CandidateKind::Lan);
        assert_eq!(c.fingerprint, j.fingerprint);
    }

    #[tokio::test]
    async fn unreachable_peer_gives_no_path() {
        let keys = SessionKeys::derive(&SessionSecret([4; 16]));
        let (js, _) = loopback_sockets().await;
        let (tx, rx) = mpsc::channel(1);
        tx.send(info(vec![lan("127.0.0.1:9".parse().unwrap())]))
            .await
            .unwrap();
        let started = Instant::now();
        let e = err(connect(js, args(Role::Joiner, &keys, [7; 32], "bob", vec![]), rx).await);
        let elapsed = started.elapsed();
        assert!(
            matches!(e, ConnectError::NoPath { remote: Some(ref s) } if *s == info(vec![]).summary),
            "{e:?}"
        );
        assert!(elapsed >= ms(1900) && elapsed < ms(3000), "{elapsed:?}");
        drop(tx);
    }

    #[tokio::test]
    async fn creator_gives_up_after_wait() {
        let keys = SessionKeys::derive(&SessionSecret([5; 16]));
        let (cs, _) = loopback_sockets().await;
        let started = Instant::now();
        let e = err(connect(
            cs,
            args(Role::Creator, &keys, [7; 32], "alice", vec![]),
            closed_rx(),
        )
        .await);
        let elapsed = started.elapsed();
        assert!(matches!(e, ConnectError::NoOneJoined), "{e:?}");
        assert!(elapsed >= ms(2900) && elapsed < ms(4000), "{elapsed:?}");
    }

    #[tokio::test]
    async fn ignores_junk_and_late_stun() {
        let keys = SessionKeys::derive(&SessionSecret([6; 16]));
        let psk = derive_psk(&keys, "");
        let (cs, caddr) = loopback_sockets().await;
        let (js, _) = loopback_sockets().await;
        let third = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let creator = connect(
            cs,
            args(Role::Creator, &keys, psk, "alice", vec![]),
            closed_rx(),
        );
        let rest = async {
            let mut junk = vec![0u8; 64];
            rand::thread_rng().fill(&mut junk[..]);
            // Header-only Binding Success Response (0x0101), as a late STUN answer.
            let mut stun = crate::stun::build_binding_request(&[9; 12]).to_vec();
            stun[0] = 0x01;
            let foreign_probe = probe(&[0x55; 32], [1; 12]).encode();
            for pkt in [
                junk,
                stun,
                foreign_probe,
                vec![T_HS1],
                vec![T_HS2],
                vec![T_DATA; 9],
            ] {
                third.send_to(&pkt, caddr).await.unwrap();
            }
            tokio::time::sleep(ms(100)).await;
            let j = connect(
                js,
                args(Role::Joiner, &keys, psk, "bob", vec![lan(caddr)]),
                closed_rx(),
            )
            .await;
            let mut buf = [0u8; 64];
            let silent = tokio::time::timeout(ms(500), third.recv_from(&mut buf))
                .await
                .is_err();
            (j, silent)
        };
        let (c, (j, silent)) = tokio::join!(creator, rest);
        assert_eq!(c.unwrap().peer_username, "bob");
        assert_eq!(j.unwrap().peer_username, "alice");
        assert!(silent, "the creator answered junk");
    }

    #[test]
    fn candidates_are_filtered_merged_and_ranked() {
        use CandidateKind::*;
        let c = |kind, a: &str| Candidate {
            kind,
            addr: a.parse().unwrap(),
        };
        let mut list = Vec::new();
        for cand in [
            c(Lan, "0.0.0.0:5"),
            c(Ipv6, "[::]:5"),
            c(Lan, "10.0.0.1:0"),
            c(Mapped, "224.0.0.1:5"),
            c(Ipv6, "[ff02::1]:5"),
            c(Lan, "255.255.255.255:5"),
            c(PeerReflexive, "10.0.0.2:5"),
            c(Lan, "10.0.0.2:5"),
            c(PeerReflexive, "10.0.0.2:5"),
            c(Reflexive, "200.1.1.1:5"),
            c(Mapped, "189.1.1.1:5"),
            c(Mapped, "189.1.1.2:5"),
        ] {
            add_candidate(&mut list, cand);
        }
        assert_eq!(
            list,
            vec![
                c(Lan, "10.0.0.2:5"),
                c(Reflexive, "200.1.1.1:5"),
                c(Mapped, "189.1.1.1:5"),
                c(Mapped, "189.1.1.2:5")
            ]
        );

        // Highest priority wins; among equals, the one confirmed first.
        let confirmed: Vec<SocketAddr> = ["200.1.1.1:5", "189.1.1.1:5", "189.1.1.2:5"]
            .map(|a| a.parse().unwrap())
            .to_vec();
        assert_eq!(best_path(&confirmed, &list), Some(c(Mapped, "189.1.1.1:5")));
        assert_eq!(best_path(&[], &list), None);
    }

    #[test]
    fn handshake_survives_resends_and_garbage() {
        let keys = SessionKeys::derive(&SessionSecret([8; 16]));
        let (psk, now) = ([7; 32], Instant::now());
        let (ca, ja) = (
            args(Role::Creator, &keys, psk, "alice", vec![]),
            args(Role::Joiner, &keys, psk, "bob", vec![]),
        );
        let caddr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let jaddr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let (mut creator, mut joiner) =
            (Checks::new(&ca, false, now), Checks::new(&ja, false, now));

        joiner.confirm(caddr, now);
        joiner.choose_path(now).unwrap();
        let (to, hs1) = joiner.outbox.pop().unwrap();
        assert_eq!(to, caddr);

        // A resent Hs1 gets the very same Hs2 back.
        for _ in 0..2 {
            assert!(creator.on_datagram(jaddr, &hs1, now).unwrap().is_none());
        }
        let hs2 = std::mem::take(&mut creator.outbox);
        assert_eq!(hs2.len(), 2);
        assert_eq!(hs2[0], hs2[1]);
        assert_eq!(hs2[0].0, jaddr);

        // Empty and garbage Hs2 are ignored; the real one still completes.
        for junk in [vec![T_HS2], vec![T_HS2; 81]] {
            assert!(joiner.on_datagram(caddr, &junk, now).unwrap().is_none());
        }
        let session = joiner.on_datagram(caddr, &hs2[0].1, now).unwrap().unwrap();
        assert_eq!(session.peer_username, "alice");

        // Any one of the three Pings completes the creator.
        let pings = std::mem::take(&mut joiner.outbox);
        assert_eq!(pings.len(), 3);
        let done = creator
            .on_datagram(jaddr, &pings[1].1, now)
            .unwrap()
            .unwrap();
        assert_eq!(
            (done.peer_username.as_str(), done.fingerprint),
            ("bob", session.fingerprint)
        );
    }

    #[test]
    fn per_datagram_receive_errors_are_not_fatal() {
        use io::ErrorKind::*;
        assert!(is_transient(&ConnectionReset.into()));
        assert!(is_transient(&ConnectionRefused.into()));
        assert!(!is_transient(&InvalidInput.into()));
    }

    #[test]
    fn error_copy_is_exact() {
        let text = |e: ConnectError| e.to_string();
        assert_eq!(
            text(ConnectError::NoOneJoined),
            "No one joined within 10 minutes. Create a new session to try again."
        );
        assert_eq!(
            text(ConnectError::WrongPassword),
            "wrong password or invalid code"
        );
        assert_eq!(
            text(ConnectError::NoPath { remote: None }),
            "No direct path to the other peer."
        );
        assert_eq!(text(ConnectError::Io(io::Error::other("boom"))), "boom");
    }
}
