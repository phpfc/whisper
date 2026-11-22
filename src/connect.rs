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
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant, MissedTickBehavior};

use crate::candidates::{Candidate, CandidateKind};
use crate::crypto::{initiator, responder, Transport};
use crate::gather::{NetSummary, Sockets};
use crate::keys::SessionKeys;
use crate::session::validate_username;
use crate::util::is_transient;
use crate::wire::{probe, probe_ack, verify, ChatPayload, Packet, MAX_DATAGRAM};

/// Our probes still waiting for a `ProbeAck` are forgotten after this.
const TXID_TTL: Duration = Duration::from_secs(5);

/// Lengths an NNpsk0 message 1 can have: the ephemeral key (32), then the
/// encrypted username (at most 32) and its tag (16).
const HS1_LEN: std::ops::RangeInclusive<usize> = 48..=80;

/// At most this many peer-reflexive candidates are learned. A replayed probe
/// with a spoofed source must not turn us into a prober of arbitrary hosts.
const MAX_PEER_REFLEXIVE: usize = 4;

/// At most this many candidates are taken from the code and the peer's
/// records together; later ones are ignored.
const MAX_SIGNALED: usize = 16;

/// How many txids of received probes are remembered.
const SEEN_PROBES: usize = 4096;

/// The txids of the last [`SEEN_PROBES`] valid probes received.
#[derive(Default)]
struct SeenTxids {
    set: HashSet<[u8; 12]>,
    order: VecDeque<[u8; 12]>,
}

impl SeenTxids {
    /// Remembers `txid`. False if it is already remembered.
    fn insert(&mut self, txid: [u8; 12]) -> bool {
        if !self.set.insert(txid) {
            return false;
        }
        self.order.push_back(txid);
        if self.order.len() > SEEN_PROBES {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
        true
    }
}

/// Receive buffer size, above anything we send: a bigger datagram is junk.
const RECV_BUF: usize = 2048;

/// `Ping`s the joiner sends to finish. The creator completes on the first one
/// it can open, so the others cover for loss.
const FINAL_PINGS: usize = 3;

/// A joiner suspects the creator's record is stale once it is older than the
/// creator's wait plus this: the creator has probably given up by then.
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

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

/// The current Unix time in milliseconds, the clock of `PeerInfo::published_ms`.
pub fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
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
    /// A handshake under way (the joiner's `Hs1`, the creator's `Hs2`) holds
    /// off the other deadlines for this long.
    pub wrong_password_after: Duration,
    /// The creator gives up with `NoOneJoined` after this long.
    pub creator_wait: Duration,
    /// The joiner gives up with `NoPath` this long after the first `PeerInfo`.
    /// The creator does so this long after each newer one, unless something
    /// from the joiner got through: then a path exists, and it waits out
    /// `creator_wait` for a joiner that completes the handshake.
    pub joiner_with_remote: Duration,
    /// The joiner gives up with `NoPath` after this long without any `PeerInfo`.
    pub joiner_without_remote: Duration,
    /// After a stale `PeerInfo` the joiner gives up with `Expired` this long
    /// later, unless a path answers first.
    pub stale_grace: Duration,
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
            stale_grace: Duration::from_secs(10),
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
    // The creator's record is so old that it has given up, and no path answered.
    Expired,
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
            ConnectError::Expired => {
                f.write_str("This session code has expired. Ask your peer for a new one.")
            }
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
                    Some(info) => checks.add_peer_info(info, Instant::now(), unix_ms()),
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
            _ = sleep_until(checks.effective_deadline()) => Err(checks.deadline_error()),
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
    hs2_sent: Instant,
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
    /// Entries of `remote` that came from the code or a `PeerInfo`.
    signaled: usize,
    /// Entries of `remote` learned from the source of a probe.
    learned: usize,
    /// Probes sent: txid -> (destination, when).
    pending: HashMap<[u8; 12], (SocketAddr, Instant)>,
    /// Valid probes received, for the whole connect phase. A replay is still
    /// answered but teaches no new address.
    seen_probes: SeenTxids,
    /// Addresses that answered a probe of ours, in order of confirmation.
    confirmed: Vec<SocketAddr>,
    /// Set from a fresh `PeerInfo`; a stale one leaves it alone.
    remote_summary: Option<NetSummary>,
    /// The latest `PeerInfo` is older than the creator waits.
    stale_remote: bool,
    deadline: Instant,
    /// Creator: the end of its wait for someone to join.
    wait_until: Instant,
    /// Creator: an authenticated probe or a failed `Hs1` came in, so a path
    /// exists and a `NoPath` deadline no longer applies.
    peer_heard: bool,
    tiebreak_at: Option<Instant>,
    dialing: Option<Dialing>,
    answered: Option<Answered>,
    warned: bool,
    outbox: Vec<(SocketAddr, Vec<u8>)>,
}

impl<'a> Checks<'a> {
    fn new(args: &ConnectArgs<'a>, has_v6: bool, now: Instant) -> Self {
        let wait = match args.role {
            Role::Creator => args.timeouts.creator_wait,
            Role::Joiner => args.timeouts.joiner_without_remote,
        };
        let mut checks = Self {
            role: args.role,
            probe_key: args.keys.probe_key,
            psk: args.psk,
            username: args.username,
            t: args.timeouts,
            has_v6,
            remote: Vec::new(),
            signaled: 0,
            learned: 0,
            pending: HashMap::new(),
            seen_probes: SeenTxids::default(),
            confirmed: Vec::new(),
            remote_summary: None,
            stale_remote: false,
            deadline: now + wait,
            wait_until: now + wait,
            peer_heard: false,
            tiebreak_at: None,
            dialing: None,
            answered: None,
            warned: false,
            outbox: Vec::new(),
        };
        for c in &args.initial_remote {
            checks.add_signaled(*c);
        }
        checks
    }

    /// A candidate from the code or a `PeerInfo`. New addresses past
    /// [`MAX_SIGNALED`] are ignored; a known one can still get a better kind.
    fn add_signaled(&mut self, c: Candidate) {
        let known = self.remote.iter().any(|k| k.addr == c.addr);
        if (known || self.signaled < MAX_SIGNALED) && add_candidate(&mut self.remote, c) {
            self.signaled += 1;
        }
    }

    /// Creator: something from the peer got through, so a path exists. The
    /// peer may just retry (with the right password, say): wait for it.
    fn heard_peer(&mut self) {
        if self.role == Role::Creator && !self.peer_heard {
            self.peer_heard = true;
            self.deadline = self.deadline.max(self.wait_until);
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

    /// The peer's candidates arrived. `now_ms` is the Unix time.
    ///
    /// A joiner that gets a record older than the creator waits only takes it
    /// as a hint: the creator has probably given up, but our clock may be the
    /// one that is off, so its candidates are still probed. The deadline moves
    /// up to `stale_grace` from now (never later than it was), and a deadline
    /// reached with nothing connected is then `Expired`. A fresh record
    /// afterwards puts the normal deadline back.
    ///
    /// A creator gives each newer record `joiner_with_remote` to get through
    /// (a new record is a new attempt), and never less than its full wait
    /// once it has heard from the peer.
    fn add_peer_info(&mut self, info: PeerInfo, now: Instant, now_ms: i64) {
        let with_remote = now + self.t.joiner_with_remote;
        if self.role == Role::Joiner && self.is_stale(info.published_ms, now_ms) {
            self.stale_remote = true;
            self.deadline = self.deadline.min(now + self.t.stale_grace);
        } else {
            match self.role {
                Role::Creator if self.peer_heard => {
                    self.deadline = with_remote.max(self.wait_until);
                }
                Role::Creator => self.deadline = with_remote,
                Role::Joiner if self.remote_summary.is_none() => self.deadline = with_remote,
                Role::Joiner => {}
            }
            self.stale_remote = false;
            self.remote_summary = Some(info.summary);
        }
        for c in info.candidates {
            self.add_signaled(c);
        }
    }

    /// A record published at `published_ms` is older than the creator waits.
    fn is_stale(&self, published_ms: i64, now_ms: i64) -> bool {
        let limit =
            i64::try_from((self.t.creator_wait + EXPIRY_MARGIN).as_millis()).unwrap_or(i64::MAX);
        now_ms.saturating_sub(published_ms) > limit
    }

    /// When to give up. A handshake under way is never cut short:
    /// - joiner: `max(deadline, first Hs1 + wrong_password_after)`, and
    ///   `WrongPassword` is due at `first Hs1 + wrong_password_after` anyway,
    ///   so that instant is the answer;
    /// - creator: `max(deadline, min(Hs2, deadline) + wrong_password_after)`,
    ///   so a stream of new `Hs1`s never pushes it past
    ///   `deadline + wrong_password_after`.
    fn effective_deadline(&self) -> Instant {
        let grace = self.t.wrong_password_after;
        match (&self.dialing, &self.answered) {
            (Some(d), _) => d.first_sent + grace,
            (None, Some(a)) => self.deadline.max(a.hs2_sent.min(self.deadline) + grace),
            (None, None) => self.deadline,
        }
    }

    fn deadline_error(&self) -> ConnectError {
        match (self.role, &self.remote_summary) {
            // A path answered; the peer never accepted our handshake.
            (Role::Joiner, _) if self.dialing.is_some() => ConnectError::WrongPassword,
            // Only a stale record, and nothing answered.
            (Role::Joiner, _) if self.stale_remote => ConnectError::Expired,
            // A path existed, but nobody completed the handshake on it.
            (Role::Creator, _) if self.peer_heard => ConnectError::NoOneJoined,
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
            // A source that cannot be a peer (port 0, broadcast, ...) gets
            // nothing back.
            Packet::Probe { txid, .. } if usable(src) && verify(&self.probe_key, &packet) => {
                // One answer per probe, replay or not: never more traffic out
                // than in. Only a txid never seen before may teach us its
                // source.
                self.outbox
                    .push((src, probe_ack(&self.probe_key, txid).encode()));
                if self.seen_probes.insert(txid) {
                    self.learn(src);
                }
                self.heard_peer();
            }
            Packet::ProbeAck { txid, .. } if verify(&self.probe_key, &packet) => {
                if self.pending.remove(&txid).is_some() {
                    self.confirm(src, now);
                }
                self.heard_peer();
            }
            Packet::Hs1(body) if self.role == Role::Creator => self.answer(src, body, now)?,
            Packet::Hs2(body) if self.role == Role::Joiner => return self.finish(src, body),
            Packet::Data { nonce, ciphertext } if self.role == Role::Creator => {
                return Ok(self.first_data(src, nonce, ciphertext));
            }
            _ => {}
        }
        Ok(None)
    }

    /// A source we did not know about becomes a peer-reflexive candidate,
    /// up to `MAX_PEER_REFLEXIVE` (no eviction). Returns whether `src` is a
    /// candidate now.
    fn learn(&mut self, src: SocketAddr) -> bool {
        if self.remote.iter().any(|c| c.addr == src) {
            return true;
        }
        if self.learned >= MAX_PEER_REFLEXIVE || !usable(src) {
            return false;
        }
        self.learned += 1;
        self.remote.push(Candidate {
            kind: CandidateKind::PeerReflexive,
            addr: src,
        });
        true
    }

    fn confirm(&mut self, src: SocketAddr, now: Instant) {
        if !self.learn(src) || self.confirmed.contains(&src) {
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
    fn answer(&mut self, src: SocketAddr, body: &[u8], now: Instant) -> Result<(), ConnectError> {
        if let Some(a) = self.answered.as_ref().filter(|a| a.hs1 == body) {
            // A resend from the peer gets the same Hs2 again. A copy that
            // someone replays from another address gets nothing.
            if a.session.peer == src {
                self.outbox.push((src, a.hs2.clone()));
            }
            return Ok(());
        }
        // What cannot be an NNpsk0 message 1 is not worth a Noise attempt,
        // and must not use up the one wrong-password warning.
        if !HS1_LEN.contains(&body.len()) {
            return Ok(());
        }
        let grace = self.t.wrong_password_after;
        let busy = self
            .answered
            .as_ref()
            .is_some_and(|a| now < a.hs2_sent + grace);
        match respond(&self.psk, body, self.username, src, now)? {
            // Another valid Hs1 while the accepted handshake can still finish:
            // keep it, and answer nothing so the newcomer fails cleanly with
            // WrongPassword instead of stealing the session.
            Some(_) if busy => {}
            Some(a) => {
                self.outbox.push((src, a.hs2.clone()));
                self.answered = Some(a);
            }
            None => {
                self.heard_peer();
                if !self.warned {
                    self.warned = true;
                    println!("Someone tried to join with the wrong password.");
                }
            }
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

/// Creator's half of the handshake; the `Hs2` goes out at `now`. `None` when
/// `hs1` does not authenticate (wrong password, junk) or carries an invalid
/// username.
fn respond(
    psk: &[u8; 32],
    hs1: &[u8],
    username: &str,
    peer: SocketAddr,
    now: Instant,
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
        hs2_sent: now,
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
/// Returns whether `c` was added as a new entry.
fn add_candidate(list: &mut Vec<Candidate>, c: Candidate) -> bool {
    if !usable(c.addr) {
        return false;
    }
    match list.iter_mut().find(|known| known.addr == c.addr) {
        Some(known) => {
            if c.kind.priority() > known.kind.priority() {
                known.kind = c.kind;
            }
            false
        }
        None => {
            list.push(c);
            true
        }
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
            stale_grace: ms(500),
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
            published_ms: unix_ms(),
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

    /// Everything `s` receives until `until`.
    async fn received(s: &UdpSocket, until: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(Ok((n, _))) = tokio::time::timeout_at(until, s.recv_from(&mut buf)).await {
            out.push(buf[..n].to_vec());
        }
        out
    }

    #[tokio::test]
    async fn replayed_probe_teaches_at_most_one_address() {
        let keys = SessionKeys::derive(&SessionSecret([11; 16]));
        let (cs, caddr) = loopback_sockets().await;
        let creator = connect(
            cs,
            args(Role::Creator, &keys, [7; 32], "alice", vec![]),
            closed_rx(),
        );
        let mut replayers = Vec::new();
        for _ in 0..3 {
            replayers.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        }
        let watch = async {
            // One genuine probe, then the same bytes replayed from two more sources.
            let bytes = probe(&keys.probe_key, [7; 12]).encode();
            for s in &replayers {
                s.send_to(&bytes, caddr).await.unwrap();
            }
            let until = Instant::now() + ms(400);
            let (a, b, c) = tokio::join!(
                received(&replayers[0], until),
                received(&replayers[1], until),
                received(&replayers[2], until)
            );
            [a, b, c]
        };
        tokio::pin!(creator);
        let got = tokio::select! {
            c = &mut creator => panic!("creator stopped: {:?}", c.err()),
            got = watch => got,
        };
        let count = |packets: &[Vec<u8>], probes: bool| {
            packets
                .iter()
                .filter(|p| match Packet::decode(p) {
                    Some(Packet::ProbeAck { txid, .. }) => !probes && txid == [7; 12],
                    Some(Packet::Probe { .. }) => probes,
                    _ => false,
                })
                .count()
        };
        // Each copy is answered once (1:1, no amplification)...
        let acks: Vec<usize> = got.iter().map(|p| count(p, false)).collect();
        assert_eq!(acks, [1, 1, 1]);
        // ...but only the first source became a candidate worth probing.
        let probed: Vec<bool> = got.iter().map(|p| count(p, true) > 0).collect();
        assert_eq!(probed, [true, false, false]);
    }

    #[tokio::test]
    async fn joiner_handshake_outlives_no_path_deadline() {
        let keys = SessionKeys::derive(&SessionSecret([12; 16]));
        let (psk_a, psk_b) = (derive_psk(&keys, "a"), derive_psk(&keys, "b"));
        let (cs, caddr) = loopback_sockets().await;
        let (js, _) = loopback_sockets().await;
        let mut ja = args(Role::Joiner, &keys, psk_b, "bob", vec![lan(caddr)]);
        ja.timeouts.joiner_without_remote = ms(800);
        let started = Instant::now();
        // The creator shows up at ~300 ms, so the first Hs1 leaves at ~350 ms
        // and its wrong-password wait (1 s) runs past the 800 ms deadline.
        let creator = async {
            tokio::time::sleep(ms(300)).await;
            let ca = args(Role::Creator, &keys, psk_a, "alice", vec![]);
            connect(cs, ca, closed_rx()).await
        };
        tokio::pin!(creator);
        let j = tokio::select! {
            c = &mut creator => panic!("creator stopped waiting: {:?}", c.err()),
            j = connect(js, ja, closed_rx()) => j,
        };
        let elapsed = started.elapsed();
        let e = err(j);
        assert!(matches!(e, ConnectError::WrongPassword), "{e:?}");
        assert!(elapsed >= ms(1200) && elapsed < ms(2500), "{elapsed:?}");
    }

    #[tokio::test]
    async fn creator_handshake_outlives_no_path_deadline() {
        let keys = SessionKeys::derive(&SessionSecret([13; 16]));
        let psk = [7; 32];
        let (cs, caddr) = loopback_sockets().await;
        let fake_joiner = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tx, rx) = mpsc::channel(1);
        tx.send(info(vec![])).await.unwrap();
        let mut ca = args(Role::Creator, &keys, psk, "alice", vec![]);
        ca.timeouts.joiner_with_remote = ms(800);
        let started = Instant::now();
        // Sends a valid Hs1 at ~300 ms, takes the Hs2 and never sends Data.
        let joiner = async {
            tokio::time::sleep(ms(300)).await;
            let mut hs = initiator(&psk).unwrap();
            let mut msg = [0u8; 128];
            let n = hs.write_message(b"bob", &mut msg).unwrap();
            let hs1 = Packet::Hs1(&msg[..n]).encode();
            fake_joiner.send_to(&hs1, caddr).await.unwrap();
            let got = received(&fake_joiner, Instant::now() + ms(300)).await;
            assert!(got
                .iter()
                .any(|p| matches!(Packet::decode(p), Some(Packet::Hs2(_)))));
        };
        let (c, ()) = tokio::join!(connect(cs, ca, rx), joiner);
        let elapsed = started.elapsed();
        let e = err(c);
        assert!(
            matches!(e, ConnectError::NoPath { remote: Some(_) }),
            "{e:?}"
        );
        // Not at 800 ms: the answered handshake gets 1 s from the Hs2 (~300 ms).
        assert!(elapsed >= ms(1200) && elapsed < ms(2500), "{elapsed:?}");
        drop(tx);
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

    /// A joiner that picked `to` and sent its `Hs1`, with that `Hs1` packet.
    fn dialing_joiner<'a>(
        a: &ConnectArgs<'a>,
        to: SocketAddr,
        now: Instant,
    ) -> (Checks<'a>, Vec<u8>) {
        let mut joiner = Checks::new(a, false, now);
        joiner.confirm(to, now);
        joiner.choose_path(now).unwrap();
        let (_, hs1) = joiner.outbox.pop().unwrap();
        (joiner, hs1)
    }

    #[test]
    fn competing_hs1_does_not_take_over_the_accepted_handshake() {
        let keys = SessionKeys::derive(&SessionSecret([14; 16]));
        let (psk, now) = ([7; 32], Instant::now());
        let ca = args(Role::Creator, &keys, psk, "alice", vec![]);
        let aa = args(Role::Joiner, &keys, psk, "bob", vec![]);
        let ba = args(Role::Joiner, &keys, psk, "carol", vec![]);
        let caddr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let a_addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let b_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut creator = Checks::new(&ca, false, now);
        let (mut a, a_hs1) = dialing_joiner(&aa, caddr, now);
        let (_b, b_hs1) = dialing_joiner(&ba, caddr, now);

        creator.on_datagram(a_addr, &a_hs1, now).unwrap();
        let (_, hs2_a) = creator.outbox.pop().unwrap();
        let session = a.on_datagram(caddr, &hs2_a, now).unwrap().unwrap();

        // B's equally valid Hs1 lands between Hs2_A and A's Ping: no answer
        // and no warning, so B fails cleanly with WrongPassword.
        creator.on_datagram(b_addr, &b_hs1, now + ms(10)).unwrap();
        assert!(creator.outbox.is_empty());
        assert!(!creator.warned);

        // A's Ping still completes the creator, with A.
        let ping = a.outbox.remove(0).1;
        let done = creator
            .on_datagram(a_addr, &ping, now + ms(20))
            .unwrap()
            .unwrap();
        assert_eq!((done.peer, done.peer_username.as_str()), (a_addr, "bob"));
        assert_eq!(done.fingerprint, session.fingerprint);
    }

    #[test]
    fn alternating_hs1s_cannot_stretch_the_creator_deadline() {
        let keys = SessionKeys::derive(&SessionSecret([15; 16]));
        let (psk, t0) = ([7; 32], Instant::now());
        let ca = args(Role::Creator, &keys, psk, "alice", vec![]);
        let aa = args(Role::Joiner, &keys, psk, "bob", vec![]);
        let ba = args(Role::Joiner, &keys, psk, "carol", vec![]);
        let caddr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let a_addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let b_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut creator = Checks::new(&ca, false, t0);
        let (_a, a_hs1) = dialing_joiner(&aa, caddr, t0);
        let (_b, b_hs1) = dialing_joiner(&ba, caddr, t0);
        let grace = ca.timeouts.wrong_password_after;
        let limit = creator.deadline + grace;

        // A new valid Hs1 every wrong_password_after, until well past the
        // 3 s deadline. Each lands after the previous window, so it takes over.
        for i in 0..10u32 {
            let (src, hs1) = if i % 2 == 0 {
                (a_addr, &a_hs1)
            } else {
                (b_addr, &b_hs1)
            };
            creator.on_datagram(src, hs1, t0 + grace * i).unwrap();
            assert_eq!(std::mem::take(&mut creator.outbox).len(), 1, "Hs1 #{i}");
            assert!(creator.effective_deadline() <= limit, "Hs1 #{i}");
        }
    }

    #[test]
    fn peer_reflexive_candidates_are_capped() {
        let keys = SessionKeys::derive(&SessionSecret([9; 16]));
        let known = lan("10.0.0.9:5".parse().unwrap());
        let a = args(Role::Joiner, &keys, [7; 32], "bob", vec![known]);
        let now = Instant::now();
        let mut checks = Checks::new(&a, false, now);
        let learned = |c: &Checks| {
            c.remote
                .iter()
                .filter(|c| c.kind == CandidateKind::PeerReflexive)
                .count()
        };

        // Six fresh probes from six sources: all answered, only four learned.
        for i in 0..6u8 {
            let src = SocketAddr::from(([127, 0, 0, 1], 3000 + u16::from(i)));
            let fresh = probe(&keys.probe_key, [i; 12]).encode();
            checks.on_datagram(src, &fresh, now).unwrap();
        }
        assert_eq!(std::mem::take(&mut checks.outbox).len(), 6);
        assert_eq!(learned(&checks), 4);
        assert_eq!(checks.remote[0], known);

        // A ProbeAck from yet another source cannot get past the cap either.
        checks.send_probes(now);
        let txid = *checks.pending.keys().next().unwrap();
        let ack = probe_ack(&keys.probe_key, txid).encode();
        checks
            .on_datagram("127.0.0.1:4000".parse().unwrap(), &ack, now)
            .unwrap();
        assert_eq!(learned(&checks), 4);
        assert!(checks.confirmed.is_empty());
        assert!(checks.tiebreak_at.is_none());
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
        assert_eq!(
            text(ConnectError::Expired),
            "This session code has expired. Ask your peer for a new one."
        );
        assert_eq!(text(ConnectError::Io(io::Error::other("boom"))), "boom");
    }

    /// A record the creator published 12 min ago, with `candidates`.
    fn stale_info(candidates: Vec<Candidate>) -> PeerInfo {
        PeerInfo {
            published_ms: unix_ms() - 12 * 60 * 1000,
            ..info(candidates)
        }
    }

    #[tokio::test]
    async fn stale_creator_info_is_expired() {
        let keys = SessionKeys::derive(&SessionSecret([16; 16]));
        let (js, _) = loopback_sockets().await;
        let (tx, rx) = mpsc::channel(1);
        // The creator published 12 min ago and nothing answers its candidate.
        tx.send(stale_info(vec![lan("127.0.0.1:9".parse().unwrap())]))
            .await
            .unwrap();
        let mut a = args(Role::Joiner, &keys, [7; 32], "bob", vec![]);
        a.timeouts.stale_grace = ms(500);
        let started = Instant::now();
        let e = err(connect(js, a, rx).await);
        let elapsed = started.elapsed();
        assert!(matches!(e, ConnectError::Expired), "{e:?}");
        // Not at once (the record is only a hint), and well before the 2 s of
        // `joiner_with_remote`: after the grace.
        assert!(
            elapsed >= ms(450) && elapsed < ms(500) + Duration::from_secs(1),
            "{elapsed:?}"
        );
        drop(tx);
    }

    #[tokio::test]
    async fn stale_record_from_a_reachable_creator_still_connects() {
        // The joiner's clock is far ahead of the creator's: its record looks
        // old, but the creator is right there.
        let keys = SessionKeys::derive(&SessionSecret([18; 16]));
        let psk = derive_psk(&keys, "");
        let (cs, caddr) = loopback_sockets().await;
        let (js, _) = loopback_sockets().await;
        let (tx, rx) = mpsc::channel(1);
        let mut ja = args(Role::Joiner, &keys, psk, "bob", vec![]);
        ja.timeouts.stale_grace = ms(1500);
        let creator = connect(
            cs,
            args(Role::Creator, &keys, psk, "alice", vec![]),
            closed_rx(),
        );
        let joiner = connect(js, ja, rx);
        let feed = async {
            tokio::time::sleep(ms(100)).await;
            tx.send(stale_info(vec![lan(caddr)])).await.unwrap();
        };
        let (c, j, ()) = tokio::join!(creator, joiner, feed);
        let (c, j) = (c.unwrap(), j.unwrap());
        assert_eq!((j.peer, j.path), (caddr, CandidateKind::Lan));
        assert_eq!(c.fingerprint, j.fingerprint);
        assert_eq!(j.peer_username, "alice");
    }

    #[test]
    fn stale_info_shortens_the_deadline_until_a_fresh_one_arrives() {
        let keys = SessionKeys::derive(&SessionSecret([17; 16]));
        let (t0, now_ms) = (Instant::now(), 1_000_000_000_000_i64);
        let aged = |secs: i64| PeerInfo {
            published_ms: now_ms - secs * 1000,
            ..info(vec![lan("10.0.0.7:5".parse().unwrap())])
        };
        let mut a = args(Role::Joiner, &keys, [7; 32], "bob", vec![]);
        a.timeouts.stale_grace = ms(500);
        // creator_wait + 60 s = 63 s: the limit is exclusive.
        let mut joiner = Checks::new(&a, false, t0);
        let normal = joiner.deadline;
        joiner.add_peer_info(aged(63), t0 + ms(100), now_ms);
        assert!(!joiner.stale_remote);
        assert_eq!(
            joiner.deadline,
            t0 + ms(100) + a.timeouts.joiner_with_remote
        );

        // A record dated in the future (clock skew) is not old either.
        let mut ahead = Checks::new(&a, false, t0);
        ahead.add_peer_info(aged(-3600), t0, now_ms);
        assert!(!ahead.stale_remote);

        // A stale one only shortens the deadline, and keeps its candidates.
        let mut joiner = Checks::new(&a, false, t0);
        joiner.add_peer_info(aged(64), t0 + ms(100), now_ms);
        assert!(joiner.stale_remote);
        assert_eq!(joiner.deadline, t0 + ms(600));
        assert_eq!(joiner.remote.len(), 1);
        assert!(matches!(joiner.deadline_error(), ConnectError::Expired));

        // Never later than the deadline it already had.
        let mut late = Checks::new(&a, false, t0);
        late.add_peer_info(aged(64), t0 + normal.duration_since(t0), now_ms);
        assert_eq!(late.deadline, normal);

        // A newer, fresh record clears the flag and the normal rule applies.
        joiner.add_peer_info(aged(1), t0 + ms(200), now_ms);
        assert!(!joiner.stale_remote);
        assert_eq!(
            joiner.deadline,
            t0 + ms(200) + a.timeouts.joiner_with_remote
        );
        assert!(matches!(
            joiner.deadline_error(),
            ConnectError::NoPath { remote: Some(_) }
        ));

        // A handshake under way wins over the flag.
        let mut dialing = Checks::new(&a, false, t0);
        dialing.add_peer_info(aged(64), t0, now_ms);
        dialing.confirm("10.0.0.7:5".parse().unwrap(), t0);
        dialing.choose_path(t0).unwrap();
        assert!(dialing.stale_remote);
        assert!(matches!(
            dialing.deadline_error(),
            ConnectError::WrongPassword
        ));
        assert_eq!(
            dialing.effective_deadline(),
            t0 + a.timeouts.wrong_password_after
        );
    }

    #[test]
    fn a_creator_never_treats_a_record_as_stale() {
        let keys = SessionKeys::derive(&SessionSecret([19; 16]));
        let (t0, now_ms) = (Instant::now(), 1_000_000_000_000_i64);
        let a = args(Role::Creator, &keys, [7; 32], "alice", vec![]);
        let mut creator = Checks::new(&a, false, t0);
        // The joiner left a record an hour ago: the creator takes it as is.
        let old = PeerInfo {
            published_ms: now_ms - 3600 * 1000,
            ..info(vec![])
        };
        creator.add_peer_info(old, t0, now_ms);
        assert!(!creator.stale_remote);
        assert_eq!(creator.deadline, t0 + a.timeouts.joiner_with_remote);
        assert!(matches!(
            creator.deadline_error(),
            ConnectError::NoPath { remote: Some(_) }
        ));
    }

    #[tokio::test]
    async fn creator_with_a_record_outlasts_a_joiner_with_the_wrong_password() {
        let keys = SessionKeys::derive(&SessionSecret([20; 16]));
        let (psk_a, psk_b) = (derive_psk(&keys, "a"), derive_psk(&keys, "b"));
        let (cs, caddr) = loopback_sockets().await;
        let (js, jaddr) = loopback_sockets().await;
        let (tx, rx) = mpsc::channel(1);
        tx.send(info(vec![lan(jaddr)])).await.unwrap();
        let mut ca = args(Role::Creator, &keys, psk_a, "alice", vec![]);
        ca.timeouts.joiner_with_remote = ms(800);
        let started = Instant::now();
        let creator = connect(cs, ca, rx);
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
        assert!(matches!(err(j), ConnectError::WrongPassword));
        // The path exists, so the 800 ms after the record no longer apply:
        // the creator waits its full time for a joiner that gets it right.
        assert!(tokio::time::timeout(ms(500), &mut creator).await.is_err());
        let e = err(creator.await);
        let elapsed = started.elapsed();
        assert!(matches!(e, ConnectError::NoOneJoined), "{e:?}");
        assert!(elapsed >= ms(2900) && elapsed < ms(4000), "{elapsed:?}");
        drop(tx);
    }

    #[test]
    fn creator_deadline_follows_each_record_until_the_peer_is_heard() {
        let keys = SessionKeys::derive(&SessionSecret([21; 16]));
        let (t0, now_ms) = (Instant::now(), 1_000_000_000_000_i64);
        let a = args(Role::Creator, &keys, [7; 32], "alice", vec![]);
        let (jwr, wait) = (a.timeouts.joiner_with_remote, a.timeouts.creator_wait);
        let joiner: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let mut creator = Checks::new(&a, false, t0);

        // Each newer record starts the wait over.
        creator.add_peer_info(info(vec![lan(joiner)]), t0 + ms(100), now_ms);
        assert_eq!(creator.deadline, t0 + ms(100) + jwr);
        creator.add_peer_info(info(vec![lan(joiner)]), t0 + ms(500), now_ms);
        assert_eq!(creator.deadline, t0 + ms(500) + jwr);
        // Nothing from the joiner got through: no path.
        assert!(matches!(
            creator.deadline_error(),
            ConnectError::NoPath { remote: Some(_) }
        ));

        // An authenticated probe proves the path: back to the full wait.
        let p = probe(&keys.probe_key, [1; 12]).encode();
        creator.on_datagram(joiner, &p, t0 + ms(600)).unwrap();
        assert_eq!(creator.deadline, t0 + wait);
        assert!(matches!(
            creator.deadline_error(),
            ConnectError::NoOneJoined
        ));
        // A record after that never cuts the wait short, and a late one
        // still gets its own time.
        creator.add_peer_info(info(vec![]), t0 + ms(700), now_ms);
        assert_eq!(creator.deadline, t0 + wait);
        creator.add_peer_info(info(vec![]), t0 + ms(2900), now_ms);
        assert_eq!(creator.deadline, t0 + ms(2900) + jwr);
        assert!(matches!(
            creator.deadline_error(),
            ConnectError::NoOneJoined
        ));
    }

    #[test]
    fn a_failed_hs1_also_proves_the_path_but_junk_does_not() {
        let keys = SessionKeys::derive(&SessionSecret([22; 16]));
        let t0 = Instant::now();
        let ca = args(Role::Creator, &keys, [7; 32], "alice", vec![]);
        let wrong = args(Role::Joiner, &keys, [8; 32], "bob", vec![]);
        let (caddr, jaddr): (SocketAddr, SocketAddr) = (
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
        );
        let mut creator = Checks::new(&ca, false, t0);
        creator.add_peer_info(info(vec![]), t0, 0);
        let record_deadline = creator.deadline;

        creator.on_datagram(jaddr, &[T_HS1; 20], t0).unwrap();
        assert_eq!(creator.deadline, record_deadline);

        let (_j, hs1) = dialing_joiner(&wrong, caddr, t0);
        creator.on_datagram(jaddr, &hs1, t0).unwrap();
        assert_eq!(creator.deadline, t0 + ca.timeouts.creator_wait);
        assert!(creator.outbox.is_empty());
    }

    #[test]
    fn cached_hs2_goes_only_to_the_answered_peer() {
        let keys = SessionKeys::derive(&SessionSecret([23; 16]));
        let (psk, now) = ([7; 32], Instant::now());
        let ca = args(Role::Creator, &keys, psk, "alice", vec![]);
        let ja = args(Role::Joiner, &keys, psk, "bob", vec![]);
        let caddr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let jaddr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let elsewhere: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut creator = Checks::new(&ca, false, now);
        let (_j, hs1) = dialing_joiner(&ja, caddr, now);

        creator.on_datagram(jaddr, &hs1, now).unwrap();
        assert_eq!(std::mem::take(&mut creator.outbox).len(), 1);
        // The same Hs1 replayed from another address is not answered...
        creator.on_datagram(elsewhere, &hs1, now).unwrap();
        assert!(creator.outbox.is_empty());
        // ...but a resend from the peer still is.
        creator.on_datagram(jaddr, &hs1, now).unwrap();
        let resent = std::mem::take(&mut creator.outbox);
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0].0, jaddr);
    }

    #[test]
    fn signaled_candidates_are_capped_without_eviction() {
        let keys = SessionKeys::derive(&SessionSecret([24; 16]));
        let now = Instant::now();
        let at = |i: u16| SocketAddr::from(([10, 0, 0, 1], 1000 + i));
        let initial: Vec<Candidate> = (0..10).map(|i| lan(at(i))).collect();
        let a = args(Role::Joiner, &keys, [7; 32], "bob", initial);
        let mut checks = Checks::new(&a, false, now);
        let more: Vec<Candidate> = (10..30).map(|i| lan(at(i))).collect();
        checks.add_peer_info(info(more), now, unix_ms());
        assert_eq!(checks.remote.len(), MAX_SIGNALED);
        // The first ones stay; the extras were ignored.
        assert!(checks.remote.iter().map(|c| c.addr).eq((0..16).map(at)));

        // A known address can still be upgraded once the cap is reached...
        let upgraded = Candidate {
            kind: CandidateKind::Lan,
            addr: at(0),
        };
        checks.add_peer_info(info(vec![upgraded]), now, unix_ms());
        assert_eq!(checks.remote.len(), MAX_SIGNALED);

        // ...and peer-reflexive candidates have their own budget.
        for i in 0..6u8 {
            let src = SocketAddr::from(([127, 0, 0, 1], 3000 + u16::from(i)));
            let p = probe(&keys.probe_key, [i; 12]).encode();
            checks.on_datagram(src, &p, now).unwrap();
        }
        assert_eq!(checks.remote.len(), MAX_SIGNALED + MAX_PEER_REFLEXIVE);
    }

    #[test]
    fn only_a_plausible_hs1_triggers_the_wrong_password_warning() {
        let keys = SessionKeys::derive(&SessionSecret([25; 16]));
        let now = Instant::now();
        let ca = args(Role::Creator, &keys, [7; 32], "alice", vec![]);
        let wrong = args(Role::Joiner, &keys, [8; 32], "bob", vec![]);
        let caddr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let jaddr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let mut creator = Checks::new(&ca, false, now);

        // Too short or too long to be NNpsk0 message 1: not even a try.
        for len in [0, 1, 47, 81, 200] {
            let mut junk = vec![0x5Au8; 1 + len];
            junk[0] = T_HS1;
            creator.on_datagram(jaddr, &junk, now).unwrap();
            assert!(!creator.warned, "{len} bytes");
        }
        // A real Hs1 under another password is what the warning is for.
        let (_j, hs1) = dialing_joiner(&wrong, caddr, now);
        creator.on_datagram(jaddr, &hs1, now).unwrap();
        assert!(creator.warned);
    }

    #[test]
    fn a_replayed_probe_teaches_nothing_even_after_the_ttl() {
        let keys = SessionKeys::derive(&SessionSecret([26; 16]));
        let t0 = Instant::now();
        let a = args(Role::Joiner, &keys, [7; 32], "bob", vec![]);
        let mut checks = Checks::new(&a, false, t0);
        let first: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let later: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let p = probe(&keys.probe_key, [9; 12]).encode();

        checks.on_datagram(first, &p, t0).unwrap();
        assert_eq!(checks.remote.len(), 1);
        // Long after any per-probe timer, the same probe from elsewhere is
        // still answered once, and still teaches no address.
        let late = t0 + Duration::from_secs(60);
        checks.send_probes(late);
        checks.outbox.clear();
        checks.on_datagram(later, &p, late).unwrap();
        assert_eq!(checks.outbox.len(), 1);
        assert_eq!(checks.outbox[0].0, later);
        assert_eq!(checks.remote.len(), 1);
    }

    #[test]
    fn seen_probes_remember_the_most_recent_ones() {
        let mut seen = SeenTxids::default();
        let txid = |i: u32| {
            let mut t = [0u8; 12];
            t[..4].copy_from_slice(&i.to_be_bytes());
            t
        };
        assert!(seen.insert(txid(0)));
        assert!(!seen.insert(txid(0)));
        for i in 1..SEEN_PROBES as u32 {
            assert!(seen.insert(txid(i)));
        }
        // Full: the oldest is still there until one more comes in.
        assert!(!seen.insert(txid(0)));
        assert!(seen.insert(txid(SEEN_PROBES as u32)));
        assert!(seen.insert(txid(0)));
        assert!(!seen.insert(txid(SEEN_PROBES as u32)));
    }

    #[test]
    fn probes_from_unusable_sources_are_not_answered() {
        let keys = SessionKeys::derive(&SessionSecret([27; 16]));
        let now = Instant::now();
        let a = args(Role::Creator, &keys, [7; 32], "alice", vec![]);
        let mut checks = Checks::new(&a, false, now);
        let p = probe(&keys.probe_key, [3; 12]).encode();
        for src in [
            "0.0.0.0:5",
            "10.0.0.1:0",
            "224.0.0.1:5",
            "255.255.255.255:5",
            "[ff02::1]:5",
        ] {
            checks.on_datagram(src.parse().unwrap(), &p, now).unwrap();
            assert!(checks.outbox.is_empty(), "{src}");
        }
        assert!(checks.remote.is_empty());
        // The same probe from a real address is answered.
        checks
            .on_datagram("127.0.0.1:4000".parse().unwrap(), &p, now)
            .unwrap();
        assert_eq!(checks.outbox.len(), 1);
    }
}
