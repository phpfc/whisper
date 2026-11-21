//! Rendezvous signaling over the public Mainline DHT.
//!
//! Each peer publishes its connection candidates as a BEP44 mutable item,
//! sealed with ChaCha20-Poly1305 under a key derived from the session secret,
//! and polls for the other peer's item. Both peers sign with the same key (also
//! derived from the secret); the salt tells the creator's item from the
//! joiner's.

use std::cmp::Reverse;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context};
use mainline::async_dht::AsyncDht;
use mainline::{MutableItem, SigningKey};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::mpsc;

use crate::connect::{PeerInfo, Role};
use crate::keys::SessionKeys;

/// Salt of the item the creator publishes.
pub const SALT_CREATOR: &[u8] = b"c";
/// Salt of the item the joiner publishes.
pub const SALT_JOINER: &[u8] = b"j";
/// BEP44 limit on the size of a stored value, in bytes.
pub const MAX_VALUE: usize = 1000;
/// Candidates beyond this many (lowest priority first) are not published.
pub const MAX_PEER_CANDIDATES: usize = 8;

/// Size of the Poly1305 tag appended to the ciphertext.
const TAG_LEN: usize = 16;
/// How many times the initial publish is attempted.
const PUBLISH_ATTEMPTS: usize = 3;
/// Pause between failed publish attempts.
const PUBLISH_RETRY: Duration = Duration::from_secs(5);

/// Starts a DHT client node that bootstraps from the default public nodes.
pub fn public_dht() -> std::io::Result<AsyncDht> {
    Ok(mainline::Dht::client()?.as_async())
}

fn salt(role: Role) -> &'static [u8] {
    match role {
        Role::Creator => SALT_CREATOR,
        Role::Joiner => SALT_JOINER,
    }
}

fn other(role: Role) -> Role {
    match role {
        Role::Creator => Role::Joiner,
        Role::Joiner => Role::Creator,
    }
}

/// Serializes `info` (keeping the best [`MAX_PEER_CANDIDATES`] candidates) and
/// encrypts it as `nonce(12) || ciphertext || tag(16)`.
pub fn seal_info(record_key: &[u8; 32], info: &PeerInfo) -> anyhow::Result<Vec<u8>> {
    let mut info = info.clone();
    info.candidates.sort_by_key(|c| Reverse(c.kind.priority()));
    info.candidates.truncate(MAX_PEER_CANDIDATES);
    seal(record_key, &serde_json::to_vec(&info)?)
}

/// Decrypts and parses a value produced by [`seal_info`].
pub fn open_info(record_key: &[u8; 32], bytes: &[u8]) -> anyhow::Result<PeerInfo> {
    ensure!(bytes.len() >= NONCE_LEN + TAG_LEN, "record too short");
    let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| anyhow!("bad nonce"))?;
    let mut plain = ciphertext.to_vec();
    let plain = cipher(record_key)?
        .open_in_place(nonce, Aad::empty(), &mut plain)
        .map_err(|_| anyhow!("record does not decrypt"))?;
    Ok(serde_json::from_slice(plain)?)
}

fn cipher(record_key: &[u8; 32]) -> anyhow::Result<LessSafeKey> {
    let key = UnboundKey::new(&CHACHA20_POLY1305, record_key)
        .map_err(|_| anyhow!("invalid record key"))?;
    Ok(LessSafeKey::new(key))
}

/// Encrypts `plain` under a fresh random nonce and checks the BEP44 limit.
fn seal(record_key: &[u8; 32], plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow!("no randomness for the nonce"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + plain.len() + TAG_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plain);
    let tag = cipher(record_key)?
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut out[NONCE_LEN..],
        )
        .map_err(|_| anyhow!("record does not encrypt"))?;
    out.extend_from_slice(tag.as_ref());
    ensure!(
        out.len() <= MAX_VALUE,
        "record is {} bytes, over the {MAX_VALUE}-byte limit",
        out.len()
    );
    Ok(out)
}

/// Publishes our own candidates to the DHT and reads the peer's.
pub struct Signaling {
    dht: AsyncDht,
    signer: SigningKey,
    record_key: [u8; 32],
}

impl Signaling {
    pub fn new(keys: &SessionKeys, dht: AsyncDht) -> Self {
        Self {
            dht,
            signer: SigningKey::from_bytes(&keys.dht_seed),
            record_key: keys.record_key,
        }
    }

    /// Stores `info` under the salt of `own`, using its `published_ms` as the
    /// BEP44 sequence number.
    pub async fn publish(&self, own: Role, info: &PeerInfo) -> anyhow::Result<()> {
        let sealed = seal_info(&self.record_key, info)?;
        let item = MutableItem::new(
            self.signer.clone(),
            &sealed,
            info.published_ms,
            Some(salt(own)),
        );
        self.dht
            .put_mutable(item, None)
            .await
            .context("publishing to the DHT failed")?;
        Ok(())
    }

    /// Looks up the most recent record of `remote`. `None` when there is none
    /// yet, or when it cannot be opened with our key.
    pub async fn fetch(&self, remote: Role) -> Option<PeerInfo> {
        let public_key = self.signer.verifying_key().to_bytes();
        let item = self
            .dht
            .get_mutable_most_recent(&public_key, Some(salt(remote)))
            .await?;
        open_info(&self.record_key, item.value()).ok()
    }
}

/// Publishes `info` in the background, then polls for the other role's record
/// every `poll` and forwards each one newer than the last forwarded. Stops
/// when the returned receiver is dropped.
pub fn spawn(
    sig: Signaling,
    own: Role,
    info: PeerInfo,
    poll: Duration,
) -> mpsc::Receiver<PeerInfo> {
    let (tx, rx) = mpsc::channel(4);
    tokio::spawn(run(sig, own, info, poll, tx));
    rx
}

async fn run(
    sig: Signaling,
    own: Role,
    info: PeerInfo,
    poll: Duration,
    tx: mpsc::Sender<PeerInfo>,
) {
    // `closed` also interrupts the retry sleeps and in-flight DHT queries.
    tokio::select! {
        _ = tx.closed() => {}
        _ = publish_and_poll(&sig, own, &info, poll, &tx) => {}
    }
}

async fn publish_and_poll(
    sig: &Signaling,
    own: Role,
    info: &PeerInfo,
    poll: Duration,
    tx: &mpsc::Sender<PeerInfo>,
) {
    for attempt in 1..=PUBLISH_ATTEMPTS {
        if sig.publish(own, info).await.is_ok() {
            break;
        }
        // Keep polling even if the peer will not be able to find us.
        if attempt < PUBLISH_ATTEMPTS {
            tokio::time::sleep(PUBLISH_RETRY).await;
        }
    }

    let mut last_sent: Option<i64> = None;
    loop {
        if let Some(remote) = sig.fetch(other(own)).await {
            if last_sent.map_or(true, |last| remote.published_ms > last) {
                last_sent = Some(remote.published_ms);
                if tx.send(remote).await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidates::{Candidate, CandidateKind};
    use crate::gather::NetSummary;
    use crate::keys::SessionSecret;
    use crate::stun::NatMapping;
    use std::time::Instant;

    fn info(n: usize) -> PeerInfo {
        let cands = (0..n)
            .map(|i| Candidate {
                kind: CandidateKind::Ipv6,
                addr: format!("[2804:14c:65a1:4321:abcd:ef01:2345:{:x}]:65535", i)
                    .parse()
                    .unwrap(),
            })
            .collect();
        PeerInfo {
            candidates: cands,
            published_ms: 1_700_000_000_000,
            summary: NetSummary {
                ipv6: true,
                mapped: false,
                cgnat: Some(true),
                nat: NatMapping::EndpointDependent,
            },
        }
    }

    fn info_at(n: usize, published_ms: i64) -> PeerInfo {
        PeerInfo {
            published_ms,
            ..info(n)
        }
    }

    fn testnet_dht(testnet: &mainline::Testnet) -> AsyncDht {
        mainline::Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .bind_address(std::net::Ipv4Addr::LOCALHOST)
            .build()
            .unwrap()
            .as_async()
    }

    #[test]
    fn sealed_info_roundtrips_and_needs_the_key() {
        let s = seal_info(&[1; 32], &info(3)).unwrap();
        assert_eq!(open_info(&[1; 32], &s).unwrap(), info(3));
        assert!(open_info(&[2; 32], &s).is_err());
    }

    #[test]
    fn worst_case_fits_bep44_and_truncates_to_eight() {
        let s = seal_info(&[1; 32], &info(12)).unwrap();
        assert!(s.len() <= MAX_VALUE);
        assert_eq!(
            open_info(&[1; 32], &s).unwrap().candidates.len(),
            MAX_PEER_CANDIDATES
        );
    }

    #[test]
    fn longest_possible_record_still_fits() {
        // Longest kind name and longest IPv6 text form, eight times over.
        let mut worst = info(8);
        for (i, c) in worst.candidates.iter_mut().enumerate() {
            c.kind = CandidateKind::PeerReflexive;
            c.addr = format!("[2804:14c:65a1:4321:abcd:ef01:2345:abc{:x}]:65535", i)
                .parse()
                .unwrap();
        }
        worst.published_ms = i64::MAX;
        worst.summary.cgnat = Some(false);
        let s = seal_info(&[1; 32], &worst).unwrap();
        println!("worst-case sealed size: {} bytes", s.len());
        assert!(s.len() <= MAX_VALUE);
    }

    #[test]
    fn truncation_keeps_the_highest_priority_candidates() {
        let mut mixed = info(10);
        // The last two are the only `Lan` ones; they must survive truncation.
        for c in &mut mixed.candidates[8..] {
            c.kind = CandidateKind::Lan;
        }
        let opened = open_info(&[1; 32], &seal_info(&[1; 32], &mixed).unwrap()).unwrap();
        assert_eq!(opened.candidates.len(), MAX_PEER_CANDIDATES);
        assert_eq!(opened.candidates[0].kind, CandidateKind::Lan);
        assert_eq!(opened.candidates[1].kind, CandidateKind::Lan);
        assert!(opened.candidates[2..]
            .iter()
            .all(|c| c.kind == CandidateKind::Ipv6));
    }

    #[test]
    fn oversized_value_is_rejected() {
        let overhead = NONCE_LEN + TAG_LEN;
        assert!(seal(&[1; 32], &vec![0u8; MAX_VALUE - overhead]).is_ok());
        assert!(seal(&[1; 32], &vec![0u8; MAX_VALUE - overhead + 1]).is_err());
    }

    #[test]
    fn open_rejects_garbage_and_tampering() {
        assert!(open_info(&[1; 32], &[]).is_err());
        assert!(open_info(&[1; 32], &[0u8; NONCE_LEN + TAG_LEN - 1]).is_err());
        assert!(open_info(&[1; 32], &[0u8; 64]).is_err());
        let mut s = seal_info(&[1; 32], &info(2)).unwrap();
        *s.last_mut().unwrap() ^= 1;
        assert!(open_info(&[1; 32], &s).is_err());
    }

    #[test]
    fn nonce_is_random_per_seal() {
        let a = seal_info(&[1; 32], &info(2)).unwrap();
        let b = seal_info(&[1; 32], &info(2)).unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    #[tokio::test]
    async fn publish_and_fetch_over_testnet() {
        let testnet = mainline::Testnet::builder(5).build().unwrap();
        let dht = || testnet_dht(&testnet);
        let keys = SessionKeys::derive(&SessionSecret([4; 16]));
        let (a, b) = (Signaling::new(&keys, dht()), Signaling::new(&keys, dht()));
        a.publish(Role::Creator, &info(2)).await.unwrap();
        assert_eq!(b.fetch(Role::Creator).await, Some(info(2)));
        assert_eq!(b.fetch(Role::Joiner).await, None);
    }

    #[tokio::test]
    async fn fetch_ignores_records_sealed_with_another_key() {
        let testnet = mainline::Testnet::builder(5).build().unwrap();
        let keys = SessionKeys::derive(&SessionSecret([5; 16]));
        let mut other = keys.clone();
        other.record_key = [9; 32];
        let a = Signaling::new(&other, testnet_dht(&testnet));
        let b = Signaling::new(&keys, testnet_dht(&testnet));
        a.publish(Role::Creator, &info(2)).await.unwrap();
        assert_eq!(b.fetch(Role::Creator).await, None);
    }

    #[tokio::test]
    async fn spawn_delivers_each_newer_remote_info_once() {
        let testnet = mainline::Testnet::builder(5).build().unwrap();
        let keys = SessionKeys::derive(&SessionSecret([6; 16]));
        let creator = Signaling::new(&keys, testnet_dht(&testnet));
        let joiner = Signaling::new(&keys, testnet_dht(&testnet));
        joiner
            .publish(Role::Joiner, &info_at(2, 1000))
            .await
            .unwrap();

        let mut rx = spawn(
            creator,
            Role::Creator,
            info_at(1, 500),
            Duration::from_millis(50),
        );
        let wait = Duration::from_secs(20);
        let first = tokio::time::timeout(wait, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, info_at(2, 1000));

        // Same record is polled again but must not be re-sent; a newer one is.
        joiner
            .publish(Role::Joiner, &info_at(3, 2000))
            .await
            .unwrap();
        let second = tokio::time::timeout(wait, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second, info_at(3, 2000));

        // The creator's own record was published meanwhile.
        assert_eq!(joiner.fetch(Role::Creator).await, Some(info_at(1, 500)));
    }

    #[tokio::test]
    async fn run_ends_when_the_receiver_is_dropped() {
        let testnet = mainline::Testnet::builder(5).build().unwrap();
        let keys = SessionKeys::derive(&SessionSecret([7; 16]));
        let sig = Signaling::new(&keys, testnet_dht(&testnet));
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::spawn(run(
            sig,
            Role::Creator,
            info(1),
            Duration::from_millis(50),
            tx,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!task.is_finished());
        drop(rx);
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("poll loop did not stop after the receiver was dropped")
            .unwrap();
        println!("run stopped {:?} after drop", started.elapsed());
    }
}
