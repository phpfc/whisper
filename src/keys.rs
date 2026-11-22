//! Session secret and per-purpose key derivation.
//!
//! The invite code carries a 128-bit [`SessionSecret`]. Every key the session
//! needs (DHT signing seed, record encryption, probe HMAC, Argon2 salt and the
//! Noise PSK base) is derived from it with HKDF-SHA256 under a distinct `info`
//! label, so the outputs are independent of each other.

use argon2::Argon2;
use rand::Rng;
use ring::hkdf;

const INFO_DHT: &[u8] = b"whisper/v3/dht";
const INFO_RECORD: &[u8] = b"whisper/v3/record";
const INFO_PROBE: &[u8] = b"whisper/v3/probe";
const INFO_ARGON_SALT: &[u8] = b"whisper/v3/argon-salt";
const INFO_PSK_BASE: &[u8] = b"whisper/v3/psk-base";
const INFO_PSK: &[u8] = b"whisper/v3/psk";

/// 128-bit secret shared through the session code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionSecret(pub [u8; 16]);

impl SessionSecret {
    /// Generates a fresh random secret.
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }
}

/// Keys derived from a [`SessionSecret`], one per purpose.
#[derive(Clone)]
pub struct SessionKeys {
    /// Seed of the ed25519 key that signs DHT records.
    pub dht_seed: [u8; 32],
    /// ChaCha20-Poly1305 key for DHT record values.
    pub record_key: [u8; 32],
    /// HMAC key that tags connectivity probes.
    pub probe_key: [u8; 32],
    /// Salt for the Argon2id password hash.
    pub argon_salt: [u8; 16],
    /// Secret-only half of the Noise PSK, before the password is mixed in.
    pub psk_base: [u8; 32],
}

impl SessionKeys {
    /// Derives every session key from the secret.
    pub fn derive(secret: &SessionSecret) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&secret.0);
        Self {
            dht_seed: expand(&prk, INFO_DHT),
            record_key: expand(&prk, INFO_RECORD),
            probe_key: expand(&prk, INFO_PROBE),
            argon_salt: expand(&prk, INFO_ARGON_SALT),
            psk_base: expand(&prk, INFO_PSK_BASE),
        }
    }
}

/// Derives the Noise PSK from the session keys and the (possibly empty)
/// password: `HKDF(psk_base || Argon2id(password, argon_salt))`.
pub fn derive_psk(keys: &SessionKeys, password: &str) -> [u8; 32] {
    let mut argon_out = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &keys.argon_salt, &mut argon_out)
        .expect("Argon2 hashing failed");

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&keys.psk_base);
    ikm[32..].copy_from_slice(&argon_out);

    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&ikm);
    expand(&prk, INFO_PSK)
}

/// Output length marker for `ring::hkdf`.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand of `prk` under `info` into an `N`-byte array.
fn expand<const N: usize>(prk: &hkdf::Prk, info: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    prk.expand(&[info], Len(N))
        .and_then(|okm| okm.fill(&mut out))
        .expect("HKDF output length is within bounds");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let s = SessionSecret([9; 16]);
        let (a, b) = (SessionKeys::derive(&s), SessionKeys::derive(&s));
        assert_eq!(a.dht_seed, b.dht_seed);
        let outs = [a.dht_seed, a.record_key, a.probe_key, a.psk_base];
        for i in 0..outs.len() {
            for j in i + 1..outs.len() {
                assert_ne!(outs[i], outs[j]);
            }
        }
        assert_ne!(
            SessionKeys::derive(&SessionSecret([1; 16])).dht_seed,
            a.dht_seed
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Wire contract: both peers must derive the same keys, whichever
    /// version each runs. The HKDF values were checked against an
    /// independent HKDF-SHA256 (Python `hmac`/`hashlib`).
    #[test]
    fn derivation_matches_known_answers() {
        let k = SessionKeys::derive(&SessionSecret(std::array::from_fn(|i| i as u8)));
        assert_eq!(
            hex(&k.dht_seed),
            "57e1bc905300704262d4abcc55f7f4b75120b7c1c33996fd21e657c09c1fcc02"
        );
        assert_eq!(
            hex(&k.record_key),
            "914bc4664c5ca0e04fd2c883169cfb69eb8a827509cb8453dc467e6ec40f72de"
        );
        assert_eq!(
            hex(&k.probe_key),
            "92997aa334044a0822875e0059fb8a7fbb39e6847f0f8429e9bd592ad83666e3"
        );
        assert_eq!(hex(&k.argon_salt), "b0e2941636916a6c10e0674ccd2d9a91");
        assert_eq!(
            hex(&k.psk_base),
            "1827ddc0051dedd5efd4bc1b4d0691361338d8e83f42bff29e8907f57d1348fa"
        );
        assert_eq!(
            hex(&derive_psk(&k, "pw")),
            "fd33f8f749031487819f09032d3504c00d2aa51f6964a3cb80b7f043b03809cb"
        );
    }

    #[test]
    fn psk_depends_on_password_and_allows_empty() {
        let k = SessionKeys::derive(&SessionSecret([9; 16]));
        assert_eq!(derive_psk(&k, ""), derive_psk(&k, ""));
        assert_ne!(derive_psk(&k, ""), derive_psk(&k, "secret"));
        assert_ne!(derive_psk(&k, "a"), derive_psk(&k, "b"));
    }
}
