use anyhow::{anyhow, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{PublicKey, StaticSecret};
use rand_core::OsRng;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct CryptoSession {
    shared_secret: [u8; 32],
    rng: SystemRandom,
    nonce_counter: AtomicU64,
}

impl CryptoSession {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self {
            shared_secret,
            rng: SystemRandom::new(),
            nonce_counter: AtomicU64::new(0),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.shared_secret)
            .map_err(|_| anyhow!("Failed to create encryption key"))?;
        let key = LessSafeKey::new(unbound_key);

        // Nonce híbrido: 4 bytes random + 8 bytes counter
        // Isso garante unicidade mesmo com múltiplas instâncias
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes[..4])
            .map_err(|_| anyhow!("Failed to generate nonce random part"))?;

        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("Encryption failed"))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(anyhow!("Ciphertext too short"));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = Nonce::assume_unique_for_key(
            nonce_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid nonce"))?,
        );

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.shared_secret)
            .map_err(|_| anyhow!("Failed to create decryption key"))?;
        let key = LessSafeKey::new(unbound_key);

        let mut in_out = encrypted_data.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("Decryption failed"))?;

        Ok(plaintext.to_vec())
    }
}

pub struct KeyExchange {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyExchange {
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Deriva o shared secret usando ECDH X25519.
    /// StaticSecret permite múltiplas derivações com diferentes peers.
    pub fn derive_shared_secret(&self, peer_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public).to_bytes()
    }
}

/// Gera um fingerprint legível de uma chave pública.
/// Retorna os primeiros 32 caracteres hex do SHA-256 da chave.
pub fn fingerprint(public_key: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    // Formata como 8 grupos de 4 caracteres hex
    let hex: String = hash.iter().take(16).map(|b| format!("{:02X}", b)).collect();
    format!(
        "{} {} {} {}",
        &hex[0..8],
        &hex[8..16],
        &hex[16..24],
        &hex[24..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = KeyExchange::new();
        let bob = KeyExchange::new();

        let alice_public = alice.public_key().clone();
        let bob_public = bob.public_key().clone();

        let alice_shared = alice.derive_shared_secret(&bob_public);
        let bob_shared = bob.derive_shared_secret(&alice_public);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_multiple_derivations() {
        // Verifica que StaticSecret permite múltiplas derivações
        let alice = KeyExchange::new();
        let bob = KeyExchange::new();
        let carol = KeyExchange::new();

        let bob_public = bob.public_key().clone();
        let carol_public = carol.public_key().clone();

        let alice_bob_shared = alice.derive_shared_secret(&bob_public);
        let alice_carol_shared = alice.derive_shared_secret(&carol_public);

        // Shared secrets devem ser diferentes
        assert_ne!(alice_bob_shared, alice_carol_shared);

        // Mas Bob deve derivar o mesmo shared secret com Alice
        let alice_public = alice.public_key().clone();
        let bob_alice_shared = bob.derive_shared_secret(&alice_public);
        assert_eq!(alice_bob_shared, bob_alice_shared);
    }

    #[test]
    fn test_encryption_decryption() {
        let shared_secret = [42u8; 32];
        let crypto = CryptoSession::new(shared_secret);

        let message = b"Hello, secure world!";
        let encrypted = crypto.encrypt(message).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let shared_secret = [42u8; 32];
        let crypto = CryptoSession::new(shared_secret);

        let message = b"test";
        let encrypted1 = crypto.encrypt(message).unwrap();
        let encrypted2 = crypto.encrypt(message).unwrap();

        // Nonces devem ser diferentes (primeiros 12 bytes)
        assert_ne!(&encrypted1[..12], &encrypted2[..12]);
    }

    #[test]
    fn test_fingerprint() {
        let key = [0u8; 32];
        let fp = fingerprint(&key);
        // Deve ter formato "XXXX XXXX XXXX XXXX" (35 chars com espaços)
        assert_eq!(fp.len(), 35);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }
}
