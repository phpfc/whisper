use anyhow::{anyhow, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;

pub struct CryptoSession {
    shared_secret: [u8; 32],
    rng: SystemRandom,
}

impl CryptoSession {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self {
            shared_secret,
            rng: SystemRandom::new(),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.shared_secret)
            .map_err(|_| anyhow!("Failed to create encryption key"))?;
        let key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow!("Failed to generate nonce"))?;
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
    #[allow(dead_code)]
    secret: EphemeralSecret,
    public: PublicKey,
}

impl KeyExchange {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    #[allow(dead_code)]
    pub fn derive_shared_secret(self, peer_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public).to_bytes()
    }
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
    fn test_encryption_decryption() {
        let shared_secret = [42u8; 32];
        let crypto = CryptoSession::new(shared_secret);

        let message = b"Hello, secure world!";
        let encrypted = crypto.encrypt(message).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(message.to_vec(), decrypted);
    }
}
