use argon2::Argon2;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;

/// Validation constants
pub const MAX_USERNAME_LEN: usize = 32;
pub const MAX_MESSAGE_LEN: usize = 4096;

/// Validates a username (1-32 chars, alphanumeric + underscore)
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() {
        return Err("Username cannot be empty");
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err("Username too long (max 32 characters)");
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err("Username can only contain letters, numbers, and underscores");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Creates a new SessionId with 128 bits of cryptographic entropy in base58.
    pub fn new() -> Self {
        let bytes: [u8; 16] = rand::thread_rng().gen();
        Self(bs58::encode(bytes).into_string())
    }

    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session info for P2P connection
/// Format: <ip>:<port>#<session_id>#<salt>
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub peer_addr: SocketAddr,
    pub id: SessionId,
    pub salt: [u8; 16],
}

impl SessionInfo {
    pub fn new(peer_addr: SocketAddr, id: SessionId, salt: [u8; 16]) -> Self {
        Self { peer_addr, id, salt }
    }

    /// Serializes to shareable format: <ip>:<port>#<session_id>#<salt>
    pub fn to_code(&self) -> String {
        let salt_b58 = bs58::encode(&self.salt).into_string();
        format!("{}#{}#{}", self.peer_addr, self.id.as_str(), salt_b58)
    }

    /// Parses the format: <ip>:<port>#<session_id>#<salt>
    pub fn from_code(s: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = s.split('#').collect();

        if parts.len() != 3 {
            return Err(anyhow::anyhow!(
                "Invalid session code format. Expected: <ip>:<port>#<session_id>#<salt>"
            ));
        }

        let peer_addr: SocketAddr = parts[0]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid peer address: {}", parts[0]))?;

        let id = SessionId::from_string(parts[1].to_string());

        let salt_bytes = bs58::decode(parts[2])
            .into_vec()
            .map_err(|_| anyhow::anyhow!("Invalid salt encoding"))?;

        if salt_bytes.len() != 16 {
            return Err(anyhow::anyhow!("Invalid salt length"));
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);

        Ok(Self { peer_addr, id, salt })
    }
}

impl std::fmt::Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_code())
    }
}

#[derive(Debug, Clone)]
pub struct SessionAuth {
    #[allow(dead_code)]
    password_hash: [u8; 32],
    salt: [u8; 16],
}

impl SessionAuth {
    /// Creates new authentication with Argon2id and random salt.
    pub fn new(password: &str) -> Self {
        let salt: [u8; 16] = rand::thread_rng().gen();
        let mut password_hash = [0u8; 32];

        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut password_hash)
            .expect("Argon2 hashing failed");

        Self { password_hash, salt }
    }

    /// Creates SessionAuth from a known salt (for joiner).
    pub fn with_salt(password: &str, salt: [u8; 16]) -> Self {
        let mut password_hash = [0u8; 32];

        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut password_hash)
            .expect("Argon2 hashing failed");

        Self { password_hash, salt }
    }

    /// Verifies password using constant-time comparison.
    #[allow(dead_code)]
    pub fn verify(&self, password: &str) -> bool {
        let mut test_hash = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &self.salt, &mut test_hash)
            .expect("Argon2 hashing failed");

        self.password_hash.ct_eq(&test_hash).into()
    }

    /// Verifies a hash directly using constant-time comparison.
    #[allow(dead_code)]
    pub fn verify_hash(&self, hash: &[u8; 32]) -> bool {
        self.password_hash.ct_eq(hash).into()
    }

    #[allow(dead_code)]
    pub fn hash(&self) -> &[u8; 32] {
        &self.password_hash
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
}

/// Chat message for P2P communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatMessage {
    /// Encrypted chat text
    Text { ciphertext: Vec<u8> },
    /// Keepalive to maintain NAT mapping
    Ping,
    Pong,
}
