use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub relay_addr: String,
}

impl SessionInfo {
    pub fn new(id: SessionId, relay_addr: String) -> Self {
        Self { id, relay_addr }
    }

    pub fn to_string(&self) -> String {
        format!("{}@{}", self.id.as_str(), self.relay_addr)
    }

    pub fn from_string(s: &str) -> anyhow::Result<Self> {
        if let Some((id_part, relay_part)) = s.split_once('@') {
            Ok(Self {
                id: SessionId::from_string(id_part.to_string()),
                relay_addr: relay_part.to_string(),
            })
        } else {
            Ok(Self {
                id: SessionId::from_string(s.to_string()),
                relay_addr: "127.0.0.1:8080".to_string(),
            })
        }
    }
}

impl std::fmt::Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct SessionAuth {
    password_hash: [u8; 32],
}

impl SessionAuth {
    pub fn new(password: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let password_hash: [u8; 32] = hasher.finalize().into();
        Self { password_hash }
    }

    #[allow(dead_code)]
    pub fn verify(&self, password: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let test_hash: [u8; 32] = hasher.finalize().into();
        self.password_hash == test_hash
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.password_hash
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub sender: String,
    pub content: Vec<u8>,
    pub timestamp: u64,
}

#[allow(dead_code)]
impl Message {
    pub fn new(sender: String, content: Vec<u8>) -> Self {
        Self {
            sender,
            content,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SessionMessage {
    Join {
        session_id: SessionId,
        password_hash: [u8; 32],
        public_key: Vec<u8>,
        username: String,
    },
    JoinAck {
        success: bool,
        peer_public_keys: Vec<(String, Vec<u8>)>,
    },
    PeerJoined {
        username: String,
        public_key: Vec<u8>,
    },
    PeerLeft {
        username: String,
    },
    ChatMessage {
        sender: String,
        encrypted_message: Vec<u8>,
    },
    KeyExchange {
        from: String,
        to: String,
        public_key: Vec<u8>,
    },
}
