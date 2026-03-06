use crate::session::SessionId;
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Invite {
    pub session_id: SessionId,
    pub public_addr: SocketAddr,
    pub password_hash: [u8; 32],
    pub public_key: Vec<u8>,
    pub username: String,
}

impl Invite {
    pub fn new(
        session_id: SessionId,
        public_addr: SocketAddr,
        password_hash: [u8; 32],
        public_key: Vec<u8>,
        username: String,
    ) -> Self {
        Self {
            session_id,
            public_addr,
            password_hash,
            public_key,
            username,
        }
    }

    pub fn to_string(&self) -> Result<String> {
        let json = serde_json::to_string(self)?;
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(json);
        Ok(format!("tchat://{}", encoded))
    }

    pub fn from_string(s: &str) -> Result<Self> {
        let encoded = s.strip_prefix("tchat://")
            .ok_or_else(|| anyhow::anyhow!("Invalid invite format"))?;
        let json = general_purpose::URL_SAFE_NO_PAD.decode(encoded)?;
        let invite = serde_json::from_slice(&json)?;
        Ok(invite)
    }

    pub fn to_qr_code(&self) -> Result<String> {
        let invite_str = self.to_string()?;
        let code = QrCode::new(invite_str.as_bytes())?;
        let qr_string = code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        Ok(qr_string)
    }

    pub fn display(&self) -> String {
        let invite_str = self.to_string().unwrap_or_else(|_| "Error".to_string());
        format!(
            "Session ID: {}\nInvite Code:\n{}\n",
            self.session_id, invite_str
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionId;

    #[test]
    fn test_invite_encoding() {
        let session_id = SessionId::new();
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let invite = Invite::new(
            session_id,
            addr,
            [0u8; 32],
            vec![1, 2, 3],
            "Alice".to_string(),
        );

        let encoded = invite.to_string().unwrap();
        assert!(encoded.starts_with("tchat://"));

        let decoded = Invite::from_string(&encoded).unwrap();
        assert_eq!(decoded.username, "Alice");
        assert_eq!(decoded.public_addr, addr);
    }
}
