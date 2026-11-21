//! Shareable session code (v3).
//!
//! `base58(3 || secret[16] || n || n * addr)`, where each address is
//! `[4] ip(4) port(2, BE)` or `[6] ip(16) port(2, BE)`.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, SocketAddr};

use crate::keys::SessionSecret;

/// First byte of every code this version creates and accepts.
pub const CODE_VERSION: u8 = 3;

/// At most this many direct addresses are carried in a code.
pub const MAX_DIRECT: usize = 3;

const TAG_V4: u8 = 4;
const TAG_V6: u8 = 6;

const OLD_FORMAT_ERROR: &str = "This code is from an older whisper version (0.2). \
Ask your peer to update and create a new session.";

// One message for a wrong version and for a cut-off code: truncating a base58
// string changes every decoded byte, the version byte included, so the two
// cases cannot be told apart.
const INVALID_ERROR: &str = "Invalid session code. \
Check that you copied all of it and that you both run the latest whisper.";

/// What the creator shares with the peer: the session secret and the
/// addresses the peer can try to reach the creator on directly.
#[derive(Debug, PartialEq)]
pub struct SessionCode {
    pub secret: SessionSecret,
    pub direct: Vec<SocketAddr>,
}

impl SessionCode {
    /// Encodes the code as a base58 string. Addresses past [`MAX_DIRECT`] are
    /// dropped so the result always decodes.
    pub fn encode(&self) -> String {
        let direct = &self.direct[..self.direct.len().min(MAX_DIRECT)];
        let mut out = Vec::with_capacity(1 + 16 + 1 + direct.len() * 19);
        out.push(CODE_VERSION);
        out.extend_from_slice(&self.secret.0);
        out.push(direct.len() as u8);
        for addr in direct {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(TAG_V4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(TAG_V6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        bs58::encode(out).into_string()
    }

    /// Parses a code as pasted by a user. Whitespace anywhere and quotes
    /// around the code are ignored.
    pub fn decode(s: &str) -> Result<Self> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let cleaned = cleaned.trim_matches(['"', '\'', '`']);
        if cleaned.contains('#') {
            bail!(OLD_FORMAT_ERROR);
        }
        Self::parse(cleaned).ok_or_else(|| anyhow!(INVALID_ERROR))
    }

    fn parse(s: &str) -> Option<Self> {
        let bytes = bs58::decode(s).into_vec().ok()?;
        let mut buf = bytes.as_slice();

        if take(&mut buf, 1)?[0] != CODE_VERSION {
            return None;
        }
        let secret = SessionSecret(take(&mut buf, 16)?.try_into().ok()?);
        let n = take(&mut buf, 1)?[0] as usize;
        if n > MAX_DIRECT {
            return None;
        }

        let mut direct = Vec::with_capacity(n);
        for _ in 0..n {
            let ip = match take(&mut buf, 1)?[0] {
                TAG_V4 => IpAddr::from(<[u8; 4]>::try_from(take(&mut buf, 4)?).ok()?),
                TAG_V6 => IpAddr::from(<[u8; 16]>::try_from(take(&mut buf, 16)?).ok()?),
                _ => return None,
            };
            let port = u16::from_be_bytes(take(&mut buf, 2)?.try_into().ok()?);
            direct.push(SocketAddr::new(ip, port));
        }

        // Anything left over means this is not a code we produced.
        buf.is_empty().then_some(Self { secret, direct })
    }
}

/// Splits `n` bytes off the front of `buf`, or `None` if it is too short.
fn take<'a>(buf: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, tail) = buf.split_at_checked(n)?;
    *buf = tail;
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SessionCode {
        SessionCode {
            secret: SessionSecret([5; 16]),
            direct: vec![
                "189.40.1.2:40000".parse().unwrap(),
                "[2804:14c:65a1:4321:abcd:ef01:2345:6789]:41000"
                    .parse()
                    .unwrap(),
                "192.168.0.10:40000".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn roundtrip_with_and_without_direct() {
        let c = sample();
        assert_eq!(SessionCode::decode(&c.encode()).unwrap(), c);
        let bare = SessionCode {
            secret: SessionSecret([5; 16]),
            direct: vec![],
        };
        assert_eq!(SessionCode::decode(&bare.encode()).unwrap(), bare);
        assert!(bare.encode().len() <= 30);
        assert!(c.encode().len() <= 90);
    }

    #[test]
    fn decode_tolerates_whitespace_and_quotes() {
        let e = sample().encode();
        let (a, b) = e.split_at(20);
        for pasted in [
            format!("  {e}\n"),
            format!("\"{e}\""),
            format!("`{a}\n{b}`"),
            format!("{a} {b}"),
        ] {
            assert_eq!(SessionCode::decode(&pasted).unwrap(), sample());
        }
    }

    #[test]
    fn rejects_old_truncated_and_foreign_codes() {
        let old = SessionCode::decode("203.45.67.89:54321#7kJ9xnYpQm#QgT98sXCthe3").unwrap_err();
        assert!(old.to_string().contains("older whisper version"));
        let e = sample().encode();
        assert!(SessionCode::decode(&e[..e.len() - 4])
            .unwrap_err()
            .to_string()
            .contains("copied all of it"));
        let mut bytes = bs58::decode(&e).into_vec().unwrap();
        bytes.truncate(bytes.len() - 3);
        assert!(SessionCode::decode(&bs58::encode(&bytes).into_string())
            .unwrap_err()
            .to_string()
            .contains("copied all of it"));
        let mut v2 = bs58::decode(&e).into_vec().unwrap();
        v2[0] = 2;
        assert!(SessionCode::decode(&bs58::encode(v2).into_string())
            .unwrap_err()
            .to_string()
            .contains("copied all of it"));
    }

    #[test]
    fn rejects_malformed_structure() {
        let raw = |bytes: &[u8]| bs58::encode(bytes).into_string();
        let expect_invalid = |bytes: &[u8]| {
            let err = SessionCode::decode(&raw(bytes)).unwrap_err();
            assert!(err.to_string().contains("copied all of it"), "{bytes:?}");
        };

        let mut head = vec![CODE_VERSION];
        head.extend_from_slice(&[5; 16]);

        let mut too_many = head.clone();
        too_many.push(MAX_DIRECT as u8 + 1);
        for _ in 0..=MAX_DIRECT {
            too_many.extend_from_slice(&[4, 1, 2, 3, 4, 0, 80]);
        }
        expect_invalid(&too_many);

        let mut trailing = head.clone();
        trailing.extend_from_slice(&[0, 0]);
        expect_invalid(&trailing);

        let mut bad_tag = head.clone();
        bad_tag.extend_from_slice(&[1, 5, 1, 2, 3, 4, 0, 80]);
        expect_invalid(&bad_tag);

        expect_invalid(&head);
        expect_invalid(&[]);
        assert!(SessionCode::decode("0OIl").is_err());
        assert!(SessionCode::decode("").is_err());
    }

    #[test]
    fn encode_caps_direct_addresses() {
        let mut c = sample();
        c.direct.push("10.0.0.1:1".parse().unwrap());
        let decoded = SessionCode::decode(&c.encode()).unwrap();
        assert_eq!(decoded.direct, c.direct[..MAX_DIRECT]);
    }
}
