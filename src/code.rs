//! Shareable session code (v3).
//!
//! `base58(3 || secret[16] || n || n * addr || check[2])`, where each address
//! is `[4] ip(4) port(2, BE)` or `[6] ip(16) port(2, BE)`, and `check` is the
//! first 2 bytes of SHA-256 over everything before it.

use anyhow::{anyhow, bail, Result};
use ring::digest::{digest, SHA256};
use std::net::{IpAddr, SocketAddr};

use crate::keys::SessionSecret;

/// First byte of every code this version creates and accepts.
pub const CODE_VERSION: u8 = 3;

/// At most this many direct addresses are carried in a code.
pub const MAX_DIRECT: usize = 3;

const TAG_V4: u8 = 4;
const TAG_V6: u8 = 6;

/// Bytes of checksum at the end of a code. A typo is caught right away
/// instead of turning into a wrong secret or a wrong address (it slips
/// through one time in 65536).
const CHECK_LEN: usize = 2;

/// Invisible characters that chat apps and editors slip into copied text.
const ZERO_WIDTH: [char; 5] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{2060}'];

/// Quotes a code may be pasted between, typographic ones included.
const QUOTES: [char; 7] = [
    '"', '\'', '`', '\u{201C}', '\u{201D}', '\u{2018}', '\u{2019}',
];

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
        let check = checksum(&out);
        out.extend_from_slice(&check);
        bs58::encode(out).into_string()
    }

    /// Parses a code as pasted by a user. Whitespace and zero-width
    /// characters anywhere, and quotes (straight or typographic) around the
    /// code, are ignored.
    pub fn decode(s: &str) -> Result<Self> {
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && !ZERO_WIDTH.contains(c))
            .collect();
        let cleaned = cleaned.trim_matches(QUOTES);
        if cleaned.contains('#') {
            bail!(OLD_FORMAT_ERROR);
        }
        Self::parse(cleaned).ok_or_else(|| anyhow!(INVALID_ERROR))
    }

    fn parse(s: &str) -> Option<Self> {
        let bytes = bs58::decode(s).into_vec().ok()?;
        let (body, check) = bytes.split_at_checked(bytes.len().checked_sub(CHECK_LEN)?)?;
        if checksum(body) != check {
            return None;
        }
        let mut buf = body;

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

/// The first [`CHECK_LEN`] bytes of SHA-256 over `bytes`.
fn checksum(bytes: &[u8]) -> [u8; CHECK_LEN] {
    let mut check = [0u8; CHECK_LEN];
    check.copy_from_slice(&digest(&SHA256, bytes).as_ref()[..CHECK_LEN]);
    check
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

    const KNOWN_CODE: &str = "QWzMFuFBesCTtXToSWRRi3zcaEzTNrfR49Hf";

    /// `bytes` with a valid checksum, in base58: the structure alone decides.
    fn checked(bytes: &[u8]) -> String {
        let mut out = bytes.to_vec();
        out.extend_from_slice(&checksum(bytes));
        bs58::encode(out).into_string()
    }

    #[test]
    fn decode_tolerates_typographic_quotes_and_invisible_characters() {
        let e = sample().encode();
        let (a, b) = e.split_at(20);
        for pasted in [
            format!("\u{201C}{e}\u{201D}"),
            format!("\u{2018}{e}\u{2019}"),
            format!("\u{201C}{e}\""),
            format!("\u{FEFF}{e}"),
            format!("{a}\u{200B}{b}"),
            format!("{a}\u{200C}{b}\u{200D}"),
            format!("\u{201C}{a}\u{2060} {b}\u{201D}\n"),
        ] {
            assert_eq!(
                SessionCode::decode(&pasted).unwrap(),
                sample(),
                "{pasted:?}"
            );
        }
    }

    #[test]
    fn a_single_mistyped_character_is_caught() {
        const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let bare = SessionCode {
            secret: SessionSecret([5; 16]),
            direct: vec![],
        };
        for code in [sample().encode(), bare.encode()] {
            for (i, original) in code.char_indices() {
                for c in ALPHABET.chars().filter(|&c| c != original) {
                    let mut typo = code.clone();
                    typo.replace_range(i..i + 1, c.encode_utf8(&mut [0; 4]));
                    let err = SessionCode::decode(&typo).expect_err(&typo);
                    assert!(err.to_string().contains("copied all of it"), "{typo}");
                }
            }
        }
    }

    #[test]
    fn a_wrong_checksum_is_rejected() {
        let mut bytes = bs58::decode(sample().encode()).into_vec().unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let err = SessionCode::decode(&bs58::encode(bytes).into_string()).unwrap_err();
        assert!(err.to_string().contains("copied all of it"));
    }

    /// Wire contract: the checksum and the layout, pinned. The checksum of
    /// "abc" is the start of the well-known SHA-256 test vector `ba7816bf...`.
    #[test]
    fn code_matches_known_answers() {
        assert_eq!(checksum(b"abc"), [0xba, 0x78]);
        let code = SessionCode {
            secret: SessionSecret(std::array::from_fn(|i| i as u8)),
            direct: vec!["189.40.1.2:40000".parse().unwrap()],
        };
        assert_eq!(code.encode(), KNOWN_CODE);
        assert_eq!(SessionCode::decode(KNOWN_CODE).unwrap(), code);
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
        // Version 2 with a valid checksum: the version byte alone rejects it.
        let mut v2 = bs58::decode(&e).into_vec().unwrap();
        v2.truncate(v2.len() - CHECK_LEN);
        v2[0] = 2;
        assert!(SessionCode::decode(&checked(&v2))
            .unwrap_err()
            .to_string()
            .contains("copied all of it"));
    }

    #[test]
    fn rejects_malformed_structure() {
        let expect_invalid = |bytes: &[u8]| {
            let err = SessionCode::decode(&checked(bytes)).unwrap_err();
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
        // Shorter than a checksum.
        assert!(SessionCode::decode(&bs58::encode([3]).into_string()).is_err());
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
