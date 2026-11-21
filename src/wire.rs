//! Binary UDP packet format.
//!
//! Every datagram starts with a type byte. All types are >= 0xA0, so they can
//! never be mistaken for STUN (whose first byte is 0x00..=0x3F, RFC 7983) when
//! both share one socket.
//!
//! - `Probe` / `ProbeAck`: `[type][txid 12][tag 16]`, exactly 29 bytes. The tag
//!   is a truncated HMAC-SHA256 under the session probe key, so only someone
//!   holding the session code can produce or validate one.
//! - `Hs1` / `Hs2`: `[type][noise handshake message]`.
//! - `Data`: `[type][nonce u64 BE][ChaCha20-Poly1305 ciphertext]`.
//!
//! [`decode`](Packet::decode) takes untrusted network input and never panics.

use ring::hmac;
use subtle::ConstantTimeEq;

/// Largest datagram we ever send, kept under a typical path MTU so it is never
/// fragmented.
pub const MAX_DATAGRAM: usize = 1200;

pub const T_PROBE: u8 = 0xA1;
pub const T_PROBE_ACK: u8 = 0xA2;
pub const T_HS1: u8 = 0xA3;
pub const T_HS2: u8 = 0xA4;
pub const T_DATA: u8 = 0xA5;

const TXID_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PROBE_LEN: usize = 1 + TXID_LEN + TAG_LEN;
const DATA_HEADER_LEN: usize = 1 + 8;

#[derive(Debug, PartialEq)]
pub enum Packet<'a> {
    Probe {
        txid: [u8; TXID_LEN],
        tag: [u8; TAG_LEN],
    },
    ProbeAck {
        txid: [u8; TXID_LEN],
        tag: [u8; TAG_LEN],
    },
    Hs1(&'a [u8]),
    Hs2(&'a [u8]),
    Data {
        nonce: u64,
        ciphertext: &'a [u8],
    },
}

impl<'a> Packet<'a> {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Packet::Probe { txid, tag } => encode_probe(T_PROBE, txid, tag),
            Packet::ProbeAck { txid, tag } => encode_probe(T_PROBE_ACK, txid, tag),
            Packet::Hs1(bytes) => encode_raw(T_HS1, bytes),
            Packet::Hs2(bytes) => encode_raw(T_HS2, bytes),
            Packet::Data { nonce, ciphertext } => {
                let mut out = Vec::with_capacity(DATA_HEADER_LEN + ciphertext.len());
                out.push(T_DATA);
                out.extend_from_slice(&nonce.to_be_bytes());
                out.extend_from_slice(ciphertext);
                out
            }
        }
    }

    /// Parses a datagram. Returns `None` for anything that is not a
    /// well-formed packet of ours (STUN, junk, wrong length).
    pub fn decode(buf: &'a [u8]) -> Option<Self> {
        let (&kind, rest) = buf.split_first()?;
        match kind {
            T_PROBE | T_PROBE_ACK => {
                if buf.len() != PROBE_LEN {
                    return None;
                }
                let txid = rest[..TXID_LEN].try_into().ok()?;
                let tag = rest[TXID_LEN..].try_into().ok()?;
                Some(if kind == T_PROBE {
                    Packet::Probe { txid, tag }
                } else {
                    Packet::ProbeAck { txid, tag }
                })
            }
            T_HS1 => Some(Packet::Hs1(rest)),
            T_HS2 => Some(Packet::Hs2(rest)),
            T_DATA => {
                if buf.len() < DATA_HEADER_LEN {
                    return None;
                }
                let (nonce, ciphertext) = rest.split_at(8);
                Some(Packet::Data {
                    nonce: u64::from_be_bytes(nonce.try_into().ok()?),
                    ciphertext,
                })
            }
            _ => None,
        }
    }
}

fn encode_probe(kind: u8, txid: &[u8; TXID_LEN], tag: &[u8; TAG_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROBE_LEN);
    out.push(kind);
    out.extend_from_slice(txid);
    out.extend_from_slice(tag);
    out
}

fn encode_raw(kind: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(kind);
    out.extend_from_slice(bytes);
    out
}

/// `HMAC-SHA256(probe_key, [kind] || txid)` truncated to 16 bytes. The type
/// byte is part of the input, so a `Probe` tag is not valid on a `ProbeAck`.
fn probe_tag(probe_key: &[u8; 32], kind: u8, txid: &[u8; TXID_LEN]) -> [u8; TAG_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, probe_key);
    let mut msg = [0u8; 1 + TXID_LEN];
    msg[0] = kind;
    msg[1..].copy_from_slice(txid);
    let full = hmac::sign(&key, &msg);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full.as_ref()[..TAG_LEN]);
    tag
}

pub fn probe(probe_key: &[u8; 32], txid: [u8; 12]) -> Packet<'static> {
    Packet::Probe {
        txid,
        tag: probe_tag(probe_key, T_PROBE, &txid),
    }
}

pub fn probe_ack(probe_key: &[u8; 32], txid: [u8; 12]) -> Packet<'static> {
    Packet::ProbeAck {
        txid,
        tag: probe_tag(probe_key, T_PROBE_ACK, &txid),
    }
}

/// Checks the tag of a `Probe` or `ProbeAck` in constant time. Any other
/// packet type is rejected.
pub fn verify(probe_key: &[u8; 32], p: &Packet) -> bool {
    let (kind, txid, tag) = match p {
        Packet::Probe { txid, tag } => (T_PROBE, txid, tag),
        Packet::ProbeAck { txid, tag } => (T_PROBE_ACK, txid, tag),
        _ => return false,
    };
    probe_tag(probe_key, kind, txid).ct_eq(tag).into()
}

/// What an encrypted `Data` packet carries.
#[derive(Debug, PartialEq)]
pub enum ChatPayload {
    Text(String),
    Ping,
    Pong,
    Bye,
}

impl ChatPayload {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ChatPayload::Text(text) => {
                let mut out = Vec::with_capacity(1 + text.len());
                out.push(0);
                out.extend_from_slice(text.as_bytes());
                out
            }
            ChatPayload::Ping => vec![1],
            ChatPayload::Pong => vec![2],
            ChatPayload::Bye => vec![3],
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        match b {
            [0, text @ ..] => Some(ChatPayload::Text(
                std::str::from_utf8(text).ok()?.to_owned(),
            )),
            [1] => Some(ChatPayload::Ping),
            [2] => Some(ChatPayload::Pong),
            [3] => Some(ChatPayload::Bye),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 32] = [3; 32];

    #[test]
    fn packets_roundtrip() {
        for p in [
            probe(&K, [1; 12]),
            probe_ack(&K, [2; 12]),
            Packet::Hs1(b"abc"),
            Packet::Hs2(b"def"),
            Packet::Data {
                nonce: 7,
                ciphertext: b"xyz",
            },
        ] {
            assert_eq!(Packet::decode(&p.encode()), Some(p));
        }
    }

    #[test]
    fn rejects_stun_junk_and_bad_lengths() {
        let stun = crate::stun::build_binding_request(&[0; 12]);
        assert_eq!(Packet::decode(&stun), None);
        assert_eq!(Packet::decode(&[]), None);
        assert_eq!(Packet::decode(&[T_PROBE, 1, 2]), None);
        assert_eq!(Packet::decode(&[T_DATA, 0, 0]), None);
    }

    #[test]
    fn decode_never_panics_and_probe_length_is_exact() {
        for kind in [T_PROBE, T_PROBE_ACK, T_HS1, T_HS2, T_DATA, 0xA0, 0xFF] {
            for len in 0..40 {
                let mut buf = vec![0u8; len];
                if let Some(first) = buf.first_mut() {
                    *first = kind;
                }
                let decoded = Packet::decode(&buf);
                let is_probe = kind == T_PROBE || kind == T_PROBE_ACK;
                assert_eq!(is_probe && decoded.is_some(), is_probe && len == 29);
            }
        }
    }

    #[test]
    fn probe_tags_are_keyed_and_typed() {
        let p = probe(&K, [1; 12]);
        assert!(verify(&K, &p));
        assert!(!verify(&[4; 32], &p));
        let Packet::Probe { txid, tag } = p else {
            unreachable!()
        };
        assert!(!verify(&K, &Packet::ProbeAck { txid, tag }));
    }

    #[test]
    fn chat_payload_roundtrip_and_invalid_utf8() {
        for p in [
            ChatPayload::Text("olá".into()),
            ChatPayload::Ping,
            ChatPayload::Pong,
            ChatPayload::Bye,
        ] {
            assert_eq!(ChatPayload::decode(&p.encode()), Some(p));
        }
        assert_eq!(ChatPayload::decode(&[0, 0xFF, 0xFE]), None);
    }

    #[test]
    fn max_text_fits_one_datagram() {
        let text = "a".repeat(crate::session::MAX_MESSAGE_LEN);
        let plain = ChatPayload::Text(text).encode();
        let ct = vec![0u8; plain.len() + 16]; // tag do ChaChaPoly
        assert!(
            Packet::Data {
                nonce: u64::MAX,
                ciphertext: &ct
            }
            .encode()
            .len()
                <= MAX_DATAGRAM
        );
    }
}
