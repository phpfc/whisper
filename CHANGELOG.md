# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Session code v3: `base58(3 || secret[16] || direct addresses)`, a 128-bit secret and up to
  three direct addresses (router port, IPv6, LAN). About 69 characters at most. **Not
  compatible with 0.2 codes**
- Connection by candidates: LAN, IPv6, router-mapped, STUN-reflexive and peer-reflexive
  addresses. Both peers probe all of them at once, and the first path that completes the
  handshake carries the chat, so whoever can be reached becomes the host automatically
- Automatic router port opening through UPnP, NAT-PMP and PCP, announced as
  `UDP port N opened on your router (closed on exit)` and removed on exit (Esc, Ctrl-C or
  end of session)
- Candidate exchange over the public BitTorrent Mainline DHT, as encrypted BEP44 records, for
  hole punching between two NATs. No server run by the project
- Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s` handshake, with a 64-packet anti-replay window and
  a session fingerprint shown on both sides
- Authenticated connectivity probes, so the open port is not a reflector
- `whisper doctor`, which reports IPv6, router port mapping, CGNAT, NAT mapping type and DHT
  reachability
- Connection failures now say why, for both sides, instead of a generic timeout
- A joiner using an expired code gets `This session code has expired. Ask your peer for a
  new one.`

### Changed
- The password (`-p`) is optional. If used, both peers must pass the same one. It now takes
  part in the key (Argon2id), where before it was never used by the key exchange
- Messages are limited to 1000 bytes
- `README.md` and `ARCHITECTURE.md` describe the zero-infrastructure model
- `SECURITY.md` rewritten for the current protocol

### Removed
- One-sided hole punching and the unauthenticated X25519 key exchange
- `P2P_TROUBLESHOOTING.md`, `RELAYS.md` and `DEPLOY.md`, which described the relay model

## [0.1.0] - 2026-03-06

### Added
- Initial release of t-chat
- End-to-end encryption using ChaCha20-Poly1305
- X25519 key exchange for secure communication
- Embedded relay server with automatic startup
- STUN-based public IP discovery
- UPnP automatic port forwarding
- Session-based chat with password protection
- Terminal UI using Ratatui
- Three modes: Create, Join, Server
- Session code format: `session_id@relay_address`
- Automatic fallback to embedded relay when no public relays available
- SHA-256 password hashing
- Zero-configuration setup

### Security Notes
- See SECURITY.md for known vulnerabilities and recommendations
- Suitable for casual use between friends
- NOT recommended for adversarial environments without implementing security improvements

[0.1.0]: https://github.com/phpfc/t-chat/releases/tag/v0.1.0
