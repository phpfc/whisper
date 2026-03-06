# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
