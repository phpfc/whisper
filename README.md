# Whisper

Secure P2P terminal chat. Zero config, no servers needed.

## Features

- **True P2P**: Direct connection via UDP hole punching - no relay servers
- **E2E Encrypted**: X25519 key exchange + ChaCha20-Poly1305
- **Zero Config**: No router setup, no server deployment, just run it
- **Ephemeral**: Messages exist only in transit, never stored

## Installation

### Homebrew (macOS)
```bash
brew tap phpfc/whisper
brew install whisper
```

### Windows
Download from [Releases](https://github.com/phpfc/whisper/releases), extract, and run `whisper.exe`.

Or via PowerShell:
```powershell
Invoke-WebRequest -Uri "https://github.com/phpfc/whisper/releases/download/v0.2.1/whisper-0.2.1-x86_64-pc-windows-msvc.zip" -OutFile whisper.zip
Expand-Archive whisper.zip -DestinationPath C:\whisper
C:\whisper\whisper.exe --help
```

### Build from Source
```bash
cargo install --git https://github.com/phpfc/whisper
```

## Usage

### Create a session
```bash
whisper create -u alice -p mysecret
```

Output:
```
Discovering public endpoint via STUN...
Your endpoint: 203.45.67.89:54321

Share this session code with your peer:
203.45.67.89:54321#7kJ9xnYpQm#QgT98sXCthe3

Waiting for peer to connect...
```

### Join a session
```bash
whisper join "203.45.67.89:54321#7kJ9xnYpQm#QgT98sXCthe3" -u bob -p mysecret
```

That's it. You're chatting with E2E encryption.

## How It Works

```
┌─────────┐                              ┌─────────┐
│  Alice  │                              │   Bob   │
└────┬────┘                              └────┬────┘
     │ 1. STUN query                          │
     ▼                                        ▼
┌─────────┐                              ┌─────────┐
│ Google  │                              │ Google  │
│  STUN   │                              │  STUN   │
└─────────┘                              └─────────┘
     │ 2. Get public IP:port                  │
     ▼                                        ▼
┌─────────┐  3. Share code out-of-band   ┌─────────┐
│  Alice  │ ◄──────────────────────────► │   Bob   │
└────┬────┘                              └────┬────┘
     │                                        │
     │  4. UDP hole punch + key exchange      │
     │◄══════════════════════════════════════►│
     │       5. Encrypted P2P chat            │
     └────────────────────────────────────────┘
```

1. Both peers query STUN servers to discover their public IP:port
2. Alice generates a session code containing her endpoint + session ID + salt
3. Bob receives the code (via any channel - SMS, email, etc.)
4. Both send UDP packets to punch through NAT, then exchange X25519 keys
5. Direct encrypted chat begins

## Security

| Component | Implementation |
|-----------|---------------|
| Key Exchange | X25519 ECDH |
| Encryption | ChaCha20-Poly1305 |
| Password KDF | Argon2id |
| Nonce | Counter-based (no collision) |

**What STUN servers see**: Your public IP (required for NAT traversal)
**What STUN servers DON'T see**: Session codes, messages, passwords, keys

## Limitations

- **Symmetric NAT**: ~15-20% of corporate/carrier-grade NAT won't work. The connection will fail explicitly.
- **Both online**: Unlike relay-based chat, both peers must be online simultaneously.
- **1-to-1 only**: Currently supports two participants per session.

These are architectural tradeoffs for true P2P with zero infrastructure.

## License

MIT
