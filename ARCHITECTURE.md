# t-chat Architecture

## Core Principle

**Zero infrastructure dependency.** If it requires deploying a server, it's a bug.

## Design Constraints

### MUST

1. **Work without any server deployment** - Users run the binary, it works
2. **Use only publicly available infrastructure** - STUN servers (Google, Cloudflare) are acceptable because they're free, always available, and we don't control them
3. **Establish direct P2P connections** - All chat traffic flows directly between peers
4. **End-to-end encryption** - No intermediary can read messages
5. **Fail explicitly** - If P2P connection cannot be established, fail with clear error. Never fallback to localhost or broken state

### MUST NOT

1. **Depend on relay servers we control** - No "public relay" lists, no deploy instructions
2. **Require router configuration** - No manual port forwarding
3. **Require technical knowledge** - No IP addresses to configure, no server setup
4. **Fallback to local-only mode** - This hides the failure and confuses users

### MAY

1. **Use STUN servers** - For public IP discovery (Google, Cloudflare - always available)
2. **Fail on symmetric NAT** - ~15-20% of corporate networks. Acceptable tradeoff.

---

## Architecture: UDP Hole Punching

### Overview

```
┌─────────┐                                    ┌─────────┐
│  Alice  │                                    │   Bob   │
└────┬────┘                                    └────┬────┘
     │                                              │
     │  1. STUN request                             │
     ▼                                              │
┌─────────────┐                              ┌─────────────┐
│ STUN Server │                              │ STUN Server │
│  (Google)   │                              │  (Google)   │
└─────────────┘                              └─────────────┘
     │                                              │
     │  2. Returns public IP:port                   │
     ▼                                              ▼
┌─────────┐                                    ┌─────────┐
│  Alice  │  3. Exchange addresses via         │   Bob   │
│         │     session code (out-of-band)     │         │
└────┬────┘                                    └────┬────┘
     │                                              │
     │  4. Both send UDP packets simultaneously    │
     │◄────────────────────────────────────────────►│
     │                                              │
     │  5. NAT hole punched, direct connection     │
     │◄════════════════════════════════════════════►│
     │           (encrypted P2P chat)              │
└─────────┘                                    └─────────┘
```

### Session Flow

#### Alice (Creator)

```bash
t-chat create -u alice -p secret123
```

1. Bind UDP socket to `0.0.0.0:<random_port>`
2. Query STUN to discover `<public_ip>:<mapped_port>`
3. Generate session ID and encryption salt
4. Display session code: `<public_ip>:<port>#<session_id>#<salt>`
5. Wait for incoming hole punch packets
6. On connection: perform key exchange, start chat

#### Bob (Joiner)

```bash
t-chat join <session_code> -u bob -p secret123
```

1. Parse session code → get Alice's `<ip>:<port>`, session ID, salt
2. Bind UDP socket to `0.0.0.0:<random_port>`
3. Query STUN to discover own `<public_ip>:<mapped_port>` (for bidirectional punch)
4. Send UDP packets to Alice's address (this punches hole in Bob's NAT)
5. Alice receives packet, replies (punches hole in Alice's NAT)
6. Connection established, perform key exchange, start chat

### Hole Punching Mechanism

```
Time    Alice's NAT                    Bob's NAT
─────────────────────────────────────────────────────
  0     [blocked]                      [blocked]

  1     Alice sends UDP to Bob:5000
        → NAT creates mapping
        → Alice:3000 ↔ external:4000
        [Bob's NAT drops packet - no mapping yet]

  2     Bob sends UDP to Alice:4000
        → NAT creates mapping
        → Bob:5000 ↔ external:6000
        → Packet reaches Alice! (mapping exists)

  3     Alice replies to Bob:6000
        → Packet reaches Bob! (mapping exists)

  4     [bidirectional communication established]
```

### Session Code Format

```
<ip>:<port>#<session_id>#<salt>

Example:
203.45.67.89:54321#7kJ9xnYpQm#QgT98sXCthe3FEB5
```

Components:
- `ip:port` - Alice's public endpoint (from STUN)
- `session_id` - Random identifier (base58, 128 bits)
- `salt` - Argon2 password salt (base58, 128 bits)

### Protocol Messages (UDP)

All messages are JSON + newline, encrypted after key exchange.

```rust
enum Message {
    // Hole punching phase
    Punch { session_id: String },
    PunchAck { session_id: String, public_key: Vec<u8> },

    // Key exchange
    KeyExchange { public_key: Vec<u8> },
    KeyExchangeAck { public_key: Vec<u8> },

    // Chat (encrypted payload)
    Chat { ciphertext: Vec<u8> },

    // Keepalive (maintains NAT mapping)
    Ping,
    Pong,
}
```

### NAT Keepalive

NAT mappings expire (typically 30-120 seconds). Send keepalive every 15 seconds:

```
Alice ──► Ping ──► Bob
Alice ◄── Pong ◄── Bob
```

### Encryption

Same as before:
- **Key Exchange**: X25519 ECDH
- **Cipher**: ChaCha20-Poly1305
- **Password**: Argon2id with session salt
- **Nonce**: Counter-based (no collision)

---

## Failure Modes

### Expected Failures (Handle Gracefully)

| Scenario | Behavior |
|----------|----------|
| STUN unreachable | Try multiple servers, fail after all exhausted |
| Symmetric NAT | Hole punch fails, show clear error |
| Peer offline | Timeout after 30s, show "peer not reachable" |
| Wrong password | Key exchange fails, show "authentication failed" |

### Unacceptable Failures (Never Do This)

| Anti-pattern | Why it's wrong |
|--------------|----------------|
| Fallback to localhost | Hides failure, doesn't work |
| Suggest manual port forward | Requires technical knowledge |
| Suggest deploying relay | Violates zero-infrastructure principle |

---

## STUN Servers (Public Infrastructure)

These are free, reliable, and we don't control them:

```
stun.l.google.com:19302
stun1.l.google.com:19302
stun2.l.google.com:19302
stun3.l.google.com:19302
stun4.l.google.com:19302
stun.cloudflare.com:3478
stun.stunprotocol.org:3478
```

---

## Limitations (Documented, Not Hidden)

1. **Symmetric NAT**: ~15-20% of corporate/carrier-grade NAT won't work. This is acceptable - we fail explicitly.

2. **Both peers online**: Unlike relay model, both must be online simultaneously. This is inherent to P2P.

3. **UDP only**: Some networks block UDP. Rare, but possible. Fail explicitly.

4. **Single peer**: Current design is 1-to-1 chat. Group chat would need mesh networking (future work).

---

## Future Considerations

### If we ever need relay-like functionality:

1. **User-hosted relays**: Users can optionally run `t-chat relay` on their own infrastructure
2. **DHT discovery**: Peers find each other via distributed hash table (like BitTorrent)
3. **TURN fallback**: As last resort, use public TURN servers (rare, for symmetric NAT)

But these are **optional enhancements**, not requirements. Core functionality MUST work P2P.
