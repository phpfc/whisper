# Whisper Architecture

## Core Principle

**Zero infrastructure cost.** If the project has to host, maintain or pay for a server, it's a bug.

Free public services that nobody on the project operates are fine: the STUN servers of
Google and Cloudflare, and the BitTorrent Mainline DHT. Relaying chat data is not, even
through a free service.

The full design and its rationale are in
[docs/superpowers/specs/2026-11-20-p2p-sem-infra-design.md](docs/superpowers/specs/2026-11-20-p2p-sem-infra-design.md)
(written in Portuguese). This file describes what the code does.

## Design Constraints

### MUST

1. **Work with no server of ours** - Users run the binary, it works
2. **Use only public, free infrastructure** - STUN (Google, Cloudflare) and the default
   Mainline DHT bootstrap nodes. We don't control them and don't pay for them
3. **Carry all chat traffic directly between the peers**
4. **End-to-end encryption, authenticated by the session code** - No intermediary can read
   messages, and nobody without the code can complete a handshake
5. **Fail explicitly** - If no direct path exists, say why. Never fall back to localhost or
   a broken state
6. **Show what it does to the network** - Opening a router port is announced, and the port
   is closed on exit

### MUST NOT

1. **Use a relay or TURN** - Not ours, not public, not user-hosted
2. **Ship an account key** - No paid-service credentials in the binary
3. **Require manual network setup** - No port forwarding, no firewall rules, no IP addresses
   to configure
4. **Leave a port open** - The router mapping is removed on every normal exit, and a
   permanent mapping is never created
5. **Fall back to local-only mode** - It hides the failure and confuses users

### MAY

1. **Use STUN and the DHT** - STUN to learn the public address and the type of NAT, the DHT
   to exchange encrypted candidates
2. **Open a router port by itself** - Through UPnP, NAT-PMP or PCP, with a notice
3. **Fail when both peers are behind symmetric NAT** (and neither has IPv6 or a router
   port) - That case needs a relay, which is out of bounds

---

## Overview

Each peer gathers **candidates**: addresses where it might be reached. The creator puts a
few in the session code and publishes all of them, encrypted, on the DHT. The joiner
publishes its own on the DHT. Both then probe every candidate of the other at the same time.
Among the paths that answer, the joiner takes the one with the highest priority and runs the
Noise handshake on it; that path carries the chat.

"Host" is not a negotiated role. It is whichever side has an address the other can reach.
The roles that exist are only *creator* (the one who made the code, the Noise responder)
and *joiner* (the one who used it, the Noise initiator).

```
 creator                                                joiner
 gather candidates ─┐                           ┌─ decode code, gather candidates
 show code ─────────┼──── out of band (chat) ───┼─> probe the code's addresses at once
 publish "c" ───────┤                           ├── publish "j"
 read "j" ──────────┘      BitTorrent DHT        └── read "c"
        └─── both probe every candidate every 200 ms (hole punching) ───┘
            best path that answers + valid handshake = chat
```

### Connection ladder

These are not tried one after the other: every candidate is probed at once, and the order
below is only the priority among the paths that answer.

1. **LAN / IPv6**: private IPv4 or global IPv6 addresses on the machine's interfaces
2. **Router port**: opened through UPnP, NAT-PMP or PCP, advertised as `mapped`
3. **Hole punching**: simultaneous probes to the candidates exchanged over the DHT,
   including the address STUN reported (`reflexive`)
4. **Explained failure**: `No direct path. You: ... Other peer: ...`

### Modules

| Module | Role |
|--------|------|
| `main.rs` | `create`, `join` and `doctor`; wires the steps together and releases the router port on every way out |
| `gather.rs` | Binds the UDP sockets and collects candidates, the router mapping and the NAT diagnosis |
| `candidates.rs` | Candidate kinds and priority, address classification (public, private, CGNAT), CGNAT detection |
| `portmap.rs` | Router port mapping (UPnP / NAT-PMP / PCP) through the `portmapper` crate |
| `stun.rs` | Hand-written async STUN client; tells whether the NAT mapping depends on the destination |
| `code.rs` | Session code v3 |
| `keys.rs` | Session secret, per-purpose key derivation, PSK derivation |
| `signal.rs` | Encrypted BEP44 records on the Mainline DHT (`mainline` crate) |
| `connect.rs` | Probing, path selection, handshake, timeouts |
| `wire.rs` | Binary packet format |
| `crypto/` | Noise handshake (`snow` crate), transport and replay window, session fingerprint |
| `cli/` | The ratatui chat UI and the keepalive |
| `doctor.rs` | `whisper doctor` and the failure explanations |
| `cancel.rs` | Ctrl-C handling, so a router mapping is released even if you cancel early |

---

## Session Code (v3)

```
base58( 3 || secret[16] || n || n * address || check[2] )     n <= 3
address = 4 || ipv4[4] || port[2]  |  6 || ipv6[16] || port[2]
check   = first 2 bytes of SHA-256 over everything before it
```

- `secret`: 128 random bits. Everything else is derived from it (see Cryptography)
- `address`: the direct candidates, those that work without signaling: the router-mapped
  address and, if present, one IPv6 and one LAN address, in that order. They let the joiner
  connect at once, before the DHT answers
- `check`: catches a mistyped or cut-off code at once, with `Invalid session code...`
  (a typo slips through about once in 65,536)
- Length: 27 characters with no addresses, 72 with all three
- The leading `3` is the format version. Codes from 0.2 (`ip:port#id#salt`) are rejected
  with a message saying so
- Decoding ignores whitespace and zero-width characters anywhere, and straight or
  typographic quotes around the code

Example (yours will differ; this one does not decode):
`4kE7Ytq0OIlXw9RbMz3NfVcH8pJs2LgAeQd5Ku6nTW1yBo0OIlCrmZxS7vGh4iDaFj9P`

## Candidates

Two UDP sockets are bound: IPv4 on `0.0.0.0:0` and, if the machine has a global IPv6
address, IPv6 on the address the OS would send from (found by connecting a UDP socket to a
public address, which sends nothing). Bound like that, everything leaves from the address we
advertise, so the peer's stateful firewall lets the replies in. If that bind fails, the IPv6
socket goes on `[::]:0`. The same socket is used for STUN, for the port mapping and for the
chat, so the NAT mappings learned along the way are the ones the chat uses.

| Kind | Source | Priority |
|------|--------|----------|
| `lan` | Private IPv4 on an interface (never CGNAT space, so VPN addresses stay out) | 5 |
| `ipv6` | The global IPv6 (2000::/3) the socket is bound to; with `[::]`, up to 3 from the interfaces | 4 |
| `mapped` | Router-mapped external address, only if it is public | 3 |
| `reflexive` | Address STUN saw | 2 |
| `peer-reflexive` | Source of a valid probe from an address we did not know | 1 |

A `mapped` address that is private, in 100.64.0.0/10 or in a reserved range (DS-Lite's
192.0.0.0/29, documentation and benchmark ranges, multicast, 240/4) means another NAT
upstream. It is dropped, and the mapping is closed again right away instead of being left on
the router.
At most 16 candidates are taken from the code and the peer's records. When a valid probe
arrives from an unknown address (the other NAT picked a new port), we answer it and it
becomes a candidate, up to 4 of them.

## Router Port Mapping

- The `portmapper` crate asks for the local UDP port of the IPv4 socket through UPnP, PCP
  and NAT-PMP, whichever the router speaks, and renews it
- Shown as `UDP port {port} opened on your router (closed on exit)`
- Removed on Esc, on Ctrl-C and at the end of the session. If the process is killed, the
  mapping stays until the router's lease runs out. The crate fixes the lease at 2 hours and
  it points at a port where nothing listens
- A router that only accepts permanent leases gets no mapping, and the DHT path covers it
- No protocol needs administrator rights

## DHT Signaling

- Each peer publishes one BEP44 mutable item. Both sign with the same Ed25519 key, derived
  from the secret, so no key is exchanged. The salt tells them apart: `c` for the creator,
  `j` for the joiner
- Value: `nonce(12) || ChaCha20-Poly1305(JSON) || tag(16)`, at most 1000 bytes. The JSON is
  the candidates (best 8), a network summary (IPv6, mapped port, CGNAT, NAT type) and the
  publication time, which doubles as the BEP44 sequence number
- Both sides poll the other's item every 3 s. The initial publish is tried 3 times, 5 s
  apart. If it fails, polling goes on
- A joiner that reads a creator record older than 11 minutes (10 min wait plus 1 min of
  margin) treats it as a hint that the creator gave up. It still probes, in case its own
  clock is the one that is off, and reports `This session code has expired. Ask your peer
  for a new one.` 10 s later if nothing answers
- Records are not deleted on exit. They expire on their own and are unreadable without the
  code
- If the DHT cannot be started, a joiner whose code has direct addresses carries on with
  those, and says so. Without any it stops at once
- Once the node runs, a background check (10 s at most) tells whether it bootstraps; nothing
  waits for it. A joiner whose code has no direct address stops as soon as that check fails
  and no STUN server answered either: UDP is blocked and nobody can be found. Otherwise a
  connection that fails says, at the end, that the DHT is unreachable or that UDP seems
  blocked
- The DHT client binds a port the system picks, not the usual 6881

## Connectivity Checks

All packets start with a type byte of `0xA1` or more, so they are never mistaken for STUN
on the shared socket (STUN starts with `0x00`..`0x3F`).

| Packet | Format |
|--------|--------|
| `Probe`, `ProbeAck` | `[type][txid 12][tag 16]`, the tag an HMAC-SHA256 under the probe key |
| `Hs1`, `Hs2` | `[type][Noise handshake message]` |
| `Data` | `[type][nonce u64][ChaCha20-Poly1305 ciphertext]` |

- Every 200 ms each side sends a `Probe` to every remote candidate. A valid `Probe` is
  answered with one `ProbeAck` to the packet's source address (never to port 0, broadcast or
  multicast). A replayed probe is still answered once but teaches no address
- Anything that does not parse, fails the tag check or fails Noise is dropped without a
  reply: no amplification, and no reply to unauthenticated packets, so the open port does
  not answer scans for whisper
- The joiner waits 300 ms after the first confirmed address, takes the confirmed one with
  the highest priority and sends `Hs1` there (resent every 500 ms). The creator answers with
  `Hs2`, and resends that same `Hs2` only to the address the `Hs1` came from. The joiner then
  sends `Ping`s, and the first one the creator can open completes the session

## Cryptography

| Item | How it's built |
|------|----------------|
| Derived keys | HKDF-SHA256 over the 128-bit secret, one label per use: DHT signing seed, record key, probe key, Argon2 salt, PSK base |
| PSK | `HKDF(psk_base \|\| Argon2id(password, salt))`. With no password, Argon2id gets an empty one |
| Handshake | `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`, no static keys: authentication comes from the PSK |
| Transport | ChaCha20-Poly1305 with an explicit nonce per packet |
| Replay | 64-packet sliding window, as in WireGuard |
| Fingerprint | First 16 bytes of the handshake hash, shown on both sides |

A wrong password fails the handshake and shows `wrong password or invalid code`. A
mistyped code never gets that far: its checksum fails. A well-formed code with another
secret (from another session, say) does not either: its probes carry a tag that does not
verify, so nobody answers and no handshake starts. Messages are at most 1000 bytes, so a datagram stays
under 1200 bytes and is never fragmented.

## Timeouts

| What | Value |
|------|-------|
| Probe interval | 200 ms |
| Creator waits for a peer | 10 min |
| Joiner gives up after the creator's candidates arrive | 45 s |
| Creator gives up after the joiner's candidates arrive, if nothing from the joiner got through | 45 s after the latest record |
| Joiner gives up if the creator's candidates never arrive | 60 s |
| STUN step, all servers together | 6 s at most |
| DHT bootstrap check | 10 s at most, in the background |
| Wrong password reported | 5 s after the first handshake message |
| Keepalive | 15 s |
| "Connection lost" shown | 45 s without a valid packet |

---

## Failure Modes

### Expected (handled with a message)

| Scenario | Behavior |
|----------|----------|
| No one joins | After 10 min: `No one joined within 10 minutes. Create a new session to try again.` If the DHT never bootstrapped, the message says the DHT is unreachable or that UDP seems blocked instead |
| Joiner gets through but cannot finish (wrong password) | The creator keeps waiting its 10 min for a joiner with the right password, and warns once |
| Wrong password | `wrong password or invalid code`, 5 s after the first handshake message |
| Code from 0.2 | Says it is from an older version and to ask for a new one |
| Code cut short or mistyped | `Invalid session code. Check that you copied all of it...` at once: the checksum catches it (a typo slips through about once in 65,536) |
| Old code | `This session code has expired. Ask your peer for a new one.` |
| No direct path | `No direct path. You: ... Other peer: ...`, naming symmetric NAT, CGNAT or "cannot host" for each side, and pointing to `whisper doctor` |
| Other peer never seen | After 60 s with no record from the creator: `The other peer never showed up. Check that the code is complete and that they are still waiting...`. Also what a well-formed code from another session ends in |
| DHT unreachable | With a direct address in the code, only direct connections are tried, and a failure says the DHT is unreachable (or UDP seems blocked) instead of "never showed up". Without one, the joiner stops and says why: at once if the DHT cannot start, within about 10 s if neither a DHT node nor a STUN server answers |
| Peer goes silent | `Connection to X lost.` in the chat |

### Unacceptable (never do this)

| Anti-pattern | Why it's wrong |
|--------------|----------------|
| Fallback to localhost | Hides the failure, doesn't work |
| Silent port mapping, or one that outlives the app | The user must know what was done to the router |
| Suggest deploying a relay | Violates the zero-infrastructure principle |
| Hardcoded account keys | A shared key in the binary gets abused and revoked |

---

## Public Infrastructure

STUN servers. `stun.l.google.com` and `stun.cloudflare.com`, two operators, are asked from
the same socket: the same external address from both means the NAT mapping does not depend
on the destination (hole punching works), different addresses mean symmetric NAT. If
neither answers, the others are tried just to learn the address. The whole step takes 6 s at
most:

```
stun.l.google.com:19302
stun1.l.google.com:19302
stun2.l.google.com:19302
stun3.l.google.com:19302
stun4.l.google.com:19302
stun.cloudflare.com:3478
```

DHT: the default Mainline bootstrap nodes of the `mainline` crate, used as a client.

---

## Limitations (Documented, Not Hidden)

1. **Symmetric NAT on both sides**, when neither side has IPv6 or a router port: no direct
   path exists. The error says so
2. **Both peers online**: they must be online at the same time. This is inherent to P2P
3. **UDP only**: some networks block it. We fail explicitly, and say that UDP seems blocked
4. **Single peer**: 1-to-1 chat. Groups would need a different design
5. **No long-term identity**: the code (and password) is the only credential. See
   [SECURITY.md](SECURITY.md)

## Non-Goals

Group chat, offline messages, mobile apps, symmetric-on-both-sides NAT traversal (port
prediction and the like), and compatibility with 0.2 codes.
