# Whisper

Secure P2P terminal chat. One code, no servers, no network setup.

## Features

- **Direct P2P**: your messages go straight to your peer over UDP, never through a relay
- **E2E encrypted**: Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s`, keyed by the session code
- **Zero infrastructure cost**: no server is run or paid for by this project. It only uses public STUN servers and the BitTorrent DHT
- **Zero config**: no port forwarding, no server deployment. If your router supports it, whisper opens a port for you and tells you
- **Ephemeral**: messages exist only in transit, never stored

## Installation

> Use 0.3.0 or newer on both sides. Releases up to 0.2.x predate the connection
> model described below, and their session codes are not compatible with it.

### Homebrew (macOS)
```bash
brew tap phpfc/whisper
brew install whisper
```

### Windows
Download from [Releases](https://github.com/phpfc/whisper/releases), extract, and run `whisper.exe`.

Or via PowerShell:
```powershell
Invoke-WebRequest -Uri "https://github.com/phpfc/whisper/releases/download/v0.3.0/whisper-0.3.0-x86_64-pc-windows-msvc.zip" -OutFile whisper.zip
Expand-Archive whisper.zip -DestinationPath C:\whisper -Force
C:\whisper\whisper.exe doctor
```

### Build from Source
```bash
cargo install --git https://github.com/phpfc/whisper
```

Building needs Rust 1.89 or newer (`rustup update stable`).

## Usage

### Create a session
```bash
whisper create -u alice
```

Output:
```
Gathering network info...
UDP port 54321 opened on your router (closed on exit)

========================================
SESSION CODE:

  4kE7Ytq0OIlXw9RbMz3NfVcH8pJs2LgAeQd5Ku6nTW1yBo0OIlCrmZxS7vGh4iDaFj9P   (example; yours will differ)

Share this code with your peer.
========================================

Waiting for your peer to join... (Ctrl-C to cancel)
```

The `UDP port ... opened` line only appears if your router granted a port. Send the code to
your peer over any channel (WhatsApp, SMS, email). The creator waits up to 10 minutes for
someone to join. If a peer shows up but no direct path is possible, it says why within about
45 seconds.

### Join a session
```bash
whisper join "<code>" -u bob
```

Once the connection is up, each side sees something like this:
```
Connected to alice via mapped
Session fingerprint: 3F9A0C11 52B7E4D8 9A01C6F2 7D3E84B5 (should match your peer's)
```

`via` is the kind of path that worked (`lan`, `ipv6`, `mapped`, `reflexive` or
`peer-reflexive`). Compare the fingerprint with your peer over another channel if
you want to be sure nobody else is on the line. Press Esc or Ctrl-C to leave the chat.
Messages are at most 1000 bytes.

### Optional password

The code already carries a 128-bit secret, so a password is optional. Use one as extra
protection, for example if the code might be seen by someone else, and send it over a
different channel. If one side uses a password, **both** must pass the same one:

```bash
whisper create -u alice -p mysecret
whisper join "<code>" -u bob -p mysecret
```

A wrong password fails with `wrong password or invalid code`. A code that is cut short or
mistyped is rejected at once with `Invalid session code...`: the code ends in a checksum that
catches typos (all but about one in 65,000). A well-formed code with a different secret, such
as one from an older session, finds nobody to answer, and after about a minute the joiner
ends with `The other peer never showed up...`. Quotes around the code, typographic ones
included, and invisible characters that chat apps add when copying are ignored.

### Check your network
```bash
whisper doctor
```

Tells you whether this network can host sessions or join them, without connecting to anyone.
Example (addresses are masked):

```
Global IPv6:   yes (2804:14c:…)
Router:        no port mapping protocol found
CGNAT:         unknown
NAT mapping:   endpoint-independent (good for hole punching)
DHT:           reachable (3.5 s)
Verdict:       can likely reach peers that have IPv6
```

| Line | Meaning |
|------|---------|
| Global IPv6 | This machine has a public IPv6 address (no NAT in the way) |
| Router | Which of UPnP, NAT-PMP and PCP the router answers to; any of them lets whisper open a port |
| CGNAT | Whether your ISP shares one public IPv4 address among many customers |
| NAT mapping | `endpoint-independent` works for hole punching; `symmetric` generally does not |
| DHT | Whether the BitTorrent DHT is reachable, and how long it took to bootstrap |
| Verdict | One line: `can host sessions`, `can likely reach peers that have IPv6`, `cannot host; hole punching likely works` or `direct connections unlikely from this network` |

Doctor says so before it opens a router port to test it, and closes it again before exiting.
When a connection fails, the error message says what is wrong with each side and points here.

## How It Works

Each peer gathers **candidates**, the addresses where it might be reached. Both peers then
probe all of the other's candidates at once, in both directions. Among the paths that answer,
the joiner prefers the one with the highest priority (`lan`, then `ipv6`, `mapped`,
`reflexive`, `peer-reflexive`) and runs the encrypted handshake on it. Nobody is "the
server": whoever has a reachable address ends up being the one the other connects to. These
are the ways it can connect, from simplest to most involved. They are all tried at the same
time, not one after the other:

1. **LAN or IPv6.** Peers on the same network, or with public IPv6 addresses, connect with
   no NAT in the way.
2. **A port on your router.** whisper asks your router for a port through UPnP, NAT-PMP or
   PCP and prints `UDP port N opened on your router (closed on exit)`. That address goes
   inside the session code (along with your IPv6 and LAN addresses, if you have them), so
   your peer can connect right away. The port is removed when you leave (Esc, Ctrl-C or
   the end of the session). The router's lease is 2 hours, so if the process is killed the
   mapping lingers until it expires, pointing at a closed port. A second Ctrl-C while the
   port is being released quits at once and leaves it to expire the same way.
3. **Hole punching through the DHT.** Each peer publishes its candidates as an encrypted
   record on the public BitTorrent Mainline DHT, and reads the other's. Knowing where the
   other is, both send packets at the same time, which opens a path through both NATs.
4. **An explained failure.** If nothing works, the error says why for each side (CGNAT,
   symmetric NAT, no IPv6...) instead of hanging or falling back to something broken.

```
  Alice (creator)                                       Bob (joiner)
  gather candidates                                     read code
  open router port (maybe)                              gather candidates
  show code ───────────── you send it ────────────────> try the code's addresses
  publish record ──┐                                ┌── publish record
                   └──────── BitTorrent DHT ────────┘
  read Bob's record                                     read Alice's record
        └── both probe every candidate every 200 ms ──┘
        best path that answers + valid handshake = chat
```

Probes and the handshake are authenticated with keys derived from the code, so packets from
anyone who does not have it are dropped without an answer. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the details and [SECURITY.md](SECURITY.md) for the
threat model.

### Windows firewall

The first time you run whisper on Windows, the firewall asks whether to allow it. **Also
tick "Public networks"**: Windows treats new networks as Public, and only Private is ticked
by default. Without it, a peer cannot reach you directly through the address in the code, so
the connection waits for the DHT round and can take up to about 20 seconds instead of a few.
macOS and most Linux desktops need nothing.

## What Third Parties See

| Who | What they see |
|-----|---------------|
| STUN servers (Google, Cloudflare) | Your public IP address. Not the code, not your messages |
| BitTorrent DHT nodes | An encrypted blob, plus the IP of whoever publishes or looks it up. Without the code the record cannot be looked up or read |
| Your peer | Your public IP (any direct connection needs it), the other addresses you advertise (LAN, IPv6) and your username |
| Your messages | Only you and your peer. No server, STUN server or DHT node ever sees them |

## Security

| Component | Implementation |
|-----------|---------------|
| Handshake | Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s` |
| Pre-shared key | Derived from the code's 128-bit secret and Argon2id(password) |
| Transport | ChaCha20-Poly1305 with explicit nonces and a 64-packet anti-replay window |
| DHT records | ChaCha20-Poly1305, key derived from the code |
| Probes | HMAC-tagged; unauthenticated packets get no reply |

More in [SECURITY.md](SECURITY.md).

## Limitations

- **Symmetric NAT on both sides**: if both peers are behind symmetric NAT and neither has
  IPv6 or a router port, no direct path exists, and without a relay they cannot connect.
  The error tells you so. Try another network, such as Wi-Fi instead of mobile data.
- **Codes expire**: the creator stops waiting after 10 minutes. A joiner using an old code
  gets `This session code has expired. Ask your peer for a new one.` about 10 seconds
  later.
- **Both online**: both peers must be online at the same time.
- **1-to-1 only**: two participants per session.
- **Messages are at most 1000 bytes.**
- **UDP only**: networks that block UDP cannot be used. When no STUN server and no DHT node
  answers, the error says that UDP seems blocked.
- **Code format**: session codes changed and are not compatible with 0.2.

## License

MIT
