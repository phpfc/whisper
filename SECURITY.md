# Security

whisper is a 1-to-1 terminal chat. Two people share a session code over some channel, and
their machines connect directly. This file says what that protects, what it gives away, and
where it stops. The mechanics are in [ARCHITECTURE.md](ARCHITECTURE.md).

## Threat model

Considered:

- Someone watching or tampering with the network path: reading, injecting, replaying
- Curious operators of the public services used: STUN servers and BitTorrent DHT nodes
- Strangers scanning the internet for open UDP ports

Not considered: a compromised computer (it sees everything you do), an attacker who can
already read the channel you sent the code through (see Known limits), and a global
adversary correlating traffic across the whole network.

## What is protected

- **Messages**: confidential and authenticated end to end. The handshake is Noise
  `NNpsk0_25519_ChaChaPoly_BLAKE2s`, keyed by a pre-shared key built from the code's
  128-bit secret and, if you set one, Argon2id(password). Every session uses fresh X25519
  keys. No server, STUN server or DHT node sees a message
- **Replay**: every packet carries a nonce, and a 64-packet window drops duplicates and
  anything too old
- **Probes**: connectivity probes carry an HMAC tag derived from the code. Packets without a
  valid tag get no reply, so the open port is not a reflector and does not answer scans
- **DHT records**: encrypted with ChaCha20-Poly1305 under a key derived from the code, and
  signed with a key derived from it too. Without the code they can be neither found nor read
- **Wrong password or code**: the handshake fails and you get `wrong password or invalid
  code`
- **Router port**: opened only while whisper runs and closed on exit. If the process is
  killed, the router drops it when its 2-hour lease ends, and nothing listens on it meanwhile

## What leaks

- **STUN servers (Google, Cloudflare)**: your public IP and port, whenever you create, join
  or run `whisper doctor`. Not the code, not messages
- **DHT nodes**: an encrypted blob and the IP of whoever publishes or reads it. A node that
  stores the record can see that two IPs touched the same key at about the same time, a hint
  that two people are talking, but not who they are or what they say. Records are not
  deleted on exit; they expire by themselves
- **Your peer**: your public IP (a direct connection needs it), the LAN and IPv6 addresses
  you advertise, a network summary (IPv6, port mapping, CGNAT, NAT type) and your username.
  Only share a code with someone you would give your IP to
- **Anyone on your network path**: that you exchange UDP with your peer's IP, and the
  timing and size of the packets, including a keepalive every 15 s. Encryption does not hide
  message length

## Known limits

- **No long-term identity keys.** The code, plus the password if there is one, is the only
  credential. Whoever has both can join as your peer, and the creator accepts the first
  handshake that completes
- **A leaked code is enough to join** when no password was set. If the code may have been
  seen by someone else, use a password and send it through a different channel
- **Compare the session fingerprint.** It is shown on both sides and must match. If
  someone who holds the code sits in the middle, the two sides will see different ones.
  whisper cannot check this for you, so do it over another channel
- **Passwords can be guessed offline** by someone who has the code and recorded a handshake,
  slowed by Argon2id. Pick a long one
- **Your own machine**: whisper keeps no history, but your terminal's scrollback may
- **Not audited**: the code has not been independently reviewed. Use it for conversations
  between people who trust each other, not as a hardened system

## Reporting a problem

Open an issue at <https://github.com/phpfc/whisper/issues>. If it could put users at risk,
leave out the exploit details and ask for a private way to send them, or use GitHub's
private vulnerability reporting on the repository if it is enabled. Only the latest release
is supported.
