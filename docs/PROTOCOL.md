# peck Protocol Specification

**Version**: 1.0  
**Status**: Implemented (matches daemon.py + native-transport.js)

This document specifies the wire-level protocol for establishing a direct
P2P tunnel between a browser client and a peck daemon, using Nostr relays
as the signaling layer and WebRTC for the data channel.

The goal: a third-party implementation built from this spec (without reading
peck's source) should interoperate with the reference daemon.

---

## Overview

```
 ┌──────────┐                    Nostr Relays                   ┌──────────┐
 │ Browser  │ ◄──────── NIP-44 encrypted DMs ────────────────► │  Daemon   │
 │ (client) │   (announce → offer → answer → candidates)       │ (Python)  │
 │          │                                                   │           │
 │  WebRTC  │ ◄─────────── direct P2P DataChannel ───────────► │  aiortc   │
 │          │             (NAT hole punched)                    │           │
 └──────────┘                                                   └──────────┘
```

**Roles**:
- **Daemon** (server-side, Python): listens on Nostr relays for announce DMs,
  creates WebRTC offers, proxies HTTP requests from the DataChannel to local
  backends.
- **Client** (browser, JS): resolves the daemon's npub, sends announce DM,
  receives the offer, completes the WebRTC handshake, sends HTTP requests
  over the DataChannel.

**Design constraints**:
- No TURN relay — pure hole-punching. If both peers are behind symmetric NAT,
  the connection fails (relay mode `--relay-mode` is an optional fallback).
- No direct TCP between peers before WebRTC is established — all signaling
  flows through Nostr relays as NIP-44 v2 encrypted DMs.

---

## Transport Layers

### Layer 1: Nostr (Signaling)

All signaling messages are **NIP-44 v2 encrypted Direct Messages** — Nostr
`kind=4` events with NIP-44 encrypted `content`.

Both sides generate **ephemeral Nostr keypairs** (secp256k1 / BIP-340
Schnorr). The daemon's pubkey is published via dns2nostr DNS TXT records or
passed directly in the URL.

**Event structure** (standard NIP-01 event, kind=4):
```json
{
  "kind": 4,
  "pubkey": "<sender_xonly_pubkey_hex>",
  "created_at": 1786000000,
  "tags": [["p", "<recipient_xonly_pubkey_hex>"]],
  "content": "<nip44_v2_ciphertext_base64>",
  "id": "<sha256_event_id_hex>",
  "sig": "<bip340_schnorr_sig_hex>"
}
```

**Event ID** is computed per NIP-01:
```
sha256( JSON.stringify([0, pubkey, created_at, kind, tags, content]) )
```

**Signature** is BIP-340 Schnorr over the event ID.

**Relay subscription filter**:
```json
["REQ", "<subscription_id>", {"kinds": [4], "#p": ["<own_pubkey>"]}]
```

### Layer 2: WebRTC DataChannel (Data)

Once the WebRTC handshake completes, the DataChannel carries the **peck
binary stream protocol** (multiplexed HTTP — see below). The DataChannel is
`ordered: true` (reliable mode).

---

## Message Types

All signaling messages are JSON objects, encrypted as the `content` field of
a NIP-44 DM.

### 1. Announce (Client → Daemon)

Sent by the client to initiate a connection. The daemon responds with a
WebRTC offer.

```json
{
  "peerId": "a1b2c3d4e5f6a7b8",
  "type": "announce",
  "client_ip": "203.0.113.42",
  "ip_preference": "both"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `peerId` | yes | Random 16-hex-char session identifier (8 random bytes) |
| `type` | yes | Must be `"announce"` |
| `client_ip` | no | Client's self-declared public IP (resolved via STUN). Used for policy checks before WebRTC work begins. |
| `ip_preference` | no | `"ipv4"`, `"ipv6"`, or `"both"` (default). Hints the daemon to filter ICE candidates. |

**Daemon behavior on receive**:
1. Rate-limit check (per-npub and global announce limits)
2. Policy evaluation: if IP-based rules are active and `client_ip` is missing,
   the daemon sends a `request-ip` message and waits for a re-announce
3. If a terms-of-service challenge is configured, sends `terms-challenge`
   instead of an offer
4. Otherwise: creates a `PeerSession`, generates a WebRTC offer, and sends it

### 2. Offer (Daemon → Client)

The daemon creates the WebRTC offer (it is the offerer). Contains the full
SDP with ICE candidates included (non-trickle on the daemon side — it waits
for ICE gathering to complete before sending).

```json
{
  "type": "offer",
  "sdp": "v=0\r\no=- 123456 2 IN IP4 127.0.0.1\r\n..."
}
```

The SDP includes:
- Host candidates (daemon's WireGuard exit IPs or local interfaces)
- `srflx` candidates (STUN-reflexive addresses from Google STUN)
- An `a=candidate` line for the DataChannel (label 0)

**SDP candidate filtering**: the daemon filters out any host candidate whose
IP does not match its configured WireGuard/server IPs. This prevents leaking
internal interface addresses. STUN `srflx` candidates are always kept.

### 3. Answer (Client → Daemon)

The client applies the offer, then sends back the answer SDP. Trickle ICE is
used on the client side — the answer may arrive before all client candidates
are gathered.

```json
{
  "type": "answer",
  "sdp": "v=0\r\no=- 789012 2 IN IP4 127.0.0.1\r\n..."
}
```

### 4. Candidate (Bidirectional)

ICE candidates sent via **trickle ICE** — each candidate is sent as soon as
it is gathered, in its own DM.

```json
{
  "type": "candidate",
  "sdp": "candidate:842163049 1 udp 1677729535 203.0.113.42 12345 typ srflx..."
}
```

The `sdp` field contains the raw ICE candidate string (the `a=candidate:`
line value without the prefix). Both sides send candidates to each other
until gathering is complete.

**Client side**: `RTCPeerConnection.onicecandidate` fires → each candidate
sent immediately as a DM.

**Daemon side**: candidates are included in the offer SDP (non-trickle). The
daemon receives the client's trickle candidates via DMs and applies them via
`pc.addIceCandidate()`.

### 5. Terms Challenge (Daemon → Client, optional)

If the daemon's policy requires a terms-of-service acceptance, it sends this
instead of an offer:

```json
{
  "type": "terms-challenge",
  "version": "2026-07-01",
  "text": "By connecting, you agree to..."
}
```

The client displays the terms and sends a `terms-accept`:

```json
{
  "type": "terms-accept",
  "version": "2026-07-01"
}
```

The daemon then proceeds with the offer.

### 6. Request IP (Daemon → Client, optional)

If the daemon has IP-based policy rules but the announce did not include
`client_ip`:

```json
{
  "type": "request-ip"
}
```

The client resolves its public IP via STUN and re-sends the announce with
the `client_ip` field populated.

---

## Connection Sequence

```
Client                                          Daemon
  │                                               │
  │  1. Subscribe to relays (kind=4, #p=self)      │
  │  2. Resolve own IP via STUN                    │
  │                                               │
  │  ──── announce {peerId, client_ip} ─────────► │
  │                                               │  3. Policy check
  │                                               │  4. Create PeerSession
  │                                               │  5. createOffer() + ICE gathering
  │                                               │  6. Filter SDP candidates
  │  ◄────────── offer {sdp} ──────────────────── │
  │                                               │
  │  7. setRemoteDescription(offer)               │
  │  8. createAnswer()                            │
  │                                               │
  │  ──── answer {sdp} ─────────────────────────► │
  │                                               │  9. setRemoteDescription(answer)
  │                                               │
  │  10. ICE candidates (trickle)                 │
  │  ──── candidate {sdp} ──────────────────────► │  11. addIceCandidate()
  │  ◄────────── candidate {sdp} ───────────────── │  (if daemon has late candidates)
  │                                               │
  │  ═══ WebRTC DataChannel open ════════════════════════════ │
  │                                               │
  │  ◄═════ HTTP over DataChannel ═════════════► │
```

---

## WebRTC Configuration

### ICE Servers

The client uses Google STUN servers (no TURN):

```javascript
const STUN_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];
```

### ICE Candidate Types

| Type | Source | Direction |
|------|--------|-----------|
| `host` | Daemon: WireGuard exit IPs. Client: local interfaces. | Both |
| `srflx` | STUN-reflexive (public IP via Google STUN) | Both |

mDNS host candidates (`.local`) from the browser are resolved separately via
the STUN probe — the client sends its resolved srflx IP in the announce DM.

### ICE Gathering Timeout

The daemon waits for ICE gathering to complete before sending the offer
(includes all candidates in the SDP). Timeout: `--connect-timeout` (default
15s).

The client uses trickle ICE — candidates are sent as they arrive, without
waiting for gathering to complete.

---

## Binary Stream Protocol (DataChannel)

Once the DataChannel is open, HTTP requests/responses are multiplexed over
it using the peck binary frame format.

### Frame Format

```
[StreamID:2][Port:2][Type:1][Payload:var]   (big-endian, 5-byte header)
```

| Field | Size | Description |
|-------|------|-------------|
| StreamID | 2 bytes | Unique ID for this HTTP request/response pair |
| Port | 2 bytes | Target port on the daemon side (e.g. 80 for HTTP) |
| Type | 1 byte | Frame type (see below) |
| Payload | variable | Raw bytes (HTTP data for DATA frames) |

### Frame Types

| Type | Value | Description |
|------|-------|-------------|
| `OPEN` | `0x00` | Opens a new stream. Payload = raw HTTP request bytes. |
| `DATA` | `0x01` | Continuation data for an existing stream. |
| `CLOSE` | `0x02` | Graceful close — sender is done writing. |
| `RST` | `0x03` | Reset — error, stream aborted. Payload may contain error message. |

### HTTP Exchange

1. **Client sends `OPEN`**: payload = raw HTTP/1.1 request
   (`GET /path HTTP/1.1\r\nHost: ...\r\n\r\n`)
2. **Daemon proxies** to the local backend, collects the response
3. **Daemon sends `DATA`** frames with the response (may be chunked across
   multiple frames for large responses)
4. **Daemon sends `CLOSE`** when the response is complete

For errors (backend unreachable, invalid request), the daemon sends `RST`
with an error message payload.

### Multiplexing

Multiple streams can be open simultaneously on a single DataChannel, each
identified by its `StreamID`. The client assigns StreamIDs incrementally.
The daemon matches responses to requests by StreamID.

---

## Session Lifecycle

| Phase | Event | Timeout |
|-------|-------|---------|
| **Idle** | No data on DataChannel | `--idle-timeout` (default 1200s / 20 min) |
| **Connect** | From announce to DataChannel open | `--connect-timeout` (default 15s) |
| **Closing** | Either side closes the DataChannel | Immediate |

The daemon tracks sessions by client pubkey. Only one active session per
pubkey — a new announce from the same pubkey replaces the old session.

**Reconnection**: if the DataChannel drops, the client retries by sending a
new announce. Configurable via `reconnect.max_attempts` (default 3) and
`reconnect.delays_ms` (default `[5000, 10000, 20000]`).

---

## Relay Redundancy

Both client and daemon connect to multiple Nostr relays simultaneously. The
daemon round-robins outbound signaling messages across relays (per-session
rotation). The client broadcasts each DM to ALL connected relays.

Event deduplication: the daemon tracks seen event IDs (up to 1000, FIFO
pruned to 500) to handle the same event arriving via multiple relays.

---

## Security Model

### Encryption

All signaling is NIP-44 v2 encrypted (ChaCha20-Poly1305 + HKDF). The
WebRTC DataChannel is encrypted by DTLS (standard WebRTC). No plaintext
signaling ever passes through relays.

### Self-Declared Client IP

The `client_ip` in the announce is self-declared (resolved by the client via
STUN). It cannot be cryptographically verified at signaling time. The daemon
runs a **second filter**: it checks the actual `srflx` IPs in the WebRTC SDP
answer against the access-control policy. This second filter catches
announces with spoofed IPs.

### Daemon Trust Model

The daemon operator controls the backend. Content served through the tunnel
executes in the client's browser origin (same-origin as the peck client).
This is the same trust model as visiting any website. See the main README
§ "Security Model" for mitigations (encrypted vault, CSP, nsec isolation).

---

## Reference Implementation

| Component | File |
|-----------|------|
| Daemon signaling | `daemon/daemon.py` — `handle_dm()`, `handle_announce()`, `PeerSession` |
| Daemon crypto | `daemon/crypto_helpers.py` — `make_event()`, `get_pubkey()` |
| Daemon WebRTC | `daemon/daemon.py` — `PeerSession.create_offer()`, `receive_answer()` |
| Daemon binary protocol | `daemon/protocol.py` — `encode_frame()`, `decode_frame()` |
| Client signaling | `browser/src/native-transport.js` — `NativeTransport` |
| Client binary protocol | `browser/src/protocol.js` |
| NIP-44 (Python) | `daemon/nip44.py` |
| NIP-44 (Browser) | `browser/src/nip44-browser.js` |

For a minimal end-to-end example, see [`examples/minimal-tunnel.py`](../examples/minimal-tunnel.py).
