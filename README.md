# peck

**Nostr-signaled WebRTC tunnel. Punch through NAT with nothing but a Nostr public key.**

`peck` connects a browser directly to any server behind NAT — no TURN, no VPN, no port forwarding. WebRTC hole-punching with [Nostr](https://github.com/nostr-protocol/nostr) relays as the signaling layer. All signaling is [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) encrypted.

> **Status**: Beta. E2E-validated in production at [dns2nostr.com](https://dns2nostr.com).
>
> **Try it out**: Visit [peck.dns2nostr.com](https://peck.dns2nostr.com) to see a live peck tunnel in action.

---

## Why?

Exposing a home server, self-hosted app, or anything behind NAT usually means:

- Port forwarding (requires router access, breaks on CGNAT)
- TURN relay (centralized, expensive, single point of failure)
- VPN overlay (extra software on both sides, routing complexity)

`peck` needs none of that. The browser opens a direct P2P tunnel to the daemon using only the daemon's Nostr npub as identity. Nostr relays carry the encrypted signaling handshake — they never route traffic and never see plaintext.

## How it works

```
 ┌──────────┐                    Nostr Relays                   ┌──────────┐
 │ Browser  │ ◄──────── NIP-44 encrypted DMs ────────────────► │  Daemon   │
 │          │   (announce, offer, answer, ICE candidates)      │ (Python)  │
 │          │                                                   │           │
 │  WebRTC  │ ◄─────────── direct P2P DataChannel ───────────► │  aiortc   │
 │  client  │             (NAT hole punched)                    │           │
 │          │                                                   │           │
 │  fetch() │ ── HTTP over DataChannel ──────────────────────► │ localhost │
 └──────────┘                                                   └──────────┘
```

1. Daemon starts, generates a Nostr keypair, connects to relays
2. Browser resolves the daemon's npub from the URL hostname
3. Browser sends an encrypted `announce` DM via Nostr relays
4. Daemon responds with a WebRTC `offer` (SDP) — also encrypted
5. Browser sends back the `answer` + ICE candidates (trickle)
6. WebRTC DataChannel opens — direct P2P tunnel established
7. HTTP requests from the browser flow over the DataChannel to the daemon's local backend

**Privacy**: The web server only serves static files. It never sees the npub, relay traffic, or tunneled content. The signaling is end-to-end encrypted between browser and daemon. Nostr relays carry ciphertext only.

## Quick Start

### Prerequisites

**Daemon**: Python 3.10+, and system dependencies for `aiortc`:

```bash
# Debian/Ubuntu
sudo apt install libavdevice-dev libavfilter-dev libavformat-dev libavcodec-dev libavutil-dev libswscale-dev libswresample-dev libsrtp2-dev

# Create venv and install
python3 -m venv venv
source venv/bin/activate
pip install aiortc aiohttp coincurve aiohttp-websockets loguru pyyaml
```

**Browser client**: Any static file server (nginx, caddy, python -m http.server). A subdomain per daemon is recommended (e.g. `npub1abc.yourdomain.com`).

### 1. Start the daemon

```bash
# Generate a Nostr private key (32-byte hex)
python3 -c "import secrets; print(secrets.token_hex(32))" > ~/.config/peck/nsec
chmod 600 ~/.config/peck/nsec

# Run the daemon
python daemon.py \
  --nsec-file ~/.config/peck/nsec \
  --ports 80:http://127.0.0.1:8080 \
  --relays wss://relay.damus.io,wss://relay.primal.net \
  --wg-ips <your-server-ipv4> \
  --domain-suffix yourdomain.com
```

The daemon prints its npub on startup. That's the public identity browsers connect to.

> **Key format**: The nsec file accepts both hex (64 chars) and bech32 (`nsec1...`) format. Both are decoded automatically.

### 2. Serve the browser client

Deploy these files to your web server:

```
/var/www/peck/
├── client.html
├── sw.js
├── peck-config.json          (optional)
├── vendor/                   # @noble/* bundles (see below)
│   ├── secp256k1.mjs
│   ├── sha2.mjs
│   ├── hmac.mjs
│   ├── chacha.mjs
│   └── utils.mjs
└── src/
    ├── client.js
    ├── native-transport.js
    ├── nip44-browser.js
    ├── protocol.js
    ├── wg-country-codes.js
    └── geoip-data.js
```

**Vendored crypto bundles**: The browser client uses [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1), [@noble/hashes](https://github.com/paulmillr/noble-hashes), and [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) for NIP-44 encryption. These are vendored as self-hosted `.mjs` bundles (no CDN dependency at runtime). To generate them:

```bash
npm install
mkdir -p vendor
# Bundle each dependency as a single .mjs file
npx esbuild @noble/secp256k1 --bundle --format=esm --outfile=vendor/secp256k1.mjs
npx esbuild @noble/hashes/sha2 --bundle --format=esm --outfile=vendor/sha2.mjs
npx esbuild @noble/hashes/hmac --bundle --format=esm --outfile=vendor/hmac.mjs
npx esbuild @noble/ciphers/chacha --bundle --format=esm --outfile=vendor/chacha.mjs
npx esbuild @noble/hashes/utils --bundle --format=esm --outfile=vendor/utils.mjs
```

The import map in `client.html` maps `@noble/*` to `/vendor/*.mjs`. See [THIRD_PARTY.md](THIRD_PARTY.md) for license information.

**Optional**: Create a `peck-config.json` to override defaults:

```json
{
  "default_relays": [
    "wss://relay.damus.io",
    "wss://relay.primal.net"
  ],
  "reconnect": {
    "max_attempts": 3,
    "delays_ms": [5000, 10000, 20000]
  },
  "ice_gathering_timeout_ms": 3000,
  "info_mandatory": "npub"
}
```

If `peck-config.json` is absent, hardcoded defaults apply (fully backward compatible).

### 3. Connect

Visit `https://npub1xxx.yourdomain.com/` — the browser auto-resolves the npub from the subdomain and connects.

No DNS lookup needed for npub-based subdomains — the npub is parsed directly from the hostname. Zero latency, zero DNS footprint.

For human-readable subdomains (`blog.yourdomain.com`), set a DNS TXT record:

```
blog.yourdomain.com.  IN  TXT  "npub=<hex-pubkey>"
```

The browser does a DoH (DNS-over-HTTPS) lookup to resolve the alias.

## Architecture

### Signaling: NIP-44 v2 encrypted DMs

All signaling between browser and daemon uses NIP-44 v2 encrypted Direct Messages (Nostr kind=4 events). Both sides generate ephemeral Nostr keypairs. Messages are encrypted with the recipient's public key and signed with ChaCha20-Poly1305 + HKDF-chacha20.

The browser side uses `@noble/secp256k1`, `@noble/hashes`, and `@noble/ciphers` (vendored, no CDN dependency). The daemon uses `coincurve` for Schnorr signing.

### Transport: native WebRTC

**Browser**: Native `RTCPeerConnection` + `RTCDataChannel`. No WebRTC polyfills, no `werift`, no `wrtc` npm packages.

**Daemon**: Python `aiortc`. Handles the WebRTC offer/answer exchange and manages the DataChannel.

### HTTP over DataChannel

Once the DataChannel is open, the browser sends HTTP requests as binary frames over the channel. The daemon parses them, forwards to the local backend, and streams responses back. A multiplexer (`protocol.js` / `ports.py`) supports multiple concurrent streams over a single DataChannel.

A Service Worker intercepts `fetch()` calls and routes them through the tunnel, so existing web apps work without modification.

### Multi-port routing

The daemon supports multiple backend ports via path-prefix routing (`/_p<port>/path`) or subdomain routing. See `--ports-config` for multi-backend setups.

## Configuration

### Daemon CLI flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--nsec-file` | yes | — | Path to Nostr private key file |
| `--relays` | yes | — | Comma-separated Nostr relay URLs |
| `--wg-ips` | yes | — | Comma-separated WireGuard/server IPv4 addresses |
| `--ports` | no | `80:http://127.0.0.1:8080` | Port mapping: `extern:http://backend` |
| `--ports-config` | no | — | YAML/JSON multi-port config |
| `--backends` | no | — | YAML route table for multi-backend mode |
| `--domain-suffix` | no | `localhost` | Domain suffix for Host-header parsing |
| `--context-alias` | no | derived from npub | Alias for the daemon's context-root |
| `--wg-ip6s` | no | — | Comma-separated IPv6 addresses |
| `--idle-timeout` | no | `1200` (20 min) | Session idle timeout in seconds |
| `--connect-timeout` | no | `15` | WebRTC connection timeout in seconds |
| `--policy-file` | no | — | YAML access-control policy |
| `--audit-log` | no | — | JSON-Lines audit log (pubkeys/IPs hashed) |
| `--geoip-db` | no | — | MaxMind GeoLite2 Country `.mmdb` path |
| `--relay-mode` | no | off | Run as relay daemon (bridges failed hole-punches) |
| `--relay-price` | no | `0` | Streaming payment rate in sat/min (0 = free) |

### Access control (`policy.yaml`)

Optional policy engine for IP allow/deny, GeoIP-based region blocking, terms-of-service challenges, and rate limiting. See `policy.yaml.example`.

### Client config (`peck-config.json`)

| Key | Default | Description |
|-----|---------|-------------|
| `default_relays` | 5 relays (damus, primal, nostr.net, oxtr, no.str.cr) | Pre-populated when user has none |
| `reconnect.max_attempts` | `3` | Max reconnection attempts |
| `reconnect.delays_ms` | `[5000, 10000, 20000]` | Delays between attempts (ms) |
| `ice_gathering_timeout_ms` | `3000` | ICE candidate gathering timeout |
| `info_mandatory` | `"never"` | Info gate: `never` / `npub` / `always` |

## Repository Layout

```
peck/
├── daemon.py                  # Python daemon (aiortc + aiohttp + coincurve)
├── client.py                  # CLI test client
├── nip44.py                   # NIP-44 v2 encryption (Python)
├── policy.py                  # Access control policy engine
├── policy.yaml.example        # Example policy config
├── route_table.py             # Multi-level subdomain routing
├── ports.py                   # Multi-port configuration
│
├── src/                       # Browser client (ES modules)
│   ├── client.js              # Connect, tunnel, navigate
│   ├── native-transport.js    # NIP-44 DM signaling + WebRTC
│   ├── nip44-browser.js       # Browser-side NIP-44 v2
│   ├── protocol.js            # Binary stream multiplexing
│   ├── wg-country-codes.js    # IP → country flag (geoip)
│   └── geoip-data.js          # GeoIP database (bundled)
│
├── examples/
│   ├── client.html            # Full browser client (~97 KB)
│   ├── peck-config.example.json
│   ├── sw.js                  # Service Worker (sub-asset tunneling)
│   └── test-site/             # Example site for testing
│
├── vendor/                   # @noble/* crypto bundles (generated, see README)
│
├── deploy/                    # systemd service files
│   ├── peck-daemon.service
│   └── peck-daemon-netns.service   # Network namespace variant
│
├── scripts/
│   ├── peck-vpn.sh            # WireGuard multi-tunnel bootstrap
│   └── peck-vpn-netns.sh      # Network namespace setup
│
├── build.mjs                  # esbuild bundler
└── package.json
```

## Browser Support

Chrome/Edge 90+, Firefox 88+, Safari 15+. Requires:
- ES modules
- WebRTC DataChannels
- Service Workers (for sub-asset tunneling)
- `RTCPeerConnection` with ICE candidate gathering

## Dependencies

**Daemon (Python)**:
- `aiortc` — WebRTC for Python (asyncio)
- `aiohttp` — HTTP server + client
- `coincurve` — secp256k1 Schnorr signing
- `pyyaml` — config parsing
- `loguru` — structured logging

**Browser client**:
- `@noble/secp256k1` — Schnorr signatures (vendored)
- `@noble/hashes` — SHA-256, HKDF (vendored)
- `@noble/ciphers` — ChaCha20-Poly1305 (vendored)
- `esbuild` — build tool

No runtime CDN dependencies. All cryptographic code is self-hosted.

## Related Projects

| Project | Responsibility |
|---------|----------------|
| **peck** (this repo) | WebRTC tunnel daemon + browser client |
| [dns2nostr](https://dns2nostr.com) | Name registry — DNS TXT records for npub aliases |
| [nostreach](https://nostreach.com) | The ecosystem peck belongs to |

## Limitations

- **No TURN relay**: If both peers are behind symmetric NAT, hole-punching may fail. A relay daemon mode (`--relay-mode`) can bridge failed connections.
- **HTTP only**: The DataChannel tunnel carries HTTP. HTTPS between browser and web server is handled by the hosting layer (nginx/caddy).
- **Single-session**: One browser tab = one tunnel. Multiple tabs each establish independent connections.

## Proof of Concept — Not a Privacy Tool

The WireGuard multi-tunnel feature provides **IP diversity** (preventing trivial correlation between connections), not anonymity. While all tests so far are successful and promising, anonymity behind the VPNs cannot be guaranteed. IP leaks through WebRTC, DNS, or other browser side-channels are possible and have not been exhaustively ruled out.

If you need genuine anonymity, rely on established methods (Tor, properly configured VPN chains, hardened browser profiles).

## Further Documentation

- [WireGuard Multi-Tunnel Setup](docs/WIREGUARD.md) — IP diversity, network namespaces, multi-WG configuration
- [Access Control & Policy](docs/ACCESS_CONTROL.md) — IP filtering, GeoIP blocking, terms-of-service, audit logging
- [Third-Party Licenses](THIRD_PARTY.md) — Dependencies and their licenses

## License

MIT — Copyright (c) 2026 [nostreach.com](https://nostreach.com)
