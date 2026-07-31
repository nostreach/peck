# Third-Party Licenses

This project uses the following open-source libraries. We thank their authors.

## Browser Client

### @noble/secp256k1 (MIT)
- Author: Paul Miller (https://paulmillr.com)
- Source: https://github.com/paulmillr/noble-secp256k1
- Vendored at: `vendor/secp256k1.mjs`
- Used for: Schnorr (BIP-340) signatures for Nostr events

### @noble/hashes (MIT)
- Author: Paul Miller (https://paulmillr.com)
- Source: https://github.com/paulmillr/noble-hashes
- Vendored at: `vendor/sha2.mjs`, `vendor/hmac.mjs`, `vendor/utils.mjs`
- Used for: SHA-256, HKDF, HMAC — core primitives for NIP-44 encryption

### @noble/ciphers (MIT)
- Author: Paul Miller (https://paulmillr.com)
- Source: https://github.com/paulmillr/noble-ciphers
- Vendored at: `vendor/chacha.mjs`
- Used for: ChaCha20-Poly1305 AEAD encryption (NIP-44 v2)

### esbuild (MIT)
- Author: Evan Wallace
- Source: https://github.com/evanw/esbuild
- Used for: JavaScript bundling (build-time only, not shipped)

## Python Daemon

### aiortc (BSD-3-Clause)
- Author: Jeremy Lainé
- Source: https://github.com/aiortc/aiortc
- Used for: WebRTC implementation (RTCPeerConnection, DataChannel)

### aiohttp (Apache-2.0)
- Author: aiohttp contributors
- Source: https://github.com/aio-libs/aiohttp
- Used for: Async HTTP server/client

### coincurve (Apache-2.0 OR BSD-3-Clause)
- Author: Ofek Lev
- Source: https://github.com/ofek/coincurve
- Used for: secp256k1 elliptic curve operations, Schnorr signing

### loguru (MIT)
- Author: Delgan Ma
- Source: https://github.com/Delgan/loguru
- Used for: Structured logging

### PyYAML (MIT)
- Author: Kirill Simonov
- Source: https://github.com/yaml/pyyaml
- Used for: YAML config parsing

---

All listed licenses are compatible with peck's MIT license.
