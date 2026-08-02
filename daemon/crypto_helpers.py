"""
peck crypto helpers — secp256k1 key derivation, Nostr event signing, nsec loading.

Extracted from daemon.py — standalone crypto utilities with no class dependencies.
"""

import hashlib
import json
import time

import coincurve


# ─── secp256k1 pubkey helpers ───────────────────────────────────────────────

def get_pubkey(privkey_hex: str) -> str:
    """Derive x-only pubkey (32 bytes / 64 hex) from privkey."""
    sk = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    return sk.public_key.format(compressed=True)[1:].hex()


# ─── NIP-01 event building ──────────────────────────────────────────────────

def make_event(privkey_hex: str, recipient_pubkey: str, content: str, kind: int = 4) -> dict:
    """Create and sign a Nostr event (BIP-340 Schnorr signature)."""
    pub = get_pubkey(privkey_hex)
    created_at = int(time.time())
    tags = [["p", recipient_pubkey]] if kind == 4 else []

    canonical = json.dumps([0, pub, created_at, kind, tags, content], separators=(",", ":"))
    event_id = hashlib.sha256(canonical.encode()).hexdigest()

    sk = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    sig_bytes = sk.sign_schnorr(bytes.fromhex(event_id))

    return {
        "kind": kind,
        "content": content,
        "tags": tags,
        "created_at": created_at,
        "pubkey": pub,
        "id": event_id,
        "sig": sig_bytes.hex(),
    }


# ─── nsec loading / Bech32m decoding ────────────────────────────────────────

def load_nsec(path: str) -> str:
    """Load a Nostr private key from a file.

    Accepts both formats:
    - Hex (64 chars, no prefix)
    - Bech32 (nsec1...)  — decoded to hex internally
    """
    with open(path) as f:
        content = f.read().strip()
    if content.startswith("nsec1"):
        return _nsec_to_hex(content)
    return content


def _nsec_to_hex(nsec: str) -> str:
    """Decode a Nostr nsec (Bech32m) to a 32-byte hex string."""
    from bech32m import _bech32m_decode, _convertbits
    hrp, data = _bech32m_decode(nsec)
    if hrp != "nsec" or data is None:
        raise ValueError(f"invalid nsec: {nsec[:20]}")
    decoded = _convertbits(data, 5, 8, False)
    if len(decoded) != 32:
        raise ValueError(f"nsec decoded to {len(decoded)} bytes, expected 32")
    return bytes(decoded).hex()
