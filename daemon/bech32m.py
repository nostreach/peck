"""
Bech32m encoder/decoder (BIP-350) for Nostr npub <-> pubkey hex conversion.

Single canonical implementation — used by route_table.py, policy.py, and daemon.py.
"""

from typing import Iterable

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2bc830a3

_BECH32_CHARSET_REV = {c: i for i, c in enumerate(_BECH32_CHARSET)}


def _bech32_polymod(values: list[int]) -> int:
    """BIP-173 / BIP-350 polymod function."""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32m_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ _BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32m_encode(hrp: str, data: list[int]) -> str:
    combined = data + _bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join([_BECH32_CHARSET[d] for d in combined])


def _bech32m_decode(s: str) -> tuple[str, list[int] | None]:
    """Decode a Bech32m string. Returns (hrp, data) or (hrp, None) on checksum failure."""
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return s[:pos] if pos >= 0 else s, None
    hrp = s[:pos]
    data_part = s[pos + 1:]
    data = []
    for c in data_part:
        v = _BECH32_CHARSET_REV.get(c)
        if v is None:
            return hrp, None
        data.append(v)
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != _BECH32M_CONST:
        return hrp, None
    return hrp, data[:-6]  # strip 6-byte checksum


def _convertbits(data: Iterable[int], frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid value for convertbits")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def pubkey_hex_to_npub(pubkey_hex: str) -> str:
    """Encode a 32-byte x-only pubkey (hex) as a Nostr npub (Bech32m)."""
    data = _convertbits(bytes.fromhex(pubkey_hex), 8, 5)
    return _bech32m_encode("npub", data)


def npub_to_pubkey_hex(npub: str) -> str:
    """Decode a Nostr npub (Bech32m) back to a 32-byte x-only pubkey hex string."""
    hrp, data = _bech32m_decode(npub)
    if hrp != "npub" or data is None:
        raise ValueError(f"invalid npub: {npub[:20]}")
    decoded = _convertbits(data, 5, 8, False)
    if decoded is None or len(decoded) != 32:
        raise ValueError(f"npub does not decode to 32 bytes: {npub[:20]}")
    return bytes(decoded).hex()


def normalize_pubkey(p: str) -> str:
    """Accept npub1... or hex (64 chars); return 64-char lowercase hex."""
    p = p.strip().lower()
    if p.startswith("npub1"):
        return npub_to_pubkey_hex(p)
    if len(p) == 64:
        try:
            bytes.fromhex(p)
            return p
        except ValueError:
            pass
    raise ValueError(f"invalid pubkey (not npub1... or 64-char hex): {p[:20]}")
