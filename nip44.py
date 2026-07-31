"""
NIP-44 v2 implementation for Python.

Reference: https://github.com/nostr-protocol/nips/blob/master/44.md
Test vectors: https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json

Design:
- ECDH on secp256k1 (unhashed X coordinate, BIP-340 style)
- HKDF-extract with sha256, salt='nip44-v2'
- Per-message: 32-byte random nonce
- HKDF-expand(PRK=conversation_key, info=nonce, L=76) → (chacha_key, chacha_nonce, hmac_key)
- Custom padding (powers-of-two, min 32 bytes)
- ChaCha20 (RFC 8439, counter=0)
- HMAC-SHA256(key=hmac_key, msg=concat(nonce, ciphertext)) → MAC
- base64(version=2, nonce, ciphertext, mac)
"""

import base64
import hashlib
import hmac
import math
import secrets

import coincurve

# ─── Constants ───────────────────────────────────────────────────────────────

VERSION = 2
MIN_PLAINTEXT_SIZE = 1
MAX_PLAINTEXT_SIZE = 2**32 - 1
EXTENDED_PREFIX_THRESHOLD = 65536

# ─── secp256k1 ECDH ──────────────────────────────────────────────────────────

def _ecdh_shared_x(privkey_bytes: bytes, pubkey_xonly_hex: str) -> bytes:
    """
    Compute unhashed 32-byte X coordinate of ECDH(privkey, pubkey).

    NIP-44 explicitly does NOT hash the ECDH output (unlike NIP-04 which uses SHA-256).
    coincurve.PrivateKey.ecdh() DOES hash by default (sha256) with no way to disable.

    Workaround: use PublicKey.multiply(scalar) which performs pubkey * privkey
    (equivalent to ECDH) and returns the shared point. We then extract its X coordinate.
    """
    xonly_bytes = bytes.fromhex(pubkey_xonly_hex)
    # Reconstruct compressed pubkey (try 0x02 prefix, fall back to 0x03)
    pub_compressed = None
    for prefix in (b"\x02", b"\x03"):
        try:
            pub = coincurve.PublicKey(prefix + xonly_bytes)
            _ = pub.format()  # validate
            pub_compressed = pub
            break
        except Exception:
            continue
    if pub_compressed is None:
        raise ValueError("invalid pubkey")

    # shared_point = pubkey * privkey
    shared_point = pub_compressed.multiply(privkey_bytes)
    # X coordinate = bytes 1..33 of compressed format
    return shared_point.format(compressed=True)[1:]


# ─── HKDF (RFC 5869) ────────────────────────────────────────────────────────

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with SHA-256. Returns 32-byte PRK."""
    if len(salt) == 0:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand with SHA-256."""
    if length > 255 * 32:
        raise ValueError("HKDF expand length too large")
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# ─── Conversation & message keys ────────────────────────────────────────────

def get_conversation_key(privkey_hex: str, pubkey_xonly_hex: str) -> bytes:
    """
    Long-term conversation key between A and B.
    conv(Apriv, Bpub) == conv(Bpriv, Apub)
    """
    shared_x = _ecdh_shared_x(bytes.fromhex(privkey_hex), pubkey_xonly_hex)
    salt = b"nip44-v2"
    return hkdf_extract(salt, shared_x)


def get_message_keys(conversation_key: bytes, nonce: bytes) -> tuple:
    """Per-message keys: (chacha_key, chacha_nonce, hmac_key)."""
    if len(conversation_key) != 32:
        raise ValueError("invalid conversation_key length")
    if len(nonce) != 32:
        raise ValueError("invalid nonce length")
    keys = hkdf_expand(conversation_key, nonce, 76)
    return keys[0:32], keys[32:44], keys[44:76]


# ─── Padding ────────────────────────────────────────────────────────────────

def calc_padded_len(unpadded_len: int) -> int:
    """Calculate the padded length for a given unpadded length."""
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (floor_log2(unpadded_len - 1) + 1)
    if next_power <= 256:
        chunk = 32
    else:
        chunk = next_power // 8
    return chunk * ((unpadded_len - 1) // chunk + 1)


def floor_log2(n: int) -> int:
    """Floor of log2(n). n must be > 0."""
    if n <= 0:
        raise ValueError("log2 of non-positive number")
    return n.bit_length() - 1


def pad(plaintext: str) -> bytes:
    """Pad plaintext to a fixed length (powers-of-two scheme)."""
    unpadded = plaintext.encode("utf-8")
    unpadded_len = len(unpadded)
    if unpadded_len < MIN_PLAINTEXT_SIZE or unpadded_len > MAX_PLAINTEXT_SIZE:
        raise ValueError("invalid plaintext length")

    if unpadded_len >= EXTENDED_PREFIX_THRESHOLD:
        prefix = b"\x00\x00" + unpadded_len.to_bytes(4, "big")  # 6 bytes
    else:
        prefix = unpadded_len.to_bytes(2, "big")  # 2 bytes

    suffix_len = calc_padded_len(unpadded_len) - unpadded_len
    suffix = b"\x00" * suffix_len
    return prefix + unpadded + suffix


def unpad(padded: bytes) -> str:
    """Remove padding from a padded byte array."""
    first_two = int.from_bytes(padded[0:2], "big")
    if first_two == 0:
        unpadded_len = int.from_bytes(padded[2:6], "big")
        if unpadded_len < EXTENDED_PREFIX_THRESHOLD:
            raise ValueError("invalid padding")
        prefix_len = 6
    else:
        unpadded_len = first_two
        prefix_len = 2

    unpadded = padded[prefix_len:prefix_len + unpadded_len]
    if (unpadded_len == 0
            or len(unpadded) != unpadded_len
            or len(padded) != prefix_len + calc_padded_len(unpadded_len)):
        raise ValueError("invalid padding")
    return unpadded.decode("utf-8")


# ─── ChaCha20 ───────────────────────────────────────────────────────────────

def _chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    ChaCha20 stream cipher (RFC 8439), counter starts at 0.

    Python stdlib doesn't ship ChaCha20 directly, but `cryptography` does
    via algorithms.ChaCha20. Same as what we already depend on for AES.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.backends import default_backend
    # RFC 8439: first 16 bytes = counter (LE) + nonce
    # cryptography's ChaCha20 takes a 16-byte nonce where first 4 bytes = counter (LE),
    # next 12 = actual nonce. Counter 0 → first 4 bytes = 0x00000000.
    # The 12-byte nonce from NIP-44 fits into bytes [4:16] of the algorithm's "nonce".
    # Wait — NIP-44's chacha_nonce is 12 bytes (bytes 32..44 of the HKDF output).
    algorithm = algorithms.ChaCha20(key, b"\x00\x00\x00\x00" + nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# ─── HMAC-SHA256 ────────────────────────────────────────────────────────────

def _hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
    """HMAC-SHA256(key, concat(aad, message)). AAD must be 32 bytes."""
    if len(aad) != 32:
        raise ValueError("AAD must be 32 bytes")
    return hmac.new(key, aad + message, hashlib.sha256).digest()


def _is_equal_ct(a: bytes, b: bytes) -> bool:
    """Constant-time equality check."""
    return hmac.compare_digest(a, b)


# ─── Public API ─────────────────────────────────────────────────────────────

def encrypt(plaintext: str, privkey_hex: str, recipient_pubkey_xonly_hex: str) -> str:
    """
    Encrypt a plaintext string to a recipient's pubkey (x-only hex).
    Returns base64 payload.

    A fresh 32-byte nonce is generated per call.
    """
    conversation_key = get_conversation_key(privkey_hex, recipient_pubkey_xonly_hex)
    nonce = secrets.token_bytes(32)
    return encrypt_with_key(plaintext, conversation_key, nonce)


def encrypt_with_key(plaintext: str, conversation_key: bytes, nonce: bytes) -> str:
    """Encrypt with explicit conversation_key and nonce (for testing)."""
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    padded = pad(plaintext)
    ciphertext = _chacha20(chacha_key, chacha_nonce, padded)
    mac = _hmac_aad(hmac_key, ciphertext, nonce)
    payload = bytes([VERSION]) + nonce + ciphertext + mac
    return base64.b64encode(payload).decode("ascii")


def decrypt(payload: str, privkey_hex: str, sender_pubkey_xonly_hex: str) -> str:
    """Decrypt a base64 payload from a sender's pubkey (x-only hex)."""
    conversation_key = get_conversation_key(privkey_hex, sender_pubkey_xonly_hex)
    return decrypt_with_key(payload, conversation_key)


def decrypt_with_key(payload: str, conversation_key: bytes) -> str:
    """Decrypt with explicit conversation_key (for testing)."""
    nonce, ciphertext, mac = _decode_payload(payload)
    _chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    calculated_mac = _hmac_aad(hmac_key, ciphertext, nonce)
    if not _is_equal_ct(calculated_mac, mac):
        raise ValueError("invalid MAC")
    padded = _chacha20(_chacha_key, chacha_nonce, ciphertext)
    return unpad(padded)


def _decode_payload(payload: str) -> tuple:
    """Decode base64 payload → (nonce, ciphertext, mac)."""
    plen = len(payload)
    if plen == 0 or payload[0] == "#":
        raise ValueError("unknown version")
    if plen < 132:
        raise ValueError("invalid payload size")
    data = base64.b64decode(payload)
    dlen = len(data)
    if dlen < 99:
        raise ValueError("invalid data size")
    version = data[0]
    if version != VERSION:
        raise ValueError(f"unknown version {version}")
    nonce = data[1:33]
    ciphertext = data[33:dlen - 32]
    mac = data[dlen - 32:dlen]
    return nonce, ciphertext, mac


# ─── Self-test against official test vectors ────────────────────────────────

def _run_self_test():
    """Validate against paulmillr/nip44 test vectors. Returns (passed, failed)."""
    import json
    import urllib.request

    url = "https://raw.githubusercontent.com/paulmillr/nip44/main/nip44.vectors.json"
    with urllib.request.urlopen(url) as resp:
        vectors = json.loads(resp.read().decode())

    passed = 0
    failed = 0

    # get_conversation_key
    for case in vectors["v2"]["valid"]["get_conversation_key"]:
        try:
            ck = get_conversation_key(case["sec1"], case["pub2"])
            if ck.hex() == case["conversation_key"]:
                passed += 1
            else:
                failed += 1
                print(f"  ✗ get_conversation_key: expected {case['conversation_key'][:16]}… got {ck.hex()[:16]}…")
        except Exception as e:
            failed += 1
            print(f"  ✗ get_conversation_key: exception {e}")

    # get_message_keys
    gmk = vectors["v2"]["valid"]["get_message_keys"]
    ck_gmk = bytes.fromhex(gmk["conversation_key"])
    for case in gmk["keys"]:
        try:
            nonce = bytes.fromhex(case["nonce"])
            chacha_key, chacha_nonce, hmac_key = get_message_keys(ck_gmk, nonce)
            expected = (case["chacha_key"], case["chacha_nonce"], case["hmac_key"])
            got = (chacha_key.hex(), chacha_nonce.hex(), hmac_key.hex())
            if got == expected:
                passed += 1
            else:
                failed += 1
                print(f"  ✗ get_message_keys mismatch")
                print(f"    expected: {expected}")
                print(f"    got:      {got}")
        except Exception as e:
            failed += 1
            print(f"  ✗ get_message_keys: exception {e}")

    # calc_padded_len (list of [length, padded] pairs)
    for pair in vectors["v2"]["valid"]["calc_padded_len"]:
        try:
            length, expected_padded = pair
            got = calc_padded_len(length)
            if got == expected_padded:
                passed += 1
            else:
                failed += 1
                print(f"  ✗ calc_padded_len({length}): expected {expected_padded}, got {got}")
        except Exception as e:
            failed += 1
            print(f"  ✗ calc_padded_len({pair}): exception {e}")

    # encrypt_decrypt (full roundtrip with provided nonce)
    for case in vectors["v2"]["valid"]["encrypt_decrypt"]:
        try:
            ck = bytes.fromhex(case["conversation_key"])
            nonce = bytes.fromhex(case["nonce"])
            # Encrypt with known nonce
            payload = encrypt_with_key(case["plaintext"], ck, nonce)
            if payload == case["payload"]:
                passed += 1
            else:
                failed += 1
                print(f"  ✗ encrypt: payload mismatch for {case['plaintext'][:30]!r}")
                print(f"    expected: {case['payload'][:60]}…")
                print(f"    got:      {payload[:60]}…")
            # Decrypt back
            plaintext = decrypt_with_key(payload, ck)
            if plaintext != case["plaintext"]:
                failed += 1
                print(f"  ✗ decrypt: plaintext mismatch")
        except Exception as e:
            failed += 1
            print(f"  ✗ encrypt_decrypt: exception {e}")

    # encrypt_decrypt_long_msg
    for case in vectors["v2"]["valid"]["encrypt_decrypt_long_msg"]:
        try:
            ck = bytes.fromhex(case["conversation_key"])
            nonce = bytes.fromhex(case["nonce"])
            # Long-msg cases use pattern + repeat instead of literal plaintext
            plaintext = case["pattern"] * case["repeat"]
            payload = encrypt_with_key(plaintext, ck, nonce)
            # We can't compare payload directly (too large); compare SHA-256
            import hashlib
            expected_sha = case.get("payload_sha256")
            actual_sha = hashlib.sha256(payload.encode("ascii")).hexdigest()
            if expected_sha and actual_sha == expected_sha:
                passed += 1
            elif not expected_sha:
                # Fall back to decrypt roundtrip
                decrypted = decrypt_with_key(payload, ck)
                if decrypted == plaintext:
                    passed += 1
                else:
                    failed += 1
                    print(f"  ✗ long_msg decrypt mismatch (len={len(plaintext)})")
            else:
                failed += 1
                print(f"  ✗ long_msg payload_sha256 mismatch (len={len(plaintext)})")
                print(f"    expected: {expected_sha}")
                print(f"    got:      {actual_sha}")
        except Exception as e:
            failed += 1
            print(f"  ✗ long_msg: exception {e}")

    return passed, failed


if __name__ == "__main__":
    print("Running NIP-44 self-test against official vectors…")
    p, f = _run_self_test()
    print(f"\nResult: {p} passed, {f} failed")
    if f == 0:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ FAILURES — see output above")
        exit(1)
