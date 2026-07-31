"""
NIP-44 v2 test suite — offline roundtrip + property tests.

Run with:
    python nip44_test.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nip44 import (
    get_conversation_key,
    get_message_keys,
    calc_padded_len,
    encrypt_with_key,
    decrypt_with_key,
    encrypt,
    decrypt,
    pad,
    unpad,
    _ecdh_shared_x,
)

import secrets
import coincurve

# calc_padded_len: [length, padded]
PADDED_LEN_VECTORS = [
    [0, 32], [1, 32], [32, 32], [33, 64], [64, 64], [65, 96],
    [96, 96], [97, 128], [128, 128], [129, 160], [320, 320], [321, 384],
]

PASS = 0
FAIL = 0

def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print(f"  ✗ {label}")


def test_calc_padded_len():
    print("── calc_padded_len ──")
    for length, expected in PADDED_LEN_VECTORS:
        got = calc_padded_len(length)
        check(got == expected, f"calc_padded_len({length}) = {got}, expected {expected}")


def test_padding_roundtrip():
    print("── padding roundtrip ──")
    for length in [1, 16, 31, 32, 33, 64, 100, 200, 500, 1000, 4096]:
        msg = "a" * length
        padded = pad(msg)
        unpadded = unpad(padded)
        check(unpadded == msg, f"pad/unpad({length}): roundtrip mismatch")


def _make_keypair():
    """Generate a random keypair and return (sec_hex, pub_xonly_hex)."""
    sec = secrets.token_bytes(32)
    pk = coincurve.PrivateKey(sec)
    # x-only pubkey = first 32 bytes of uncompressed (skip 0x04 prefix)
    pub_xonly = pk.public_key.format(compressed=False)[1:33].hex()
    return sec.hex(), pub_xonly


def test_encrypt_decrypt_roundtrip():
    print("── encrypt/decrypt roundtrip ──")
    sec_a, pub_a = _make_keypair()
    sec_b, pub_b = _make_keypair()

    messages = [
        "a",
        "Hello, World!",
        "🌍 unicode test 🔐",
        "A" * 100,
        "B" * 1000,
        '{"type":"announce","peerId":"abc1234567890def"}',
        "x" * 65535,
    ]

    for msg in messages:
        # A encrypts to B
        encrypted = encrypt(msg, sec_a, pub_b)
        check(encrypted != msg, f"encrypt({msg[:20]!r}): ciphertext should differ")
        # B decrypts from A
        decrypted = decrypt(encrypted, sec_b, pub_a)
        check(decrypted == msg, f"roundtrip({msg[:20]!r}): mismatch")


def test_bidirectional():
    print("── bidirectional ──")
    # Party A: sec_a, pub_a (pub_a derived from sec_a)
    # Party B: sec_b, pub_b
    sec_a, pub_a = _make_keypair()
    sec_b, pub_b = _make_keypair()

    # A → B: A encrypts with (sec_a, pub_b); B decrypts with (sec_b, pub_a)
    msg = "alice to bob"
    encrypted = encrypt(msg, sec_a, pub_b)
    decrypted = decrypt(encrypted, sec_b, pub_a)
    check(decrypted == msg, "A→B: decrypt mismatch")

    # B → A: B encrypts with (sec_b, pub_a); A decrypts with (sec_a, pub_b)
    msg2 = "bob to alice"
    encrypted2 = encrypt(msg2, sec_b, pub_a)
    decrypted2 = decrypt(encrypted2, sec_a, pub_b)
    check(decrypted2 == msg2, "B→A: decrypt mismatch")


def test_empty_message():
    print("── single-char message ──")
    sec_a, pub_a = _make_keypair()
    sec_b, pub_b = _make_keypair()
    encrypted = encrypt("x", sec_a, pub_b)
    decrypted = decrypt(encrypted, sec_b, pub_a)
    check(decrypted == "x", "single-char message: roundtrip mismatch")


def test_invalid_payload():
    print("── invalid payload handling ──")
    sec_a, pub_a = _make_keypair()
    sec_b, pub_b = _make_keypair()

    try:
        decrypt("0", sec_b, pub_a)
        check(False, "short payload: should raise")
    except Exception:
        check(True, "short payload: correctly raised")

    try:
        decrypt("not-valid-base64!!", sec_b, pub_a)
        check(False, "malformed payload: should raise")
    except Exception:
        check(True, "malformed payload: correctly raised")


def test_nonce_uniqueness():
    print("── nonce uniqueness ──")
    sec_a, pub_a = _make_keypair()
    sec_b, pub_b = _make_keypair()
    encrypted1 = encrypt("same message", sec_a, pub_b)
    encrypted2 = encrypt("same message", sec_a, pub_b)
    check(encrypted1 != encrypted2, "same message, different nonce → different ciphertext")


def test_message_key_derivation():
    print("── message key derivation ──")
    ck = secrets.token_bytes(32)
    nonce1 = secrets.token_bytes(32)
    nonce2 = secrets.token_bytes(32)

    ck1, cn1, hk1 = get_message_keys(ck, nonce1)
    ck2, cn2, hk2 = get_message_keys(ck, nonce2)

    check(ck1 != ck2, "different nonces → different chacha_key")
    check(hk1 != hk2, "different nonces → different hmac_key")


if __name__ == "__main__":
    print()
    test_calc_padded_len()
    test_padding_roundtrip()
    test_encrypt_decrypt_roundtrip()
    test_bidirectional()
    test_empty_message()
    test_invalid_payload()
    test_nonce_uniqueness()
    test_message_key_derivation()

    print(f"\n{'='*40}")
    print(f"NIP-44 tests: {PASS} passed, {FAIL} failed")
    if FAIL > 0:
        sys.exit(1)
    print("All tests passed ✅")
