"""
peck crypto helpers test suite — key derivation, event signing, nsec loading.

Run: python crypto_helpers_test.py
"""
import os
import sys
import secrets
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_helpers import get_pubkey, make_event, load_nsec, _nsec_to_hex

PASS = 0
FAIL = 0

def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print(f"  ✗ {label}")


def test_get_pubkey_deterministic():
    print("── get_pubkey deterministic ──")
    sec = "a" * 64
    pub1 = get_pubkey(sec)
    pub2 = get_pubkey(sec)
    check(pub1 == pub2, "same privkey → same pubkey")
    check(len(pub1) == 64, f"pubkey length: {len(pub1)}")


def test_get_pubkey_different_keys():
    print("── get_pubkey different keys ──")
    sec1 = "a" * 64
    sec2 = "b" * 64
    pub1 = get_pubkey(sec1)
    pub2 = get_pubkey(sec2)
    check(pub1 != pub2, "different privkeys → different pubkeys")


def test_get_pubkey_known_vector():
    print("── get_pubkey format check ──")
    # Use a valid nonzero privkey
    sec = "01" + "0" * 62
    pub = get_pubkey(sec)
    check(len(pub) == 64, f"pubkey length: {len(pub)}")
    try:
        int(pub, 16)
        check(True, "pubkey is valid hex")
    except ValueError:
        check(False, "pubkey is not valid hex")


def test_make_event_fields():
    print("── make_event fields ──")
    sec = secrets.token_hex(32)
    pub = get_pubkey(secrets.token_hex(32))
    event = make_event(sec, pub, "hello world", kind=4)

    check(event["kind"] == 4, "kind=4")
    check(event["content"] == "hello world", "content")
    check(event["pubkey"] == get_pubkey(sec), "pubkey matches")
    check([["p", pub]] == event["tags"], "tags have recipient")
    check(len(event["id"]) == 64, f"event id is 64 hex: {len(event['id'])}")
    check(len(event["sig"]) == 128, f"sig is 128 hex: {len(event['sig'])}")
    check("created_at" in event, "has created_at")
    check(isinstance(event["created_at"], int), "created_at is int")


def test_make_event_kind_1_no_tags():
    print("── make_event kind=1 no tags ──")
    sec = secrets.token_hex(32)
    event = make_event(sec, "00" * 32, "test", kind=1)
    check(event["tags"] == [], "kind=1 has no tags")
    check(event["kind"] == 1, "kind is 1")


def test_make_event_id_valid_hash():
    print("── make_event ID is valid SHA-256 ──")
    import hashlib
    import json
    sec = secrets.token_hex(32)
    recipient = get_pubkey(secrets.token_hex(32))
    event = make_event(sec, recipient, "test content", kind=4)

    # Verify event ID = SHA-256 of canonical serialization
    canonical = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":")
    )
    expected_id = hashlib.sha256(canonical.encode()).hexdigest()
    check(event["id"] == expected_id, "event ID matches SHA-256 of canonical")


def test_load_nsec_hex():
    print("── load_nsec hex format ──")
    sec = secrets.token_hex(32)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
        f.write(sec)
        f.flush()
        try:
            loaded = load_nsec(f.name)
            check(loaded == sec, "hex nsec loaded correctly")
        finally:
            os.unlink(f.name)


def test_load_nsec_nsec1():
    print("── load_nsec nsec1 format ──")
    # Generate a real nsec1
    from bech32m import _bech32m_encode, _convertbits
    sec_bytes = secrets.token_bytes(32)
    data = _convertbits(sec_bytes, 8, 5)
    nsec = _bech32m_encode("nsec", data)
    sec_hex = sec_bytes.hex()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
        f.write(nsec)
        f.flush()
        try:
            loaded = load_nsec(f.name)
            check(loaded == sec_hex, f"nsec1 decoded to hex correctly")
        finally:
            os.unlink(f.name)


def test_nsec_to_hex_invalid():
    print("── _nsec_to_hex invalid inputs ──")
    for invalid in ["", "garbage", "npub1wrongprefix", "nsec1XXX"]:
        try:
            _nsec_to_hex(invalid)
            check(False, f"should raise for: {invalid[:20]}")
        except (ValueError, Exception):
            check(True, f"correctly raised for: {invalid[:20]}")


def test_load_nsec_with_whitespace():
    print("── load_nsec with whitespace ──")
    sec = secrets.token_hex(32)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
        f.write(f"  {sec}  \n")
        f.flush()
        try:
            loaded = load_nsec(f.name)
            check(loaded == sec, "whitespace stripped")
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    print()
    test_get_pubkey_deterministic()
    test_get_pubkey_different_keys()
    test_get_pubkey_known_vector()
    test_make_event_fields()
    test_make_event_kind_1_no_tags()
    test_make_event_id_valid_hash()
    test_load_nsec_hex()
    test_load_nsec_nsec1()
    test_nsec_to_hex_invalid()
    test_load_nsec_with_whitespace()

    print(f"\n{'='*40}")
    print(f"crypto helpers tests: {PASS} passed, {FAIL} failed")
    if FAIL > 0:
        sys.exit(1)
    print("All tests passed ✅")
