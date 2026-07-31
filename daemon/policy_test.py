"""
Unit tests for policy.py (Spec 026 — Access Control / Gate).

Covers: 5 user stories from spec.md
  US1: private daemon (allow specific pubkey, deny rest)
  US2: block abuse pubkey (allow rest)
  US3: loud-deny with message (byte-identical size)
  US4: hot-reload via reload()
  US5: ASN/GeoIP (mocked lookup)
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from policy import (
    AuditLogger,
    Decision,
    Policy,
    PolicyEngine,
    PolicyLoadError,
    PolicyRule,
    LOUD_DENY_PAD_SIZE,
    normalise_pubkey,
    npub_to_pubkey_hex,
    pad_message,
)

# Daemon's well-known test pubkey (hex) — use a stable fixture
ALICE_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
ALICE_HEX = "a" * 64  # use a real-shape hex
BOB_HEX = "b" * 64
BOT_HEX = "c" * 64


def _make_engine(yaml_text: str) -> PolicyEngine:
    """Build a PolicyEngine from inline YAML."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        path = f.name
    return PolicyEngine.from_path(path)


class TestNormalisePubkey(unittest.TestCase):
    def test_hex_passthrough(self):
        h = "ab" * 32
        self.assertEqual(normalise_pubkey(h), h)

    def test_hex_uppercase_normalised(self):
        h = "AB" * 32
        self.assertEqual(normalise_pubkey(h), ("ab" * 32))

    def test_round_trip_npub(self):
        # Encode hex → npub, decode back via policy.normalise_pubkey
        from route_table import pubkey_hex_to_npub
        npub = pubkey_hex_to_npub(ALICE_HEX)
        self.assertEqual(normalise_pubkey(npub), ALICE_HEX)

    def test_invalid_npub(self):
        # Any invalid npub string should raise ValueError
        with self.assertRaises(ValueError):
            # "npub1" + invalid data → either charset error or checksum error
            normalise_pubkey("npub1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

    def test_invalid_hex(self):
        with self.assertRaises(ValueError):
            normalise_pubkey("xyz")


class TestPolicyRule(unittest.TestCase):
    def test_empty_rule_matches_all(self):
        rule = PolicyRule(effect="deny")
        self.assertTrue(rule.matches(ALICE_HEX, None))
        self.assertTrue(rule.matches(BOB_HEX, "1.2.3.4"))

    def test_pubkey_match(self):
        rule = PolicyRule(pubkeys=[ALICE_HEX], effect="allow")
        self.assertTrue(rule.matches(ALICE_HEX, None))
        self.assertFalse(rule.matches(BOB_HEX, None))

    def test_client_ip_match(self):
        rule = PolicyRule(client_ips=["10.0.0.0/8"], effect="deny")
        self.assertTrue(rule.matches(ALICE_HEX, "10.1.2.3"))
        self.assertFalse(rule.matches(ALICE_HEX, "11.0.0.1"))

    def test_ip_missing_skips_rule(self):
        rule = PolicyRule(client_ips=["10.0.0.0/8"], effect="deny")
        self.assertFalse(rule.matches(ALICE_HEX, None))

    def test_and_matching(self):
        rule = PolicyRule(pubkeys=[ALICE_HEX], client_ips=["1.2.3.0/24"], effect="deny")
        # Both match
        self.assertTrue(rule.matches(ALICE_HEX, "1.2.3.10"))
        # Only pubkey matches
        self.assertFalse(rule.matches(ALICE_HEX, "9.9.9.9"))
        # Only IP matches
        self.assertFalse(rule.matches(BOB_HEX, "1.2.3.10"))

    def test_asn_match_with_lookup(self):
        rule = PolicyRule(asn=[12345], effect="deny")
        lookup = lambda ip: {"asn": 12345, "country": "DE"}
        self.assertTrue(rule.matches(ALICE_HEX, "1.2.3.4", geoip_lookup=lookup))

    def test_asn_no_lookup_no_match(self):
        rule = PolicyRule(asn=[12345], effect="deny")
        # No lookup provided → ASN criteria can't be evaluated → no match
        self.assertFalse(rule.matches(ALICE_HEX, "1.2.3.4", geoip_lookup=None))


class TestPolicyEngine(unittest.TestCase):
    def test_default_allow_no_policy_file(self):
        engine = PolicyEngine()  # no path
        d = engine.decide(ALICE_HEX, None)
        self.assertEqual(d.effect, "allow")

    def test_default_deny_with_empty_rules(self):
        engine = _make_engine("""
default_effect: deny
rules: []
""")
        d = engine.decide(ALICE_HEX, None)
        self.assertEqual(d.effect, "deny")

    def test_us1_private_daemon(self):
        """User Story 1: allow only ALICE, deny everyone else."""
        engine = _make_engine(f"""
default_effect: deny
rules:
  - comment: "alice allowed"
    pubkeys: ["{ALICE_HEX}"]
    effect: allow
""")
        d_alice = engine.decide(ALICE_HEX, None)
        self.assertEqual(d_alice.effect, "allow")
        self.assertEqual(d_alice.matched_comment, "alice allowed")

        d_bob = engine.decide(BOB_HEX, None)
        self.assertEqual(d_bob.effect, "deny")
        self.assertIsNone(d_bob.matched_comment)  # default, no rule

    def test_us2_block_abuse(self):
        """User Story 2: default allow, deny specific abuse pubkey."""
        engine = _make_engine(f"""
default_effect: allow
rules:
  - comment: "block bot"
    pubkeys: ["{BOT_HEX}"]
    effect: deny
""")
        d_bot = engine.decide(BOT_HEX, None)
        self.assertEqual(d_bot.effect, "deny")
        self.assertEqual(d_bot.matched_comment, "block bot")

        d_alice = engine.decide(ALICE_HEX, None)
        self.assertEqual(d_alice.effect, "allow")

    def test_us3_loud_deny_with_message(self):
        """User Story 3: loud-deny with message, byte-identical size."""
        engine = _make_engine(f"""
default_effect: allow
rules:
  - comment: "freerider"
    pubkeys: ["{BOB_HEX}"]
    effect: loud-deny
    message: "payment required, see https://example.com/pay"
""")
        d = engine.decide(BOB_HEX, None)
        self.assertEqual(d.effect, "loud-deny")
        self.assertEqual(d.message, "payment required, see https://example.com/pay")

        # Byte-identical size: pad_message truncates/pads to LOUD_DENY_PAD_SIZE
        padded1 = pad_message("short")
        padded2 = pad_message("a much longer message " * 20)
        self.assertEqual(len(padded1.encode()), LOUD_DENY_PAD_SIZE)
        self.assertEqual(len(padded2.encode()), LOUD_DENY_PAD_SIZE)

    def test_us4_hot_reload(self):
        """User Story 4: reload() picks up policy changes."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(f"""
default_effect: allow
rules:
  - pubkeys: ["{ALICE_HEX}"]
    effect: deny
""")
            path = f.name

        engine = PolicyEngine.from_path(path)
        self.assertEqual(engine.decide(ALICE_HEX, None).effect, "deny")

        # Edit file
        with open(path, "w") as f:
            f.write(f"""
default_effect: allow
rules:
  - pubkeys: ["{BOB_HEX}"]
    effect: deny
""")

        engine.reload()
        self.assertEqual(engine.decide(ALICE_HEX, None).effect, "allow")  # was deny
        self.assertEqual(engine.decide(BOB_HEX, None).effect, "deny")    # now deny

    def test_us4_reload_syntax_error_keeps_old(self):
        """User Story 4: on reload error, old policy stays active."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(f"""
default_effect: allow
rules:
  - pubkeys: ["{ALICE_HEX}"]
    effect: deny
""")
            path = f.name

        engine = PolicyEngine.from_path(path)
        self.assertEqual(engine.decide(ALICE_HEX, None).effect, "deny")

        # Corrupt the file
        with open(path, "w") as f:
            f.write("this: is: not: valid: yaml: [[[")
        engine.reload()
        # Old policy still active
        self.assertEqual(engine.decide(ALICE_HEX, None).effect, "deny")

    def test_us5_asn_filter(self):
        """User Story 5: ASN block via mocked geoip lookup."""
        engine = _make_engine("""
default_effect: allow
rules:
  - comment: "block bad ASN"
    asn: [12345]
    effect: deny
""")
        # Wire in a mock lookup
        engine.geoip_lookup = lambda ip: {"asn": 12345, "country": "DE"}
        d_bad = engine.decide(ALICE_HEX, "1.2.3.4")
        self.assertEqual(d_bad.effect, "deny")

        engine.geoip_lookup = lambda ip: {"asn": 99999, "country": "DE"}
        d_ok = engine.decide(ALICE_HEX, "1.2.3.4")
        self.assertEqual(d_ok.effect, "allow")

    def test_first_match_wins(self):
        engine = _make_engine(f"""
default_effect: allow
rules:
  - comment: "alice deny"
    pubkeys: ["{ALICE_HEX}"]
    effect: deny
  - comment: "alice allow"
    pubkeys: ["{ALICE_HEX}"]
    effect: allow
""")
        d = engine.decide(ALICE_HEX, None)
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.matched_comment, "alice deny")
        self.assertEqual(d.matched_index, 0)

    def test_missing_client_ip_falls_back_to_pubkey_rules(self):
        """FR-010: missing IP doesn't break pubkey-only rules."""
        engine = _make_engine(f"""
default_effect: allow
rules:
  - comment: "block bot by pubkey"
    pubkeys: ["{BOT_HEX}"]
    effect: deny
  - comment: "block some ASN"
    asn: [12345]
    effect: deny
""")
        # Bot pubkey blocked even without IP
        d = engine.decide(BOT_HEX, None)
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.matched_comment, "block bot by pubkey")

        # Alice without IP — ASN rule can't match, default allow
        d = engine.decide(ALICE_HEX, None)
        self.assertEqual(d.effect, "allow")


class TestPadMessage(unittest.TestCase):
    def test_pads_short_message(self):
        padded = pad_message("hi")
        self.assertEqual(len(padded.encode()), LOUD_DENY_PAD_SIZE)

    def test_truncates_long_message(self):
        padded = pad_message("x" * 1000)
        self.assertEqual(len(padded.encode()), LOUD_DENY_PAD_SIZE)

    def test_none_message(self):
        padded = pad_message(None)
        self.assertEqual(len(padded.encode()), LOUD_DENY_PAD_SIZE)


class TestAuditLogger(unittest.TestCase):
    def test_hashes_pubkey_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "audit.log")
            audit = AuditLogger(log_path)
            decision = Decision(effect="deny", matched_comment="test-rule")
            audit.log_decision(decision, ALICE_HEX, "1.2.3.4")

            with open(log_path) as f:
                content = f.read()
            # Pubkey is hashed — no plaintext in file
            self.assertNotIn(ALICE_HEX, content)
            # But it's a pbkdf2 hash
            self.assertIn("$pbkdf2-sha256$", content)

    def test_plaintext_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "audit.log")
            audit = AuditLogger(log_path, plaintext=True)
            decision = Decision(effect="deny")
            audit.log_decision(decision, ALICE_HEX, "1.2.3.4")

            with open(log_path) as f:
                content = f.read()
            self.assertIn(ALICE_HEX, content)
            self.assertIn("1.2.3.4", content)

    def test_json_lines_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "audit.log")
            audit = AuditLogger(log_path)
            audit.log_decision(
                Decision(effect="loud-deny", matched_comment="paid-only"),
                ALICE_HEX, "1.2.3.4",
            )

            import json
            with open(log_path) as f:
                lines = [l for l in f.read().splitlines() if l and not l.startswith("#")]
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["effect"], "loud-deny")
            self.assertEqual(entry["rule"], "paid-only")


class TestPolicyYAMLLoading(unittest.TestCase):
    def test_invalid_effect(self):
        with self.assertRaises(PolicyLoadError):
            _make_engine("""
default_effect: frobnicate
rules: []
""")

    def test_invalid_rule_effect(self):
        with self.assertRaises(PolicyLoadError):
            _make_engine("""
default_effect: allow
rules:
  - effect: frobnicate
""")

    def test_invalid_client_ip(self):
        with self.assertRaises(PolicyLoadError):
            _make_engine("""
default_effect: allow
rules:
  - client_ips: ["not-an-ip"]
    effect: deny
""")

    def test_empty_rules_key(self):
        engine = _make_engine("""
default_effect: deny
""")
        d = engine.decide(ALICE_HEX, None)
        self.assertEqual(d.effect, "deny")

    def test_missing_file_defaults_to_allow_all(self):
        engine = PolicyEngine.from_path("/nonexistent/policy.yaml")
        self.assertEqual(engine.decide(ALICE_HEX, None).effect, "allow")


if __name__ == "__main__":
    unittest.main()
