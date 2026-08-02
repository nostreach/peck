"""
peck Policy-Engine — Spec 026 (Access Control / Gate).

A single-filter-point policy engine: given an incoming announce (pubkey +
self-declared client_ip), decide allow / deny / loud-deny.

Design (see specs/026-access-control/spec.md + plan.md):
  - One YAML policy file, hot-reloadable via reload() (SIGHUP)
  - Rule matching is top-down, first-match-wins; empty lists match all
  - Backwards compatible: no policy file = default_effect: allow
  - Privacy-by-design: audit log uses PBKDF2-salted hashes
  - Loud-deny payloads are byte-identical (FR-008, anti-enumeration)

Schema (YAML):

    default_effect: allow            # allow | deny | loud-deny
    rules:
      - comment: "alice allowed"
        pubkeys: [npub1alice…]       # list of npub OR hex pubkeys
        client_ips: [10.0.0.0/8]     # list of IPv4/IPv6 CIDR
        asn: [12345]                 # list of ASN integers (optional, needs geoip2)
        country: [DE]                # list of ISO 3166-1 alpha-2 (optional, needs geoip2)
        effect: allow                # allow | deny | loud-deny
        message: "..."               # only for loud-deny (optional)
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from bech32m import npub_to_pubkey_hex, normalize_pubkey as normalise_pubkey

log = logging.getLogger("peck.policy")

# All Bech32m functions now live in bech32m.py (CQ-3 dedup).


# ─── Data classes ──────────────────────────────────────────────────────

@dataclass
class RegionDef:
    """A named group of countries + ASNs, reusable across rules."""
    countries: frozenset[str] = field(default_factory=frozenset)
    asns: frozenset[int] = field(default_factory=frozenset)


@dataclass
class PolicyRule:
    """One rule in the policy. All criteria AND-matched; empty = match-all."""
    comment: Optional[str] = None
    pubkeys: list[str] = field(default_factory=list)        # normalised to hex
    client_ips: list[str] = field(default_factory=list)      # kept as strings, parsed lazily
    asn: list[int] = field(default_factory=list)
    country: list[str] = field(default_factory=list)         # uppercase ISO codes
    effect: str = "allow"                                    # allow | deny | loud-deny
    message: Optional[str] = None                            # only for loud-deny
    # Region matching (resolved at Policy.from_dict time from region definitions)
    region_countries: frozenset[str] = field(default_factory=frozenset)
    region_asns: frozenset[int] = field(default_factory=frozenset)
    # Terms of Service
    require_terms: bool = False
    terms_text: Optional[str] = None
    terms_version: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict, regions: Optional[dict[str, RegionDef]] = None) -> "PolicyRule":
        if d.get("effect") not in (None, "allow", "deny", "loud-deny"):
            raise ValueError(f"rule has invalid effect: {d.get('effect')!r}")
        pubkeys_in = d.get("pubkeys") or []
        pubkeys = []
        for p in pubkeys_in:
            try:
                pubkeys.append(normalise_pubkey(p))
            except ValueError as e:
                raise ValueError(f"rule 'pubkeys' has bad entry: {e}") from e
        # Normalise IPs lazily — validate at load time
        client_ips = list(d.get("client_ips") or [])
        for ip in client_ips:
            try:
                ipaddress.ip_network(ip, strict=False)
            except ValueError as e:
                raise ValueError(f"rule 'client_ips' has bad entry {ip!r}: {e}") from e
        asn_in = d.get("asn") or []
        if not isinstance(asn_in, list) or any(not isinstance(a, int) for a in asn_in):
            raise ValueError(f"rule 'asn' must be list of ints, got: {asn_in!r}")
        country_in = [str(c).upper() for c in (d.get("country") or [])]

        # Region resolution
        region_name = d.get("region")
        region_countries: frozenset[str] = frozenset()
        region_asns: frozenset[int] = frozenset()
        if region_name:
            if not regions or region_name not in regions:
                raise ValueError(f"rule references undefined region: {region_name!r}")
            rd = regions[region_name]
            region_countries = rd.countries
            region_asns = rd.asns

        # Terms of Service
        require_terms = bool(d.get("require_terms", False))
        terms_text = d.get("terms_text")
        terms_file = d.get("terms_file")
        terms_version = d.get("terms_version")

        if require_terms:
            # terms_file takes precedence over terms_text
            if terms_file:
                try:
                    terms_text = Path(terms_file).read_text()
                    log.info(f"Loaded terms from {terms_file} ({len(terms_text)} chars)")
                except OSError as e:
                    raise ValueError(f"Cannot read terms_file {terms_file!r}: {e}") from e
            if not terms_text:
                raise ValueError("rule has require_terms=true but no terms_text or terms_file")
            if not terms_version:
                raise ValueError("rule has require_terms=true but no terms_version")
        elif terms_text or terms_file:
            log.warning(f"rule has terms_text/terms_file without require_terms — ignored")

        return cls(
            comment=d.get("comment"),
            pubkeys=pubkeys,
            client_ips=client_ips,
            asn=asn_in,
            country=country_in,
            effect=d.get("effect", "allow"),
            message=d.get("message"),
            region_countries=region_countries,
            region_asns=region_asns,
            require_terms=require_terms,
            terms_text=terms_text if require_terms else None,
            terms_version=terms_version if require_terms else None,
        )

    def matches(self, pubkey_hex: str, client_ip: Optional[str],
                geoip_lookup: Optional[callable] = None) -> bool:
        """All non-empty criteria must match. Empty criterion = match-all."""
        if self.pubkeys and pubkey_hex not in self.pubkeys:
            return False
        if self.client_ips:
            if not client_ip or not _ip_in_any(client_ip, self.client_ips):
                return False
        # GeoIP-based criteria: direct (country, asn) + region (region_countries, region_asns)
        needs_geoip = bool(self.asn or self.country or self.region_countries or self.region_asns)
        if needs_geoip:
            if not client_ip or not geoip_lookup:
                return False  # IP-based criteria with no IP / no lookup → no match
            info = geoip_lookup(client_ip)
            client_country = info.get("country")
            client_asn = info.get("asn")
            if self.asn and client_asn not in self.asn:
                return False
            if self.country and client_country not in self.country:
                return False
            if self.region_countries and client_country not in self.region_countries:
                return False
            if self.region_asns and client_asn not in self.region_asns:
                return False
        return True


def _ip_in_any(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


@dataclass
class Policy:
    default_effect: str = "allow"
    rules: list[PolicyRule] = field(default_factory=list)
    regions: dict[str, RegionDef] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        default = d.get("default_effect", "allow")
        if default not in ("allow", "deny", "loud-deny"):
            raise ValueError(f"default_effect must be allow|deny|loud-deny, got: {default!r}")

        # Parse regions block
        regions: dict[str, RegionDef] = {}
        regions_raw = d.get("regions") or {}
        if not isinstance(regions_raw, dict):
            raise ValueError(f"'regions' must be a mapping, got {type(regions_raw).__name__}")
        for name, spec in regions_raw.items():
            if not isinstance(spec, dict):
                raise ValueError(f"region {name!r} must be a mapping, got {type(spec).__name__}")
            countries = frozenset(str(c).upper() for c in (spec.get("countries") or []))
            asns = frozenset(int(a) for a in (spec.get("asns") or []))
            regions[name] = RegionDef(countries=countries, asns=asns)

        rules_raw = d.get("rules") or []
        if not isinstance(rules_raw, list):
            raise ValueError(f"'rules' must be a list, got {type(rules_raw).__name__}")
        rules = [PolicyRule.from_dict(r, regions=regions) for r in rules_raw]
        return cls(default_effect=default, rules=rules, regions=regions)

    @classmethod
    def allow_all(cls) -> "Policy":
        return cls(default_effect="allow", rules=[])


@dataclass
class Decision:
    effect: str                   # allow | deny | loud-deny
    message: Optional[str] = None # only for loud-deny
    matched_comment: Optional[str] = None  # rule.comment for logging/audit
    matched_index: Optional[int] = None    # 0-based rule index, None = default
    # Terms of Service (only set when matched rule has require_terms=true)
    terms_text: Optional[str] = None
    terms_version: Optional[str] = None


# ─── Loud-deny payload (FR-008: byte-identical size) ───────────────────

# FR-008: All loud-deny messages padded to identical size so clients
# can't enumerate deny reasons by payload length. 256 bytes is enough
# for a short human-readable message and leaves room.
LOUD_DENY_PAD_SIZE = 256


def pad_message(msg: Optional[str]) -> str:
    """Pad message to exactly LOUD_DENY_PAD_SIZE bytes (null-padded)."""
    raw = (msg or "").encode("utf-8")
    if len(raw) > LOUD_DENY_PAD_SIZE:
        # Truncate on utf-8 boundary to avoid mojibake
        raw = raw[:LOUD_DENY_PAD_SIZE]
        # back off to last complete utf-8 char
        while raw and (raw[-1] & 0xC0) == 0x80:
            raw = raw[:-1]
    padded = raw.ljust(LOUD_DENY_PAD_SIZE, b"\x00")
    return padded.decode("utf-8", errors="replace")


# ─── Audit log (optional) ──────────────────────────────────────────────

class AuditLogger:
    """
    Privacy-by-design audit log: pubkeys and IPs are hashed with PBKDF2
    (100k iterations) + salt. Within one daemon run, the same client
    produces the same hash (correlation possible). Across runs, the salt
    rotates (correlation impossible).

    JSON-Lines format:
      {"ts": "2026-07-19T12:00:00Z", "pubkey_hash": "...", "ip_hash": "...",
       "effect": "deny", "rule": "block-abuse"}
    """

    def __init__(self, path: str, salt: Optional[bytes] = None, plaintext: bool = False):
        self.path = path
        self.plaintext = plaintext
        if salt is None:
            salt = secrets.token_bytes(16)
            # Write salt once at start of new file so runs are self-documenting
            self._salt_header_written = False
        else:
            self._salt_header_written = True
        self.salt = salt

    def _hash(self, value: str) -> str:
        if self.plaintext:
            return value
        h = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), self.salt, 100_000)
        return "$pbkdf2-sha256$" + h.hex()

    def log_decision(self, decision: Decision, pubkey_hex: str, client_ip: Optional[str]) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pubkey": self._hash(pubkey_hex),
            "ip": self._hash(client_ip) if client_ip else None,
            "effect": decision.effect,
            "rule": decision.matched_comment,
        }
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a") as f:
            if not self._salt_header_written:
                # First entry of a new run: emit a comment line with the salt
                # so the run can be (later) re-correlated if the operator
                # extracts the salt from daemon logs.
                if os.path.getsize(self.path) == 0:
                    f.write(f"# salt={self.salt.hex()}\n")
                self._salt_header_written = True
            f.write(json.dumps(entry) + "\n")


# ─── Policy engine ─────────────────────────────────────────────────────

class PolicyEngine:
    """
    Loads a YAML policy from disk, decides each announce, supports
    hot-reload via reload(). Thread-safe via atomic swap.

    Usage:
        engine = PolicyEngine.from_path("/etc/peck/policy.yaml")
        decision = engine.decide(pubkey_hex, client_ip)
        # later, on SIGHUP:
        engine.reload()
    """

    def __init__(
        self,
        policy_path: Optional[str] = None,
        policy: Optional[Policy] = None,
        audit_logger: Optional[AuditLogger] = None,
        geoip_lookup: Optional[callable] = None,
    ):
        self.policy_path = policy_path
        self.audit_logger = audit_logger
        self.geoip_lookup = geoip_lookup
        if policy is not None:
            self._policy = policy
        elif policy_path:
            self._policy = self._load_from_path(policy_path)
        else:
            self._policy = Policy.allow_all()
            log.info("no policy file — running default-allow (backwards compat)")

    @classmethod
    def from_path(cls, path: str, **kwargs) -> "PolicyEngine":
        return cls(policy_path=path, **kwargs)

    def _load_from_path(self, path: str) -> Policy:
        try:
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
        except FileNotFoundError:
            log.warning(f"policy file {path!r} not found — running default-allow")
            return Policy.allow_all()
        except yaml.YAMLError as e:
            raise PolicyLoadError(f"YAML parse error in {path}: {e}") from e
        if not isinstance(raw, dict):
            raise PolicyLoadError(f"policy root must be a mapping, got {type(raw).__name__}")
        try:
            policy = Policy.from_dict(raw)
        except ValueError as e:
            raise PolicyLoadError(f"policy schema error in {path}: {e}") from e
        log.info(f"policy loaded from {path}: {len(policy.rules)} rules, default={policy.default_effect}")
        return policy

    def reload(self) -> None:
        """
        Reload policy from disk. On error, keep the old policy and log.
        Atomic from the decide()-perspective: we swap self._policy in one
        assignment.
        """
        if not self.policy_path:
            log.info("reload requested but no policy_path set — nothing to reload")
            return
        try:
            new_policy = self._load_from_path(self.policy_path)
            self._policy = new_policy  # atomic swap
            log.info(f"policy reloaded: {len(new_policy.rules)} rules, default={new_policy.default_effect}")
        except PolicyLoadError as e:
            log.error(f"policy reload failed: {e} — keeping old policy ({len(self._policy.rules)} rules)")
        except Exception as e:
            log.error(f"policy reload unexpected error: {e} — keeping old policy")

    def decide(self, pubkey_hex: str, client_ip: Optional[str]) -> Decision:
        """
        First-match-wins. Empty criteria on a rule match-all.
        Returns Decision with effect in {allow, deny, loud-deny}.

        Side effect: writes to audit log if configured AND effect != allow.
        """
        # Normalise pubkey
        try:
            pubkey_norm = normalise_pubkey(pubkey_hex)
        except ValueError:
            # Malformed pubkey — log and default-deny for safety
            log.warning(f"malformed pubkey in decide(): {pubkey_hex[:20]}… — defaulting")
            decision = Decision(
                effect=self._policy.default_effect if self._policy.default_effect == "allow" else "deny",
                matched_comment="malformed-pubkey",
            )
            self._maybe_audit(decision, pubkey_hex, client_ip)
            return decision

        for idx, rule in enumerate(self._policy.rules):
            if rule.matches(pubkey_norm, client_ip, self.geoip_lookup):
                decision = Decision(
                    effect=rule.effect,
                    message=rule.message,
                    matched_comment=rule.comment,
                    matched_index=idx,
                    terms_text=rule.terms_text if rule.require_terms else None,
                    terms_version=rule.terms_version if rule.require_terms else None,
                )
                self._maybe_audit(decision, pubkey_norm, client_ip)
                return decision

        # No rule matched → default
        decision = Decision(
            effect=self._policy.default_effect,
            matched_comment=None,
            matched_index=None,
        )
        self._maybe_audit(decision, pubkey_norm, client_ip)
        return decision

    def _maybe_audit(self, decision: Decision, pubkey_hex: str, client_ip: Optional[str]) -> None:
        if self.audit_logger and decision.effect != "allow":
            self.audit_logger.log_decision(decision, pubkey_hex, client_ip)

    # Operator convenience
    @property
    def rule_count(self) -> int:
        return len(self._policy.rules)

    @property
    def default_effect(self) -> str:
        return self._policy.default_effect


class PolicyLoadError(Exception):
    """Raised when the policy file fails to parse or validate."""
    pass
