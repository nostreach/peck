"""
peck route_table — Spec 024: Multi-Level Subdomain Routing.

A RouteTable maps subdomain paths to backend URLs, supporting:
- Default route (empty subdomain path → root backend)
- Specific routes (e.g. ["blog"] → blog backend)
- Nested routes (e.g. ["v2", "api"] → v2.api backend)
- Wildcard fallback ("*")
- Port-based backwards compatibility (--ports)

Resolution order (most specific first):
    1. Exact match on full subdomain path
    2. Wildcard "*" (if configured)
    3. None (caller emits 404)

The table is loaded from YAML or built from legacy --ports mappings.
"""

from __future__ import annotations

import re
from typing import Optional

from bech32m import pubkey_hex_to_npub, npub_to_pubkey_hex


# ─── Re-exports for backwards compat (client.py, daemon.py import from here) ──
# All Bech32m functions now live in bech32m.py (CQ-3 dedup).
# route_table.py re-exports the two public functions for callers that still
# import from route_table.


# ─── RouteTable ───────────────────────────────────────────────────────────


class RouteTableError(Exception):
    """Raised on invalid route-table configuration."""


# RFC 1035 limits
MAX_LABEL_LEN = 63
MAX_HOSTNAME_LEN = 253

# A single DNS label: letters, digits, hyphens. No leading/trailing hyphen.
_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def extract_subdomain_path(
    host_header: str,
    context_root: str,
    domain_suffix: str,
) -> Optional[list[str]]:
    """Parse a Host header into the subdomain path relative to the context-root.

    Algorithm (Spec 024 FR-009):
        1. Strip port if present (FR-007)
        2. Validate hostname length (FR-017)
        3. Strip domain suffix (FR-006 rejects foreign suffixes)
        4. Strip context-root (FR-011 rejects foreign contexts)
        5. Validate each label (RFC 1035)
        6. Return remaining labels in original order

    Returns:
        List of subdomain labels (e.g. ["v2", "api"]), or [] for root,
        or None if the host is invalid/foreign.
    """
    if not host_header:
        return None

    # FR-007: strip port
    if ":" in host_header:
        host_header = host_header.rsplit(":", 1)[0]

    # FR-017: total length
    if len(host_header) > MAX_HOSTNAME_LEN:
        return None

    # FR-006: must end with domain suffix
    suffix = "." + domain_suffix.lstrip(".")
    if not host_header.endswith(suffix):
        return None

    # Strip suffix → "blog.npub1abc" or "v2.api.npub1abc" or "npub1abc"
    prefix = host_header[: -len(suffix)]
    if not prefix:
        return None  # host == domain suffix itself, no context-root

    labels = prefix.split(".")

    # FR-011: last label must be context_root
    if not labels or labels[-1] != context_root:
        return None

    # Empty-label rejection (..npub1abc.example.com → ["", "", "npub1abc"])
    subdomains = labels[:-1]
    for label in subdomains:
        if not label:
            return None
        # FR-017: label length
        if len(label) > MAX_LABEL_LEN:
            return None
        # RFC 1035 label syntax (alphanumerics + hyphens, no leading/trailing hyphen)
        if not _LABEL_RE.match(label):
            return None

    return subdomains


class RouteTable:
    """A hierarchical route table for one context-root.

    Spec 024:
        FR-001: host → backend_url mappings
        FR-002: default entry (empty host)
        FR-003: nested routes (≥10 levels)
        FR-004: wildcard fallback
        FR-005/FR-006/FR-007: Host-header parsing in resolve_host()
    """

    def __init__(
        self,
        backends: Optional[dict[str, str]] = None,
        wildcard: Optional[str] = None,
        context_root: Optional[str] = None,
        domain_suffix: str = "localhost",
    ) -> None:
        # backends maps "path/like/this" → URL (empty string = root)
        self._backends: dict[tuple[str, ...], str] = {}
        self._wildcard: Optional[str] = wildcard
        self.context_root = context_root
        self.domain_suffix = domain_suffix

        if backends:
            for key, url in backends.items():
                self._set(key, url)

    # ─── Configuration ────────────────────────────────────────────────

    def _set(self, path_key: str, backend_url: str) -> None:
        """Add or replace a route.

        path_key formats:
            ""       → root (empty subdomain)
            "blog"   → single level
            "api/v2" → nested (in subdomain-LEFT order, so "api/v2" matches ["v2","api"])
            "*"      → wildcard (special)
        """
        if path_key == "*":
            self._wildcard = backend_url
            return

        if path_key == "":
            self._backends[()] = backend_url
            return

        # "api/v2" means: when subdomain path is ["v2", "api"], route here.
        labels = path_key.split("/")
        for label in labels:
            if not label:
                raise RouteTableError(f"empty label in path key: {path_key!r}")
        self._backends[tuple(reversed(labels))] = backend_url

    # ─── Resolution ────────────────────────────────────────────────────

    def resolve(self, subdomain_path: list[str]) -> Optional[str]:
        """Resolve a subdomain path to a backend URL.

        Order (Spec 024):
            1. Exact match on the full subdomain path
            2. Wildcard "*" (if configured)
            3. None (→ caller emits 404)
        """
        # 1. Exact match
        key = tuple(subdomain_path)
        if key in self._backends:
            return self._backends[key]

        # Special case: empty path → root backend (if configured)
        if not subdomain_path and () in self._backends:
            return self._backends[()]

        # 2. Wildcard (only matches non-root paths — root has its own default)
        if self._wildcard is not None and subdomain_path:
            return self._wildcard

        # 3. No match
        return None

    def resolve_host(self, host_header: str) -> Optional[str]:
        """Parse Host header → subdomain path → backend URL. None if invalid/foreign."""
        if not self.context_root:
            raise RouteTableError("resolve_host requires context_root")

        path = extract_subdomain_path(host_header, self.context_root, self.domain_suffix)
        if path is None:
            return None
        return self.resolve(path)

    # ─── Loaders ──────────────────────────────────────────────────────

    @classmethod
    def from_dict(
        cls,
        config: dict,
        context_root: Optional[str] = None,
        domain_suffix: str = "localhost",
    ) -> "RouteTable":
        """Build a RouteTable from a parsed config dict (YAML/JSON).

        Schema:
            backends:
                "": http://root:8080
                blog: http://blog:8080
                api/v2: http://apiv2:3000
            wildcard: http://catchall:8080    # optional
        """
        backends = config.get("backends") or {}
        wildcard = config.get("wildcard")
        return cls(
            backends=backends,
            wildcard=wildcard,
            context_root=context_root,
            domain_suffix=domain_suffix,
        )

    @classmethod
    def from_yaml(
        cls,
        path: str,
        context_root: Optional[str] = None,
        domain_suffix: str = "localhost",
    ) -> "RouteTable":
        """Load a RouteTable from a YAML file."""
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise RouteTableError("PyYAML is required to load YAML config: pip install pyyaml") from e
        with open(path) as f:
            config = yaml.safe_load(f)
        return cls.from_dict(config, context_root=context_root, domain_suffix=domain_suffix)

    @classmethod
    def from_ports(cls, port_map: dict[str, str]) -> "RouteTable":
        """Backwards-compat: build a RouteTable from legacy --ports mapping.

        Takes the first port's backend as the single default route.
        """
        if not port_map:
            raise RouteTableError("empty port map")
        first_url = next(iter(port_map.values()))
        return cls(backends={"": first_url})

    # ─── Introspection ────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._backends) + (1 if self._wildcard else 0)

    def __repr__(self) -> str:
        n = len(self._backends)
        w = " +wildcard" if self._wildcard else ""
        return f"<RouteTable {n} routes{w} ctx={self.context_root} suffix={self.domain_suffix}>"
