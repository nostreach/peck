"""
peck ports module — Spec 029: Path-Prefix Multi-Port.

Provides:
  - PortsMap: {port: backend_url} with operator-defined default_port
  - parse_path_prefix(path) -> (port, stripped_path): extracts /_p<port>/ prefix
  - load_ports_config(path) -> PortsMap: YAML/JSON loader

Used by the daemon to route requests based on the /_p<port>/ prefix in the
request path. The default_port is used when no prefix is present.

Path syntax:
  /                         → (default_port, /)
  /foo/bar                  → (default_port, /foo/bar)
  /_p9090/                  → (9090, /)
  /_p9090/invoices/123      → (9090, /invoices/123)
  /_p0/                     → ValueError (port 0 invalid)
  /_p99999/                 → ValueError (port > 65535)
"""

from __future__ import annotations

import json
import re
import os
from dataclasses import dataclass, field
from typing import Optional, Tuple

_PATH_PREFIX_RE = re.compile(r"^/_p(\d{1,5})(/.*)?$")


class PortsConfigError(Exception):
    """Raised when the ports config file is invalid."""


@dataclass
class PortsMap:
    """Operator-defined mapping of wire-ports to backend URLs, with default_port.

    Attributes:
        ports: dict of {port_int: backend_url_string}
        default_port: which port to use when no /_p<port>/ prefix is present
        _source_path: file path the config was loaded from (for reload), None if from dict
    """
    ports: dict
    default_port: int = 80
    _source_path: Optional[str] = field(default=None, repr=False)

    def __post_init__(self):
        if not isinstance(self.ports, dict):
            raise PortsConfigError(f"ports must be a dict, got {type(self.ports)}")
        if not self.ports:
            raise PortsConfigError("ports map cannot be empty")
        for k, v in self.ports.items():
            if not isinstance(k, int) or not (1 <= k <= 65535):
                raise PortsConfigError(f"invalid port key {k!r} (must be int 1-65535)")
            if not isinstance(v, str) or not v:
                raise PortsConfigError(f"invalid backend url for port {k}: {v!r}")
        if not isinstance(self.default_port, int) or not (1 <= self.default_port <= 65535):
            raise PortsConfigError(
                f"invalid default_port {self.default_port!r} (must be int 1-65535)"
            )
        if self.default_port not in self.ports:
            raise PortsConfigError(
                f"default_port {self.default_port} is not in ports map "
                f"(available: {sorted(self.ports.keys())})"
            )

    def __len__(self) -> int:
        return len(self.ports)

    def __contains__(self, port: int) -> bool:
        return port in self.ports

    def get(self, port: int) -> Optional[str]:
        return self.ports.get(port)

    def reload(self) -> "PortsMap":
        """Hot-reload from source path. Raises if no source path or file invalid.

        Returns the new PortsMap (caller should replace its reference atomically).
        """
        if self._source_path is None:
            raise PortsConfigError("cannot reload: PortsMap was not loaded from a file")
        new = load_ports_config(self._source_path)
        return new


def parse_path_prefix(path: str, default_port: int) -> Tuple[int, str]:
    """Extract port from /_p<port>/ prefix, returning (port, stripped_path).

    Examples:
        parse_path_prefix("/", 80)              → (80, "/")
        parse_path_prefix("/foo", 80)           → (80, "/foo")
        parse_path_prefix("/_p9090/", 80)       → (9090, "/")
        parse_path_prefix("/_p9090/invoices", 80) → (9090, "/invoices")
        parse_path_prefix("/_p9090", 80)        → (9090, "/")  # no trailing slash
        parse_path_prefix("/_p0/", 80)          → ValueError
        parse_path_prefix("/_p99999/", 80)      → ValueError
        parse_path_prefix("/_pabc/", 80)        → (80, "/_pabc/")  # no match, default

    Args:
        path: HTTP request path (may include query — caller should strip)
        default_port: port to use when no prefix matches

    Returns:
        (port, effective_path) — effective_path always starts with "/"

    Raises:
        ValueError: if /_p<port>/ is present but port is out of range (0 or > 65535)
    """
    if not path or not path.startswith("/"):
        # Malformed — treat as default
        return (default_port, path or "/")

    m = _PATH_PREFIX_RE.match(path)
    if m is None:
        # No prefix — use default port, path unchanged
        return (default_port, path)

    port_str = m.group(1)
    remainder = m.group(2)

    port = int(port_str)
    if port < 1 or port > 65535:
        raise ValueError(f"port out of range: {port}")

    # Remainder is either None (path was /_p9090 with no slash) or starts with /
    if remainder is None or remainder == "":
        effective = "/"
    else:
        effective = remainder

    return (port, effective)


def load_ports_config(path: str) -> PortsMap:
    """Load a PortsMap from a YAML or JSON file.

    Schema:
        default_port: 9090           # optional, default 80
        ports:
          80: http://10.0.0.1:8081
          9090: http://10.0.0.2:9090

    The file extension determines the parser (.json → JSON, otherwise YAML).
    Port keys in YAML/JSON may be ints or strings — they're coerced to int.

    Args:
        path: filesystem path to the config file

    Returns:
        PortsMap with _source_path set (reloadable)

    Raises:
        FileNotFoundError: file does not exist
        PortsConfigError: schema invalid (missing ports, bad port values, etc.)
    """
    ext = os.path.splitext(path)[1].lower()
    with open(path) as f:
        if ext == ".json":
            try:
                config = json.load(f)
            except json.JSONDecodeError as e:
                raise PortsConfigError(f"invalid JSON: {e}") from e
        else:
            try:
                import yaml  # type: ignore
            except ImportError as e:
                raise PortsConfigError(
                    "PyYAML is required to load YAML config: pip install pyyaml"
                ) from e
            try:
                config = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise PortsConfigError(f"invalid YAML: {e}") from e

    return _build_ports_map(config, source_path=path)


def from_ports_legacy(port_map: dict) -> PortsMap:
    """Build a PortsMap from the legacy --ports dict (backwards compat).

    The first port in the dict becomes default_port. Order-preserving dict
    insertion is assumed (Python 3.7+).
    """
    if not port_map:
        raise PortsConfigError("empty port map")
    first_port = next(iter(port_map.keys()))
    return PortsMap(ports=dict(port_map), default_port=first_port)


def _build_ports_map(config: dict, source_path: Optional[str] = None) -> PortsMap:
    """Internal: validate a parsed config dict and construct PortsMap."""
    if not isinstance(config, dict):
        raise PortsConfigError(
            f"config root must be a mapping, got {type(config).__name__}"
        )

    ports_section = config.get("ports")
    if ports_section is None:
        raise PortsConfigError(
            "config missing 'ports:' section (got keys: "
            f"{list(config.keys()) or '(empty)'})"
        )
    if not isinstance(ports_section, dict):
        raise PortsConfigError(
            f"'ports' must be a mapping, got {type(ports_section).__name__}"
        )
    if not ports_section:
        raise PortsConfigError("'ports' section cannot be empty")

    # Coerce keys to int (YAML may parse "80:" as string if unquoted)
    ports_int = {}
    for k, v in ports_section.items():
        try:
            port_int = int(k)
        except (ValueError, TypeError) as e:
            raise PortsConfigError(f"invalid port key {k!r}: not an integer") from e
        ports_int[port_int] = v

    default_port = config.get("default_port")
    if default_port is None:
        # Default = first port in dict (Python 3.7+ preserves insertion order)
        default_port = next(iter(ports_int.keys()))
    else:
        try:
            default_port = int(default_port)
        except (ValueError, TypeError) as e:
            raise PortsConfigError(
                f"invalid default_port {default_port!r}: not an integer"
            ) from e

    return PortsMap(
        ports=ports_int,
        default_port=default_port,
        _source_path=source_path,
    )
