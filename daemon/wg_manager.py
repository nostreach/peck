"""
WireGuard management helpers (extracted from daemon.py).

These are standalone helpers that do not depend on PeerSession/PeckDaemon.
"""

import logging
import random
import re
import subprocess
from typing import Optional

log = logging.getLogger("peck")


def get_connected_wg_ips() -> dict:
    """Spec 034: Return IPs of WG interfaces with active handshake.

    Runs `wg show all` and parses interface names + latest handshake timestamps.
    Then maps interface names to their assigned IPs via `ip addr`.

    Returns:
        {interface_name: {"ipv4": "x.x.x.x", "ipv6": "fd00:...", "handshake_ago": seconds}}
        Only interfaces with a handshake within the last 5 minutes are included.
    """
    HANDSHAKE_MAX_AGE = 300  # 5 minutes

    try:
        result = subprocess.run(
            ["wg", "show", "all"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode != 0:
            log.warning(f"wg show all failed: {result.stderr.strip()}")
            return {}
    except Exception as e:
        log.warning(f"wg show all error: {e}")
        return {}

    # Parse wg output: "interface: wgN" blocks with "latest handshake: N ago"
    connected = {}  # iface -> handshake_ago_seconds
    current_iface = None
    for line in result.stdout.split("\n"):
        m = re.match(r"interface:\s+(\S+)", line)
        if m:
            current_iface = m.group(1)
            connected[current_iface] = None
            continue
        hm = re.search(r"latest handshake:\s+(\d+).+?ago", line)
        if hm and current_iface:
            connected[current_iface] = int(hm.group(1))

    # Filter: only interfaces with recent handshake
    active_ifaces = {iface for iface, age in connected.items()
                     if age is not None and age <= HANDSHAKE_MAX_AGE}

    if not active_ifaces:
        log.warning(f"no WG interfaces with active handshake (checked: {list(connected.keys())})")
        return {}

    # Map interface → IPs via `ip addr show`
    try:
        result = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=3
        )
    except Exception as e:
        log.warning(f"ip addr show error: {e}")
        return {}

    iface_info = {}
    for line in result.stdout.split("\n"):
        # Format: "1630: wg0    inet 10.0.0.1/32 scope global wg0"
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        if iface not in active_ifaces:
            continue
        if iface not in iface_info:
            iface_info[iface] = {"ipv4": None, "ipv6": None, "handshake_ago": connected[iface]}

        if parts[2] == "inet":
            ip_cidr = parts[3]
            ip_str = ip_cidr.split("/")[0]
            iface_info[iface]["ipv4"] = ip_str
        elif parts[2] == "inet6":
            ip_cidr = parts[3]
            ip_str = ip_cidr.split("/")[0]
            # Skip link-local addresses
            if not ip_str.startswith("fe80"):
                iface_info[iface]["ipv6"] = ip_str

    return iface_info


def pick_wg_pair(wg_ips: list, wg_ip6s: list, ip_preference: str = "both") -> tuple:
    """Spec 034: Pick a correlated (IPv4, IPv6) pair from a connected WG tunnel.

    Filters by:
    1. Active WireGuard handshake (within last 5 min) — prevents stale tunnel IPs
    2. ip_preference: "ipv4" / "ipv6" / "both" — only pick tunnels with matching addresses

    Graceful degradation: if no tunnel matches the preference, falls back to
    all configured wg_ips (legacy behavior).

    Returns:
        (ipv4_str_or_None, ipv6_str_or_None)
    """
    connected = get_connected_wg_ips()

    if not connected:
        # No handshake data — fall back to configured IPs
        log.debug("no handshake data, using configured wg_ips")
        idx = random.randint(0, len(wg_ips) - 1)
        ip4 = wg_ips[idx]
        ip6 = wg_ip6s[idx] if idx < len(wg_ip6s) else None
        return (ip4, ip6)

    # Build candidate list from connected tunnels
    candidates = []
    for iface, info in connected.items():
        ip4 = info["ipv4"]
        ip6 = info["ipv6"]

        # Filter by ip_preference
        if ip_preference == "ipv4" and not ip4:
            continue
        if ip_preference == "ipv6" and not ip6:
            continue
        # "both" or matched preference
        if not ip4 and not ip6:
            continue
        candidates.append((ip4, ip6))

    if not candidates:
        # No tunnel matches preference — fall back to all connected
        log.info(f"no tunnel matches ip_preference={ip_preference}, falling back to all connected")
        for iface, info in connected.items():
            ip4 = info["ipv4"]
            ip6 = info["ipv6"]
            if ip4 or ip6:
                candidates.append((ip4, ip6))

    if not candidates:
        # Still nothing — ultimate fallback to configured IPs
        log.warning("no connected WG tunnels with IPs, falling back to configured wg_ips")
        idx = random.randint(0, len(wg_ips) - 1)
        ip4 = wg_ips[idx]
        ip6 = wg_ip6s[idx] if idx < len(wg_ip6s) else None
        return (ip4, ip6)

    return random.choice(candidates)
