# Access Control & Policy

peck includes a policy engine that controls **who** can connect to your daemon and **under what conditions**. It supports pubkey whitelisting, IP filtering, GeoIP-based region blocking, terms-of-service challenges, and audit logging.

## Overview

Every incoming connection passes through `PolicyEngine.decide()` before any WebRTC work begins. The engine is a **single filter point** — all rules evaluated top-down, first match wins, default action applies if nothing matches.

```
Client sends announce (NIP-44 encrypted DM)
        │
        ▼
   ┌─────────────────────────────────┐
   │        Policy Engine             │
   │                                  │
   │   1. Pubkey check                │──── allow/deny by npub
   │   2. IP check (self-declared)    │──── allow/deny by CIDR
   │   3. GeoIP check (country/ASN)   │──── allow/deny by region
   │   4. Terms challenge?             │──── send ToS if required
   │                                  │
   └──────┬───────────────────────────┘
          │
    allow │ deny (silent)
          │ loud-deny (sends reason)
          │
    ▼              ▼
   WebRTC        Rejected
   offer
```

**Second filter (ICE-level)**: When GeoIP is active, the daemon re-checks policy against the actual WebRTC ICE candidate IPs — catching clients who spoofed their self-declared IP.

## Configuration

### Policy File

Create a YAML policy file and pass it via `--policy-file`:

```bash
python daemon.py \
  --nsec-file ~/.config/peck/nsec \
  --relays wss://relay.damus.io \
  --wg-ips 10.0.0.1 \
  --ports 80:http://127.0.0.1:8080 \
  --policy-file policy.yaml \
  --geoip-db /usr/share/GeoIP/GeoLite2-Country.mmdb \
  --audit-log /var/log/peck-audit.jsonl
```

See `policy.yaml.example` for a complete example.

### Policy YAML Schema

```yaml
# Default action when no rule matches
# Values: allow | deny | loud-deny
default_effect: allow

# Named region groups (referenced by rules via `region:`)
regions:
  eu:
    countries: [DE, AT, FR, NL, BE, IT, ES, ...]
    asns: [12345, 67890]

# Ordered rules — first match wins
rules:
  # --- Pubkey whitelist ---
  - comment: "Trusted admin"
    pubkeys:
      - npub1abc123...        # npub1 or 64-char hex both work
    effect: allow

  # --- IP-based ---
  - comment: "Internal network"
    client_ips:
      - 10.0.0.0/8            # IPv4 CIDR
      - 2001:db8::/32         # IPv6 CIDR
    effect: allow

  - comment: "Blocked abuse range"
    client_ips:
      - 203.0.113.0/24
    effect: deny              # silent deny

  - comment: "Blocked with reason"
    client_ips:
      - 198.51.100.0/24
    effect: loud-deny         # client sees the message
    message: "Your IP range is blocked. Contact admin@example.com"

  # --- GeoIP-based (requires --geoip-db) ---
  - comment: "EU users"
    region: eu                # references regions: block above
    effect: allow

  - comment: "Blocked countries"
    country: [CN, RU]         # ISO 3166-1 alpha-2 codes
    effect: deny

  - comment: "Blocked ASN"
    asn: [16509]              # ASN integers
    effect: deny

  # --- Terms of Service ---
  - comment: "Require ToS acceptance"
    effect: allow
    require_terms: true
    terms_version: "1.0"
    terms_text: |
      By using this service, you agree to:
      1. No illegal activity
      2. No abuse of the service
      3. The operator is not responsible for content
```

### Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `comment` | string | Human label (written to audit log) |
| `pubkeys` | list | npub1... or 64-char hex pubkeys |
| `client_ips` | list | IPv4/IPv6 CIDR ranges |
| `country` | list | ISO 3166-1 alpha-2 codes (requires `--geoip-db`) |
| `asn` | list | ASN integers (requires `--geoip-db`) |
| `region` | string | References a named group from the `regions:` block |
| `effect` | string | `allow` / `deny` / `loud-deny` |
| `message` | string | Human message (only for `loud-deny`) |
| `require_terms` | bool | Require ToS acceptance before tunnel |
| `terms_text` | string | Inline terms text |
| `terms_file` | path | Path to terms text file (takes precedence over `terms_text`) |
| `terms_version` | string | Version string (required if `require_terms: true`) |

**Matching logic**: All non-empty criteria on a rule must match (AND). Empty/omitted criteria match any value.

### Regions Block

Define reusable groups of countries and ASNs:

```yaml
regions:
  eu:
    countries: [DE, AT, FR, NL, BE, IT, ES]
    asns: [12345, 67890]
```

Rules reference them via `region: eu`.

## Features in Detail

### IP Allow/Deny Lists

Match client IPs against CIDR ranges. Rules are evaluated in order; first match wins.

```yaml
rules:
  - client_ips: [10.0.0.0/8, 2001:db8::/32]
    effect: allow
```

**How it works**: The client's IP is self-declared via STUN resolution. The client sends its `srflx` IP in the announce message. The policy engine checks this IP against the CIDR rules.

**Important caveat**: `client_ip` is self-declared and could be spoofed. For strong IP-based blocking, enable `--geoip-db` to activate the **ICE second filter** (see below).

### GeoIP Region Blocking

Block or allow connections based on geographic location. Requires a MaxMind GeoLite2 Country database.

```yaml
rules:
  - region: eu
    effect: allow
  - country: [CN, RU]
    effect: deny
  - asn: [16509]
    effect: deny
```

**Setup**:
1. Download [GeoLite2 Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) `.mmdb` file (free, requires MaxMind account)
2. Pass to daemon: `--geoip-db /path/to/GeoLite2-Country.mmdb`
3. Install Python lib: `pip install geoip2`

All lookups are local/offline (no external API calls).

If `--geoip-db` is omitted but country/asn rules exist, the daemon logs a warning and those rules silently don't match.

### ICE Second Filter (Anti-Spoofing)

When `--geoip-db` is active, the daemon performs a **second policy check** after receiving the WebRTC answer. It parses the remote SDP for `srflx` ICE candidates — the actual server-reflexive IPs from the WebRTC layer.

If any candidate IP violates the policy, the daemon terminates the session immediately. This catches clients who declared a fake IP in their announce but whose real IP appears in ICE candidates.

### Terms of Service Challenge

Require users to accept terms before the tunnel is established.

**Flow**:

1. Client announces → policy rule matches with `require_terms: true`
2. Daemon sends `terms-challenge` DM with terms text + version
3. Browser shows a modal with the terms
4. User clicks Accept → browser sends `terms-accept` DM
5. Daemon validates version, proceeds with WebRTC offer
6. **30-second timeout**: If no acceptance within 30s, session is discarded

```yaml
rules:
  - effect: allow
    require_terms: true
    terms_version: "1.0"
    terms_text: |
      Your terms text here...
```

**Auto-accept**: If the user has enabled "Auto-accept terms" in Settings and previously accepted the same version, the browser sends the acceptance immediately without showing the modal.

**Per-session**: Once accepted in a browser session, reconnects to the same daemon auto-accept that version silently (sessionStorage).

### Silent Deny vs Loud Deny

| Aspect | `deny` | `loud-deny` |
|--------|--------|-------------|
| Daemon behavior | Silent — sends nothing | Sends encrypted DM with reason |
| Client experience | Connection timeout (no response) | "Access denied" + message shown |
| Auto-reconnect | Client may retry | Client stops reconnecting |
| Message padding | N/A | Padded to 256 bytes (prevents length-based enumeration) |

```yaml
rules:
  - client_ips: [203.0.113.0/24]
    effect: loud-deny
    message: "Your IP range is blocked. Contact admin@example.com"
```

### Request-IP Flow

If the daemon's policy has IP-based rules but the client's announce didn't include a `client_ip`, the daemon asks the client to resolve it:

1. Daemon sends `request-ip` DM
2. Browser performs a fresh STUN resolution (creates a throwaway `RTCPeerConnection`, gathers ICE candidates, extracts `srflx` IPs)
3. Browser re-announces with the resolved `client_ip`
4. Daemon runs policy checks

This only happens when IP-based rules are configured.

### Audit Logging

Log policy decisions (deny/loud-deny only — allows are not logged).

```bash
--audit-log /var/log/peck-audit.jsonl
```

**Privacy-by-design**: Pubkeys and IPs are hashed with **PBKDF2-HMAC-SHA256** (100,000 iterations) using a random per-run salt.

- **Within one daemon run**: same client → same hash (correlation possible)
- **Across runs**: salt rotates (correlation impossible)

```bash
# Default: hashed (recommended)
--audit-log /var/log/peck-audit.jsonl

# Plaintext (NOT recommended — debugging only)
--audit-log /var/log/peck-audit.jsonl --audit-log-plaintext
```

**Log format** (JSON-Lines):

```json
{"ts":"2026-07-31T14:33:12Z","pubkey":"$pbkdf2-sha256$a1b2...","ip":"$pbkdf2-sha256$d4e5...","effect":"deny","rule":"Blocked countries"}
```

### Hot-Reload (SIGHUP)

Reload the policy file without restarting the daemon:

```bash
kill -HUP $(pidof python3)
```

The daemon re-reads the YAML, performs an **atomic swap** of the policy engine. On error (bad YAML), it keeps the old policy active (fail-safe). Also reloads `ports_map` if configured.

## Client-Side Settings

The browser client stores policy-related preferences in cookies (cross-subdomain) and localStorage:

| Setting | Values | Description |
|---------|--------|-------------|
| `peck_auto_accept_terms` | `true` / `false` | Auto-accept future terms versions |
| `peck_accepted_terms_version` | e.g. `"1.0"` | Last accepted version |
| `peck_ip_preference` | `both` / `ipv4` / `ipv6` | IP version for WebRTC |
| `peck_reconnect_mode` | `off` / `on` / `smart` | Auto-reconnect behavior |

### Reconnect Modes

| Mode | Behavior |
|------|----------|
| `off` | No automatic reconnect |
| `on` | Always reconnect (may leak real IP if VPN drops) |
| `smart` (default) | Reconnect only if external IP is unchanged |

## Default Behavior (No Policy File)

Without `--policy-file`, the daemon runs in **default-allow** mode:

- All connections accepted
- No terms challenge
- No IP/region filtering
- No audit logging

Fully backward-compatible — existing deployments without a policy file continue to work unchanged.

## CLI Flags Summary

| Flag | Default | Description |
|------|---------|-------------|
| `--policy-file` | none | Path to YAML policy file |
| `--geoip-db` | none | MaxMind GeoLite2 Country `.mmdb` path |
| `--audit-log` | none | JSON-Lines audit log path |
| `--audit-log-plaintext` | off | Write raw pubkeys/IPs (NOT recommended) |
| `--idle-timeout` | 1200 (20 min) | Disconnect idle sessions after N seconds |
| `--connect-timeout` | 15 | WebRTC connection timeout in seconds |
