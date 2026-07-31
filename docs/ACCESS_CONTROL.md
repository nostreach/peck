# Access Control & Policy

peck includes a policy engine that controls **who** can connect to your daemon and **under what conditions**. It supports IP filtering, GeoIP-based region blocking, terms-of-service challenges, and audit logging.

## Overview

```
Client sends announce
        │
        ▼
   ┌─────────────────────┐
   │   Policy Engine      │
   │                       │
   │   1. IP check         │──── allow/deny by CIDR
   │   2. Region check     │──── allow/deny by country/ASN
   │   3. Terms challenge  │──── send ToS, wait for accept
   │   4. Rate limit       │──── (if configured)
   │                       │
   └───────┬───────────────┘
           │
     allow │ deny
           │
     ▼          ▼
   Connect   Reject (silent or loud)
```

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
default: allow

# IP-based rules
ip_rules:
  - cidr: 10.0.0.0/8
    action: allow
    comment: "Internal network"

  - cidr: 192.168.1.0/24
    action: deny
    comment: "Blocked subnet"

  - cidr: 203.0.113.0/24
    action: deny
    comment: "Known abuse range"

# GeoIP-based rules (requires --geoip-db)
region_rules:
  - region: EU
    action: allow
    comment: "EU users only"

  - country: CN
    action: deny

  - country: US,RU
    action: deny
    comment: "Blocked countries"

  - asn: 16509
    action: deny
    comment: "Block specific ASN"

# Terms of service challenge
terms:
  version: "1.0"
  text: |
    By using this service, you agree to the following terms:
    1. No illegal activity
    2. No abuse of the service
    3. The operator is not responsible for content
  require_accept: true
  auto_accept_cookie: true

# Rate limiting (per pubkey)
rate_limits:
  max_connections_per_hour: 10
  max_bandwidth_mbps: 50
```

## Features

### IP Allow/Deny Lists

Match client IPs against CIDR ranges. Rules are evaluated in order; first match wins.

```yaml
ip_rules:
  - cidr: 10.0.0.0/8       # IPv4 CIDR
    action: allow
  - cidr: 2001:db8::/32    # IPv6 CIDR
    action: deny
```

**How it works**: The client's IP is resolved via STUN during the WebRTC handshake (the client sends its self-declared `srflx` IP in the announce message). The policy engine checks this IP against the CIDR rules.

### GeoIP Region Blocking

Block or allow connections based on the client's geographic location.

```yaml
region_rules:
  - region: EU            # Continent code
    action: allow
  - country: CN,RU        # ISO country codes (comma-separated)
    action: deny
  - asn: 16509            # ASN number
    action: deny
```

**Requires**: MaxMind GeoLite2 Country database (`.mmdb` file). Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free, requires account).

```bash
--geoip-db /usr/share/GeoIP/GeoLite2-Country.mmdb
```

The client IP from the STUN resolution is looked up in the GeoIP database to determine country/region/ASN.

### Terms of Service Challenge

Require users to accept terms before the tunnel is established.

**Flow**:

1. Client connects and sends announce
2. Daemon checks policy → terms challenge required
3. Daemon sends a `terms-challenge` DM with terms text + version
4. Browser shows a modal with the terms text
5. User clicks "Accept"
6. Browser sends `terms-accept` DM with the version
7. Daemon validates and establishes the tunnel

**Auto-accept**: If the client has previously accepted the same terms version (stored in cookie/localStorage), the acceptance is sent automatically without showing the modal again.

```yaml
terms:
  version: "1.0"
  text: |
    Your terms text here...
  require_accept: true
```

The daemon caches accepted versions per-session (sessionStorage), so reconnects within the same browser tab auto-accept.

### Request-IP Flow

The daemon may ask the client to re-resolve its public IP after the initial connection. This happens when:

- The announce message didn't include a `client_ip` (STUN resolution failed on first attempt)
- The daemon needs to verify the IP for policy compliance

**Flow**:

1. Daemon sends `request-ip` DM
2. Browser performs a fresh STUN resolution
3. Browser sends a new `announce` DM with the resolved `client_ip`
4. Daemon runs policy checks on the resolved IP

### Audit Logging

Log policy decisions (allow/deny) to a JSON-Lines file.

```bash
--audit-log /var/log/peck-audit.jsonl
```

**Privacy**: By default, pubkeys and IPs in the audit log are **SHA-256 hashed**. This allows correlation of repeated visits without storing raw identifiers.

```bash
# Default: hashed (recommended)
--audit-log /var/log/peck-audit.jsonl

# Plaintext (NOT recommended — for debugging only)
--audit-log /var/log/peck-audit.jsonl --audit-log-plaintext
```

**Log format** (one JSON object per line):

```json
{"ts": "2026-07-31T14:33:12Z", "action": "deny", "reason": "region:CN", "pubkey_sha256": "a1b2c3...", "ip_sha256": "d4e5f6..."}
```

### Silent Deny vs Loud Deny

When the policy engine rejects a connection, there are two behaviors:

- **Silent deny** (default): The daemon simply doesn't respond. The client times out after 15 seconds. The client doesn't know why it was rejected.
- **Loud deny**: The daemon sends a `deny` DM with a reason message. The browser shows the reason to the user.

Configure loud-deny per rule:

```yaml
ip_rules:
  - cidr: 10.0.0.0/8
    action: deny
    loud: true          # Send deny reason to client
    message: "Your IP range is blocked. Contact admin@example.com"
```

### Rate Limiting

Limit connections and bandwidth per pubkey.

```yaml
rate_limits:
  max_connections_per_hour: 10
  max_bandwidth_mbps: 50
```

Rate limits are tracked per pubkey (hashed) with a sliding window. Exceeded limits result in a silent deny.

## Client-Side Settings

The browser client stores policy-related preferences in cookies (cross-subdomain) and localStorage:

| Setting | Values | Description |
|---------|--------|-------------|
| `peck_auto_accept_terms` | `true` / `false` | Auto-accept future terms versions |
| `peck_accepted_terms_version` | e.g. `"1.0"` | Last accepted version |
| `peck_ip_preference` | `both` / `ipv4` / `ipv6` | IP version preference for WebRTC |
| `peck_reconnect_mode` | `off` / `on` / `smart` | Auto-reconnect behavior |

### Reconnect Modes

| Mode | Behavior |
|------|----------|
| `off` | No automatic reconnect |
| `on` | Always reconnect on disconnect (may leak real IP if VPN drops) |
| `smart` (default) | Reconnect only if external IP is unchanged (set-equality check) |

## Default Behavior (No Policy File)

Without `--policy-file`, the daemon runs in **default-allow** mode:

- All connections are accepted
- No terms challenge
- No IP or region filtering
- No audit logging
- No rate limiting

This is fully backward-compatible — existing deployments without a policy file continue to work unchanged.

## CLI Flags Summary

| Flag | Default | Description |
|------|---------|-------------|
| `--policy-file` | none | Path to YAML policy file |
| `--geoip-db` | none | MaxMind GeoLite2 Country `.mmdb` path |
| `--audit-log` | none | JSON-Lines audit log path |
| `--audit-log-plaintext` | off | Write raw pubkeys/IPs to audit log |
| `--idle-timeout` | 1200 (20 min) | Disconnect idle sessions after N seconds |
| `--connect-timeout` | 15 | WebRTC connection timeout in seconds |
