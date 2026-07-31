# WireGuard Multi-Tunnel Setup

peck uses multiple WireGuard tunnels to provide **IP diversity** — each connecting browser gets assigned a different exit IP. This prevents IP correlation and distributes traffic across multiple upstream providers.

## Why WireGuard?

Each WebRTC DataChannel requires host ICE candidates — the daemon must advertise reachable IP addresses. Without WireGuard, all clients would connect to the same server IP, making the service trivially correlatable.

With multiple WireGuard tunnels, each connecting client is assigned to a different tunnel. The daemon picks a random active tunnel per connection and uses its IP as the WebRTC host candidate.

## Architecture

```
                        ┌─────────────────────────────────┐
                        │         peck daemon              │
                        │    (runs in network namespace)    │
                        │                                   │
   Client A ───────────►│  WG tunnel 1 (wg0) ──► Exit IP A │──► Internet
   (WebRTC to IP A)     │                                   │
                        │  WG tunnel 2 (wg1) ──► Exit IP B │──► Internet
   Client B ───────────►│                                   │
   (WebRTC to IP B)     │  WG tunnel 3 (wg2) ──► Exit IP C │──► Internet
                        │                                   │
   Client C ───────────►│  ... (N tunnels, N exit IPs)      │
   (WebRTC to IP C)     │                                   │
                        └─────────────────────────────────┘
```

Each WireGuard tunnel:
- Has its own interface (`wg0`, `wg1`, `wg2`, ...)
- Routes through a different VPN provider or exit server
- Has a unique IPv4 (and optionally IPv6) address
- Is independently connectable from the internet

## Network Namespace (netns)

The daemon should run inside a dedicated network namespace. This isolates the WireGuard interfaces from the host's main routing table, preventing leaks and simplifying configuration.

```
Host namespace (eth0, default route)
│
└── peck netns
    ├── wg0 (172.x.x.x/32)  ──► VPN Provider A
    ├── wg1 (172.y.y.y/32)  ──► VPN Provider B
    ├── wg2 (172.z.z.z/32)  ──► VPN Provider C
    └── peck daemon listening here
```

### Setup with netns

Use the provided scripts:

```bash
# Bootstrap multiple WireGuard tunnels in a netns
sudo scripts/peck-vpn-netns.sh

# Or without netns (tunnels in host namespace)
sudo scripts/peck-vpn.sh
```

The scripts create WireGuard interfaces, configure routing, and bring them up. Each interface gets a unique tunnel IP.

### systemd with netns

Deploy the daemon as a systemd service that enters the netns:

```bash
# Copy service file
sudo cp deploy/peck-daemon-netns.service /etc/systemd/system/

# Edit with your configuration
sudo systemctl daemon-reload
sudo systemctl enable --now peck-daemon
```

## Daemon Configuration

Pass the WireGuard interface IPs to the daemon:

```bash
python daemon.py \
  --nsec-file ~/.config/peck/nsec \
  --relays wss://relay.damus.io,wss://relay.primal.net \
  --wg-ips 10.0.0.1,10.0.0.2,10.0.0.3 \
  --wg-ip6s fd00:1::1,fd00:2::1,fd00:3::1 \
  --ports 80:http://127.0.0.1:8080 \
  --domain-suffix yourdomain.com
```

### Flags

| Flag | Description |
|------|-------------|
| `--wg-ips` | Comma-separated WireGuard IPv4 addresses (one per tunnel) |
| `--wg-ip6s` | Comma-separated WireGuard IPv6 addresses (optional, enables IPv6) |

The order matters: `--wg-ips` and `--wg-ip6s` are paired by index. `--wg-ips 10.0.0.1,10.0.0.2` with `--wg-ip6s fd00::1,fd00::2` means tunnel 0 = `(10.0.0.1, fd00::1)`, tunnel 1 = `(10.0.0.2, fd00::2)`.

## How Tunnel Selection Works

When a new client connects, the daemon:

1. Calls `get_connected_wg_ips()` — runs `wg show all` to find interfaces with an active handshake (within last 5 minutes)
2. Filters tunnels by IP version preference (if the client requests IPv4-only or IPv6-only)
3. Picks a **random** tunnel from the active candidates
4. Uses that tunnel's IP as the `aioice` host address override for the WebRTC peer connection

```python
# Simplified from daemon.py
def pick_wg_pair(self, ip_preference="both"):
    connected = get_connected_wg_ips()  # wg show all
    candidates = [info for iface, info in connected.items()
                  if matches_preference(info, ip_preference)]
    return random.choice(candidates)   # random exit IP
```

### Graceful Degradation

- **No active handshakes**: Falls back to the configured `--wg-ips` list (static IPs, no liveness check)
- **No matching IP version**: Falls back to all connected tunnels regardless of preference
- **Single tunnel**: Works normally, all clients use the same exit IP

## IPv6 Support

IPv6 is optional but recommended for maximum compatibility with client networks.

The daemon handles IPv6 differently from IPv4 because `aioice` (the ICE library used by `aiortc`) only performs STUN for IPv4. For IPv6:

1. The daemon resolves the **public** IPv6 address at startup (NPTv6 / 1:1 NAT)
2. After ICE gathering, it patches the local SDP: replaces the private `fd00:` host candidate with the public address as a `srflx` candidate
3. Port numbers are preserved (NPTv6 1:1 mapping)

This requires the WireGuard exit to do 1:1 NPTv6 (Network Prefix Translation), not dynamic NAT66.

## Monitoring

Check which WireGuard tunnels are active:

```bash
# Inside the netns (if using netns mode)
sudo ip netns exec peck wg show all

# View recent handshakes
sudo ip netns exec peck wg show all latest-handshakes
```

The daemon logs the assigned WG IP per session:

```
📝 session [serve] for abc12345 → 10.0.0.1, ports=[80] (idle=1200s)
```

## Security Considerations

- **WireGuard is the exit point**: All tunneled traffic exits through the WireGuard tunnel, not the host's main interface. Choose VPN providers carefully.
- **netns isolation**: Without a network namespace, the daemon could accidentally expose the host's real IP as an ICE candidate. Always use netns in production.
- **DNS leaks**: Configure DNS resolution inside the netns to use the WireGuard exit's DNS resolver, not the host's.
- **Handshake freshness**: The daemon only uses tunnels with a handshake within the last 5 minutes. Stale tunnels are skipped.

## Without WireGuard (Single IP)

For testing or single-user setups, WireGuard is not required. Run the daemon directly with the server's public IP:

```bash
python daemon.py \
  --nsec-file ~/.config/peck/nsec \
  --relays wss://relay.damus.io \
  --wg-ips $(curl -s ifconfig.me) \
  --ports 80:http://127.0.0.1:8080
```

This works but all clients connect to the same IP — no IP diversity.
