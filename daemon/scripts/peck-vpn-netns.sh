#!/bin/bash
# peck-vpn-netns.sh — WireGuard in a network namespace
#
# Creates an isolated netns called "peck-vpn" with a WireGuard interface.
# All traffic in this netns goes through the VPN (kernel TCP/UDP).
# No userspace TCP stack, no node_modules patches.
#
# Usage:
#   peck-vpn-netns.sh up      — create netns + start WG
#   peck-vpn-netns.sh down    — destroy netns
#   peck-vpn-netns.sh status  — show status
#   peck-vpn-netns.sh exec CMD — run CMD inside the netns

set -euo pipefail

NETNS="peck-vpn"
WG_IF="wg0"
WG_CONFIG="${PECK_WG_CONFIG:-/etc/peck/wg0.conf}"
RESOLV_CONF="/etc/resolv.conf.peck-vpn"

# Extract config values
read_config() {
  eval "$(awk '
    /^\[Interface\]/ { section="interface"; next }
    /^\[Peer\]/ { section="peer"; next }
    /^#/ { next }
    /^$/ { next }
    {
      key=$1; sub(/=.*/,"",key); gsub(/ /,"",key)
      val=$0; sub(/^[^=]*=/,"",val); gsub(/^ +| +$/,"",val)
      if (section=="interface" && key=="PrivateKey") print "PRIVATE_KEY=\"" val "\""
      if (section=="interface" && key=="Address") print "WG_ADDR=\"" val "\""
      if (section=="interface" && key=="DNS") print "WG_DNS=\"" val "\""
      if (section=="peer" && key=="PublicKey") print "PUBLIC_KEY=\"" val "\""
      if (section=="peer" && key=="AllowedIPs") print "ALLOWED_IPS=\"" val "\""
      if (section=="peer" && key=="Endpoint") print "ENDPOINT=\"" val "\""
    }
  ' "$WG_CONFIG")"
}

# Find the endpoint IP (resolve hostname if needed)
resolve_endpoint() {
  local host="${ENDPOINT%%:*}"
  local port="${ENDPOINT##*:}"
  # If it's already an IP, use it directly
  if [[ "$host" =~ ^[0-9]+\. ]] || [[ "$host" =~ ^\[ ]]; then
    echo "$host $port"
  else
    local ip
    ip=$(dig +short "$host" A 2>/dev/null | head -1)
    [[ -z "$ip" ]] && ip=$(getent hosts "$host" 2>/dev/null | awk '{print $1}')
    echo "${ip:-$host} $port"
  fi
}

cmd_up() {
  read_config

  # Check if already running
  if ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    echo "[$NETNS] already exists. Run '$0 down' first."
    exit 0
  fi

  local endpoint_ip endpoint_port
  read -r endpoint_ip endpoint_port <<< "$(resolve_endpoint)"
  local wg_ip="${WG_ADDR%%/*}"

  echo "[$NETNS] Creating namespace..."
  ip netns add "$NETNS"

  # Create loopback
  ip netns exec "$NETNS" ip link set lo up

  # Create veth pair: peck-veth-host (host side) ↔ peck-veth-ns (namespace side)
  # This gives the namespace a route to the host for the WG endpoint
  local veth_host="peck-veth-host"
  local veth_ns="peck-veth-ns"
  ip link add "$veth_host" type veth peer name "$veth_ns"
  ip link set "$veth_ns" netns "$NETNS"

  # Host side: assign a link-local address
  ip addr add 10.200.200.1/30 dev "$veth_host"
  ip link set "$veth_host" up

  # Namespace side: assign address + default route via host
  ip netns exec "$NETNS" ip addr add 10.200.200.2/30 dev "$veth_ns"
  ip netns exec "$NETNS" ip link set "$veth_ns" up
  # Route to the WG endpoint goes via veth (to reach the internet)
  ip netns exec "$NETNS" ip route add "$endpoint_ip/32" via 10.200.200.1 dev "$veth_ns"

  # Enable IP forwarding on host + NAT for the namespace
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  # Find the host's default interface
  local host_if
  host_if=$(ip route show default | awk '{print $5; exit}')
  if [[ -n "$host_if" ]]; then
    iptables -t nat -A POSTROUTING -s 10.200.200.0/30 -o "$host_if" -j MASQUERADE 2>/dev/null || true
  fi

  # Create WG interface inside the namespace
  ip netns exec "$NETNS" ip link add "$WG_IF" type wireguard
  ip netns exec "$NETNS" ip addr add "$WG_ADDR" dev "$WG_IF"
  ip netns exec "$NETNS" wg set "$WG_IF" \
    private-key <(echo "$PRIVATE_KEY") \
    peer "$PUBLIC_KEY" \
    allowed-ips "$ALLOWED_IPS" \
    endpoint "$endpoint_ip:$endpoint_port"
  ip netns exec "$NETNS" ip link set "$WG_IF" up
  # Default route through WG (except the endpoint which goes via veth)
  ip netns exec "$NETNS" ip route add default dev "$WG_IF"

  # DNS
  if [[ -n "$WG_DNS" ]]; then
    mkdir -p /etc/netns/$NETNS
    echo "nameserver $WG_DNS" > /etc/netns/$NETNS/resolv.conf
  fi

  sleep 1

  # Verify
  echo "[$NETNS] Verifying..."
  local egress_ip
  egress_ip=$(ip netns exec "$NETNS" curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "FAILED")
  if [[ "$egress_ip" == "FAILED" ]]; then
    echo "[$NETNS] ✗ Egress IP check failed"
    ip netns exec "$NETNS" wg show "$WG_IF" 2>/dev/null || true
    exit 1
  fi

  echo "[$NETNS] ✓ VPN IP: $egress_ip"
  echo "[$NETNS] ✓ WG handshake:"
  ip netns exec "$NETNS" wg show "$WG_IF" 2>/dev/null | sed 's/^/  /'
  echo ""
  echo "[$NETNS] Ready. Run commands inside:"
  echo "  ip netns exec $NETNS <command>"
  echo "  ip netns exec $NETNS curl https://api.ipify.org"
}

cmd_down() {
  echo "[$NETNS] Tearing down..."
  ip netns del "$NETNS" 2>/dev/null || true
  ip link del peck-veth-host 2>/dev/null || true
  rm -rf /etc/netns/$NETNS 2>/dev/null || true
  echo "[$NETNS] ✓ Removed"
}

cmd_status() {
  if ! ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    echo "[$NETNS] Not running"
    exit 1
  fi
  echo "[$NETNS] Running"
  ip netns exec "$NETNS" wg show "$WG_IF" 2>/dev/null | sed 's/^/  /'
  echo ""
  echo "  Egress IP:"
  ip netns exec "$NETNS" curl -s --max-time 3 https://api.ipify.org 2>/dev/null | sed 's/^/    /'
  echo ""
}

cmd_exec() {
  if ! ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    echo "[$NETNS] Not running. Run '$0 up' first."
    exit 1
  fi
  ip netns exec "$NETNS" "$@"
}

case "${1:-}" in
  up)    cmd_up ;;
  down)  cmd_down ;;
  status) cmd_status ;;
  exec)  shift; cmd_exec "$@" ;;
  *) echo "Usage: $0 {up|down|status|exec CMD}"; exit 1 ;;
esac
