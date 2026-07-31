#!/bin/bash
# peck-vpn.sh — WireGuard in a network namespace (multi-tunnel)
#
# Uses the WG netns trick: create wgN in host ns (has internet),
# move it into "peck" ns. Source-based policy routing per tunnel.
#
# Usage:
#   peck-vpn.sh up [config1.conf config2.conf ...]
#   peck-vpn.sh down
#
# Default: ~/.config/peck/wg0.conf (single tunnel, backward compatible)

set -euo pipefail

NETNS="peck"
VETH_HOST="peck-veth"
VETH_NS="peck-veth-ns"
VETH_HOST_IP="10.200.200.1/30"
VETH_NS_IP="10.200.200.2"
RT_BASE=100  # first routing table number

case "${1:-}" in
up)
  ip netns list 2>/dev/null | cut -d' ' -f1 | grep -qx "$NETNS" && { echo "[$NETNS] already up"; exit 0; }

  # Collect config files
  shift || true
  CONFIGS=("$@")
  if [[ ${#CONFIGS[@]} -eq 0 ]]; then
    DEFAULT="~/.config/peck/wg0.conf"
    [[ -f "$DEFAULT" ]] && CONFIGS=("$DEFAULT") || { echo "[$NETNS] ✗ no config files found" >&2; exit 1; }
  fi

  # Verify all configs exist
  for c in "${CONFIGS[@]}"; do
    [[ -f "$c" ]] || { echo "[$NETNS] ✗ config not found: $c" >&2; exit 1; }
  done

  echo "[$NETNS] ${#CONFIGS[@]} tunnel(s): ${CONFIGS[*]}"

  # 1. Create netns
  ip netns add "$NETNS"
  ip netns exec "$NETNS" ip link set lo up

  # 2. Create WG interfaces (one per config)
  WG_IPS=()
  WG_IP6S=()
  for i in "${!CONFIGS[@]}"; do
    CONF="${CONFIGS[$i]}"
    IFACE="wg$i"
    TABLE=$((RT_BASE + i))

    # Read config
    PRIV=$(awk -F'= ' '/^PrivateKey/{print $2}' "$CONF")
    ADDR=$(awk -F'= ' '/^Address/{print $2}' "$CONF")
    PUB=$(awk -F'= ' '/^PublicKey/{print $2}' "$CONF")
    ALLOW=$(awk -F'= ' '/^AllowedIPs/{print $2}' "$CONF")
    EP=$(awk -F'= ' '/^Endpoint/{print $2}' "$CONF")
    DNS=$(awk -F'= ' '/^DNS/{print $2}' "$CONF")

    # Extract source IPs (strip CIDR). Address may be "IPv4/32, IPv6/128"
    SRC_IP=$(echo "$ADDR" | tr ',' '\n' | grep '\.' | head -1 | sed 's|/.*||')
    SRC_IP6=$(echo "$ADDR" | tr ',' '\n' | grep ':' | head -1 | sed 's|/.*||')

    # Resolve endpoint hostname
    HOST="${EP%%:*}"; PORT="${EP##*:}"
    IP_ADDR=$(getent hosts "$HOST" | awk '{print $1}')
    [[ -z "$IP_ADDR" ]] && IP_ADDR="$HOST"

    # Create wg$i in HOST ns (UDP socket has internet), configure, move to netns
    ip link add "$IFACE" type wireguard
    printf '%s' "$PRIV" | wg set "$IFACE" private-key /dev/stdin \
      peer "$PUB" allowed-ips "$ALLOW" endpoint "$IP_ADDR:$PORT"
    ip link set "$IFACE" netns "$NETNS"
    # Add addresses (may be multiple: "IPv4/32, IPv6/128")
    IFS=', ' read -ra ADDR_PARTS <<< "$ADDR"
    for addr_part in "${ADDR_PARTS[@]}"; do
      ip netns exec "$NETNS" ip addr add "$addr_part" dev "$IFACE"
    done
    ip netns exec "$NETNS" ip link set "$IFACE" up

    # Policy routing: source IP → matching table → matching tunnel
    ip netns exec "$NETNS" ip rule add from "$SRC_IP" table "$TABLE"
    ip netns exec "$NETNS" ip route add default dev "$IFACE" table "$TABLE"

    # IPv6 policy routing (if configured)
    if [[ -n "$SRC_IP6" ]]; then
      # Address already added in ADDR_PARTS loop above; just add policy routing
      ip netns exec "$NETNS" ip -6 rule add from "$SRC_IP6" table "$TABLE" || true
      ip netns exec "$NETNS" ip -6 route add default dev "$IFACE" table "$TABLE" || true
      # First tunnel also gets the main default route
      [[ $i -eq 0 ]] && ip netns exec "$NETNS" ip -6 route add default dev "$IFACE" || true
      WG_IP6S+=("$SRC_IP6")
    fi

    WG_IPS+=("$SRC_IP")
    echo "[$NETNS] ✓ $IFACE: $SRC_IP → $IP_ADDR:$PORT (table $TABLE)"

    # First tunnel also gets the main default route (fallback for unbound sockets)
    [[ $i -eq 0 ]] && ip netns exec "$NETNS" ip route add default dev "$IFACE"

    # DNS
    [[ $i -eq 0 ]] && {
      mkdir -p "/etc/netns/$NETNS"
      DNS_IP="${DNS:-1.1.1.1}"
      echo "nameserver $DNS_IP" > "/etc/netns/$NETNS/resolv.conf"
    }
  done

  # 3. veth pair for host→ns communication (port 80 forwarding)
  ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
  ip addr add "$VETH_HOST_IP" dev "$VETH_HOST"
  ip link set "$VETH_HOST" up
  ip link set "$VETH_NS" netns "$NETNS"
  ip netns exec "$NETNS" ip addr add "${VETH_NS_IP}/30" dev "$VETH_NS"
  ip netns exec "$NETNS" ip link set "$VETH_NS" up

  # 4. Trigger handshakes + verify
  for i in "${!CONFIGS[@]}"; do
    IFACE="wg$i"
    ip netns exec "$NETNS" ping -c1 -W3 -I "$IFACE" 1.1.1.1 >/dev/null 2>&1 || true
  done
  sleep 3

  for i in "${!CONFIGS[@]}"; do
    IFACE="wg$i"
    EXIT_IP=$(ip netns exec "$NETNS" wg show "$IFACE" 2>/dev/null | grep -q handshake \
      && ip netns exec "$NETNS" bash -c "curl -s --max-time 3 --interface $IFACE https://api.ipify.org 2>/dev/null" \
      || echo "⚠ no handshake")
    echo "[$NETNS]   $IFACE exit: $EXIT_IP"
  done

  # 5. Output WG source IPs for the daemon
  IPS_CSV=$(IFS=,; echo "${WG_IPS[*]}")
  echo "[$NETNS] ✓ VPN up — WG IPs: $IPS_CSV"
  echo "PECK_WG_IPS=$IPS_CSV" > /run/peck-wg-ips
  if [[ ${#WG_IP6S[@]} -gt 0 ]]; then
    IP6_CSV=$(IFS=,; echo "${WG_IP6S[*]}")
    echo "[$NETNS] ✓ VPN up — WG IPv6: $IP6_CSV"
    echo "PECK_WG_IP6S=$IP6_CSV" >> /run/peck-wg-ips
  fi
  ;;

down)
  ip netns del "$NETNS" 2>/dev/null || true
  ip link del "$VETH_HOST" 2>/dev/null || true
  rm -rf "/etc/netns/$NETNS" 2>/dev/null || true
  echo "[$NETNS] ✓ down"
  ;;

*)
  echo "Usage: $0 {up [config1.conf ...] | down}" >&2; exit 1
  ;;
esac
