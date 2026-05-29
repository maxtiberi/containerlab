#!/bin/sh
# Traffic generator: 20.0.0.20 <-> 20.0.0.21 on VLAN 10 at ~1Gbps
# Run as root. Pass "server" or "client" as first argument.
# Usage:
#   On 20.0.0.21 node: ./gen-traffic.sh server <parent-iface>
#   On 20.0.0.20 node: ./gen-traffic.sh client <parent-iface>

set -e

ROLE="${1:-}"
PARENT="${2:-eth0}"
VLAN_ID=10
SRC_IP="20.0.0.20"
DST_IP="20.0.0.21"
VLAN_IFACE="${PARENT}.${VLAN_ID}"
TARGET_BPS="1000M"
STREAMS=4          # parallel TCP streams to saturate 1G
DURATION=0         # 0 = run forever (use Ctrl-C to stop)

die() { echo "ERROR: $*" >&2; exit 1; }

install_deps() {
    which iperf3 >/dev/null 2>&1 && return
    echo "Installing iperf3..."
    apk add --no-cache iperf3
}

setup_vlan() {
    local ip="$1"
    which ip >/dev/null 2>&1 || apk add --no-cache iproute2

    if ! ip link show "$VLAN_IFACE" >/dev/null 2>&1; then
        echo "Creating VLAN interface $VLAN_IFACE..."
        ip link add link "$PARENT" name "$VLAN_IFACE" type vlan id "$VLAN_ID"
    fi

    ip link set "$VLAN_IFACE" up

    # Assign IP only if not already present
    if ! ip addr show "$VLAN_IFACE" | grep -q "$ip/"; then
        echo "Assigning $ip/24 to $VLAN_IFACE..."
        ip addr add "${ip}/24" dev "$VLAN_IFACE"
    fi

    echo "Interface $VLAN_IFACE is up with IP $ip"
}

run_server() {
    setup_vlan "$DST_IP"
    echo "Starting iperf3 server on $DST_IP (port 5201)..."
    # Loop so server restarts after each client disconnects
    while true; do
        iperf3 -s -B "$DST_IP" -p 5201
        echo "iperf3 server exited, restarting..."
        sleep 1
    done
}

run_client() {
    setup_vlan "$SRC_IP"

    echo "Waiting for server at $DST_IP..."
    for i in $(seq 1 30); do
        ping -c 1 -W 1 "$DST_IP" >/dev/null 2>&1 && break
        sleep 1
    done
    ping -c 1 -W 1 "$DST_IP" >/dev/null 2>&1 || die "Server $DST_IP unreachable after 30s"

    echo "Starting iperf3 client: $SRC_IP -> $DST_IP @ $TARGET_BPS with $STREAMS streams"
    # -c client mode
    # -B bind source address
    # -b target bandwidth per stream (total = STREAMS * TARGET_BPS / STREAMS = TARGET_BPS)
    # -P parallel streams
    # -t duration (0 = infinite, but iperf3 doesn't support 0; use large value)
    # -i 5 report interval in seconds
    # --omit 2 omit first 2 seconds (TCP slow-start)
    TOTAL_MBPS=$(echo "$TARGET_BPS" | tr -d 'M')
    STREAM_BPS="$((TOTAL_MBPS / STREAMS))M"

    exec iperf3 \
        -c "$DST_IP" \
        -B "$SRC_IP" \
        -b "$STREAM_BPS" \
        -P "$STREAMS" \
        -t 86400 \
        -i 5 \
        --omit 2 \
        -p 5201
}

[ "$(id -u)" -eq 0 ] || die "Must run as root"
[ -n "$PARENT" ] || die "Parent interface not specified"
ip link show "$PARENT" >/dev/null 2>&1 || die "Interface $PARENT does not exist"

install_deps

case "$ROLE" in
    server) run_server ;;
    client) run_client ;;
    *)
        echo "Usage: $0 {server|client} <parent-interface>"
        echo "  server: run on the node that will be $DST_IP (20.0.0.21)"
        echo "  client: run on the node that will be $SRC_IP (20.0.0.20)"
        exit 1
        ;;
esac
