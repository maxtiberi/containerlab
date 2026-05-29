#!/bin/sh
# Traffic generator: 20.0.0.20 <-> 20.0.0.21 on VLAN 10 at ~1Gbps
# Run as root. Pass "server" or "client" as first argument.
# Usage:
#   On 20.0.0.21 node: ./gen-traffic.sh server <parent-iface>
#   On 20.0.0.20 node: ./gen-traffic.sh client <parent-iface>

ROLE="${1:-}"
PARENT="${2:-eth0}"
VLAN_ID=10
SRC_IP="20.0.0.20"
DST_IP="20.0.0.21"
VLAN_IFACE="${PARENT}.${VLAN_ID}"
TARGET_BPS="1000M"
STREAMS=4   # parallel TCP streams to saturate 1G
PORT=5201

die() { echo "ERROR: $*" >&2; exit 1; }

install_deps() {
    which iperf3 >/dev/null 2>&1 || apk add --no-cache iperf3
    which ss    >/dev/null 2>&1 || apk add --no-cache iproute2
}

setup_vlan() {
    local ip="$1"
    which ip >/dev/null 2>&1 || apk add --no-cache iproute2

    if ! ip link show "$VLAN_IFACE" >/dev/null 2>&1; then
        echo "Creating VLAN interface $VLAN_IFACE..."
        ip link add link "$PARENT" name "$VLAN_IFACE" type vlan id "$VLAN_ID"
    fi

    ip link set "$VLAN_IFACE" up

    if ! ip addr show "$VLAN_IFACE" | grep -q "$ip/"; then
        echo "Assigning $ip/24 to $VLAN_IFACE..."
        ip addr add "${ip}/24" dev "$VLAN_IFACE"
    fi

    echo "Interface $VLAN_IFACE is up with IP $ip"
}

wait_for_listen() {
    echo "Waiting for iperf3 to be listening on port $PORT..."
    for i in $(seq 1 20); do
        ss -tlnp | grep -q ":${PORT}" && return 0
        sleep 0.5
    done
    echo "WARNING: iperf3 does not appear to be listening after 10s"
}

run_server() {
    setup_vlan "$DST_IP"
    echo "Starting iperf3 server (listening on all interfaces, port $PORT)..."
    # Do NOT use -B so iperf3 listens on 0.0.0.0 — avoids bind failures
    # Loop restarts server after each client session
    while true; do
        iperf3 -s -p "$PORT" -i 5
        echo "iperf3 server exited (code $?), restarting in 1s..."
        sleep 1
    done
}

run_client() {
    setup_vlan "$SRC_IP"

    echo "Waiting for ICMP reachability to $DST_IP..."
    for i in $(seq 1 30); do
        ping -c 1 -W 1 "$DST_IP" >/dev/null 2>&1 && break
        sleep 1
    done
    ping -c 1 -W 1 "$DST_IP" >/dev/null 2>&1 || die "$DST_IP unreachable after 30s"

    echo "Waiting for iperf3 port $PORT to be open on $DST_IP..."
    for i in $(seq 1 30); do
        # Use /dev/tcp if available, else nc
        if (echo "" | nc -w1 "$DST_IP" "$PORT") >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    TOTAL_MBPS=$(echo "$TARGET_BPS" | tr -d 'MmGg')
    STREAM_BPS="$((TOTAL_MBPS / STREAMS))M"

    echo "Starting iperf3 client: $SRC_IP -> $DST_IP @ ${STREAM_BPS} x $STREAMS streams = $TARGET_BPS total"

    exec iperf3 \
        -c "$DST_IP" \
        -B "$SRC_IP" \
        -p "$PORT" \
        -b "$STREAM_BPS" \
        -P "$STREAMS" \
        -t 86400 \
        -i 5 \
        --omit 2
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
