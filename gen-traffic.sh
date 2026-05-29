#!/bin/sh
# Multi-VLAN traffic generator using iperf3
# Run as root. Pass "server" or "client" as first argument.
# Usage:
#   On server node: ./gen-traffic.sh server
#   On client node: ./gen-traffic.sh client

ROLE="${1:-}"

# Define VLAN sessions: IFACE:VLAN_ID:SRC_IP:DST_IP:PORT
# Add or remove lines to configure more sessions
SESSIONS="
eth1:10:20.0.0.20:20.0.0.21:5201
eth2:20:20.0.1.20:20.0.1.21:5202
"

TARGET_BPS="1000M"
STREAMS=4

die() { echo "ERROR: $*" >&2; exit 1; }

install_deps() {
    which iperf3 >/dev/null 2>&1 || apk add --no-cache iperf3
    which nc     >/dev/null 2>&1 || apk add --no-cache netcat-openbsd
    which ip     >/dev/null 2>&1 || apk add --no-cache iproute2
}

setup_vlan() {
    local parent="$1" vlan_id="$2" ip="$3"
    local iface="${parent}.${vlan_id}"

    if ! ip link show "$iface" >/dev/null 2>&1; then
        echo "[$iface] Creating VLAN interface..."
        ip link add link "$parent" name "$iface" type vlan id "$vlan_id"
    fi
    ip link set "$iface" up

    if ! ip addr show "$iface" | grep -q "${ip}/"; then
        echo "[$iface] Assigning $ip/24..."
        ip addr add "${ip}/24" dev "$iface"
    fi
    echo "[$iface] Up with IP $ip"
}

run_server_session() {
    local parent="$1" vlan_id="$2" src="$3" dst="$4" port="$5"
    local iface="${parent}.${vlan_id}"

    setup_vlan "$parent" "$vlan_id" "$dst"
    echo "[$iface] iperf3 server listening on port $port..."
    while true; do
        iperf3 -s -p "$port" -i 5
        echo "[$iface] iperf3 server exited, restarting..."
        sleep 1
    done
}

run_client_session() {
    local parent="$1" vlan_id="$2" src="$3" dst="$4" port="$5"
    local iface="${parent}.${vlan_id}"

    setup_vlan "$parent" "$vlan_id" "$src"

    echo "[$iface] Waiting for ICMP to $dst..."
    for i in $(seq 1 30); do
        ping -c 1 -W 1 "$dst" >/dev/null 2>&1 && break
        sleep 1
    done
    ping -c 1 -W 1 "$dst" >/dev/null 2>&1 || { echo "[$iface] ERROR: $dst unreachable"; return 1; }

    echo "[$iface] Waiting for iperf3 port $port on $dst..."
    for i in $(seq 1 30); do
        nc -w1 "$dst" "$port" </dev/null >/dev/null 2>&1 && break
        sleep 1
    done

    local total_mbps stream_bps
    total_mbps=$(echo "$TARGET_BPS" | tr -d 'MmGg')
    stream_bps="$((total_mbps / STREAMS))M"

    echo "[$iface] Starting iperf3: $src -> $dst @ ${stream_bps} x $STREAMS streams"
    while true; do
        iperf3 -c "$dst" -B "$src" -p "$port" -b "$stream_bps" -P "$STREAMS" -t 86400 -i 5 --omit 2
        echo "[$iface] iperf3 client exited, restarting..."
        sleep 2
    done
}

run_all() {
    local mode="$1"
    local pids=""

    echo "$SESSIONS" | grep -v '^\s*$' | while IFS=: read parent vlan_id src dst port; do
        if [ "$mode" = "server" ]; then
            run_server_session "$parent" "$vlan_id" "$src" "$dst" "$port" &
        else
            run_client_session "$parent" "$vlan_id" "$src" "$dst" "$port" &
        fi
    done

    # Wait for all background jobs and exit if any fail
    wait
}

cleanup() {
    echo "Caught signal, stopping all iperf3 processes..."
    kill 0
    exit 0
}

[ "$(id -u)" -eq 0 ] || die "Must run as root"

install_deps
trap cleanup INT TERM

case "$ROLE" in
    server) run_all server ;;
    client) run_all client ;;
    *)
        echo "Usage: $0 {server|client}"
        echo ""
        echo "Configured sessions:"
        echo "$SESSIONS" | grep -v '^\s*$' | while IFS=: read parent vlan_id src dst port; do
            echo "  VLAN $vlan_id on $parent: $src -> $dst (port $port)"
        done
        exit 1
        ;;
esac
