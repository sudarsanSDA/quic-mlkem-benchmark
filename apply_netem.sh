#!/usr/bin/env bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Error: root privileges required" >&2
  exit 1
fi

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <RTT_MS> <LOSS_PCT> <MTU>" >&2
  exit 1
fi

RTT_MS=$1
LOSS_PCT=$2
MTU=$3

# Split RTT delay symmetrically across client and server interfaces (e.g., RTT=20ms -> 10ms per interface)
HALF_RTT=$(echo "$RTT_MS / 2" | bc)

# Reset existing qdiscs to prevent rule stacking
ip netns exec server_ns tc qdisc del dev veth_server root 2>/dev/null || true
ip netns exec client_ns tc qdisc del dev veth_client root 2>/dev/null || true

# Apply netem delay and loss symmetrically
ip netns exec server_ns tc qdisc add dev veth_server root netem delay ${HALF_RTT}ms loss ${LOSS_PCT}%
ip netns exec client_ns tc qdisc add dev veth_client root netem delay ${HALF_RTT}ms loss ${LOSS_PCT}%

ip netns exec server_ns ip link set dev veth_server mtu ${MTU}
ip netns exec client_ns ip link set dev veth_client mtu ${MTU}
