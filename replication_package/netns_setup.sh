#!/usr/bin/env bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Error: root privileges required" >&2
  exit 1
fi

ip netns add client_ns
ip netns add server_ns

ip link add veth_client type veth peer name veth_server

ip link set veth_client netns client_ns
ip link set veth_server netns server_ns

ip netns exec client_ns ip addr add 10.0.0.1/24 dev veth_client
ip netns exec client_ns ip link set lo up
ip netns exec client_ns ip link set veth_client up

ip netns exec server_ns ip addr add 10.0.0.2/24 dev veth_server
ip netns exec server_ns ip link set lo up
ip netns exec server_ns ip link set veth_server up
