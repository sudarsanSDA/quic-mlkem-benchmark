#!/usr/bin/env bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Error: root privileges required" >&2
  exit 1
fi

ip netns del client_ns 2>/dev/null || true
ip netns del server_ns 2>/dev/null || true
