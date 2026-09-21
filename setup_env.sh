#!/usr/bin/env bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Error: root privileges required" >&2
  exit 1
fi

apt-get update -y
apt-get install -y iproute2 tcpdump tshark python3-pip python3-venv \
    liboqs-dev git build-essential cmake ninja-build libssl-dev

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install aioquic cryptography pyshark scapy dpkt matplotlib seaborn pandas

# Avoid interactive prompt for wireshark group configuration
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common || true
if [ -n "$SUDO_USER" ]; then
    usermod -a -G wireshark "$SUDO_USER" || true
fi
