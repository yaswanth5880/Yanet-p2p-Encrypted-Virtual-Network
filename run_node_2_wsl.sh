#!/bin/bash
echo "Starting YaNet Node 2 (WSL Connector)..."
cd "$(dirname "$0")"

# Automatically find the Windows Host IP from inside WSL
WINDOWS_IP=$(ip route show default | awk '{print $3}')
echo "Detected Windows Host IP: $WINDOWS_IP"

# Run the WSL Node and connect to the Windows Node
./build_linux/yanet --port 9995 --identity yanet_data/node_b.secret --connect $WINDOWS_IP:9994
