#!/bin/sh
# Build tests/tun-gso.c and run it in its own network namespace.
#
# The namespace keeps the test away from the machine's network: it enables forwarding, turns off
# reverse path filtering and brings up two devices with addresses.
set -eu
cd "$(dirname "$0")/.."

BIN="${TMPDIR:-/tmp}/tun-gso"
cc -O2 -Wall -Wextra -Isrc/tunnel -o "$BIN" tests/tun-gso.c src/tunnel/tun.c

NS=tunvless-tungso
ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
trap 'ip netns delete "$NS" 2>/dev/null || true' EXIT
ip netns exec "$NS" ip link set lo up

# Both paths, not only the fast one: without offload tunvless computes the checksums itself, in
# separate code that is the only path on kernels without IFF_VNET_HDR.
echo "-- with offload"
ip netns exec "$NS" "$BIN"
echo "-- without offload (STEER_TUN_NOGSO)"
ip netns exec "$NS" env STEER_TUN_NOGSO=1 "$BIN"
