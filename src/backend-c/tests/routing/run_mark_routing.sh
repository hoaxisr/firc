#!/bin/sh
set -eu

HELPER=${FIRC_ROUTECHECK:?set FIRC_ROUTECHECK to the firc-routecheck binary}

if [ -z "${FIRC_ROUTING_INSIDE:-}" ]; then
    if [ "$(id -u)" = 0 ]; then
        exec env FIRC_ROUTING_INSIDE=1 unshare -mn sh "$0" "$@"
    fi
    exec env FIRC_ROUTING_INSIDE=1 unshare -Urmn sh "$0" "$@"
fi

FAR=""
SRV=""
cleanup() {
    [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
    [ -n "$FAR" ] && kill "$FAR" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

ip link set lo up
ip link add tun0 type veth peer name tun0p
ip link add wan0 type veth peer name wan0p
ip addr add 10.99.0.1/30 dev tun0
ip addr add 10.98.0.1/30 dev wan0
ip link set tun0 up
ip link set wan0 up
ip link set wan0p up
ip route add default via 10.98.0.2 dev wan0
ip route add default dev tun0 table 100
ip rule add fwmark 0x10000/0xff0000 lookup 100 priority 50

unshare -n sleep 600 &
FAR=$!
i=0
while [ "$(readlink /proc/$FAR/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "the far namespace never appeared"
    sleep 0.05
done
ip link set tun0p netns "$FAR"
far() { nsenter -t "$FAR" -n "$@"; }
far ip link set lo up
far ip addr add 10.99.0.2/30 dev tun0p
far ip link set tun0p up
far ip addr add 9.9.9.9/32 dev lo
far ip route add default dev tun0p
# nsenter itself in the background, not far(): $! is then the server, which the cleanup kills.
nsenter -t "$FAR" -n "$HELPER" serve 9.9.9.9 53 &
SRV=$!
sleep 0.2

check() { # <label> <mark-hex> <want line>
    got=$("$HELPER" send 9.9.9.9 53 "$2")
    [ "$got" = "$3" ] || fail "$1: got \"$got\", want \"$3\""
    echo "ok: $1 ($got)"
}

check "a query with the group's mark leaves by the tunnel" 0x40010000 "src=10.99.0.1 reply=yes"
check "a query without a mark leaves by the WAN" 0 "src=10.98.0.1 reply=no"
check "another group's mark is not this group's table" 0x40020000 "src=10.98.0.1 reply=no"
check "the handled bit alone routes nothing" 0x40000000 "src=10.98.0.1 reply=no"
echo "PASS: mark routing"
