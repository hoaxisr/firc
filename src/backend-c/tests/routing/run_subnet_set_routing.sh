#!/bin/sh
set -eu

HELPER=${FIRC_ROUTECHECK:?set FIRC_ROUTECHECK to the firc-routecheck binary}

if [ -z "${FIRC_ROUTING_INSIDE:-}" ]; then
    if [ "$(id -u)" = 0 ]; then
        exec env FIRC_ROUTING_INSIDE=1 unshare -mn sh "$0" "$@"
    fi
    exec env FIRC_ROUTING_INSIDE=1 unshare -Urmn sh "$0" "$@"
fi

PIDS=""
T=$(mktemp -d)
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

mount -t tmpfs tmpfs /run
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
ip link set lo up

netns() {
    unshare -n sleep 600 >/dev/null 2>&1 &
    p=$!
    i=0
    while [ "$(readlink /proc/$p/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || fail "a namespace never appeared"
        sleep 0.05
    done
    nsenter -t "$p" -n sysctl -qw net.ipv4.conf.all.arp_ignore=0 net.ipv4.conf.default.arp_ignore=0
    nsenter -t "$p" -n sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
    echo "$p"
}
in_ns() {
    p=$1
    shift
    nsenter -t "$p" -n "$@"
}

TUN=$(netns); PIDS="$PIDS $TUN"
WAN=$(netns); PIDS="$PIDS $WAN"
CA=$(netns); PIDS="$PIDS $CA"

far() {
    ip link add "$2" type veth peer name "$2p"
    ip link set "$2p" netns "$1"
    ip addr add "$3/30" dev "$2"
    ip -6 addr add "$5/64" dev "$2"
    ip link set "$2" up
    in_ns "$1" ip link set lo up
    in_ns "$1" ip addr add "$4/30" dev "$2p"
    in_ns "$1" ip -6 addr add "$6/64" dev "$2p"
    in_ns "$1" ip link set "$2p" up
    in_ns "$1" ip route add default via "$3"
    in_ns "$1" ip -6 route add default via "$5"
    for a in 10.77.1.1 10.78.1.1 2001:db8::1 2001:db9::1; do
        in_ns "$1" ip addr add "$a" dev lo
        nsenter -t "$1" -n "$HELPER" serve "$a" 53 "$7" &
        PIDS="$PIDS $!"
    done
}
far "$TUN" tun0 10.99.0.1 10.99.0.2 fd99::1 fd99::2 tunnel
far "$WAN" wan0 10.98.0.1 10.98.0.2 fd98::1 fd98::2 wan

ip link add lana type veth peer name lanac
ip link set lanac netns "$CA"
ip addr add 10.10.1.1/24 dev lana
ip -6 addr add fd10:1::1/64 dev lana
ip link set lana up
in_ns "$CA" ip link set lo up
in_ns "$CA" ip addr add 10.10.1.2/24 dev lanac
in_ns "$CA" ip -6 addr add fd10:1::2/64 dev lanac
in_ns "$CA" ip link set lanac up
in_ns "$CA" ip route add default via 10.10.1.1
in_ns "$CA" ip -6 route add default via fd10:1::1

ip route add default via 10.98.0.2 dev wan0
ip -6 route add default via fd98::2 dev wan0
ip route add default dev tun0 table 100
ip -6 route add default via fd99::2 dev tun0 table 100
ip rule add fwmark 0x50000/0xff0000 lookup 100 priority 50
ip -6 rule add fwmark 0x50000/0xff0000 lookup 100 priority 50
sleep 0.2

ask() {
    got=$(in_ns "$CA" "$HELPER" ask "$2" 53)
    [ "$got" = "from=$3" ] || fail "$1: got \"$got\", want \"from=$3\""
    echo "ok: $1"
}

rc=0
"$HELPER" sets write || rc=$?
if [ "$rc" = 77 ]; then
    echo "SKIP: no ip_set in this kernel"
    exit 77
fi
[ "$rc" = 0 ] || fail "firc-routecheck sets write"
ask "10.77.1.1, in the set, leaves by the tunnel" 10.77.1.1 tunnel
ask "10.78.1.1, outside the set, leaves by the WAN" 10.78.1.1 wan
ask "2001:db8::1, in the v6 set, leaves by the tunnel" 2001:db8::1 tunnel
ask "2001:db9::1, outside the v6 set, leaves by the WAN" 2001:db9::1 wan

"$HELPER" xtdump mangle v4 > "$T/before" || fail "firc-routecheck xtdump mangle v4"
grep -q -- "--match-set #" "$T/before" || fail "no set rule in mangle: $(cat "$T/before")"
"$HELPER" xtdump mangle v6 > "$T/before6" || fail "firc-routecheck xtdump mangle v6"
grep -q -- "--match-set #" "$T/before6" || fail "no set rule in the v6 mangle: $(cat "$T/before6")"
"$HELPER" sets swap || fail "firc-routecheck sets swap"
"$HELPER" xtdump mangle v4 > "$T/after" || fail "firc-routecheck xtdump mangle v4"
cmp -s "$T/before" "$T/after" || fail "mangle changed across the swap"
echo "ok: the swap wrote no table"
ask "after the swap, 10.78.1.1 leaves by the tunnel" 10.78.1.1 tunnel
ask "after the swap, 10.77.1.1 leaves by the WAN" 10.77.1.1 wan

"$HELPER" sets destroy || fail "a set the rule refers to was not refused"
echo "ok: a set in use is not destroyed"
"$HELPER" sets sweep || fail "the sweep left a set behind"
echo "ok: with the chain dropped, the sweep leaves no set"
echo "PASS: subnet set routing"
