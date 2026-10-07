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

fail() { # stderr: a caller capturing stdout (TUN=$(netns)) would swallow it
    echo "FAIL: $*" >&2
    exit 1
}

mount -t tmpfs tmpfs /run # iptables' lock, in this mount namespace only
sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.ip_forward=1
ip link set lo up

probe() { # <table> <rule...>
    t=$1
    shift
    iptables -t "$t" -N PROBE
    iptables -t "$t" -A PROBE "$@" 2>"$T/probe" || {
        cat "$T/probe" >&2
        fail "the kernel refused '-t $t $*' inside the user namespace; load its module (sudo modprobe -a xt_mac xt_mark xt_connmark xt_conntrack xt_nat xt_MASQUERADE nf_conntrack nf_nat iptable_nat nft_chain_nat) and run again"
    }
    iptables -t "$t" -F PROBE
    iptables -t "$t" -X PROBE
}
probe mangle -m mac --mac-source 02:00:00:00:00:0A -j RETURN
probe mangle -m mark --mark 0xf00faad/0xbf00ffff -j RETURN
probe mangle -m conntrack --ctdir REPLY -j RETURN
probe mangle -j MARK --set-xmark 0x40050000/0x40ff0000
probe mangle -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000
probe nat -o lo -j MASQUERADE
probe nat -d 192.0.2.1 -j DNAT --to-destination 192.0.2.2

netns() { # an empty network namespace; prints the pid that holds it
    unshare -n sleep 600 >/dev/null 2>&1 &
    p=$!
    i=0
    while [ "$(readlink /proc/$p/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || fail "a namespace never appeared"
        sleep 0.05
    done
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
CB=$(netns); PIDS="$PIDS $CB"

far() { # <pid> <veth> <router side> <far side> <name>
    ip link add "$2" type veth peer name "$2p"
    ip link set "$2p" netns "$1"
    ip addr add "$3/30" dev "$2"
    ip link set "$2" up
    in_ns "$1" ip link set lo up
    in_ns "$1" ip addr add "$4/30" dev "$2p"
    in_ns "$1" ip link set "$2p" up
    in_ns "$1" ip addr add 9.9.9.9/32 dev lo
    in_ns "$1" ip route add default via "$3"
    # nsenter itself in the background, not in_ns: $! is then the server, which the cleanup kills.
    nsenter -t "$1" -n "$HELPER" serve 9.9.9.9 53 "$5" &
    PIDS="$PIDS $!"
}
far "$TUN" tun0 10.99.0.1 10.99.0.2 tunnel
far "$WAN" wan0 10.98.0.1 10.98.0.2 wan

client() { # <pid> <veth> <mac> <router side> <client side>
    ip link add "$2" type veth peer name "$2c"
    ip link set "$2c" address "$3"
    ip link set "$2c" netns "$1"
    ip addr add "$4/24" dev "$2"
    ip link set "$2" up
    in_ns "$1" ip link set lo up
    in_ns "$1" ip addr add "$5/24" dev "$2c"
    in_ns "$1" ip link set "$2c" up
    in_ns "$1" ip route add default via "$4"
}
client "$CA" lana 02:00:00:00:00:0a 10.10.1.1 10.10.1.2
client "$CB" lanb 02:00:00:00:00:0b 10.10.2.1 10.10.2.2

ip route add default via 10.98.0.2 dev wan0
ip route add default dev tun0 table 100
ip rule add fwmark 0x50000/0xff0000 lookup 100 priority 50
sleep 0.2

reset() { # no firc chain, and the firmware's own chain jumped first
    for t in filter mangle nat; do
        iptables -t "$t" -F
        iptables -t "$t" -X
    done
    iptables -t mangle -N FW
    iptables -t mangle -A PREROUTING -j FW
}
firc() { # firc's chains for a selector, from the real builder, and the DNAT
    "$HELPER" devchain 5 "$@" > "$T/devchain" || fail "firc-routecheck devchain $*"
    FAKE=$(sed -n 's/^# fake //p' "$T/devchain")
    [ -n "$FAKE" ] || fail "the builder issued no fake address"
    iptables-restore --noflush < "$T/devchain" || fail "iptables-restore refused the builder's chains for: $*"
    iptables -t nat -A PREROUTING -d "$FAKE" -j DNAT --to-destination 9.9.9.9
}
ask() { # <label> <client pid> <which far end must answer> [address asked, default the fake]
    got=$(in_ns "$2" "$HELPER" ask "${4:-$FAKE}" 53)
    [ "$got" = "from=$3" ] || fail "$1: got \"$got\", want \"from=$3\""
    echo "ok: $1"
}

reset
firc
ask "no selector: A goes through the tunnel" "$CA" tunnel
ask "no selector: B goes through the tunnel" "$CB" tunnel

reset
firc allow 10.10.1.2
ask "allow by address: A, selected, goes through the tunnel" "$CA" tunnel
ask "allow by address: B, not selected, holding the same fake, goes through the WAN" "$CB" wan

reset
firc allow mac:02:00:00:00:00:0a
ask "allow by MAC: A, selected, goes through the tunnel" "$CA" tunnel
ask "allow by MAC: B, not selected, goes through the WAN" "$CB" wan

reset
firc deny 10.10.2.2
ask "deny by address: A, not denied, goes through the tunnel" "$CA" tunnel
ask "deny by address: B, denied, holding the same fake, goes through the WAN" "$CB" wan

reset
firc deny mac:02:00:00:00:00:0b
ask "deny by MAC: A, not denied, goes through the tunnel" "$CA" tunnel
ask "deny by MAC: B, denied, goes through the WAN" "$CB" wan

reset
iptables -t mangle -A FW -m mac --mac-source 02:00:00:00:00:0a -j MARK --set-xmark 0x0ffffaad/0xffffffff
firc policy Guests=0ffffaad allow policy:Guests
ask "allow by policy mark alone: A, marked into it, goes through the tunnel" "$CA" tunnel
ask "allow by policy mark alone: B, unmarked, goes through the WAN" "$CB" wan

reset
iptables -t mangle -A FW -m mac --mac-source 02:00:00:00:00:0b -j MARK --set-xmark 0x0ffffaad/0xffffffff
firc policy Guests=0ffffaad deny policy:Guests
ask "deny by policy: A, outside it, goes through the tunnel" "$CA" tunnel
ask "deny by policy: B, marked into it by the firmware, goes through the WAN" "$CB" wan

reset
iptables -t mangle -A FW -m mac --mac-source 02:00:00:00:00:0b -j MARK --set-xmark 0x0ffffaad/0xffffffff
iptables -t mangle -A FW -m mac --mac-source 02:00:00:00:00:0b -j MARK --set-xmark 0x40010000/0x40ff0000
firc policy Guests=0ffffaad deny policy:Guests
ask "deny by policy after an earlier chain wrote firc's bits: A goes through the tunnel" "$CA" tunnel
ask "deny by policy after an earlier chain wrote firc's bits: B still goes through the WAN" "$CB" wan

reset
firc policy Guests=0ffffaad segment Guests=10.10.2.0/24 deny policy:Guests
ask "deny by policy, B unlisted on its segment and unmarked: A goes through the tunnel" "$CA" tunnel
ask "deny by policy, B unlisted on its segment and unmarked: B goes through the WAN" "$CB" wan

reset
firc policy Guests=0ffffaad segment Guests=10.10.2.0/24 allow policy:Guests
ask "allow by policy, B unlisted on its segment and unmarked: B goes through the tunnel" "$CB" tunnel
ask "allow by policy, B unlisted on its segment and unmarked: A goes through the WAN" "$CA" wan

reset
firc subnet 9.9.9.9/32
ask "subnet, no selector: A goes through the tunnel" "$CA" tunnel 9.9.9.9
ask "subnet, no selector: B goes through the tunnel" "$CB" tunnel 9.9.9.9

reset
firc subnet 9.9.9.9/32 allow 10.10.1.2
ask "subnet, allow by address: A, selected, goes through the tunnel" "$CA" tunnel 9.9.9.9
ask "subnet, allow by address: B, not selected, goes through the WAN" "$CB" wan 9.9.9.9

reset
firc subnet 9.9.9.9/32 deny mac:02:00:00:00:00:0b
ask "subnet, deny by MAC: A, not denied, goes through the tunnel" "$CA" tunnel 9.9.9.9
ask "subnet, deny by MAC: B, denied, goes through the WAN" "$CB" wan 9.9.9.9

echo "PASS: selector routing"
