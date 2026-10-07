#!/bin/sh
# What the command line adds around the tunnel, on a real network: two namespaces joined by a
# veth — the host running tunvless, and the node (tests/fake-vless.py) behind it. The node's
# address is not on the link: the host reaches it only through its default gateway, so every route
# into the tunnel that covers it would loop the tunnel's own connection back into the tunnel.
#
#   * --route default with neither --mark nor --bind-dev: the server's address keeps its route
#     (a host route next to ours), so the tunnel's own connection does not loop into the tunnel;
#   * the node's name is resolved once at startup: with name resolution gone afterwards (as when
#     DNS itself goes into the tunnel), new connections still reach the node;
#   * --bind-dev and --mark keep the server's connection out of the tunnel without a host route;
#   * a subscription file: the first node that answers a probe is chosen, --list numbers the
#     usable ones, a bad --node or a bad link exits 2.
#
# Needs root, iproute2, python3 and wget. TUNVLESS — the binary (./out/tunvless).
set -u
cd "$(dirname "$0")/.."
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "routes: no binary $BIN (make)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "routes: needs root — skipped"; exit 0; }
for t in ip python3 wget base64; do command -v $t >/dev/null 2>&1 || { echo "routes: no $t — skipped"; exit 0; }; done

H=tvl-host N=tvl-node
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
GW=10.70.0.1 HOSTIP=10.70.0.2 NODE=10.71.0.1 PORT=10800
TARGET=203.0.113.7
W="$(mktemp -d)"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${TP:-}" ] && kill "$TP" 2>/dev/null
    ip netns pids $H 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns pids $N 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $H 2>/dev/null; ip netns del $N 2>/dev/null
    rm -rf /etc/netns/$H
    if [ "$fail" != 0 ]; then echo "--- tunnel log (tail)"; tail -n 20 "$W/tun.log" 2>/dev/null; fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

HX() { ip netns exec $H "$@"; }
ip netns del $H 2>/dev/null; ip netns del $N 2>/dev/null
ip netns add $H; ip netns add $N
ip link add v0 netns $H type veth peer name v1 netns $N
HX ip link set lo up; HX ip addr add $HOSTIP/24 dev v0; HX ip link set v0 up
HX ip route add default via $GW
HX sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.v0.rp_filter=0
ip netns exec $N ip link set lo up; ip netns exec $N ip addr add $GW/24 dev v1; ip netns exec $N ip link set v1 up
ip netns exec $N ip addr add $NODE/32 dev lo
# The node's name exists only in the host namespace's own hosts file (ip netns exec mounts it).
mkdir -p /etc/netns/$H
echo "$NODE node.test" > /etc/netns/$H/hosts
ip netns exec $N python3 tests/fake-vless.py --port $PORT --uuid $UUID --mb 1 --bind $NODE > "$W/srv.log" 2>&1 &
sleep 1

LINK="vless://$UUID@node.test:$PORT?security=none&type=tcp#local"

# Start tunvless in the host namespace; wait for its routes. $1.. — extra arguments.
# `ip netns exec` execs in place, so $! is tunvless itself (a shell function here would make it
# the pid of a subshell, and kill would miss the tunnel).
up() {
    ip netns exec $H "$BIN" "$@" > "$W/tun.log" 2>&1 &
    TP=$!
    i=0
    while [ $i -lt 50 ]; do
        HX ip route show 0.0.0.0/1 2>/dev/null | grep -q 'dev vl' && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
# Stop it the way an init script does (SIGTERM) and wait until the device is gone. A tunnel that
# does not stop within 5 s is killed, so the run goes on; DOWN_RC is its exit status (0 is a stop
# by the signal; 137 means it had to be killed).
down() {
    kill "$TP" 2>/dev/null
    i=0
    while kill -0 "$TP" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    kill -9 "$TP" 2>/dev/null
    wait "$TP" 2>/dev/null; DOWN_RC=$?; TP=""
    i=0
    while HX ip link show vl >/dev/null 2>&1 && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
}
# One try: wget retries a reset connection, which would hide a failed one.
fetch() { HX wget -q --tries=1 -O "$W/dl" -T 15 "http://$TARGET/x" && wc -c < "$W/dl" || echo 0; }
WANT=$((1024 * 1024))

# ---- --route default, nothing else: the server keeps its route ------------------------------------
up "$LINK" -d vl -r default
check "tunnel up with --route default" "0" "$?"
check "the server got a host route through the gateway" "1" \
    "$(HX ip route show $NODE/32 | grep -c "via $GW dev v0")"
check "download through the tunnel" "$WANT" "$(fetch)"
# Name resolution goes away (in place: the bind mount keeps the inode).
: > /etc/netns/$H/hosts
check "the node's name is gone for new lookups" "2" "$(HX getent hosts node.test >/dev/null; echo $?)"
check "download still works: the address was pinned at startup" "$WANT" "$(fetch)"
echo "$NODE node.test" > /etc/netns/$H/hosts
down
check "SIGTERM stopped the tunnel, exit code 0" "0" "$DOWN_RC"
check "SIGTERM removed the server's host route" "0" "$(HX ip route show $NODE/32 | grep -c .)"
check "  and the device with the routes into it" "0" "$(HX ip route show 0.0.0.0/1 | grep -c .)"

# ---- a host route the user already had is used, not replaced or removed ---------------------------
# Added the way a person would, with nothing to tell it from the tunnel's own (same gateway, same
# default protocol): a stop that took it for the tunnel's would remove it.
HX ip route add $NODE/32 via $GW dev v0
up "$LINK" -d vl -r default
check "tunnel up next to the user's host route" "0" "$?"
check "download through the tunnel" "$WANT" "$(fetch)"
down
check "the user's host route survived the stop" "1" \
    "$(HX ip route show $NODE/32 | grep -c "via $GW dev v0")"
HX ip route del $NODE/32

# ---- --bind-dev: no host route, the socket leaves through v0 ---------------------------------------
up "$LINK" -d vl -r default -b v0
check "tunnel up with --bind-dev" "0" "$?"
check "no host route for the server" "0" "$(HX ip route show $NODE/32 | grep -c .)"
check "download with --bind-dev" "$WANT" "$(fetch)"
down

# ---- --mark: policy routing keeps marked sockets in their own table --------------------------------
HX ip rule add fwmark 0x77 lookup 177 priority 100
HX ip route add default via $GW dev v0 table 177
up "$LINK" -d vl -r default -m 0x77
check "tunnel up with --mark" "0" "$?"
check "no host route for the server in main" "0" "$(HX ip route show $NODE/32 | grep -c .)"
check "download with --mark" "$WANT" "$(fetch)"
down
HX ip rule del fwmark 0x77 lookup 177 priority 100

# ---- a subscription file: the first node that answers ----------------------------------------------
printf '%s\n%s\n' "vless://$UUID@$NODE:$((PORT + 1))?security=none&type=tcp#dead" \
    "vless://$UUID@$NODE:$PORT?security=none&type=tcp#alive" | base64 > "$W/sub.txt"
check "--list numbers both usable nodes" "0 dead
1 alive" "$(HX timeout 10 "$BIN" --list "$W/sub.txt" | cut -f1,2 | tr '\t' ' ')"
up "$W/sub.txt" -d vl -r default -t 3
check "tunnel up from the subscription" "0" "$?"
check "the node that answered was chosen" "1" "$(grep -c 'chose alive' "$W/tun.log")"
check "download through the chosen node" "$WANT" "$(fetch)"
down

# ---- refusals ----------------------------------------------------------------------------------------
# In the test namespace and under a timeout: a refusal that does not happen starts a tunnel.
HX timeout 10 "$BIN" --node 5 "$W/sub.txt" >/dev/null 2>&1
check "--node beyond the file exits 2" "2" "$?"
HX timeout 10 "$BIN" "vless://not-a-uuid-at-all-and-far-too-long-to-be-one@$NODE:1?security=none" \
    > /dev/null 2>&1
check "an unusable link exits 2" "2" "$?"
HX timeout 10 "$BIN" -r 300.0.0.0/8 "$LINK" >/dev/null 2>&1
check "a bad --route exits 2" "2" "$?"

echo "routes: $pass ok, $fail fail"
[ "$fail" = 0 ]
