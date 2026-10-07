#!/bin/sh
# Several nodes on a real network: two namespaces joined by a veth — the host running tunvless, and
# two fake nodes (tests/fake-vless.py) behind its gateway, A and B. A serves 1 MB per request and
# B 2 MB, so the size of a download says which node carried it.
#
#   * -A 2: both nodes are active, new connections land on both, and both servers keep their
#     route outside the tunnel (--route default without --mark or --bind-dev);
#   * a node that dies loudly (its process killed) is noticed, and new connections go to the
#     other node, with the same process;
#   * a node that dies silently (its packets dropped) in the middle of a long download: the
#     download and an idle connection through it are reset within the silence threshold, not at
#     the application's timeout, and new connections work through B, with the same process;
#   * --node 1,0 sets the order of preference, a single --node is used without a startup probe,
#     a candidate whose name does not resolve is left out, several sources add up.
#
# Needs root, iproute2, nft, python3, curl, wget and bc. TUNVLESS — the binary (./out/tunvless).
set -u
cd "$(dirname "$0")/.."
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "failover: no binary $BIN (make)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "failover: needs root — skipped"; exit 0; }
for t in ip nft python3 curl wget bc; do
    command -v $t >/dev/null 2>&1 || { echo "failover: no $t — skipped"; exit 0; }
done

H=tvf-host N=tvf-node
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
GW=10.72.0.1 HOSTIP=10.72.0.2 A=10.73.0.1 B=10.73.0.2 PORT=10800
SILENCE=20
MB1=$((1024 * 1024)) MB2=$((2 * 1024 * 1024))
W="$(mktemp -d)"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    for p in ${TP:-} ${SRV_A:-} ${SRV_B:-} ${CURL:-} ${IDLE:-}; do kill "$p" 2>/dev/null; done
    ip netns pids $H 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns pids $N 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $H 2>/dev/null; ip netns del $N 2>/dev/null
    rm -rf /etc/netns/$H
    if [ "$fail" != 0 ]; then echo "--- tunnel log (tail)"; tail -n 30 "$W/tun.log" 2>/dev/null; fi
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
ip netns exec $N ip link set lo up; ip netns exec $N ip addr add $GW/24 dev v1; ip netns exec $N ip link set v1 up
ip netns exec $N ip addr add $A/32 dev lo
ip netns exec $N ip addr add $B/32 dev lo
mkdir -p /etc/netns/$H
: > /etc/netns/$H/hosts
# No resolver: a lookup fails at once instead of waiting for the host's DNS.
echo "nameserver 127.0.0.1" > /etc/netns/$H/resolv.conf

# node_up A|B mb [kbps]: (re)start a fake node.
node_up() {
    eval old=\${SRV_$1:-}
    [ -n "$old" ] && { kill "$old" 2>/dev/null; wait "$old" 2>/dev/null; }
    eval addr=\$$1
    ip netns exec $N python3 tests/fake-vless.py --port $PORT --uuid $UUID --mb "$2" \
        --kbps "${3:-0}" --bind "$addr" > "$W/srv-$1.log" 2>&1 &
    eval SRV_$1=\$!
}
node_up A 1
node_up B 2
sleep 1

LINK_A="vless://$UUID@$A:$PORT?security=none&type=tcp#nodeA"
LINK_B="vless://$UUID@$B:$PORT?security=none&type=tcp#nodeB"
printf '%s\n%s\n' "$LINK_A" "$LINK_B" > "$W/sub.txt"

# Start tunvless in the host namespace and wait for its routes; $! is tunvless itself (see routes.sh).
up() {
    ip netns exec $H "$BIN" "$@" > "$W/tun.log" 2>&1 &
    TP=$!
    i=0
    while [ $i -lt 100 ]; do
        HX ip route show 0.0.0.0/1 2>/dev/null | grep -q 'dev vl' && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
down() {
    kill "$TP" 2>/dev/null; wait "$TP" 2>/dev/null; TP=""
    i=0
    while HX ip link show vl >/dev/null 2>&1 && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
}
# The size of one download through the tunnel (0 — failed).
# One try: wget retries a reset connection, which would hide a failed one.
fetch() { HX wget -q --tries=1 -O "$W/dl" -T 10 "http://203.0.113.7/$1" && wc -c < "$W/dl" || echo 0; }
# Wait up to $2 seconds for the tunnel log to contain $1.
wait_log() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        grep -qF "$1" "$W/tun.log" && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
alive() { kill -0 "$TP" 2>/dev/null && echo yes || echo no; }

# ---- -A 2: both nodes active ----------------------------------------------------------------------
up "$W/sub.txt" -d vl -r default -A 2 -t 3
check "tunnel up with two active nodes" "0" "$?"
wait_log "active: nodeA (#0), nodeB (#1)" 20
check "the log names both active nodes" "0" "$?"
check "both servers keep their route outside the tunnel" "2" \
    "$(HX ip route show | grep -cE "^($A|$B) via $GW dev v0")"
on_a=0 on_b=0 other=0
for i in $(seq 30); do
    case "$(fetch s$i)" in
        $MB1) on_a=$((on_a + 1)) ;;
        $MB2) on_b=$((on_b + 1)) ;;
        *) other=$((other + 1)) ;;
    esac
done
check "30 downloads, none failed" "0" "$other"
check "downloads were carried by both nodes" "yes yes" \
    "$([ $on_a -gt 0 ] && echo yes || echo no) $([ $on_b -gt 0 ] && echo yes || echo no)"

# B dies loudly: its port refuses connections.
kill "$SRV_B"; wait "$SRV_B" 2>/dev/null; SRV_B=""
for i in $(seq 5); do fetch k$i >/dev/null; done
wait_log "node nodeB does not answer" 30
check "the dead node is noticed" "0" "$?"
bad=0
for i in $(seq 10); do [ "$(fetch d$i)" = "$MB1" ] || bad=$((bad + 1)); done
check "after that every download goes through A" "0" "$bad"
check "the same process carries on" "yes" "$(alive)"
down
check "SIGTERM removed both servers' host routes" "0" "$(HX ip route show | grep -cE "^($A|$B) ")"

# ---- a silent death in the middle of a download ---------------------------------------------------
node_up A 64 200
node_up B 2
sleep 1
up "$W/sub.txt" -d vl -r default -t 3 --silence $SILENCE
check "tunnel up for the silent death" "0" "$?"
check "node A was chosen" "1" "$(grep -c 'chose nodeA' "$W/tun.log")"
HX sh -c 'curl -s -o /dev/null --max-time 200 http://203.0.113.10/big; echo "rc=$?"' > "$W/curl.out" 2>&1 &
CURL=$!
HX python3 -c '
import socket
s = socket.create_connection(("203.0.113.12", 9), timeout=5)
s.settimeout(None)
s.sendall(b"hello\n")
try:
    d = s.recv(1)
    print("idle: closed %r" % d)
except ConnectionResetError:
    print("idle: reset")
except OSError as e:
    print("idle: %r" % e)
' > "$W/idle.out" 2>&1 &
IDLE=$!
sleep 5
now() { date +%s.%N; }
T0=$(now)
HX nft add table inet dead
HX nft add chain inet dead out '{ type filter hook output priority -300; policy accept; }'
HX nft add chain inet dead in '{ type filter hook input priority -300; policy accept; }'
HX nft add rule inet dead out ip daddr $A tcp dport $PORT drop
HX nft add rule inet dead in ip saddr $A tcp sport $PORT drop
curl_t="" idle_t="" ok_t=""
while :; do
    t=$(echo "$(now) - $T0" | bc)
    [ -z "$curl_t" ] && ! kill -0 "$CURL" 2>/dev/null && curl_t=$t
    [ -z "$idle_t" ] && ! kill -0 "$IDLE" 2>/dev/null && idle_t=$t
    if [ -z "$ok_t" ]; then
        [ "$(HX curl -s -o /dev/null --max-time 3 -w '%{size_download}' http://203.0.113.11/p 2>/dev/null)" = "$MB2" ] &&
            ok_t=$(echo "$(now) - $T0" | bc)
    fi
    [ -n "$curl_t" ] && [ -n "$idle_t" ] && [ -n "$ok_t" ] && break
    [ "$(echo "$t > 120" | bc)" = 1 ] && break
    sleep 1
done
echo "     download ended after ${curl_t:-—} s, idle connection after ${idle_t:-—} s, B works after ${ok_t:-—} s"
lim=$((SILENCE + 15))
within() { [ -n "$1" ] && [ "$(echo "$1 <= $2" | bc)" = 1 ] && echo yes || echo no; }
check "the stalled download is reset (curl 56) within $lim s" "rc=56 yes" \
    "$(cat "$W/curl.out") $(within "$curl_t" $lim)"
check "the idle connection through A is reset within $lim s" "idle: reset yes" \
    "$(cat "$W/idle.out") $(within "$idle_t" $lim)"
check "new connections work through B within 90 s" "yes" "$(within "$ok_t" 90)"
check "the log names the replacement" "1" "$(grep -c 'node nodeA does not answer — nodeB takes its place' "$W/tun.log")"
check "the same process carries on" "yes" "$(alive)"
down
HX nft delete table inet dead

# ---- candidates on the command line ---------------------------------------------------------------
node_up A 1
sleep 1
check "--probe -n 1,0 checks in the given order" "1 nodeB ok
0 nodeA ok" "$(HX "$BIN" --probe -n 1,0 -t 3 "$W/sub.txt" 2>/dev/null | cut -f1-3 | tr '\t' ' ')"
up "$W/sub.txt" -d vl -r default -n 1,0 -t 3
check "--node 1,0: B is preferred" "1" "$(grep -c 'chose nodeB' "$W/tun.log")"
check "  and carries the downloads" "$MB2" "$(fetch p)"
down

printf '%s\n' "vless://$UUID@$A:$((PORT + 1))?security=none&type=tcp#deaf" >> "$W/sub.txt"
up "$W/sub.txt" -d vl -r default -n 2 -t 3
check "a single --node comes up without a startup probe, even if it is dead" "0" "$?"
wait_log "no active node answers" 20
check "  and the pool reports that it does not answer" "0" "$?"
check "  while new connections are refused" "0" "$(fetch q)"
down

printf '%s\n' "vless://$UUID@ghost.invalid:$PORT?security=none&type=tcp#ghost" "$LINK_A" > "$W/sub2.txt"
up "$W/sub2.txt" -d vl -r default -t 3
check "a candidate whose name does not resolve is left out" "1" \
    "$(grep -c 'node ghost: ghost.invalid does not resolve — left out of the candidates' "$W/tun.log")"
check "  and the tunnel comes up on the others" "$MB1" "$(fetch g)"
down

check "several sources add up, numbered in order" "0 nodeA
1 nodeB
2 ghost
3 nodeA" "$("$BIN" --list "$LINK_A" "$LINK_B" "$W/sub2.txt" 2>/dev/null | cut -f1,2 | tr '\t' ' ')"
"$BIN" --active 0 "$LINK_A" >/dev/null 2>&1
check "--active 0 exits 2" "2" "$?"
"$BIN" --by node "$LINK_A" >/dev/null 2>&1
check "an unknown --by exits 2" "2" "$?"

echo "failover: $pass ok, $fail fail"
[ "$fail" = 0 ]
