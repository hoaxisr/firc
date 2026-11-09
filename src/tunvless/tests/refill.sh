#!/bin/sh
set -u
cd "$(dirname "$0")/.."
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "refill: no binary $BIN (make)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "refill: needs root — skipped"; exit 0; }
for t in ip nft python3 awk; do
    command -v $t >/dev/null 2>&1 || { echo "refill: no $t — skipped"; exit 0; }
done

H=tvr-host N=tvr-node
U=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
U2=3c9e5a7f-1b2d-4e8a-b6c4-0d9f2e7a5b13
GW=10.80.0.1 HOSTIP=10.80.0.2 A=10.81.0.1
TAB=$(printf '\t')
PG=10800 PR=10801 PQ=10802 PU=10803
W="$(mktemp -d)"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    exec 8>&- 2>/dev/null
    for p in ${TP:-} ${TSP:-} ${SRV_G:-} ${SRV_R:-} ${SRV_Q:-}; do kill "$p" 2>/dev/null; done
    ip netns pids $H 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns pids $N 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $H 2>/dev/null; ip netns del $N 2>/dev/null
    rm -rf /etc/netns/$H
    if [ "$fail" != 0 ]; then echo "--- tunnel log (tail)"; tail -n 40 "$W/tun.log" 2>/dev/null
        echo "--- events (tail)"; tail -n 20 "$W/ev" 2>/dev/null; fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

HX() { ip netns exec $H "$@"; }
NX() { ip netns exec $N "$@"; }
ip netns del $H 2>/dev/null; ip netns del $N 2>/dev/null
ip netns add $H; ip netns add $N
ip link add v0 netns $H type veth peer name v1 netns $N
HX ip link set lo up; HX ip addr add $HOSTIP/24 dev v0; HX ip link set v0 up
HX ip route add default via $GW
NX ip link set lo up; NX ip addr add $GW/24 dev v1; NX ip link set v1 up
NX ip addr add $A/32 dev lo
mkdir -p /etc/netns/$H
: > /etc/netns/$H/hosts
echo "nameserver 127.0.0.1" > /etc/netns/$H/resolv.conf

HX nft add table inet tvr
HX nft add counter inet tvr c801
HX nft add chain inet tvr out '{ type filter hook output priority 0; policy accept; }'
HX nft add rule inet tvr out tcp dport $PR ct state new ct mark 0 ct mark set 1 counter name c801
NX nft add table inet tvr
NX nft add chain inet tvr in '{ type filter hook input priority 0; policy accept; }'
NX nft add rule inet tvr in tcp dport $PU drop

conns() { HX nft list counter inet tvr c801 | sed -n 's/.*packets \([0-9]*\).*/\1/p'; }
now() { date +%s.%N; }
le() { awk -v a="$1" -v b="$2" 'BEGIN { print (a != "" && a + 0 <= b + 0) ? "yes" : "no" }'; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN { if (a == "" || b == "") print ""; else printf "%.1f\n", a - b }'; }

FV='import importlib.util as u
s = u.spec_from_file_location("fv", "tests/fake-vless.py")
m = u.module_from_spec(s)
s.loader.exec_module(m)
m.Server.request_queue_size = 128
m.main()'
srv() {
    ip netns exec $N python3 -c "$FV" --port "$2" --uuid "$3" --mb 1 --bind $A > "$W/srv-$1.log" 2>&1 &
    eval SRV_$1=\$!
}
srv_stop() {
    eval p=\${SRV_$1:-}
    [ -n "$p" ] && { kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; }
    eval SRV_$1=""
}
listening() {
    i=0
    while [ $i -lt 50 ]; do
        NX python3 -c "import socket; socket.create_connection(('$A', $1), 1).close()" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
srv G $PG $U
srv R $PR $U2
listening $PG; listening $PR

lnk() { printf 'vless://%s@%s:%s?security=none&type=tcp#%s' "$U" "$A" "$2" "$1"; }
LG=$(lnk g $PG) LQ=$(lnk q $PQ)
rs() { k=$1; while [ $k -le $2 ]; do lnk "r$k" $PR; echo; k=$((k + 1)); done; }
us() { k=1; while [ $k -le $1 ]; do lnk "u$k" $PU; echo; k=$((k + 1)); done; }

settle() {
    last=$(conns) same=0 i=0
    while [ $i -lt $(($1 * 5)) ] && [ $same -lt 10 ]; do
        sleep 0.2; i=$((i + 1)); c=$(conns)
        if [ "$c" = "$last" ]; then same=$((same + 1)); else same=0 last=$c; fi
    done
    echo "$last"
}
grow() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        [ "$(conns)" -gt "$1" ] && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
ev_at() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        t=$(grep -F "$1" "$W/ev" 2>/dev/null | head -1 | cut -d' ' -f1)
        [ -n "$t" ] && { echo "$t"; return 0; }
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
wait_log() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        grep -qF "$1" "$W/tun.log" && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}

up() {
    rm -f "$W/in" "$W/out"; mkfifo "$W/in" "$W/out"
    : > "$W/ev"
    python3 -u -c '
import sys, time
for l in sys.stdin:
    sys.stdout.write("%.3f %s" % (time.time(), l))
    sys.stdout.flush()
' < "$W/out" > "$W/ev" & TSP=$!
    ip netns exec $H "$BIN" --control -d tvr0 "$@" < "$W/in" > "$W/out" 2> "$W/tun.log" & TP=$!
    exec 8> "$W/in"
    cat "$W/nodes" >&8
}
down() {
    exec 8>&-
    kill "$TP" 2>/dev/null; wait "$TP" 2>/dev/null; TP=""
    kill "$TSP" 2>/dev/null; wait "$TSP" 2>/dev/null; TSP=""
    i=0
    while HX ip link show tvr0 >/dev/null 2>&1 && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
}

b=$(conns)
{ lnk r1 $PR; printf '\n\n'; } | HX "$BIN" --probe -t 3 - > "$W/probe.out" 2>&1
C=$(($(settle 5) - b))
P=$((C + 1))
echo "     calibration: a probe of a silent node makes C=$C connections, a pool probe P=$P"
check "calibration: the probe of r1 fails" 1 "$(grep -c "^0${TAB}r1${TAB}failed${TAB}" "$W/probe.out")"
check "calibration: a probe makes at least one connection" yes "$([ "$C" -ge 1 ] && echo yes || echo no)"

{ echo "$LG"; rs 1 20; echo "$LQ"; echo; } > "$W/nodes"
S=15

b=$(conns)
up -A 2
ev_at '"type":"ready"' 20 > /dev/null
check "extra: ready" 0 "$?"
T0=$(now)
# catches: an extra-mode round probing more than 8 free candidates
check "extra: the first round probes 8 (S+8P)" $((S + 8 * P)) "$(($(settle 10) - b))"
sleep "$(awk -v t="$T0" -v n="$(now)" 'BEGIN { d = 45 - (n - t); print (d > 0 ? d : 0) }')"
# catches: an extra-mode pause shorter than 300 s after a round that probed
check "extra: still S+8P at 45 s" $((S + 8 * P)) "$(($(conns) - b))"
printf 'wake\n%s\n\n' "$(lnk r1 $PR)" >&8
T1=$(now)
grow $((b + S + 8 * P)) 5
# catches: a wake that is not acted on at once, or does not clear r1 and skip r2..r8 in backoff
check "extra: a wake runs a round of 8 at once (S+16P)" $((S + 16 * P)) "$(($(settle 5) - b))"
sleep "$(awk -v t="$T1" -v n="$(now)" 'BEGIN { d = 20 - (n - t); print (d > 0 ? d : 0) }')"
check "extra: still S+16P at 20 s after the wake" $((S + 16 * P)) "$(($(conns) - b))"
down

b=$(conns)
up -A 1 --interval 5
ev_at '"type":"active","nodes":["g"]' 20 > /dev/null
check "down: g active" 0 "$?"
check "down: the start costs S" "$S" "$(($(settle 5) - b))"
srv_stop G
ev_at '"type":"active","nodes":[]' 20 > /dev/null
check "down: the death reported with no node" 0 "$?"
r1=$(($(settle 5) - b))
# catches: a down round not capped at 16, or not taking the untried candidates in fircd's order
check "down: the death round probes r1..r16 (S+16P)" $((S + 16 * P)) "$r1"
grow $((b + r1)) 25
r2=$(($(settle 5) - b))
# catches: a second round that does not take r17..r20, q, then the oldest failed r1..r11
check "down: round 2 probes r17..r20, q and r1..r11 (S+31P)" $((S + 31 * P)) "$r2"
check "down: no round adds more than 16P" yes \
    "$([ $((r1 - S)) -le $((16 * P)) ] && [ $((r2 - r1)) -le $((16 * P)) ] && echo yes || echo no)"
srv Q $PQ $U
listening $PQ
TQ=$(now)
lim=$((2 * (30 + 4) + 10))
tq=$(ev_at '"type":"active","nodes":["q"]' $lim)
echo "     q active $(sub "$tq" "$TQ") s after it came up, without a wake"
# catches: a rotation that leaves q out, or a pause past 30 s
check "down: q is found without a wake within $lim s" yes "$(le "$(sub "$tq" "$TQ")" $lim)"
down
srv_stop Q

srv G $PG $U
listening $PG
up -A 1 --interval 5
ev_at '"type":"active","nodes":["g"]' 20 > /dev/null
check "down + wake: g active" 0 "$?"
settle 5 > /dev/null
srv_stop G
ev_at '"type":"active","nodes":[]' 20 > /dev/null
check "down + wake: the death reported with no node" 0 "$?"
settle 5 > /dev/null
srv Q $PQ $U
listening $PQ
printf 'wake\n%s\n\n' "$LQ" >&8
TW=$(now)
tq=$(ev_at '"type":"active","nodes":["q"]' 20)
echo "     q active $(sub "$tq" "$TW") s after the wake"
# catches: a wake that waits out the 15-s pause of a down slot
check "down + wake: q active within 10 s" yes "$(le "$(sub "$tq" "$TW")" 10)"
down
srv_stop Q

{ echo "$LG"; us 10; rs 1 6; echo; } > "$W/nodes"
srv G $PG $U
listening $PG
up -A 1 --interval 5
ev_at '"type":"active","nodes":["g"]' 20 > /dev/null
check "silent: g active" 0 "$?"
srv_stop G
td=$(ev_at '"type":"node_down"' 20)
check "silent: g reported down" 0 "$?"
tn=$(ev_at '"type":"no_node"' 20)
echo "     no_node $(sub "$tn" "$td") s after node_down"
# catches: silent candidates probed one by one, 8 s each, instead of one 3-s pre-pass
check "silent: no_node within 6 s of node_down" yes "$(le "$(sub "$tn" "$td")" 6)"
down

{ echo "$LG"; rs 1 20; echo "$LQ"; echo; } > "$W/nodes"
srv G $PG $U
listening $PG
up -A 1 --interval 5
ev_at '"type":"active","nodes":["g"]' 20 > /dev/null
check "own back: g active" 0 "$?"
srv_stop G
ev_at '"type":"no_node"' 20 > /dev/null
check "own back: no_node" 0 "$?"
srv G $PG $U
listening $PG
TG=$(now)
i=0 tg=""
while [ $i -lt 200 ] && [ -z "$tg" ]; do
    tg=$(awk -v t="$TG" -v p='"type":"active","nodes":["g"]' '$1 >= t && index($0, p) { print $1; exit }' "$W/ev")
    [ -z "$tg" ] && sleep 0.2; i=$((i + 1))
done
echo "     g active again $(sub "$tg" "$TG") s after it came back"
# catches: a dead slot's own node re-probed at the 300-s pause, not 15/30 s
check "own back: g taken again within 35 s" yes "$(le "$(sub "$tg" "$TG")" 35)"
down

{ rs 1 20; echo "$LG"; } > "$W/start.txt"
b=$(conns)
ip netns exec $H "$BIN" "$W/start.txt" -d tvr1 -A 1 > /dev/null 2> "$W/tun.log" & TP=$!
wait_log "chose g" 15
check "start: chose g within 15 s" 0 "$?"
# catches: a start walk that stops after the first 16, or skips the pre-pass
check "start: the first walk is whole (20P)" $((20 * P)) "$(($(settle 5) - b))"
kill "$TP" 2>/dev/null; wait "$TP" 2>/dev/null; TP=""

echo "refill: $pass ok, $fail fail"
[ "$fail" = 0 ]
