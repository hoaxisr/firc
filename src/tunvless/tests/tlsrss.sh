#!/bin/sh
set -u
cd "$(dirname "$0")/.."
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "tlsrss: no binary $BIN (make)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "tlsrss: needs root — skipped"; exit 0; }
for t in ip python3 timeout; do
    command -v $t >/dev/null 2>&1 || { echo "tlsrss: no $t — skipped"; exit 0; }
done

NS=tvt-rss
U=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
MAXK=48
W="$(mktemp -d)"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${TP:-}" ] && kill "$TP" 2>/dev/null
    [ -n "${XP:-}" ] && wait "$XP" 2>/dev/null
    ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $NS 2>/dev/null
    [ "$fail" != 0 ] && { echo "--- tunnel log (tail)"; tail -n 20 "$W/tun.log" 2>/dev/null; }
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

NX() { ip netns exec $NS "$@"; }
ip netns del $NS 2>/dev/null
ip netns add $NS
NX ip link set lo up
NX ip link add d0 type dummy
NX ip addr add 10.77.0.1/24 dev d0
NX ip link set d0 up

field() { awk -v k="$1:" '$1 == k { print $2 }' "/proc/$TP/status"; }
wait_until() {
    i=0
    while [ $i -lt 50 ]; do
        eval "$1" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

NX sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$W/pid" \
    "$BIN" "vless://$U@10.77.0.1:9?type=tcp&security=none#x" --no-probe -d tv9 -r 10.99.0.0/24 \
    > /dev/null 2> "$W/tun.log" & XP=$!
wait_until '[ -s "$W/pid" ]'
check "the tunnel process writes its pid within 5 s" 0 "$?"
[ "$fail" = 0 ] || { echo "tlsrss: $pass ok, $fail fail"; exit 1; }
TP=$(cat "$W/pid")
wait_until 'NX ip link show tv9 >/dev/null 2>&1'
check "the device tv9 comes up within 5 s" 0 "$?"
sleep 1
t0=$(field Threads) r0=$(field VmRSS)
NX timeout 3 python3 -c "import socket; socket.create_connection(('10.99.0.1', 80), 2).close()" \
    > /dev/null 2>&1
wait_until '[ "$(field Threads)" -ge $((t0 + 16)) ]'
sleep 1
t1=$(field Threads) r1=$(field VmRSS)
echo "     threads $t0 -> $t1, VmRSS $r0 -> $r1 KiB"
check "one SYN starts 16 connectors" 16 "$((t1 - t0))"
per=$(((r1 - r0) / 16))
echo "     per connector $per KiB (max $MAXK)"
check "a connector adds at most $MAXK KiB of VmRSS" yes "$([ "$per" -le $MAXK ] && echo yes || echo no)"

echo "tlsrss: $pass ok, $fail fail"
[ "$fail" = 0 ]
