#!/bin/sh
# The WHOLE tunnel on a local test bed: no real node and no internet.
#
# TCP synthesis, retransmission and the spreading of connections over threads only show on real
# traffic; a unit test cannot reach them. With a real node every check would depend on someone
# else's server, and "did not recover after loss" could not be told from "the node went down".
#
# Setup: a network namespace with a fake VLESS server (tests/fake-vless.py), the tunnel
# (tunvless) and wget as the client. Loss is added by an nft rule on INPUT from the tunnel
# device, so exactly the packets we synthesized are lost.
#
# The verdict: every download is whole and byte for byte what the server sent. Retransmits and
# the threads that carried traffic are printed for information, not checked.
#
# Usage: tests/run-tunnel.sh [loss_percent] [streams]
set -eu
cd "$(dirname "$0")/.."

LOSS="${1:-0}"
STREAMS="${2:-1}"
# Eight megabytes: this tests RECOVERY, not speed, and a larger download would be slow for a
# reason unrelated to the tunnel. The client is local, so our 18 KB segment reaches it as ONE
# segment, not thirteen, and its kernel holds the ACK on the delayed-ACK timer. On a real network
# the segment is split, ACKs come often, and there is no such slowdown.
MB=8
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "no binary: $BIN (make)"; exit 2; }

NS=tunvless-tunnel
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
# The node is on an ordinary address, not in 127.0.0.0/8: such a node is rejected as one with no
# peer (sublink.c).
NODE=10.66.0.1
WORK="$(mktemp -d)"

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

LINK="vless://$UUID@$NODE:$PORT?security=none&type=tcp#local"
# Any address but localhost: the fake server ignores it, it only has to go into the tunnel.
TARGET=203.0.113.7

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
# The node's address is on lo inside the namespace: invisible outside, and not in 127.0.0.0/8.
ip netns exec "$NS" ip addr add "$NODE/32" dev lo

# The server and the tunnel both run inside the namespace; the server listens on the node address.
ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb "$MB" --bind "$NODE" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

ip netns exec "$NS" env STEER_TUN_STATS=1 "$BIN" "$LINK" -d vl -r "$TARGET/32" \
    > "$WORK/tun.log" 2>&1 &
TUN_PID=$!

# Wait for the route into the device rather than sleeping: startup time varies.
for _ in $(seq 50); do
    ip netns exec "$NS" ip route show "$TARGET/32" 2>/dev/null | grep -q 'dev vl' && break
    sleep 0.2
done
if ! ip netns exec "$NS" ip route show "$TARGET/32" 2>/dev/null | grep -q 'dev vl'; then
    echo "device vl or the route into it did not come up:"; sed 's/^/  /' "$WORK/tun.log"; exit 1
fi
sed -n 's/^/  /p' "$WORK/tun.log" | grep -iE "write offload|; threads" || true

if [ "$LOSS" != 0 ]; then
    ip netns exec "$NS" nft add table inet loss
    ip netns exec "$NS" nft add chain inet loss input \
        '{ type filter hook input priority -300; policy accept; }'
    ip netns exec "$NS" nft add rule inet loss input iifname vl \
        numgen random mod 100 lt "$LOSS" counter drop
fi

# Wait ONLY for the downloads. A bare `wait` would also wait for the server and the tunnel, which
# never exit, and the run would hang until an outside timeout, looking like a stuck tunnel.
#
# Download INTO A FILE and compare it with what the server sent: exit code 0 without a length
# check can report an absurd speed for a download that never happened, and a length check alone
# passes a retransmission that resends the wrong bytes. One try: wget retries a reset or stalled
# connection by itself, and a second connection would hide the failure of the first.
s=$(date +%s.%N)
pids=""
i=1; while [ "$i" -le "$STREAMS" ]; do
    ( ip netns exec "$NS" wget -q --tries=1 -O "$WORK/dl.$i" -T 120 "http://$TARGET/x" || true ) &
    pids="$pids $!"
    i=$((i+1))
done
for pid in $pids; do wait "$pid" || true; done
e=$(date +%s.%N)

want=$((MB * 1024 * 1024))
# The body the server sends: its filler over and over (fake-vless.py, FILLER).
python3 - "$WORK/body" "$want" <<'PY'
import runpy, sys
filler = runpy.run_path("tests/fake-vless.py")["FILLER"]
n = int(sys.argv[2])
open(sys.argv[1], "wb").write((filler * (n // len(filler) + 1))[:n])
PY
ok=0; i=1
while [ "$i" -le "$STREAMS" ]; do
    got=$(wc -c < "$WORK/dl.$i" 2>/dev/null || echo 0)
    if [ "$got" != "$want" ]; then echo "    stream $i: $got of $want bytes"
    elif ! cmp -s "$WORK/body" "$WORK/dl.$i"; then
        echo "    stream $i: not the bytes the server sent ($(cmp "$WORK/body" "$WORK/dl.$i"))"
    else ok=$((ok+1)); fi
    i=$((i+1))
done
dropped=0
[ "$LOSS" != 0 ] && dropped=$(ip netns exec "$NS" nft list table inet loss 2>/dev/null |
    sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -1)

echo "  tunnel retransmits:"
grep -o 'retransmits [0-9]*/s ([0-9.]* KB/s)' "$WORK/tun.log" 2>/dev/null |
    grep -v 'retransmits 0/s' | sort -u | tail -2 | sed 's/^/    /' || true
# Which threads actually carried traffic: in the other numbers "got faster" and "everything
# landed on one queue" look the same.
busy=$(grep -o '^tun-stats\[[0-9]\]' "$WORK/tun.log" 2>/dev/null | sort -u | tr -dc '0-9\n' | tr '\n' ' ')
work=$(grep '^tun-stats' "$WORK/tun.log" 2>/dev/null | grep -v ' 0.0 MB/s ' |
    grep -o '^tun-stats\[[0-9]\]' | sort -u | wc -l)
echo "  threads with traffic: $work (threads reporting: $busy)"

awk -v s="$s" -v e="$e" -v ok="$ok" -v n="$STREAMS" -v mb="$MB" -v l="$LOSS" -v d="${dropped:-0}" 'BEGIN{
  t=e-s
  printf "  loss %s%%, streams %s: %d/%d complete in %.1f s", l, n, ok, n, t
  if (ok==n) printf " = %.0f Mbit/s", n*mb*8/t
  printf ", dropped %s\n", d
  exit (ok==n ? 0 : 1)}'
