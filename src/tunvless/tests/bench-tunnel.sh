#!/bin/sh
# How much CPU a megabyte through the tunnel costs, and how that cost depends on the number of
# open but idle connections.
#
# run-tunnel.sh checks that the tunnel works and recovers after loss, and times the download. On
# a fast machine the download time is bound by the test network, not by the tunnel, so it does
# not show whether the tunnel got faster on a router.
#
# This measures CPU seconds per megabyte instead. That does not depend on the test machine and
# carries over to a router directly: half the cycles per megabyte means twice the megabytes on
# the same core.
#
# The second parameter, the number of idle connections, reproduces the weak spot: a browser keeps
# connections alive between requests, and a loop that pays per connection on every turn pays for
# EVERY one of them, busy or not.
#
# Usage: tests/bench-tunnel.sh [MB] [idle_connections] [streams]
set -eu
cd "$(dirname "$0")/.."

MB="${1:-32}"
IDLE="${2:-0}"
STREAMS="${3:-1}"
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "no binary: $BIN"; exit 2; }

NS=tunvless-bench
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
# The node is on an ordinary address, not in 127.0.0.0/8: such a node is rejected as one with no
# peer (sublink.c).
NODE=10.66.0.1
WORK="$(mktemp -d)"

cleanup() {
    [ -n "${IDLE_PID:-}" ] && kill "$IDLE_PID" 2>/dev/null || true
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

LINK="vless://$UUID@$NODE:$PORT?security=none&type=tcp#local"
TARGET=203.0.113.7

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
# The node's address is on lo inside the namespace: invisible outside, and not in 127.0.0.0/8.
ip netns exec "$NS" ip addr add "$NODE/32" dev lo

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb "$MB" --bind "$NODE" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

# ONE core and ONE thread, as on a router: on eight cores the difference between an expensive
# and a cheap loop spreads over idle cores and does not show.
ip netns exec "$NS" taskset -c 0 env STEER_TUN_THREADS=1 "$BIN" "$LINK" -d vl -r "$TARGET/32" \
    > "$WORK/tun.log" 2>&1 &
TUN_PID=$!

for _ in $(seq 50); do
    ip netns exec "$NS" ip route show "$TARGET/32" 2>/dev/null | grep -q 'dev vl' && break
    sleep 0.2
done
ip netns exec "$NS" ip route show "$TARGET/32" 2>/dev/null | grep -q 'dev vl' || {
    echo "device vl or the route into it did not come up:"; sed 's/^/  /' "$WORK/tun.log"; exit 1; }

# Idle connections: open them and hold them. On port 9 the fake server stays silent on purpose
# (see fake-vless.py).
if [ "$IDLE" -gt 0 ]; then
    ip netns exec "$NS" python3 - "$TARGET" "$IDLE" > "$WORK/idle.log" 2>&1 <<'PY' &
import socket, sys, time
host, n = sys.argv[1], int(sys.argv[2])
socks = []
for _ in range(n):
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect((host, 9))
        socks.append(s)
    except OSError as e:
        print("connect failed after %d: %r" % (len(socks), e))
        break
print("holding %d" % len(socks), flush=True)
time.sleep(3600)
PY
    IDLE_PID=$!
    # Wait until they are really open: the handshakes go through the pool, and measuring earlier
    # would measure setup, not the loop.
    for _ in $(seq 100); do
        grep -q '^holding' "$WORK/idle.log" 2>/dev/null && break
        sleep 0.2
    done
    sleep 1
    held=$(sed -n 's/^holding //p' "$WORK/idle.log")
    echo "  idle connections: ${held:-0} of $IDLE"
fi

# The process's CPU time from /proc: utime+stime of all its threads, in ticks.
cpu_ticks() { awk '{print $14 + $15}' "/proc/$TUN_PID/stat" 2>/dev/null || echo 0; }
HZ=$(getconf CLK_TCK)

t0=$(cpu_ticks)
s=$(date +%s.%N)
pids=""
i=1; while [ "$i" -le "$STREAMS" ]; do
    ( ip netns exec "$NS" wget -q -O "$WORK/dl.$i" -T 180 "http://$TARGET/x" || true ) &
    pids="$pids $!"
    i=$((i+1))
done
for pid in $pids; do wait "$pid" || true; done
e=$(date +%s.%N)
t1=$(cpu_ticks)

want=$((MB * 1024 * 1024))
ok=0; i=1
while [ "$i" -le "$STREAMS" ]; do
    got=$(wc -c < "$WORK/dl.$i" 2>/dev/null || echo 0)
    if [ "$got" = "$want" ]; then ok=$((ok+1)); else echo "    stream $i: $got of $want bytes"; fi
    i=$((i+1))
done

awk -v t0="$t0" -v t1="$t1" -v hz="$HZ" -v s="$s" -v e="$e" -v mb="$MB" \
    -v n="$STREAMS" -v ok="$ok" -v idle="$IDLE" 'BEGIN{
  cpu=(t1-t0)/hz; wall=e-s; total=mb*n
  printf "  idle %-4d streams %d: %d/%d complete, %.1f MB in %.2f s = %.0f Mbit/s",
         idle, n, ok, n, total, wall, total*8/wall
  printf " | CPU %.2f s = %.1f ms/MB\n", cpu, cpu*1000/total
  exit (ok==n ? 0 : 1)}'
