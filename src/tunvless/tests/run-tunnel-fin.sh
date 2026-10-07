#!/bin/sh
# The client closes its half (FIN) without waiting for the answer: nc -q0, HTTP/1.0, any
# half-close after a request. The FIN often comes IN ONE SEGMENT with the tail of the request.
#
# The tunnel must pass the tail to the server, acknowledge it together with the FIN
# (ack = seq + data + 1) and deliver to the client the answer that arrives after its FIN. The
# test server (fake-vless.py, port 7) answers only a line read to the end, so a lost tail shows
# as an empty answer.
#
# Four cases, each a different path through handle_packet:
#   ready    — FIN with data in one segment, the stream to the node already open;
#   early    — the same right after the handshake, while the stream to the node is opening;
#   separate — data and FIN in separate segments;
#   silent   — the server (port 9) neither answers nor closes: the connection must close by
#              itself within CLOSE_DRAIN_MS, not hang until the idle cleanup.
# An nft rule on output to vl counts that FIN and data really went in one segment. After each
# case no client socket may be left in LAST-ACK.
#
# Usage: tests/run-tunnel-fin.sh   (needs root: its own network namespace)
#   TUNVLESS=<binary>     default ./out/tunvless
#   TRACE=1               the tunnel's packet trace (printed on failure)
set -eu
cd "$(dirname "$0")/.."

BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "no binary: $BIN (make)"; exit 2; }

NS=tunvless-tunfin
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
NODE=10.66.0.1
TARGET=203.0.113.7
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

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add "$NODE/32" dev lo

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 1 --bind "$NODE" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

# No spare sessions: with them "early" would also get a ready stream, and the "stream still
# opening" path would not be tested at all.
ip netns exec "$NS" env STEER_TUN_SPARES=0 ${TRACE:+STEER_TUN_TRACE=1} \
    "$BIN" "$LINK" -d vl -r "$TARGET/32" > "$WORK/tun.log" 2>&1 &
TUN_PID=$!
for _ in $(seq 50); do
    ip netns exec "$NS" ip route show "$TARGET/32" 2>/dev/null | grep -q 'dev vl' && break
    sleep 0.2
done
ip netns exec "$NS" ip route show "$TARGET/32" 2>/dev/null | grep -q 'dev vl' ||
    { echo "device vl or the route into it did not come up:"; sed 's/^/  /' "$WORK/tun.log"; exit 1; }

# The client's segments with FIN and data: IP length above a bare header with options (20+32).
ip netns exec "$NS" nft add table inet fin
ip netns exec "$NS" nft add chain inet fin out '{ type filter hook output priority 0; policy accept; }'
ip netns exec "$NS" nft add rule inet fin out oifname vl 'tcp flags & fin == fin' ip length gt 64 counter

fail=0
for mode in ready early separate silent; do
    before=$(ip netns exec "$NS" nft list chain inet fin out | sed -n 's/.*packets \([0-9]*\).*/\1/p')
    got=$(ip netns exec "$NS" python3 - "$TARGET" "$mode" <<'PY'
import socket, sys, time
host, mode = sys.argv[1], sys.argv[2]
line = b"i319-" + mode.encode() + b"-" + b"x" * 3000 + b"\n"
s = socket.create_connection((host, 9 if mode == "silent" else 7), timeout=10)
if mode != "early":
    time.sleep(0.5)                      # the stream to the node has time to open
if mode == "separate":
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(line)
    time.sleep(0.3)
else:
    # CORK: the kernel merges the data tail and the FIN into one segment.
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)
    s.sendall(line)
s.shutdown(socket.SHUT_WR)
buf = b""
try:
    while True:
        c = s.recv(65536)
        if not c:
            break
        buf += c
except OSError as e:
    print("error: %r" % e, file=sys.stderr)
    buf = None
ok = buf == (b"" if mode == "silent" else b"ECHO " + line)
print("ok" if ok else "no end of stream within 10 s" if buf is None else
      "got %d bytes instead of %d" % (len(buf), len(line) + 5))
PY
)
    after=$(ip netns exec "$NS" nft list chain inet fin out | sed -n 's/.*packets \([0-9]*\).*/\1/p')
    merged=$((after - before))
    echo "  $mode: $got (FIN+data segments: $merged)"
    # The client's own FIN must be sent and acknowledged too: a socket left in LAST-ACK means the
    # tunnel never took it (our FIN once carried a zero window, and Linux sends no FIN into one).
    sleep 1
    lastack=$(ip netns exec "$NS" ss -Htn state last-ack dst "$TARGET" | wc -l)
    if [ "$lastack" != 0 ]; then
        echo "  $mode: $lastack client socket(s) left in LAST-ACK"
        ip netns exec "$NS" ss -tni state last-ack dst "$TARGET" | sed 's/^/    /'
        fail=1
    fi
    [ "$got" = ok ] || fail=1
    if [ "$mode" != separate ] && [ "$mode" != silent ] && [ "$merged" = 0 ]; then
        echo "  $mode: FIN did not merge with the data — case not reproduced"; fail=1
    fi
done

if [ "$fail" != 0 ]; then
    echo "tunnel log:"; tail -${TAIL:-20} "$WORK/tun.log" | sed 's/^/  /'
    echo "server log:"; tail -20 "$WORK/srv.log" | sed 's/^/  /'
    echo "run-tunnel-fin: FAIL"; exit 1
fi
echo "run-tunnel-fin: ok"
