#!/bin/sh
# The TUN stack's receive window against a real Linux kernel client: window scaling (RFC 7323)
# must be negotiated, so that an upload through the tunnel over a LAN with delay is not capped at
# 64 KB per round trip.
#
# Why. Without a scale the window is 65535: the client may have at most 64 KB in flight per
# connection, and a connection's speed is the window divided by the round trip. With netem at
# 3 ms each way that ceiling is 65535 bytes / 6.1 ms = 86 Mbit/s (a single upload to Xray measured
# 83, and about 1.4 Gbit/s with scaling); on a Wi-Fi LAN (2-5 ms round trip) it is 100-250 Mbit/s
# per connection, whatever the node and the CPU can do. Without delay (veth, a sub-millisecond
# round trip) the window does not limit the upload: the node does.
#
# What is checked. tunvless (the route to the target goes into TUN, as in tests/run-tunnel.sh)
# takes an upload from a real kernel client, with netem between the client and the router in both
# directions (6 ms round trip); the node is a sink without encryption (tests/sigpipe-node.py,
# port 82). Two runs:
#   * by default the client's `ss -ti` shows the router's window scale (wscale:<ours>,<its>), an
#     advertised window (snd_wnd) above 64 KB, and an upload over three times the "64 KB per
#     round trip" ceiling;
#   * with STEER_TUN_RCVWND=0 (65535, unscaled): no scale (wscale:0), a window not above 65535,
#     and a speed not above the ceiling, with a margin for measurement noise.
# A third run with a client that sends no scale option in its SYN (net.ipv4.tcp_window_scaling=0
# in its namespace): no scale, window 65535, the upload runs and does not break. That the SYN-ACK
# to such a SYN carries no option is checked by tunnelmatch (the client would ignore it anyway,
# and ss does not show it).
#
# Needs root, unshare -nm, ip, tc (netem), ss, nsenter and python3, otherwise a skip, not a
# failure. TUNVLESS — the binary (default ./out/tunvless).
set -u
skip() { echo "rcvwnd: $1 — skipped"; exit 0; }
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || skip "no binary $BIN (make)"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"; export TUNVLESS="$BIN"
HERE="$(cd "$(dirname "$0")" && pwd)"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
for t in ip tc ss python3 nsenter unshare awk; do command -v $t >/dev/null 2>&1 || skip "no $t"; done
if [ "${RCVWND_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "needs root"
    unshare -nm true 2>/dev/null || skip "unshare -nm unavailable"
    RCVWND_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "cannot mount a private /sys"
ip link set lo up
tc qdisc add dev lo root netem delay 1ms 2>/dev/null || skip "netem unavailable (sch_netem)"
tc qdisc del dev lo root
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
TARGET=203.0.113.7
SECS="${RCVWND_SECS:-4}"
DELAY="${RCVWND_DELAY:-3}"       # ms each way: the round trip is twice that
tmp="$(mktemp -d)"
mkdir -p "$tmp/st"
CPID="" NP="" MP="" CL=""
cleanup() {
    kill $CL $MP $NP $CPID 2>/dev/null
    if [ "$fail" != 0 ]; then
        echo "--- tunnel log (tail)"; tail -n 12 "$tmp/mod.log" 2>/dev/null
    fi
    if [ "${RCVWND_KEEP:-}" = 1 ]; then echo "work dir: $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- network: the router (this namespace), a client behind a veth, the node on the router's lo ---
unshare -n sleep 1800 & CPID=$!
sleep 0.3
C() { nsenter -t "$CPID" -n "$@"; }
ip link add p0 type veth peer name c0
ip link set c0 netns "$CPID"
ip addr add 10.78.1.1/24 dev p0
ip link set p0 up
C ip link set lo up
C ip addr add 10.78.1.2/24 dev c0
C ip link set c0 up
C ip route add default via 10.78.1.1
ip addr add 10.78.0.1/32 dev lo
# The LAN round trip: delay each way (the client's egress, and the router's egress to the client).
# The limit is generous: netem queues everything in flight during the delay, and with the default
# 1000 packets it would drop packets itself.
C tc qdisc add dev c0 root netem delay "${DELAY}ms" limit 100000
tc qdisc add dev p0 root netem delay "${DELAY}ms" limit 100000

python3 "$HERE/sigpipe-node.py" --bind 10.78.0.1 --port 10444 --uuid "$UUID" >"$tmp/node.out" 2>"$tmp/node.err" & NP=$!
wait_for 'grep -q ready "$tmp/node.out"' 10
LINK="vless://$UUID@10.78.0.1:10444?security=none&type=tcp#node"

# The client uploads to the node's port 82 (a sink that does not close) for SECS seconds; the
# connection stays open until the script has read ss.
cat > "$tmp/up.py" <<'PY'
import socket, sys, time
target, secs = sys.argv[1], float(sys.argv[2])
s = socket.socket()
s.settimeout(10)
s.connect((target, 82))
blob = b"\xa5" * (1 << 20)
end = time.time() + secs
try:
    while time.time() < end:
        s.send(blob)
except OSError as e:
    print("client: write failed:", e, flush=True)
print("client: sent", flush=True)
time.sleep(30)
PY

# One run: the tunnel (with the given K=V environment), the upload, and the client's ss in the
# middle and at the end, into $tmp/ss.mid.NAME and $tmp/ss.end.NAME.
run() {
    name="$1"; shift
    env "$@" "$BIN" "$LINK" -d vl -r "$TARGET/32" >"$tmp/mod.log" 2>&1 &
    MP=$!
    wait_for 'ip route show "$TARGET/32" 2>/dev/null | grep -q "dev vl"' 20
    # nsenter directly, not the C function: then $! would be a subshell, and killing it would leave
    # python running.
    nsenter -t "$CPID" -n python3 "$tmp/up.py" "$TARGET" "$SECS" >"$tmp/cl.$name" 2>&1 & CL=$!
    sleep "$(awk -v s="$SECS" 'BEGIN { print s / 2 }')"
    C ss -tin dst "$TARGET" > "$tmp/ss.mid.$name" 2>&1
    sleep "$(awk -v s="$SECS" 'BEGIN { print s / 2 + 0.5 }')"
    C ss -tin dst "$TARGET" > "$tmp/ss.end.$name" 2>&1
    kill $CL 2>/dev/null; wait $CL 2>/dev/null; CL=""
    kill $MP 2>/dev/null; wait $MP 2>/dev/null; MP=""
    ip link del vl 2>/dev/null
    sleep 1
}
# field FILE NAME: the value of the first NAME:<value> field in the ss output.
field() { tr ' ' '\n' < "$1" | sed -n "s/^$2://p" | head -n 1; }
# Mbit/s from the client's bytes_acked over the upload time.
mbit() { awk -v b="$(field "$1" bytes_acked)" -v s="$SECS" 'BEGIN { printf "%d", b * 8 / s / 1e6 }'; }
# The "64 KB window per round trip" ceiling in Mbit/s: 65535 bytes per round trip (2 × DELAY).
CEIL="$(awk -v d="$DELAY" 'BEGIN { printf "%d", 65535 * 8 / (2 * d / 1000) / 1e6 }')"

run scaled STEER_X=1
run legacy STEER_TUN_RCVWND=0
C sysctl -qw net.ipv4.tcp_window_scaling=0
run nows STEER_X=1
C sysctl -qw net.ipv4.tcp_window_scaling=1

echo "  round trip ${DELAY}x2 ms; ceiling at 64 KB per round trip: $CEIL Mbit/s"
for v in scaled legacy nows; do
    echo "  $v: $(mbit "$tmp/ss.end.$v") Mbit/s, snd_wnd $(field "$tmp/ss.mid.$v" snd_wnd), wscale $(field "$tmp/ss.mid.$v" wscale), rtt $(field "$tmp/ss.mid.$v" rtt)"
done

check "the tunnel log reports the receive window with a non-zero scale" "1" \
    "$(sed -n 's/.*receive window: up to [0-9]* KB, scale \([0-9]*\).*/\1/p' "$tmp/mod.log" | head -n 1 | grep -c '^[1-9]')"
# The scale from the client's ss: wscale:<the router's shift>,<the client's own>.
check "by default the client sees the router's window scale (wscale:N,... with N > 0)" "1" \
    "$([ "$(field "$tmp/ss.mid.scaled" wscale | cut -d, -f1)" -gt 0 ] 2>/dev/null && echo 1 || echo 0)"
check "  and a window above 64 KB (snd_wnd)" "1" "$([ "$(field "$tmp/ss.mid.scaled" snd_wnd)" -gt 65535 ] 2>/dev/null && echo 1 || echo 0)"
check "  and an upload over three times the 64 KB per round trip ceiling" "1" \
    "$([ "$(mbit "$tmp/ss.end.scaled")" -gt $((CEIL * 3)) ] && echo 1 || echo 0)"
check "STEER_TUN_RCVWND=0: no scale (wscale:0,...)" "0" "$(field "$tmp/ss.mid.legacy" wscale | cut -d, -f1)"
check "  window not above 65535" "1" "$([ "$(field "$tmp/ss.mid.legacy" snd_wnd)" -le 65535 ] 2>/dev/null && echo 1 || echo 0)"
check "  speed not above 1.5 times the ceiling (a margin for noise)" "1" \
    "$([ "$(mbit "$tmp/ss.end.legacy")" -le $((CEIL * 3 / 2)) ] && echo 1 || echo 0)"
check "client without window scaling: upload over 10 Mbit/s, window not above 65535, no scale" "1" \
    "$([ "$(mbit "$tmp/ss.end.nows")" -gt 10 ] && [ "$(field "$tmp/ss.mid.nows" snd_wnd)" -le 65535 ] && [ -z "$(field "$tmp/ss.mid.nows" wscale)" ] && echo 1 || echo 0)"

echo "rcvwnd: $pass ok, $fail fail"
[ "$fail" = 0 ]
