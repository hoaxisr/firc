#!/bin/sh
# The tunnel survives the node closing connections at speed: a write to a socket the node has
# closed is a failed write (EPIPE), not the death of the process by SIGPIPE.
#
# WHY. The node may close a connection while the stack is still writing client packets into it.
# The TLS record write (tls13_write: write() without MSG_NOSIGNAL) then gets EPIPE, and with the
# default SIGPIPE disposition the process dies. tunvless ignores SIGPIPE in main (src/main.c): the
# write returns EPIPE and the stack closes THAT connection with RST to the client.
#
# WHAT IS CHECKED. Two tunnels — over TLS 1.3 and without encryption, because the write takes
# different paths: TLS — tls13_write (only the ignored SIGPIPE saves it), none — tr_link_write (it
# also has MSG_NOSIGNAL). Behind each, a fake node (tests/sigpipe-node.py) closes connections the
# way a busy server does: FIN, then RST. A LAN client behind a veth (tests/sigpipe-client.py) drives
# dozens of connections through both tunnels for SIGPIPE_SECS seconds: uploads the node cuts early,
# uploads and downloads the client itself aborts with RST mid-transfer. Afterwards:
#   * both tunvless processes are the same pids and alive;
#   * SIGPIPE is ignored in both (SigIgn in /proc/<pid>/status);
#   * each tunnel answers at once (a line echoed);
#   * after a quiet period no more descriptors than before the load (+8: spare sessions);
#   * no node sockets left in CLOSE-WAIT (a connection closed on EPIPE only half way);
#   * the load was real: the nodes closed dozens of connections early.
#
# Needs root, unshare -nm, ip, nsenter, ss, openssl and python3 with ssl — otherwise a skip, not a
# failure. TUNVLESS — the binary (./out/tunvless). SIGPIPE_SECS — load duration, s (12).
set -u
skip() { echo "sigpipe: $1 — skipped"; exit 0; }
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
for t in ip python3 nsenter unshare openssl awk ss; do command -v $t >/dev/null 2>&1 || skip "no $t"; done
python3 -c 'import ssl' 2>/dev/null || skip "python3 has no ssl"
if [ "${SIGPIPE_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "needs root"
    unshare -nm true 2>/dev/null || skip "unshare -nm unavailable"
    SIGPIPE_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "cannot mount a private /sys"
ip link set lo up
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

SECS="${SIGPIPE_SECS:-12}"
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
TLS=203.0.113.7 NONE=203.0.113.8
tmp="$(mktemp -d)"
CPID="" NT="" NP="" T1="" T2=""
cleanup() {
    kill $NT $NP $CPID $T1 $T2 2>/dev/null
    if [ "$fail" != 0 ]; then
        echo "--- tunnel TLS (tail)"; tail -n 15 "$tmp/t-tls.log" 2>/dev/null
        echo "--- tunnel none (tail)"; tail -n 15 "$tmp/t-none.log" 2>/dev/null
        echo "--- node TLS"; tail -n 3 "$tmp/node-tls.err" 2>/dev/null
        echo "--- node none"; tail -n 3 "$tmp/node-none.err" 2>/dev/null
    fi
    if [ "${SIGPIPE_KEEP:-}" = 1 ]; then echo "work dir: $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- network: the router (this namespace), a client behind a veth, the nodes on lo ---------------
unshare -n sleep 1800 & CPID=$!
sleep 0.3
C() { nsenter -t "$CPID" -n "$@"; }
ip link add p0 type veth peer name c0
ip link set c0 netns "$CPID"
ip addr add 10.77.1.1/24 dev p0
ip link set p0 up
C ip link set lo up
C ip addr add 10.77.1.2/24 dev c0
C ip link set c0 up
C ip route add default via 10.77.1.1
# The node address is on lo: a node in 127.0.0.0/8 is refused as "nobody to answer" (sublink.c).
ip addr add 10.77.0.1/32 dev lo

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -subj "/CN=node.test" >/dev/null 2>&1
python3 "$HERE/sigpipe-node.py" --bind 10.77.0.1 --port 10443 --uuid "$UUID" --tls "$tmp/cert.pem" "$tmp/key.pem" \
    >"$tmp/node-tls.out" 2>"$tmp/node-tls.err" & NT=$!
python3 "$HERE/sigpipe-node.py" --bind 10.77.0.1 --port 10444 --uuid "$UUID" \
    >"$tmp/node-none.out" 2>"$tmp/node-none.err" & NP=$!
wait_for 'grep -q ready "$tmp/node-tls.out" && grep -q ready "$tmp/node-none.out"' 10

# The client's traffic to .7 goes into the TLS tunnel, to .8 into the plain one: --route on each.
"$BIN" "vless://$UUID@10.77.0.1:10443?encryption=none&type=tcp&security=tls&sni=node.test&allowInsecure=1#tls" \
    --insecure -d vlt -a 198.51.100.1/32 -r $TLS/32 >"$tmp/t-tls.log" 2>&1 & T1=$!
"$BIN" "vless://$UUID@10.77.0.1:10444?encryption=none&type=tcp&security=none#none" \
    -d vln -a 198.51.100.2/32 -r $NONE/32 >"$tmp/t-none.log" 2>&1 & T2=$!
wait_for 'ip route show $TLS/32 | grep -q vlt && ip route show $NONE/32 | grep -q vln' 20

ping_tunnel() { C python3 "$HERE/sigpipe-client.py" "$1" --ping >"$tmp/ping.$1" 2>&1; }
ping_tunnel $TLS; check "TLS tunnel answers before the load" "0" "$?"
ping_tunnel $NONE; check "plain tunnel answers before the load" "0" "$?"

fds() { ls "/proc/$1/fd" 2>/dev/null | wc -l; }
# SIGPIPE is signal 13, bit 12 of the SigIgn mask (0x1000).
pipe_ignored() { m="$(awk '/^SigIgn:/ { print $2 }' "/proc/$1/status" 2>/dev/null)"; [ -n "$m" ] && echo $(( (0x$m >> 12) & 1 )) || echo "?"; }
check "SIGPIPE is ignored in both tunnels" "1 1" "$(pipe_ignored $T1) $(pipe_ignored $T2)"
f1="$(fds $T1)"; f2="$(fds $T2)"

# ---- load ---------------------------------------------------------------------------------------
C python3 "$HERE/sigpipe-client.py" $TLS --storm "$SECS" >"$tmp/cl-tls.out" 2>&1 & P1=$!
C python3 "$HERE/sigpipe-client.py" $NONE --storm "$SECS" --up 4 --abort-up 2 --abort-down 2 >"$tmp/cl-none.out" 2>&1 & P2=$!
wait $P1 $P2
echo "  $(cat "$tmp/cl-tls.out")"
echo "  $(cat "$tmp/cl-none.out")"
echo "  node TLS:  $(grep '^node:' "$tmp/node-tls.err" | tail -n 1)"
echo "  node none: $(grep '^node:' "$tmp/node-none.err" | tail -n 1)"

check "both tunnels are alive after the load (same pids)" "1 1" \
    "$(kill -0 $T1 2>/dev/null && echo 1 || echo 0) $(kill -0 $T2 2>/dev/null && echo 1 || echo 0)"
ping_tunnel $TLS; check "TLS tunnel answers right after the load" "0" "$?"
ping_tunnel $NONE; check "plain tunnel answers right after the load" "0" "$?"
early() { grep '^node:' "$1" | tail -n 1 | grep -o 'closed-early=[0-9]*' | sed 's/.*=//'; }
e1="$(early "$tmp/node-tls.err")"; e2="$(early "$tmp/node-none.err")"
check "the load reached the TLS node: at least 20 connections closed early" "1" "$([ "${e1:-0}" -ge 20 ] && echo 1 || echo 0)"
check "  and the plain node: at least 10" "1" "$([ "${e2:-0}" -ge 10 ] && echo 1 || echo 0)"
# Port 81 speaks first: the client never sends, so the node learns the destination only from the
# header the stack sends alone after SERVER_FIRST_MS. Without it every download got nothing.
bin_() { grep -o 'bytes-in=[0-9]*' "$1" | sed 's/.*=//'; }
b1="$(bin_ "$tmp/cl-tls.out")"; b2="$(bin_ "$tmp/cl-none.out")"
check "downloads from a server that speaks first got data (TLS, plain)" "1 1" \
    "$([ "${b1:-0}" -gt 0 ] && echo 1 || echo 0) $([ "${b2:-0}" -gt 0 ] && echo 1 || echo 0)"
check "no upload stalled on a write (10 s socket timeout)" "0" \
    "$(cat "$tmp/cl-tls.out" "$tmp/cl-none.out" | grep -o 'up:stalled=[0-9]*' | sed 's/.*=//' | awk '{ n += $1 } END { print n + 0 }')"

# Quiet period: the stack frees closed connections within loop turns, and one closed by the node
# but not yet acknowledged by the client after CLOSE_DRAIN_MS (5 s); the margin is the spare sessions.
sleep 7
g1="$(fds $T1)"; g2="$(fds $T2)"
check "no more descriptors than before the load (+8: spare sessions)" "1 1" \
    "$([ "$g1" -le $((f1 + 8)) ] && echo 1 || echo 0) $([ "$g2" -le $((f2 + 8)) ] && echo 1 || echo 0)"
echo "  descriptors: TLS $f1 -> $g1, plain $f2 -> $g2"
check "no node sockets left in CLOSE-WAIT" "0" \
    "$(ss -tnp state close-wait 2>/dev/null | grep -c "pid=$T1,\|pid=$T2,")"

echo "sigpipe: $pass ok, $fail fail"
[ "$fail" = 0 ]
