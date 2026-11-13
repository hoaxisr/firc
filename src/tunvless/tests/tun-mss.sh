#!/bin/sh
set -u
skip() { echo "tun-mss: $1 — cannot run"; exit 77; }
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
for t in ip python3 nsenter unshare awk sysctl; do command -v $t >/dev/null 2>&1 || skip "no $t"; done
if [ "${TUNMSS_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "needs root"
    unshare -nm true 2>/dev/null || skip "unshare -nm unavailable"
    TUNMSS_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "cannot mount a private /sys"
ip link set lo up
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
    net.ipv6.conf.all.forwarding=1 || skip "cannot turn forwarding on"

UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
TARGET=203.0.113.7
TARGET6=2001:db8:9::9
tmp="$(mktemp -d)"
CPID="" NP="" MP=""
cleanup() {
    kill $MP $NP $CPID 2>/dev/null
    if [ "$fail" != 0 ]; then
        for f in "$tmp"/mod.*; do [ -f "$f" ] && { echo "--- $f (tail)"; tail -n 6 "$f"; }; done
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

unshare -n sleep 600 & CPID=$!
sleep 0.3
C() { nsenter -t "$CPID" -n "$@"; }
ip link add p0 mtu 1280 type veth peer name c0 mtu 1280 || skip "no veth"
ip link set c0 netns "$CPID"
ip addr add 10.79.1.1/24 dev p0
ip -6 addr add fd00:79:1::1/64 dev p0 nodad
ip link set p0 up
C ip link set lo up
C ip addr add 10.79.1.2/24 dev c0
C ip -6 addr add fd00:79:1::2/64 dev c0 nodad
C ip link set c0 up
C ip route add default via 10.79.1.1
C ip -6 route add default via fd00:79:1::1
ip addr add 10.79.0.1/32 dev lo

python3 "$HERE/fake-vless.py" --bind 10.79.0.1 --port 10445 --uuid "$UUID" --mb 1 \
    >"$tmp/node.out" 2>"$tmp/node.err" & NP=$!
wait_for 'grep -q serves "$tmp/node.out"' 10 || skip "the download node did not start"
LINK="vless://$UUID@10.79.0.1:10445?security=none&type=tcp#node"

python3 - "$HERE/fake-vless.py" "$tmp/body" <<'PY'
import runpy, sys
filler = runpy.run_path(sys.argv[1])["FILLER"]
n = 1 << 20
open(sys.argv[2], "wb").write((filler * (n // len(filler) + 1))[:n])
PY

cat > "$tmp/get.py" <<'PY'
import socket, sys
host, fam, out = sys.argv[1], sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_INET6 if fam == "6" else socket.AF_INET)
s.settimeout(15)
data = b""
try:
    s.connect((host, 80))
    s.sendall(b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
except OSError as e:
    print("client: %s after %d bytes" % (e, len(data)), flush=True)
s.close()
head, _, body = data.partition(b"\r\n\r\n")
open(out, "wb").write(body)
PY

frags() { awk '/^Ip:/ { if (!h) { for (i = 1; i <= NF; i++) if ($i == "FragCreates") c = i; h = 1 } else print $c }' /proc/net/snmp; }

leg() {
    name="$1" fam="$2" host="$3"
    env STEER_TUN_STATS=1 "$BIN" "$LINK" -d vl -r "$TARGET/32" >"$tmp/mod.$name" 2>&1 &
    MP=$!
    if ! wait_for 'ip route show "$TARGET/32" 2>/dev/null | grep -q "dev vl"' 20; then
        fail=$((fail + 1)); echo "FAIL $name: device vl or the route into it did not come up in 20 s"
        kill $MP 2>/dev/null; wait $MP 2>/dev/null; MP=""
        return 1
    fi
    ip -6 route replace "$TARGET6/128" dev vl
    f0="$(frags)"
    nsenter -t "$CPID" -n python3 "$tmp/get.py" "$host" "$fam" "$tmp/dl.$name" >"$tmp/cl.$name" 2>&1
    f1="$(frags)"
    echo $((f1 - f0)) > "$tmp/frag.$name"
    wait_for 'grep -q "client MSS [1-9]" "$tmp/mod.$name"' 6
    kill $MP 2>/dev/null; wait $MP 2>/dev/null; MP=""
    wait_for '! ip link show vl >/dev/null 2>&1' 5
    sed 's/^/  /' "$tmp/cl.$name"
}
whole() { cmp -s "$tmp/body" "$tmp/dl.$1" && echo yes || echo "no ($(wc -c < "$tmp/dl.$1" 2>/dev/null || echo 0) bytes)"; }
mss() { grep -o 'client MSS [0-9]*\.\.[0-9]*' "$tmp/mod.$1" | grep -v 'MSS 0\.\.0' | sort -u | tr '\n' ' ' | sed 's/ $//'; }

leg v4 4 "$TARGET"
check "IPv4: the 1 MB arrives whole" yes "$(whole v4)"
check "IPv4: tun-stats says the client's MSS" "client MSS 1240..1240" "$(mss v4)"
check "IPv4: the router fragmented nothing (FragCreates delta)" 0 "$(cat "$tmp/frag.v4")"

leg v6 6 "$TARGET6"
check "IPv6: the 1 MB arrives whole" yes "$(whole v6)"
check "IPv6: tun-stats says the client's MSS" "client MSS 1220..1220" "$(mss v6)"

echo "tun-mss: $pass ok, $fail fail"
[ "$fail" = 0 ]
