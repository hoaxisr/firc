#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

usage() {
    cat <<EOF
usage: sh tests/hy2.sh [-h]

Runs hy2probe against Xray-core's own Hysteria2 inbound in network namespaces,
then the same load through Xray's own client.

  XRAY=<binary>     Xray-core 26.10.21 or later (default: xray in PATH)
  HY2PROBE=<path>   the probe (default ./out/tests/hy2probe, make out/tests/hy2probe)
  CASES="..."       the cases to run (default: all)
  DUR=<seconds>     length of hy2-down and hy2-up (default 20)
  KEEP=<dir>        copy the work directory (configs, logs) there at the end

Needs root, ip netns, python3, openssl; without one of them, or without Xray,
it prints SKIPPED and exits 0. A case skipped inside a run is named and the
run exits 2; a failed case exits 1.

cases: $ALL_CASES
EOF
}

ALL_CASES="hy2-auth hy2-badauth hy2-tcp hy2-tcp-nobatch hy2-tcp-v6 hy2-tcp-eof hy2-tcp-eof-small
           hy2-udp hy2-udp-1200 hy2-udp-frag hy2-obfs hy2-obfs-wrong hy2-obfs-plain hy2-pin hy2-chacha hy2-rx
           hy2-loss hy2-down hy2-up"
case "${1:-}" in -h|--help) usage; exit 0 ;; "") ;; *) usage >&2; exit 2 ;; esac

PROBE="${HY2PROBE:-./out/tests/hy2probe}"
DUR="${DUR:-20}"
CASES="${CASES:-$ALL_CASES}"
XRAY="${XRAY:-$(command -v xray 2>/dev/null || true)}"

[ "$(id -u)" = 0 ] || { echo "hy2: SKIPPED — needs root (ip netns). Not a failure."; exit 0; }
for t in ip ss timeout; do
    command -v "$t" >/dev/null 2>&1 || { echo "hy2: SKIPPED — no $t. Not a failure."; exit 0; }
done
command -v python3 >/dev/null 2>&1 || { echo "hy2: SKIPPED — needs python3. Not a failure."; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "hy2: SKIPPED — needs openssl. Not a failure."; exit 0; }
[ -n "$XRAY" ] && [ -x "$XRAY" ] || { echo "hy2: SKIPPED — no Xray-core (XRAY=/path/to/xray). Not a failure."; exit 0; }
XV=$("$XRAY" version 2>/dev/null | awk 'NR == 1 { print $2 }')
printf '%s\n' "$XV" | awk -F. '{ v = $1 * 10000 + $2 * 100 + $3; exit !(NF >= 3 && v >= 261021) }' ||
    { echo "hy2: SKIPPED — Xray $XV is older than 26.10.21. Not a failure."; exit 0; }
[ -x "$PROBE" ] || { echo "hy2: no binary $PROBE (make out/tests/hy2probe)"; exit 2; }
PROBE="$(cd "$(dirname "$PROBE")" && pwd)/$(basename "$PROBE")"
ip netns add "hy2-probe-$$" 2>/dev/null || { echo "hy2: SKIPPED — ip netns unavailable. Not a failure."; exit 0; }
ip netns delete "hy2-probe-$$"

NSC="hy2c$$"; NSS="hy2s$$"
S_IP=10.94.0.1; C_IP=10.94.0.2; S_IP6=2001:db8:94::1; C_IP6=2001:db8:94::2
TARGET=203.0.113.9; TARGET6=2001:db8:9::9
SNI=hy2.test; PW=hy2-secret; OBFS=obfs-secret
P_BASE=18443; P_OBFS=18444; P_RX=18445
W="$(mktemp -d)"
cleanup() {
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
    done
    sleep 0.3
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill -9 "$p" 2>/dev/null || true; done
        ip netns delete "$n" 2>/dev/null || true
    done
    [ -n "${KEEP:-}" ] && cp -r "$W/." "$KEEP/" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

bg_in() { ns="$1"; log="$2"; shift 2; ip netns exec "$ns" "$@" > "$log" 2>&1 & }
now() { date +%s.%N; }
wait_ss() {
    i=0
    while [ $i -lt 80 ]; do
        ip netns exec "$1" ss "$2" 2>/dev/null | grep -qF "$3" && return 0
        sleep 0.25; i=$((i + 1))
    done
    return 1
}

echo "hy2: server — $("$XRAY" version 2>/dev/null | head -1)"

ip netns add "$NSC"; ip netns add "$NSS"
ip -n "$NSC" link set lo up; ip -n "$NSS" link set lo up
ip link add hyc0 netns "$NSC" type veth peer name hys0 netns "$NSS"
ip -n "$NSC" addr add "$C_IP/24" dev hyc0
ip -n "$NSS" addr add "$S_IP/24" dev hys0
ip -n "$NSC" addr add "$C_IP6/64" dev hyc0 nodad
ip -n "$NSS" addr add "$S_IP6/64" dev hys0 nodad
ip -n "$NSC" link set hyc0 up; ip -n "$NSS" link set hys0 up
ip -n "$NSS" addr add "$TARGET/32" dev lo
ip -n "$NSS" addr add "$TARGET6/128" dev lo nodad

printf '%s\n' '[ca]' 'basicConstraints=critical,CA:TRUE' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' \
    '[leaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
    'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' "subjectAltName=DNS:$SNI" > "$W/x509.cnf"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout "$W/ca.key" \
    -out "$W/ca.pem" -subj "/CN=hy2 test ca" -config "$W/x509.cnf" -extensions ca >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/leaf.key" \
    -subj "/CN=$SNI" -out "$W/leaf.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/leaf.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -set_serial 2 -days 2 \
    -extfile "$W/x509.cnf" -extensions leaf -out "$W/leaf.pem" >/dev/null 2>&1
openssl verify -CAfile "$W/ca.pem" "$W/leaf.pem" >/dev/null || { echo "hy2: the test certificate does not verify"; exit 1; }
PIN=$(openssl x509 -in "$W/leaf.pem" -outform der | openssl dgst -sha256 -r | awk '{ print $1 }')
BADPIN=$(printf '%s' "$PIN" | awk '{ c = substr($0, 1, 1); print (c == "0" ? "1" : "0") substr($0, 2) }')
BADPIN2=$(printf '%s' "$PIN" | awk '{ c = substr($0, 64, 1); print substr($0, 1, 63) (c == "0" ? "1" : "0") }')

cat > "$W/targets.py" <<'PY'
import socket, sys, threading, time
def echo(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)
    except OSError:
        pass
    c.close()
def sink(c):
    try:
        while c.recv(1 << 20):
            pass
    except OSError:
        pass
    c.close()
def fixed(n):
    b = bytes((i * 31 + 7) % 251 for i in range(n))
    def f(c):
        try:
            c.sendall(b)
        except OSError:
            pass
        c.close()
    return f
def source(c):
    b = bytes(1 << 18)
    try:
        while True:
            c.sendall(b)
    except OSError:
        pass
    c.close()
def tcp(fam, ip, port, fn):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=fn, args=(c,), daemon=True).start()
def udp(fam, ip, port):
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.bind((ip, port))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(d, a)
v4, v6 = sys.argv[1], sys.argv[2]
for a in ((socket.AF_INET, v4, 7000, echo), (socket.AF_INET, v4, 7001, sink), (socket.AF_INET, v4, 7002, source),
          (socket.AF_INET, v4, 7003, fixed(1048576)), (socket.AF_INET, v4, 7004, fixed(500)),
          (socket.AF_INET6, v6, 7000, echo)):
    threading.Thread(target=tcp, args=a, daemon=True).start()
threading.Thread(target=udp, args=(socket.AF_INET, v4, 7000), daemon=True).start()
while True:
    time.sleep(3600)
PY
bg_in "$NSS" "$W/targets.log" python3 "$W/targets.py" "$TARGET" "$TARGET6"
wait_ss "$NSS" -ltn "$TARGET:7004" && wait_ss "$NSS" -lun "$TARGET:7000" && wait_ss "$NSS" -ltn "[$TARGET6]:7000" ||
    { echo "hy2: the targets did not start:"; cat "$W/targets.log"; exit 1; }

TLS="\"security\":\"tls\",\"tlsSettings\":{\"certificates\":[{\"certificateFile\":\"$W/leaf.pem\",\"keyFile\":\"$W/leaf.key\"}]}"
HS="\"hysteriaSettings\":{\"version\":2,\"auth\":\"$PW\"}"
inb() {
    printf '{"tag":"%s","listen":"%s","port":%s,"protocol":"hysteria","settings":{"version":2,"clients":[{"auth":"%s"}]},"streamSettings":{"network":"hysteria",%s,%s%s}}' \
        "$1" "$2" "$3" "$PW" "$TLS" "$HS" "${4:+,$4}"
}
cat > "$W/xray.json" <<JSON
{"log":{"loglevel":"debug"},
 "inbounds":[$(inb base "$S_IP" $P_BASE),$(inb base6 "$S_IP6" $P_BASE),
   $(inb obfs "$S_IP" $P_OBFS "\"finalmask\":{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":\"$OBFS\"}}]}"),
   $(inb rx "$S_IP" $P_RX "\"finalmask\":{\"quicParams\":{\"brutalDown\":\"100 mbps\"}}")],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["$TARGET/32","$TARGET6/128"]}]}}]}
JSON
"$XRAY" run -test -c "$W/xray.json" > "$W/xray-test.log" 2>&1 || { echo "hy2: Xray refuses the server config:"; tail -5 "$W/xray-test.log"; exit 1; }
bg_in "$NSS" "$W/xray.log" "$XRAY" run -c "$W/xray.json"
XPID=$!
for l in "$S_IP:$P_BASE " "[$S_IP6]:$P_BASE " "$S_IP:$P_OBFS " "$S_IP:$P_RX "; do
    wait_ss "$NSS" -lun "$l" || { echo "hy2: Xray did not start ($l):"; tail -5 "$W/xray.log"; exit 1; }
done

FAIL=0; SKIPPED=""; OUT=""; RC=0; EL=0
pr() {
    lim=$1; shift
    t0=$(now)
    RC=0
    timeout -k 2 "$lim" ip netns exec "$NSC" "$PROBE" --deadline $((lim - 5)) "$@" > "$W/probe.out" 2>&1 || RC=$?
    EL=$(awk -v a="$t0" -v b="$(now)" 'BEGIN { printf "%.2f", b - a }')
    OUT=$(cat "$W/probe.out")
    cat "$W/probe.out" >> "$W/probe-$MODE.log"
    printf '    [exit %s, %ss] %s\n' "$RC" "$EL" "$(printf '%s' "$OUT" | head -1)"
    printf '%s\n' "$OUT" | sed -n '2,$s/^/        /p'
}
CA="--sni $SNI --auth $PW --ca $W/ca.pem"
base() { pr "$1" --server "$S_IP:$P_BASE" $CA $2; }
has() { printf '%s\n' "$OUT" | grep -qF -- "$1"; }
first() { printf '%s\n' "$OUT" | head -1 | grep -q -- "$1"; }
ok0() { [ "$RC" -eq 0 ] && first "$1"; }
fail1() { [ "$RC" -eq 1 ]; }
stat_of() { printf '%s\n' "$OUT" | awk -v k="$1" '/^stats / { for (i = 2; i < NF; i++) if ($i == k) print $(i + 1) }'; }
dgrams() { printf '%s\n' "$OUT" | sed -n '1s/.* datagrams \([0-9]*\).*/\1/p'; }
within() { awk -v e="$EL" -v l="$1" 'BEGIN { exit !(e <= l) }'; }

cpu_of() { sed 's/.*) //' "/proc/$1/stat" | awk '{ print $12 + $13 }'; }
xc_up() {
    cat > "$W/xc.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":18080,"protocol":"dokodemo-door","settings":{"address":"$TARGET","port":7002,"network":"tcp"}},
   {"listen":"127.0.0.1","port":18081,"protocol":"dokodemo-door","settings":{"address":"$TARGET","port":7001,"network":"tcp"}}],
 "outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"$S_IP","port":$P_BASE},
   "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"$SNI","pinnedPeerCertSha256":"$PIN"},$HS}}]}
JSON
    "$XRAY" run -test -c "$W/xc.json" > "$W/xc-test.log" 2>&1 || { echo "hy2: Xray refuses the client config:"; tail -5 "$W/xc-test.log"; return 1; }
    ip netns exec "$NSC" "$XRAY" run -c "$W/xc.json" > "$W/xc.log" 2>&1 &
    CPID=$!
    wait_ss "$NSC" -ltn "127.0.0.1:18081 " || { echo "hy2: the Xray client did not start:"; tail -5 "$W/xc.log"; xc_down; return 1; }
}
xc_down() { [ -z "${CPID:-}" ] || { kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true; }; CPID=""; }
xc_load() {
    timeout -k 2 $((DUR + 20)) ip netns exec "$NSC" python3 -c '
import resource, socket, sys, time
mode, port, dur = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port))
t0 = time.monotonic(); n = 0
if mode == "down":
    while time.monotonic() - t0 < dur:
        d = s.recv(1 << 20)
        if not d:
            break
        n += len(d)
else:
    b = bytes(1 << 16)
    while time.monotonic() - t0 < dur:
        n += s.send(b)
t1 = time.monotonic()
r = resource.getrusage(resource.RUSAGE_SELF)
print("bytes %d seconds %.3f cpu %.2f" % (n, t1 - t0, r.ru_utime + r.ru_stime))' "$1" "$2" "$DUR"
}
mbs() { printf '%s\n' "$1" | awk '/^bytes / { printf "%.1f", $2 / 1e6 / $4 }'; }
per() { printf '%s\n' "$1" | awk -v c="$2" '/^bytes / { mb = $2 / 1e6; printf "%.4f", (mb > 0 ? c / mb : 0) }'; }
TCK=$(getconf CLK_TCK)
load() {
    dir=$1; port=$2
    base $((DUR + 30)) "$dir $TARGET:$port $DUR"
    [ "$RC" -eq 0 ] && first "^bytes " || return 1
    pc=$(stat_of cpu); ps_=$(printf '%s\n' "$OUT" | awk '/^stats / { print $NF }')
    pc=$(awk -v a="$pc" -v b="$ps_" 'BEGIN { printf "%.2f", a + b }')
    xc_up || return 1
    c0=$(cpu_of "$CPID")
    xo=$(xc_load "$dir" "$3") || { echo "    the Xray client load failed: $xo"; xc_down; return 1; }
    c1=$(cpu_of "$CPID")
    xc_down
    xcpu=$(awk -v a="$c0" -v b="$c1" -v t="$TCK" 'BEGIN { printf "%.2f", (b - a) / t }')
    pycpu=$(printf '%s\n' "$xo" | awk '{ print $NF }')
    sum=$(awk -v a="$xcpu" -v b="$pycpu" 'BEGIN { printf "%.2f", a + b }')
    echo "    $dir hy2probe: $(mbs "$OUT") MB/s, cpu $pc s, $(per "$OUT" "$pc") CPU s/MB"
    echo "    $dir xray client: $(mbs "$xo") MB/s, cpu xray $xcpu s + python $pycpu s = $sum s, xray $(per "$xo" "$xcpu") + python $(per "$xo" "$pycpu") = $(per "$xo" "$sum") CPU s/MB"
    echo "    $dir note: hy2probe discards or generates the data in-process; the Xray client relays it through a loopback TCP socket to a python process."
}

run_case() {
    case "$MODE" in
    hy2-auth) base 15 auth; ok0 "^ready rx 0 " && first " udp 1$" ;;
    hy2-badauth)
        pr 15 --server "$S_IP:$P_BASE" --sni "$SNI" --auth wrong-password --ca "$W/ca.pem" auth
        fail1 && has "auth failed code 404" && within 3 ;;
    hy2-tcp) base 30 "tcp $TARGET:7000 65536"; ok0 "^echoed 65536 ok$" ;;
    hy2-tcp-nobatch)
        base 60 "--no-batch tcp $TARGET:7000 4194304"; ok0 "^echoed 4194304 ok$" && has "stats gso 0 gro 0 " ;;
    hy2-tcp-v6)
        pr 30 --server "[$S_IP6]:$P_BASE" $CA tcp "[$TARGET6]:7000" 65536; ok0 "^echoed 65536 ok$" ;;
    hy2-tcp-eof) base 30 "fetch $TARGET:7003 1048576"; ok0 "^fetched 1048576 ok closed clean$" ;;
    hy2-tcp-eof-small) base 30 "fetch $TARGET:7004 500"; ok0 "^fetched 500 ok closed clean$" ;;
    hy2-udp) base 90 "udp $TARGET:7000 100 50"; ok0 "^echoed 50 of 50 " ;;
    hy2-udp-1200) base 60 "udp $TARGET:7000 1200 20"; ok0 "^echoed 20 of 20 datagrams 20$" ;;
    hy2-udp-frag) base 60 "udp $TARGET:7000 3000 20"; ok0 "^echoed 20 of 20 " && [ "$(dgrams)" -ge 40 ] ;;
    hy2-obfs)
        pr 30 --server "$S_IP:$P_OBFS" $CA --obfs "$OBFS" tcp "$TARGET:7000" 65536; ok0 "^echoed 65536 ok$" || return 1
        pr 90 --server "$S_IP:$P_OBFS" $CA --obfs "$OBFS" udp "$TARGET:7000" 100 50; ok0 "^echoed 50 of 50 " ;;
    hy2-obfs-wrong)
        pr 30 --server "$S_IP:$P_OBFS" $CA --obfs "not-$OBFS" auth
        fail1 && within 15 && has "handshake" ;;
    hy2-obfs-plain)
        pr 30 --server "$S_IP:$P_OBFS" $CA auth; fail1 && within 15 && has "closed handshake" || return 1
        pr 30 --server "$S_IP:$P_BASE" $CA --obfs "$OBFS" auth; fail1 && within 15 && has "closed handshake" ;;
    hy2-pin)
        pr 30 --server "$S_IP:$P_BASE" --sni "$SNI" --auth "$PW" --pin "$PIN" tcp "$TARGET:7000" 65536
        ok0 "^echoed 65536 ok$" || return 1
        pr 15 --server "$S_IP:$P_BASE" --sni "$SNI" --auth "$PW" --pin "$BADPIN" auth
        fail1 && has "certificate pin mismatch" || return 1
        pr 15 --server "$S_IP:$P_BASE" --sni "$SNI" --auth "$PW" --pin "$BADPIN2" auth
        fail1 && has "certificate pin mismatch" ;;
    hy2-chacha)
        base 15 "--chacha auth"; ok0 " cipher 0x1303 " || return 1
        base 15 "--aes auth"; ok0 " cipher 0x1301 " ;;
    hy2-rx) pr 15 --server "$S_IP:$P_RX" $CA auth; ok0 "^ready rx 13107200 " ;;
    hy2-loss)
        r=0
        base 120 "tcp $TARGET:7000 4194304"; ok0 "^echoed 4194304 ok$" || r=1
        lost=$(stat_of lost); rtt=$(stat_of rtt_ms)
        echo "    lost $lost rtt_ms $rtt"
        awk -v l="${lost:-0}" -v r="${rtt:-0}" 'BEGIN { exit !(l > 0 && r >= 40) }' || r=1
        ip netns exec "$NSC" tc qdisc del dev hyc0 root 2>/dev/null || true
        ip netns exec "$NSS" tc qdisc del dev hys0 root 2>/dev/null || true
        return $r ;;
    hy2-down) load down 7002 18080 ;;
    hy2-up) load up 7001 18081 ;;
    *) echo "hy2: unknown case $MODE"; exit 2 ;;
    esac
}

for MODE in $CASES; do
    echo "hy2: case $MODE"
    if [ "$MODE" = hy2-loss ]; then
        if ! ip netns exec "$NSC" tc qdisc add dev hyc0 root netem loss 3% delay 20ms 2> "$W/tc.err" ||
           ! ip netns exec "$NSS" tc qdisc add dev hys0 root netem loss 3% delay 20ms 2>> "$W/tc.err"; then
            ip netns exec "$NSC" tc qdisc del dev hyc0 root 2>/dev/null || true
            echo "hy2: case $MODE — SKIPPED (tc netem refused: $(head -1 "$W/tc.err"); not passed)"
            SKIPPED="$SKIPPED $MODE"; continue
        fi
    fi
    if run_case; then echo "hy2: case $MODE — ok"; else FAIL=1; echo "hy2: case $MODE — FAIL"; fi
    kill -0 "$XPID" 2>/dev/null || { echo "hy2: the Xray server died:"; tail -20 "$W/xray.log"; exit 1; }
done

[ "$FAIL" -eq 0 ] || { echo "hy2: FAILED"; exit 1; }
[ -z "$SKIPPED" ] || { echo "hy2: SKIPPED, not passed:$SKIPPED"; exit 2; }
echo "hy2: all checks passed"
