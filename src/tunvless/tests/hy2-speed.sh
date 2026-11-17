#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

usage() {
    cat <<EOF
usage: sh tests/hy2-speed.sh [-h] [case...]

Measures tunvless's Hysteria2 client against Xray-core's own Hysteria2 client, one after the
other, through one Xray server on a netem line (RTT 50 ms, 40 Mbit/s each way, a queue of 1000
packets, loss on the data direction), and judges the rules printed at the start.

  XRAY=<binary>        Xray-core 26.10.21 or later (default: xray in PATH)
  TUNVLESS=<path>      the binary (default ./out/tunvless)
  HY2PROBE=<path>      the probe (default ./out/tests/hy2probe)
  CASES="..."          the cases to run, or as arguments (default: all)
  SPEED_DUR=<s>        seconds per run (default 30; another value is not binding)
  SPEED_RUNS=<n>       runs per client and cell (default 5; another value is not binding)
  SPEED_NONVACUOUS=1   cc-brutal-low with our quicParams {"congestion":"bbr"}: exit 0 only when P2 fails at 0 %
  KEEP=<dir>           an absolute directory for the logs and the whole output (run.log); required
                       for a binding run (5 runs of 30 s)

Needs root, ip netns, tc netem, nft, python3, openssl; without one of them, or without Xray, it
prints SKIPPED and exits 0. Exit 1 when P1, P2 or P3 fails; exit 3 when the run ends without a
verdict (a cell void three times, or Xray outside P2's band).

cases: $ALL_CASES
recorded only, by name ($REC_RUNS runs of SPEED_DUR s each, no rule): $REC_CASES
EOF
}

ALL_CASES="cc-brutal-low cc-brutal-up cc-bbr-up cc-brutal-down cc-over-line cc-reno-up"
REC_CASES="cc-hop-brutal cc-hop-bbr cc-fresh cc-shallow"; REC_RUNS=3
case "${1:-}" in -h|--help) usage; exit 0 ;; esac
CASES="${*:-${CASES:-$ALL_CASES}}"

BIN="${TUNVLESS:-./out/tunvless}"
PROBE="${HY2PROBE:-./out/tests/hy2probe}"
XRAY="${XRAY:-$(command -v xray 2>/dev/null || true)}"
DUR="${SPEED_DUR:-30}"; RUNS="${SPEED_RUNS:-5}"; NV="${SPEED_NONVACUOUS:-}"; KEEP="${KEEP:-}"
BINDING=""; [ "$DUR" = 30 ] && [ "$RUNS" = 5 ] && [ -z "$NV" ] && BINDING=1

[ "$(id -u)" = 0 ] || { echo "hy2-speed: SKIPPED — needs root (ip netns). Not a failure."; exit 0; }
for t in ip ss tc nft timeout getconf sha256sum; do
    command -v "$t" >/dev/null 2>&1 || { echo "hy2-speed: SKIPPED — no $t. Not a failure."; exit 0; }
done
command -v python3 >/dev/null 2>&1 || { echo "hy2-speed: SKIPPED — needs python3. Not a failure."; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "hy2-speed: SKIPPED — needs openssl. Not a failure."; exit 0; }
[ -n "$XRAY" ] && [ -x "$XRAY" ] || { echo "hy2-speed: SKIPPED — no Xray-core (XRAY=/path/to/xray). Not a failure."; exit 0; }
XV=$("$XRAY" version 2>/dev/null | awk 'NR == 1 { print $2 }')
printf '%s\n' "$XV" | awk -F. '{ v = $1 * 10000 + $2 * 100 + $3; exit !(NF >= 3 && v >= 261021) }' ||
    { echo "hy2-speed: SKIPPED — Xray $XV is older than 26.10.21. Not a failure."; exit 0; }
[ -x "$BIN" ] || { echo "hy2-speed: no binary $BIN (make)"; exit 2; }
[ -x "$PROBE" ] || { echo "hy2-speed: no binary $PROBE (make out/tests/hy2probe)"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
PROBE="$(cd "$(dirname "$PROBE")" && pwd)/$(basename "$PROBE")"
XRAY="$(cd "$(dirname "$XRAY")" && pwd)/$(basename "$XRAY")"
for c in $CASES; do
    case " $ALL_CASES $REC_CASES " in *" $c "*) ;; *) echo "hy2-speed: unknown case $c"; exit 2 ;; esac
done
[ -z "$NV" ] || [ "$CASES" = cc-brutal-low ] || { echo "hy2-speed: SPEED_NONVACUOUS=1 runs the case cc-brutal-low alone"; exit 2; }
[ -z "$BINDING" ] || [ -n "$KEEP" ] || { echo "hy2-speed: a binding run (5 x 30 s) needs KEEP=<dir> for its logs"; exit 2; }
if [ -n "$KEEP" ] && [ -z "${HY2S_TEED:-}" ]; then
    case "$KEEP" in /*) ;; *) echo "hy2-speed: KEEP must be an absolute directory"; exit 2 ;; esac
    mkdir -p "$KEEP"
    { rc=0; HY2S_TEED=1 sh "$0" "$@" || rc=$?; echo "$rc" > "$KEEP/.rc"; } 2>&1 | tee "$KEEP/run.log"
    rc=$(cat "$KEEP/.rc"); rm -f "$KEEP/.rc"
    exit "$rc"
fi
ip netns add "hy2s-probe-$$" 2>/dev/null || { echo "hy2-speed: SKIPPED — ip netns unavailable. Not a failure."; exit 0; }
ip netns delete "hy2s-probe-$$"

NSC="h2sc$$"; NSS="h2ss$$"
S_IP=10.96.0.1; C_IP=10.96.0.2; TARGET=203.0.113.9
SNI=hy2.test; PW="pw-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"; P=18443
TCK=$(getconf CLK_TCK)
W="$(mktemp -d)"
TPID=""; CPID=""; XPID=""
cleanup() {
    exec 7>&- 2>/dev/null || true
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
    done
    sleep 0.3
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill -9 "$p" 2>/dev/null || true; done
        ip netns delete "$n" 2>/dev/null || true
    done
    [ -z "$KEEP" ] || cp -r "$W/." "$KEEP/" 2>/dev/null || true
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
cpu_of() { sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{ print $12 + $13 }'; }

cat <<'RULES'
hy2-speed: rules, fixed before the run (no number in them came from a run of our code):
- Line: RTT 50 ms, 40 Mbit/s each way, a queue of 1000 packets, independent loss on the data direction only.
  Every figure is the median of five runs of 30 s, in B/s, for one client in one cell (a case at one loss).
  Bounds are inclusive.
- Controls: a cell is void, for both clients, when in any of its runs a client or the server used more than
  90 % of one core, a segment went as a GSO or GRO aggregate, a run gave no count, or a side ran another
  controller than the cell names. A void cell is run again whole with the same binaries; runs of a void
  attempt are never counted and attempts are never mixed. The first valid attempt of a cell counts. A cell
  void three times is a finding and ends the run without a verdict.
- P1 Brutal parity: in cc-brutal-up (0, 1, 3 % loss) and cc-brutal-down (0, 3 %) our median is at least 90 %
  and at most 110 % of Xray's. Inside that band, a median under 95 % or over 105 % of Xray's is a finding to
  investigate; it fails nothing.
- P2 Brutal sends at the node's rate, loss or not: in cc-brutal-low our median and Xray's are each at least
  90 % and at most 110 % of 2,097,152 B/s at 0 %, 3 % and 15 % loss. A client on BBR would deliver about
  4.8 MB/s there, about 230 %; a Brutal that does not make up for loss about 83 % at 15 %. An Xray median
  outside the band is a fault of the stand: the run ends without a verdict.
- P3 a rate above the line: in cc-over-line our median is at least 85 % and at most 115 % of Xray's. The queue drops of each client are printed; a client with no queue drops in a cell where the other shows them is a finding to investigate; it fails nothing.
- Failing P1, P2 or P3 is a defect to fix, once. If the rule still fails after the fix, Brutal is removed
  from the client; the header that announces the down rate stays. How our Brutal at 3 % compares with our BBR
  at 3 % is recorded only.
- P4 BBR: in each loss cell of cc-bbr-up (0, 1, 3 %) the cell fails when our median is under 90 % of Xray's
  median and our best run is under Xray's median. A failing cell at 1 % or 3 % means Xray's BBR is ported; a
  failure at 0 % alone is first a defect to fix, once, and means the port if it remains. No failing cell:
  the BBR that ignores loss stays, with the note that the line's deep queue never filled, so shallow buffers were not
  measured. Expected before the run: the 3 % cell fails, because ngtcp2's BBR bounds what is in flight once
  a round loses more than 2 % and Xray's reacts to loss only while starting up.
- P5 the probe's window: hy2probe runs the BBR that ignores loss in every cell. A cwnd above 64 MiB at the end of any of
  its up runs is a finding. Its down runs are printed and not judged: that window belongs to the side that
  only acknowledges.
- Reno: recorded only. Xray's Reno is known by the absence of its Brutal and BBR debug lines.
RULES
echo "hy2-speed: date $(date -u '+%Y-%m-%d %H:%M:%S UTC'), kernel $(uname -r), $(nproc) cores, load $(cut -d' ' -f1-3 /proc/loadavg), $(tc -V 2>&1 | head -1)"
echo "hy2-speed: tree $(git rev-parse HEAD 2>/dev/null || echo unknown), changed: $(git status --short 2>/dev/null | tr '\n' ' ')"
for f in "$BIN" "$PROBE" "$XRAY"; do echo "hy2-speed: sha256 $(sha256sum "$f" | awk '{ print $1 }') $(basename "$f")"; done
"$XRAY" version 2>/dev/null | sed 's/^/hy2-speed: xray: /'
[ -n "$BINDING" ] || echo "hy2-speed: $RUNS runs of $DUR s per cell$( [ -n "$NV" ] && echo ", non-vacuity mode") — NOT binding"
[ -z "$NV" ] || echo "hy2-speed: non-vacuity run — our client's quicParams in cc-brutal-low are {\"congestion\":\"bbr\"}; P2 must fail at 0 %"

ip netns add "$NSC"; ip netns add "$NSS"
ip -n "$NSC" link set lo up; ip -n "$NSS" link set lo up
ip link add htc0 netns "$NSC" type veth peer name hts0 netns "$NSS"
ip -n "$NSC" addr add "$C_IP/24" dev htc0
ip -n "$NSS" addr add "$S_IP/24" dev hts0
ip -n "$NSC" link set htc0 up; ip -n "$NSS" link set hts0 up
for a in "$TARGET" 1.1.1.1 8.8.8.8; do ip -n "$NSS" addr add "$a/32" dev lo; done
echo "hy2-speed: client netns wmem_max $(ip netns exec "$NSC" cat /proc/sys/net/core/wmem_max) rmem_max $(ip netns exec "$NSC" cat /proc/sys/net/core/rmem_max); server netns wmem_max $(ip netns exec "$NSS" cat /proc/sys/net/core/wmem_max) rmem_max $(ip netns exec "$NSS" cat /proc/sys/net/core/rmem_max)"

LIM=1000
line() {
    ip netns exec "$NSC" tc qdisc replace dev htc0 root netem delay 25ms rate 40mbit limit $LIM $1
    ip netns exec "$NSS" tc qdisc replace dev hts0 root netem delay 25ms rate 40mbit limit $LIM $2
}
lines() {
    echo "    htc0: $(ip netns exec "$NSC" tc qdisc show dev htc0 | grep netem | sed 's/ seed [0-9]*//')"
    echo "    hts0: $(ip netns exec "$NSS" tc qdisc show dev hts0 | grep netem | sed 's/ seed [0-9]*//')"
}
line "" "" 2> "$W/tc.err" || { echo "hy2-speed: SKIPPED — tc netem refused: $(head -1 "$W/tc.err"). Not a failure."; exit 0; }
for d in "$NSC htc0" "$NSS hts0"; do
    set -- $d
    { ip netns exec "$1" tc qdisc add dev "$2" clsact &&
      ip netns exec "$1" tc filter add dev "$2" egress basic match 'meta(pkt_len gt 1514)' action pass &&
      ip netns exec "$1" tc filter add dev "$2" ingress basic match 'meta(pkt_len gt 1500)' action pass; } 2> "$W/tc.err" ||
        { echo "hy2-speed: SKIPPED — no tc length counter (cls_basic, em_meta): $(head -1 "$W/tc.err"). Not a failure."; exit 0; }
done
ip netns exec "$NSC" nft -f - 2> "$W/nft.err" <<NFT || { echo "hy2-speed: SKIPPED — nft refused: $(head -1 "$W/nft.err"). Not a failure."; exit 0; }
table inet h2s { set conns { type inet_service; flags dynamic; }; counter tx { }; chain o { type filter hook output priority 0; ip daddr $S_IP udp dport $P add @conns { udp sport }; ip daddr $S_IP udp dport 20000-20009 add @conns { udp sport }; ip daddr $S_IP meta l4proto udp counter name tx; }; }
NFT
txb() { ip netns exec "$NSC" nft list counter inet h2s tx | awk '/bytes/ { for (i = 1; i <= NF; i++) if ($i == "bytes") print $(i + 1) }'; }
conns_reset() { ip netns exec "$NSC" nft flush set inet h2s conns; }
conns() { ip netns exec "$NSC" nft list set inet h2s conns | tr -d '\n' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' | tr ',' '\n' | grep -c '[0-9]' || true; }
agg() {
    for d in "$NSC htc0" "$NSS hts0"; do
        set -- $d
        for k in egress ingress; do
            v=$(ip netns exec "$1" tc -s filter show dev "$2" "$k" | awk '/Sent/ { print $4; exit }')
            printf '%s ' "${v:-0}"
        done
    done
}
adiff() {
    awk -v a="$1" -v b="$2" 'BEGIN { split(a, x, " "); split(b, y, " "); split("htc0-egress htc0-ingress hts0-egress hts0-ingress", n, " ")
        for (i = 1; i <= 4; i++) { d = y[i] - x[i]; t += d; if (d) s = s " " n[i] " " d }
        print t s }'
}
qs() {
    ip netns exec "$1" tc -s qdisc show dev "$2" | awk '
        /^qdisc netem/ { q = 1; next }
        /^qdisc/ { q = 0 }
        q && /Sent/ { for (i = 1; i <= NF; i++) { if ($i == "bytes") b = $(i - 1); if ($i == "pkt") p = $(i - 1); if ($i == "(dropped") { d = $(i + 1); sub(",", "", d) } } }
        q && /delayed/ { for (i = 1; i <= NF; i++) if ($i == "dropped") l = $(i + 1) }
        END { print p + 0, b + 0, d + 0, (l == "" ? -1 : l) }'
}

set -- $(qs "$NSC" htc0)
[ "$4" -ge 0 ] || { echo "hy2-speed: SKIPPED — netem gives no loss counter, so queue drops cannot be told from loss. Not a failure."; exit 0; }
printf '%s\n' 'import socket, time' 'u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)' \
    'u.sendto(b"x", ("'"$S_IP"'", 9)); time.sleep(0.3)' 'u.setsockopt(17, 103, 1200)' 'u.sendto(bytes(4800), ("'"$S_IP"'", 9))' > "$W/gso.py"
a0=$(agg)
ip netns exec "$NSC" timeout -k 2 10 python3 "$W/gso.py" 2> "$W/gso.err" || { echo "hy2-speed: the control's GSO send failed: $(tail -1 "$W/gso.err")"; exit 1; }
sleep 0.5
a1=$(agg)
g=$(adiff "$a0" "$a1")
echo "hy2-speed: control — one UDP GSO burst of 4 x 1200 B sent on purpose: the aggregate counter saw $g segments"
[ "${g%% *}" -gt 0 ] || { echo "hy2-speed: the aggregate counter cannot see a GSO burst; the GSO control would be vacuous"; exit 1; }
echo "hy2-speed: queue — limit 1000 packets, about $(awk 'BEGIN { printf "%d", 1000 * 1450 / 5000000 * 1000 }') ms of 1450 B packets at 5,000,000 B/s"

printf '%s\n' '[ca]' 'basicConstraints=critical,CA:TRUE' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' \
    '[leaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
    'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' "subjectAltName=DNS:$SNI" > "$W/x509.cnf"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout "$W/ca.key" \
    -out "$W/ca.pem" -subj "/CN=hy2 test ca" -config "$W/x509.cnf" -extensions ca >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/leaf.key" \
    -subj "/CN=$SNI" -out "$W/leaf.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/leaf.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -set_serial 2 -days 2 \
    -extfile "$W/x509.cnf" -extensions leaf -out "$W/leaf.pem" >/dev/null 2>&1
openssl verify -CAfile "$W/ca.pem" "$W/leaf.pem" >/dev/null || { echo "hy2-speed: the test certificate does not verify"; exit 1; }
PIN=$(openssl x509 -in "$W/leaf.pem" -outform der | openssl dgst -sha256 -r | awk '{ print $1 }')

cat > "$W/targets.py" <<'PY'
import socket, sys, threading, time
DUR = float(sys.argv[2])
def window(c, tag):
    n = 0; tot = 0; t0 = None; said = False
    try:
        while True:
            d = c.recv(1 << 20)
            if not d:
                break
            tot += len(d)
            t = time.monotonic()
            if t0 is None:
                t0 = t
            if said:
                continue
            if t - t0 < DUR:
                n += len(d)
            else:
                print("%s %d" % (tag, n), flush=True)
                said = True
    except OSError:
        pass
    if not said:
        print("%s %d short" % (tag, n), flush=True)
    print("%s-total %d" % (tag, tot), flush=True)
    c.close()
def ack(c):
    try:
        h = b""
        while len(h) < 4:
            d = c.recv(4 - len(h))
            if not d:
                raise OSError("EOF")
            h += d
        k = int.from_bytes(h, "big")
        while k > 0:
            d = c.recv(min(k, 1 << 20))
            if not d:
                raise OSError("EOF")
            k -= len(d)
        c.sendall(b"k")
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
def source(c):
    b = bytes(1 << 16)
    try:
        while True:
            c.sendall(b)
    except OSError:
        pass
    c.close()
def tcp(port, fn):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[1], port))
    s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=fn, args=(c,), daemon=True).start()
for a in ((7001, lambda c: window(c, "up")), (7002, source), (7003, sink), (7004, lambda c: window(c, "cubic")), (7010, ack)):
    threading.Thread(target=tcp, args=a, daemon=True).start()
while True:
    time.sleep(3600)
PY

cat > "$W/load.py" <<'PY'
import socket, struct, sys, time
def recvn(s, k):
    b = b""
    while len(b) < k:
        d = s.recv(k - len(b))
        if not d:
            raise OSError("EOF after %d of %d" % (len(b), k))
        b += d
    return b
mode, ip, port, host, tport, dur = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), float(sys.argv[6])
s = socket.create_connection((ip, port), 10)
s.settimeout(dur + 15)
s.sendall(b"\x05\x01\x00")
if recvn(s, 2) != b"\x05\x00":
    raise OSError("method refused")
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", tport))
if recvn(s, 10)[1] != 0:
    raise OSError("SOCKS refused")
if mode == "up":
    b = bytes(1 << 16)
    end = time.monotonic() + dur + 4
    while time.monotonic() < end:
        s.sendall(b)
    s.close()
    print("sent")
else:
    n = 0; t0 = None
    while True:
        d = s.recv(1 << 20)
        if not d:
            print("down %d short" % n)
            sys.exit(1)
        t = time.monotonic()
        if t0 is None:
            t0 = t
        if t - t0 >= dur:
            break
        n += len(d)
    s.close()
    print("down %d" % n)
PY

cat > "$W/cubic.py" <<'PY'
import socket, sys, time
host, port, dur = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.create_connection((host, port), 10)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b"cubic")
cc = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16).split(b"\0")[0].decode()
b = bytes(1 << 16)
end = time.monotonic() + dur + 4
while time.monotonic() < end:
    s.sendall(b)
s.close()
print("sent with", cc)
PY

cat > "$W/fresh.py" <<'PY'
import socket, struct, sys, time
def recvn(s, k):
    b = b""
    while len(b) < k:
        d = s.recv(k - len(b))
        if not d:
            raise OSError("EOF after %d of %d" % (len(b), k))
        b += d
    return b
ip, port, host, tport, n = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
t0 = time.monotonic()
s = socket.create_connection((ip, port), 10)
s.settimeout(30)
s.sendall(b"\x05\x01\x00")
if recvn(s, 2) != b"\x05\x00":
    raise OSError("method refused")
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", tport))
if recvn(s, 10)[1] != 0:
    raise OSError("SOCKS refused")
t1 = time.monotonic()
s.sendall(struct.pack(">I", n) + bytes(n))
if recvn(s, 1) != b"k":
    raise OSError("no acknowledgement")
t2 = time.monotonic()
s.close()
print("done %.4f %.4f" % (t2 - t0, t1 - t0))
PY

bg_in "$NSS" "$W/targets.log" python3 "$W/targets.py" "$TARGET" "$DUR"
bg_in "$NSS" "$W/check1.log" python3 tests/grpc-target.py 1.1.1.1 80
bg_in "$NSS" "$W/check2.log" python3 tests/grpc-target.py 8.8.8.8 80
wait_ss "$NSS" -ltn "$TARGET:7003" && wait_ss "$NSS" -ltn "1.1.1.1:80" && wait_ss "$NSS" -ltn "8.8.8.8:80" ||
    { echo "hy2-speed: the targets did not start:"; cat "$W/targets.log" "$W/check1.log"; exit 1; }

TLS_S="\"security\":\"tls\",\"tlsSettings\":{\"certificates\":[{\"certificateFile\":\"$W/leaf.pem\",\"keyFile\":\"$W/leaf.key\"}]}"
TLS_C="\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$SNI\",\"pinnedPeerCertSha256\":\"$PIN\"}"
HS="\"hysteriaSettings\":{\"version\":2,\"auth\":\"$PW\"}"
xqp() { printf '{"disableGSO":true,"debug":true%s}' "${1:+,$1}"; }
srv_up() {
    XSLOG="$W/xs-$CASE.log"
    cat > "$W/xs-$CASE.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"$S_IP","port":$P,"protocol":"hysteria","settings":{"version":2,"clients":[{"auth":"$PW"}]},
   "streamSettings":{"network":"hysteria",$TLS_S,$HS,"finalmask":{"quicParams":$(xqp "$1")}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["$TARGET/32","1.1.1.1/32","8.8.8.8/32"]}]}}]}
JSON
    "$XRAY" run -test -c "$W/xs-$CASE.json" > "$W/xs-test.log" 2>&1 || { echo "    Xray refuses the server config:"; tail -3 "$W/xs-test.log"; return 1; }
    echo "    server quicParams $(xqp "$1")"
    bg_in "$NSS" "$XSLOG" "$XRAY" run -c "$W/xs-$CASE.json"
    XPID=$!
    wait_ss "$NSS" -lun "$S_IP:$P " || { echo "    the Xray server did not start:"; tail -3 "$XSLOG"; return 1; }
}
srv_down() { [ -z "$XPID" ] || { kill "$XPID" 2>/dev/null || true; wait "$XPID" 2>/dev/null || true; }; XPID=""; }

evwait() {
    i=0; lim=$(($2 * 5))
    while [ $i -lt "$lim" ]; do
        grep -qF "$1" "$KEV" && return 0
        kill -0 "$TPID" 2>/dev/null || return 1
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
ours_up() {
    q=""; [ -z "$1" ] || q="&qp=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "{$1}")"
    LINK="hysteria2://$PW@$S_IP:${HOPP:-$P}?sni=$SNI$q${HOPP:+&hop=5-5&hopmode=local,remote}#N"
    echo "    our link quicParams $( [ -n "$1" ] && echo "{$1}" || echo none ), TUNVLESS_NO_BATCH=1${HOPP:+, ports $HOPP, hop every 5 s, local and remote}"
    rm -f "$W/kin"; mkfifo "$W/kin"; KEV="$W/kev-$SER"; : > "$KEV"; CLOG="$W/ours-$SER.log"
    ip netns exec "$NSC" env TUNVLESS_NO_BATCH=1 "$BIN" --control --ca "$W/ca.pem" -d vl -a 198.19.0.1/32 \
        --interval 3600 < "$W/kin" > "$KEV" 2> "$CLOG" &
    TPID=$!; CPID=$TPID
    exec 7> "$W/kin"
    printf '%s\n\n' "$LINK" >&7
    evwait '"ready"' 20 || { echo "    no ready event:"; tail -3 "$CLOG"; return 1; }
    grep -qxF 'tunvless[info]: UDP batching off' "$CLOG" || { echo "    the client does not say UDP batching off"; return 1; }
    i=0; q=0
    while [ $i -lt 150 ] && [ $q -lt 15 ]; do
        if [ "$(ip netns exec "$NSC" ss -Hun state established dst "$S_IP" | wc -l)" -eq 0 ]; then q=$((q + 1)); else q=0; fi
        sleep 0.2; i=$((i + 1))
    done
    [ $q -ge 15 ] || { echo "    the client's node checks did not end within 30 s"; return 1; }
    printf 'inbounds\n%s:1081 - - %s\n\n' "$C_IP" "$LINK" >&7
    evwait '"type":"inbound","port":1081,"state":"up"' 10 || { echo "    the inbound did not come up"; return 1; }
    SOCKS=1081
}
xc_up() {
    xh=""; [ -z "$HOPP" ] || xh=',"udp":[{"type":"udphop","settings":{"mode":"intervalLocal,intervalRemote","remotePorts":"'"$HOPP"'","interval":5}}]'
    cat > "$W/xc-$SER.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"$C_IP","port":1082,"protocol":"socks","settings":{"udp":false}}],
 "outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"$S_IP","port":$P},
   "streamSettings":{"network":"hysteria",$TLS_C,$HS,"finalmask":{"quicParams":$(xqp "$1")$xh}}}]}
JSON
    "$XRAY" run -test -c "$W/xc-$SER.json" > "$W/xc-test.log" 2>&1 || { echo "    Xray refuses the client config:"; tail -3 "$W/xc-test.log"; return 1; }
    echo "    Xray client quicParams $(xqp "$1")${HOPP:+, udphop intervalLocal,intervalRemote over $HOPP every 5 s}"
    CLOG="$W/xc-$SER.log"
    bg_in "$NSC" "$CLOG" "$XRAY" run -c "$W/xc-$SER.json"
    CPID=$!
    wait_ss "$NSC" -ltn "$C_IP:1082 " || { echo "    the Xray client did not start:"; tail -3 "$CLOG"; return 1; }
    SOCKS=1082
}
cl_down() {
    exec 7>&- 2>/dev/null || true
    [ -z "$CPID" ] || { kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true; }
    CPID=""; TPID=""
    ip netns exec "$NSC" ip link delete vl 2>/dev/null || true
}
cnt() { grep -cF "$1" "$2" 2>/dev/null || true; }
cc_ours() {
    want="tunvless[info]: hysteria2 N: link ready on port $P, up $1"
    got=$(grep -F 'link ready' "$CLOG" || true)
    echo "    ready line: ${got:-none}"
    [ -z "$HOPP" ] || got=$(printf '%s\n' "$got" | sed "s/ on port 200[0-9][0-9],/ on port $P,/")
    [ "$got" = "$want" ] || { echo "    expected: $want"; return 1; }
}
cc_xray() {
    b=$(cnt '[BrutalSender]' "$CLOG"); r=$(cnt '[BBRSender]' "$CLOG")
    echo "    Xray client debug lines: [BrutalSender] $b, [BBRSender] $r$( [ "$b" -eq 0 ] || echo "; last: $(grep -F '[BrutalSender]' "$CLOG" | tail -1)")"
    case "$1" in
    brutal) [ "$b" -gt 0 ] && [ "$r" -eq 0 ] ;;
    bbr) [ "$r" -gt 0 ] && [ "$b" -eq 0 ] ;;
    reno) [ "$b" -eq 0 ] && [ "$r" -eq 0 ] ;;
    esac || { echo "    expected the Xray client to run $1"; return 1; }
}
cc_srv() {
    b=$(tail -n "+$1" "$XSLOG" | grep -cF '[BrutalSender]' || true)
    echo "    server debug lines for this client: [BrutalSender] $b$( [ "$b" -eq 0 ] || echo "; last: $(tail -n "+$1" "$XSLOG" | grep -F '[BrutalSender]' | tail -1)")"
    case "$2" in
    brutal) [ "$b" -gt 0 ] ;;
    none) [ "$b" -eq 0 ] ;;
    esac || { echo "    expected the server to send to this client with $2"; return 1; }
}

: > "$W/res"; : > "$W/void"; : > "$W/probe"; : > "$W/conns"; : > "$W/fresh"; NOV=""
void() { echo "$CASE $LOSS a$A $K $*" >> "$W/void-now"; echo "    VOID $CASE $LOSS % attempt $A $K: $*"; }
settle() {
    j=0; set -- $(qs $dd); p0=$1
    while [ $j -lt 20 ]; do
        sleep 0.5; j=$((j + 1))
        set -- $(qs $dd); [ $(($1 - p0)) -ge 20 ] || break; p0=$1
    done
    awk -v j="$j" 'BEGIN { printf "%.1f", j / 2 }'
}
run_one() {
    ri=$1
    if [ "$DIR" = up ]; then dd="$NSC htc0"; rd="$NSS hts0"; tp=7001; else dd="$NSS hts0"; rd="$NSC htc0"; tp=7002; fi
    s0=$(qs $dd); r0=$(qs $rd); a0=$(agg); n0=$(cnt 'up ' "$W/targets.log"); q0=$(now)
    if [ -n "$COMPETE" ]; then
        b0=$(txb); m0=$(cnt 'cubic ' "$W/targets.log"); u0=$(cnt 'up-total ' "$W/targets.log")
        ip netns exec "$NSC" timeout -k 2 $((DUR + 30)) python3 "$W/cubic.py" "$TARGET" 7004 "$DUR" > "$W/cubic.out" 2>&1 & CUP=$!
    fi
    c0=$(cpu_of "$CPID") || c0=0; x0=$(cpu_of "$XPID") || x0=0; t0=$(now)
    out=$(ip netns exec "$NSC" timeout -k 2 $((DUR + 30)) python3 "$W/load.py" "$DIR" "$C_IP" "$SOCKS" "$TARGET" "$tp" "$DUR" 2>&1) || true
    c1=$(cpu_of "$CPID") || c1=$c0; x1=$(cpu_of "$XPID") || x1=$x0; t1=$(now)
    if [ "$DIR" = up ]; then
        i=0; while [ $i -lt 60 ] && [ "$(cnt 'up ' "$W/targets.log")" -le "$n0" ]; do sleep 0.25; i=$((i + 1)); done
        out=$(grep '^up ' "$W/targets.log" | sed -n "$((n0 + 1))p")
    fi
    [ -z "$COMPETE" ] || wait "$CUP" || true
    sw=$(settle)
    s1=$(qs $dd); r1=$(qs $rd); a1=$(agg); q1=$(now)
    tx=-1; tot=-1; cub=-1
    if [ -n "$COMPETE" ]; then
        b1=$(txb); tx=$((b1 - b0)); i=0
        while [ $i -lt 60 ] && { [ "$(cnt 'up-total ' "$W/targets.log")" -le "$u0" ] || [ "$(cnt 'cubic ' "$W/targets.log")" -le "$m0" ]; }; do sleep 0.25; i=$((i + 1)); done
        tot=$(grep '^up-total ' "$W/targets.log" | sed -n "$((u0 + 1))p" | awk '{ print $2 }'); tot=${tot:--1}
        cub=$(grep '^cubic ' "$W/targets.log" | sed -n "$((m0 + 1))p" | awk 'NF == 2 { print $2 }'); cub=${cub:--1}
        echo "    $K run $ri: the competing TCP flow ($(cat "$W/cubic.out")) $(awk -v b="$cub" -v d="$DUR" 'BEGIN { printf "%.3f", b / d / 1e6 }') MB/s;" \
            "the client's UDP to the server $tx B for $tot B the target received over the connection: $(awk -v a="$tx" -v b="$tot" 'BEGIN { printf "%.3f", (b > 0 ? a / b : -1) }')"
    fi
    bytes=$(printf '%s\n' "$out" | awk '/^(up|down) [0-9]+$/ { print $2 }')
    cpu=$(awk -v a="$c0" -v b="$c1" -v t="$TCK" -v w0="$t0" -v w1="$t1" 'BEGIN { printf "%d", (b - a) / t / (w1 - w0) * 100 }')
    scpu=$(awk -v a="$x0" -v b="$x1" -v t="$TCK" -v w0="$t0" -v w1="$t1" 'BEGIN { printf "%d", (b - a) / t / (w1 - w0) * 100 }')
    secs=$(awk -v a="$q0" -v b="$q1" 'BEGIN { printf "%.2f", b - a }')
    set -- $s0 $s1 $r0 $r1
    sent=$(($5 - $1)); sb=$(($6 - $2)); drop=$(($7 - $3)); lost=$(($8 - $4)); rsent=$((${13} - $9)); rb=$((${14} - ${10})); rdrop=$((${15} - ${11}))
    qd=$((drop - lost))
    lp=$(awk -v l="$lost" -v s="$sent" -v d="$drop" 'BEGIN { printf "%.2f", (s + d) ? l * 100 / (s + d) : 0 }')
    g=$(adiff "$a0" "$a1")
    if [ -n "$bytes" ]; then
        bps=$(awk -v b="$bytes" -v d="$DUR" 'BEGIN { printf "%d", b / d }')
        echo "    $K run $ri: $(awk -v b="$bps" 'BEGIN { printf "%.3f", b / 1e6 }') MB/s ($bps B/s), client cpu $cpu %, server cpu $scpu %, load $(cut -d' ' -f1 /proc/loadavg);" \
            "data netem: sent $sent pkt $sb B, lost $lost ($lp %, asked $LOSS %), queue drops $qd;" \
            "return: sent $rsent pkt $rb B, drops $rdrop; counters ${secs} s apart, drained ${sw} s; aggregates $g"
        echo "$CASE $LOSS $K $ri $bps $cpu $scpu $lp $qd $sent $sb $rsent $rb $secs $tx $tot $cub" >> "$W/att"
    else
        echo "    $K run $ri: no count ($out)"
        void "run $ri gave no count"
    fi
    [ "$cpu" -le 90 ] || void "run $ri: the client used $cpu % of a core (over 90 %)"
    [ "$scpu" -le 90 ] || void "run $ri: the server used $scpu % of a core (over 90 %)"
    [ "$g" = 0 ] || void "run $ri: segments went as GSO/GRO aggregates: $g"
}
series() {
    K=$1; shift
    SER="$CASE-$LOSS-$K-a$A"
    "$@" || { void "the client did not start"; cl_down; return 0; }
    xl=$(($(wc -l < "$XSLOG") + 1))
    conns_reset
    k=1
    while [ $k -le "$NRUNS" ]; do
        run_one $k
        if [ $k -eq 1 ]; then
            case "$K" in
            xray) cc_xray "$XCC" || void "the Xray client runs another controller" ;;
            *) cc_ours "$( [ "$K" = ours ] && echo "$OURS_UP" || echo "$NODOWN_UP")" || void "our client runs another controller" ;;
            esac
            [ -z "$SRV_CC" ] || { [ "$K" = ours-nodown ] && w=none || w=$SRV_CC; cc_srv "$xl" "$w" || void "the server sends with another controller"; }
        fi
        k=$((k + 1))
    done
    nc=$(conns)
    case "$K" in
    xray) echo "    connections: $nc client source ports to the server over the $NRUNS runs; [BBRSender] Profile lines $(cnt 'Profile:' "$CLOG")" ;;
    *) echo "    connections: $nc client source ports to the server over the $NRUNS runs; link ready lines $(cnt 'link ready' "$CLOG")" ;;
    esac
    echo "$CASE $LOSS $K $nc" >> "$W/conns-now"
    kill -0 "$CPID" 2>/dev/null || void "the client died: $(tail -1 "$CLOG")"
    cl_down
    kill -0 "$XPID" 2>/dev/null || { echo "hy2-speed: the Xray server died:"; tail -5 "$XSLOG"; exit 1; }
}
attempt() {
    : > "$W/att"; : > "$W/void-now"; : > "$W/conns-now"
    series ours ours_up "$OQ"
    [ ! -s "$W/void-now" ] || return 1
    if [ -n "$OURS_NODOWN" ]; then series ours-nodown ours_up ""; [ ! -s "$W/void-now" ] || return 1; fi
    series xray xc_up "$CQ"
    [ ! -s "$W/void-now" ]
}
probe() {
    o=$(timeout -k 2 $((DUR + 30)) ip netns exec "$NSC" "$PROBE" --no-batch --deadline $((DUR + 20)) --server "$S_IP:$P" \
        --sni "$SNI" --auth "$PW" --ca "$W/ca.pem" "$1" "$TARGET:$2" "$DUR" 2>&1) || true
    st=$(printf '%s\n' "$o" | grep '^stats ' | tail -1)
    cw=$(printf '%s\n' "$st" | awk '{ for (i = 2; i < NF; i++) if ($i == "cwnd") print $(i + 1) }')
    echo "    hy2probe $1 (the BBR that ignores loss): $(printf '%s\n' "$o" | head -1)"
    echo "    hy2probe $1 ${st:-no stats line}"
    echo "$CASE $LOSS $1 ${cw:--1}" >> "$W/probe"
}

fresh() {
    for SZ in 65536 1048576; do
        k=1
        while [ $k -le "$NRUNS" ]; do
            for K in ours xray; do
                SER="$CASE-$SZ-$K-$k"
                if [ $K = ours ]; then ours_up "$CQ" > "$W/up.out"; else xc_up "$CQ" > "$W/up.out"; fi ||
                    { sed 's/^/    /' "$W/up.out"; echo "    $K $SZ B run $k: the client did not start"; cl_down; continue; }
                q=$(ip netns exec "$NSC" ss -Hun state established dst "$S_IP" | wc -l)
                o=$(ip netns exec "$NSC" timeout -k 2 60 python3 "$W/fresh.py" "$C_IP" "$SOCKS" "$TARGET" 7010 "$SZ" 2>&1 | tail -1) || true
                sleep 0.5
                if [ $K = ours ]; then cc_ours "$OURS_UP" > "$W/cc.out" && v=ok || v=WRONG; else cc_xray "$XCC" > "$W/cc.out" && v=ok || v=WRONG; fi
                set -- $o
                if [ "${1:-}" = done ]; then
                    echo "    $K $SZ B run $k: $2 s from the SOCKS connect to the target's acknowledgement (SOCKS reply at $3 s); QUIC links before it $q; controller $v"
                    [ "$v" = WRONG ] || echo "$SZ $K $k $2" >> "$W/fresh"
                else echo "    $K $SZ B run $k: no time ($o)"; fi
                [ "$v" = ok ] || sed 's/^/    /' "$W/cc.out"
                cl_down
            done
            k=$((k + 1))
        done
    done
}
hop_srv() {
    ip netns exec "$NSS" nft list table ip h2hop > /dev/null 2>&1 ||
        echo "table ip h2hop { chain pre { type nat hook prerouting priority -100; udp dport 20000-20009 redirect to :$P; }; }" | ip netns exec "$NSS" nft -f -
}

for CASE in $CASES; do
    OURS_NODOWN=""; NODOWN_UP=""; SRV_CC=""; DIR=up; HOPP=""; COMPETE=""; FRESH=""; REC=""; LIM=1000; NRUNS=$RUNS
    case "$CASE" in
    # shows the rate is the node's, loss or not: a client on BBR there fills the line, one without compensation falls short at 15 %
    cc-brutal-low)
        LOSSES="0 3 15"; SQ='"brutalDown":"40 mbps"'; CQ='"brutalUp":"16 mbps"'
        OURS_UP="brutal 2097152 B/s, down asked nothing"; XCC=brutal
        [ -z "$NV" ] || { OQ='"congestion":"bbr"'; OURS_UP="bbr, down asked nothing"; } ;;
    # catches our Brutal sending at another rate than Xray's at the same node rate
    cc-brutal-up)
        LOSSES="0 1 3"; SQ='"brutalDown":"40 mbps"'; CQ='"brutalUp":"32 mbps"'
        OURS_UP="brutal 4194304 B/s, down asked nothing"; XCC=brutal ;;
    # shows whether the BBR that ignores loss keeps up with Xray's BBR under loss
    cc-bbr-up)
        LOSSES="0 1 3"; SQ=""; CQ=""; OURS_UP="bbr, down asked nothing"; XCC=bbr ;;
    # catches the asked down rate not reaching the server or our receiving side holding it back
    cc-brutal-down)
        LOSSES="0 3"; DIR=down; SQ='"brutalUp":"40 mbps"'; CQ='"brutalDown":"32 mbps"'
        OURS_UP="bbr, down asked 4194304 B/s"; XCC=bbr; SRV_CC=brutal
        OURS_NODOWN=1; NODOWN_UP="bbr, down asked nothing" ;;
    # catches a rate above the line costing us more goodput than it costs Xray
    cc-over-line)
        LOSSES="0"; SQ='"brutalDown":"80 mbps"'; CQ='"brutalUp":"80 mbps"'
        OURS_UP="brutal 10485760 B/s, down asked nothing"; XCC=brutal ;;
    # records Reno beside Xray's Reno
    cc-reno-up)
        LOSSES="1"; SQ=""; CQ='"congestion":"reno"'; OURS_UP="reno, down asked nothing"; XCC=reno ;;
    # records Brutal on a node hopping its local and remote ports every 5 s beside Xray's own client with the same hops
    cc-hop-brutal)
        LOSSES="0 1"; SQ='"brutalDown":"40 mbps"'; CQ='"brutalUp":"32 mbps"'
        OURS_UP="brutal 4194304 B/s, down asked nothing"; XCC=brutal; HOPP=20000-20009; REC=1 ;;
    # records BBR on the same hopping node
    cc-hop-bbr)
        LOSSES="0 1"; SQ=""; CQ=""; OURS_UP="bbr, down asked nothing"; XCC=bbr; HOPP=20000-20009; REC=1 ;;
    # records how long a 64 KiB and a 1 MiB upload take, each on a link dialled for it
    cc-fresh)
        LOSSES="0"; SQ=""; CQ=""; OURS_UP="bbr, down asked nothing"; XCC=bbr; FRESH=1; REC=1 ;;
    # records BBR on a queue of 50 packets at 1 % loss beside one CUBIC flow on the same line, outside the tunnel
    cc-shallow)
        LOSSES="1"; SQ=""; CQ=""; OURS_UP="bbr, down asked nothing"; XCC=bbr; COMPETE=1; LIM=50; REC=1 ;;
    esac
    [ -z "$REC" ] || NRUNS=$REC_RUNS
    [ -z "$HOPP" ] || hop_srv
    if [ -n "$COMPETE" ]; then
        GSEGS=$(ip -n "$NSC" -d link show htc0 | sed -n 's/.*gso_max_segs \([0-9]*\).*/\1/p')
        ip -n "$NSC" route replace "$TARGET/32" via "$S_IP"
        ip -n "$NSC" link set dev htc0 gso_max_segs 1
    fi
    [ -n "$NV" ] || OQ=$CQ
    echo "hy2-speed: case $CASE ($DIR)$( [ -z "$REC" ] || echo ", recorded only: $NRUNS runs, no rule")"
    srv_up "$SQ" || { echo "hy2-speed: the server of $CASE did not start: no verdict"; exit 3; }
    for LOSS in $LOSSES; do
        l=""; [ "$LOSS" = 0 ] || l="loss $LOSS%"
        if [ "$DIR" = up ]; then line "$l" ""; else line "" "$l"; fi
        if [ -n "$FRESH" ]; then echo "  $CASE, a link dialled for each upload"; lines; fresh; continue; fi
        A=1
        while :; do
            echo "  $CASE, loss $LOSS % on the $DIR direction, attempt $A"
            lines
            if attempt; then
                cat "$W/att" >> "$W/res"; cat "$W/conns-now" >> "$W/conns"
                break
            fi
            cat "$W/void-now" >> "$W/void"
            sed "s/^/a$A /" "$W/att" >> "$W/res-void"
            [ "$A" -lt 3 ] || {
                echo "hy2-speed: FINDING — cell $CASE $LOSS % void three times; the run ends without a verdict"
                NOV="cell $CASE $LOSS % void three times. "
                break
            }
            A=$((A + 1))
        done
        [ -z "$NOV" ] || break
        [ -n "$REC" ] || { probe up 7003; probe down 7002; }
    done
    srv_down
    [ -z "$COMPETE" ] || { ip -n "$NSC" link set dev htc0 gso_max_segs "${GSEGS:-65535}"; ip -n "$NSC" route del "$TARGET/32" 2>/dev/null || true; }
    [ -z "$NOV" ] || break
done

st() {
    awk -v c="$1" -v l="$2" -v k="$3" '$1 == c && $2 == l && $3 == k { print $5 }' "$W/res" | sort -n |
        awk '{ a[NR] = $1 } END { if (NR) printf "%d %d %d %d\n", a[1], (NR % 2 ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2), a[NR], NR }'
}
ran() { awk -v c="$1" '$1 == c { f = 1 } END { exit !f }' "$W/res"; }
mb() { awk -v b="$1" 'BEGIN { printf "%.3f", b / 1e6 }'; }
pct() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", a * 100 / b }'; }

echo "hy2-speed: results (MB/s = 10^6 B/s of goodput; $RUNS runs of $DUR s each; wire = the data device's sent bytes per counter second)"
printf '    %-15s %5s %-12s %4s %8s %8s %8s %6s %6s %7s %7s %9s %5s\n' case loss client runs min median max "cpu" "srv" "loss" "qdrops" "wire MB/s" conns
for CASE in $ALL_CASES $REC_CASES; do
    for k in ours ours-nodown xray; do
        for LOSS in 0 1 3 15; do
            s=$(st "$CASE" "$LOSS" "$k"); [ -n "$s" ] || continue
            set -- $s
            ex=$(awk -v c="$CASE" -v l="$LOSS" -v k="$k" '$1 == c && $2 == l && $3 == k { if ($6 > m) m = $6; if ($7 > sm) sm = $7; lp += $8; n++; q += $9; w += $11 / $14 }
                END { printf "%d %d %.2f %d %.3f", m, sm, lp / n, q, w / n / 1e6 }' "$W/res")
            nc=$(awk -v c="$CASE" -v l="$LOSS" -v k="$k" '$1 == c && $2 == l && $3 == k { print $4 }' "$W/conns")
            set -- $s $ex
            printf '    %-15s %3s %% %-12s %4s %8s %8s %8s %4s %% %4s %% %5s %% %7s %9s %5s\n' "$CASE" "$LOSS" "$k" "$4" "$(mb "$1")" "$(mb "$2")" "$(mb "$3")" "$5" "$6" "$7" "$8" "$9" "${nc:-?}"
        done
    done
done
[ ! -s "$W/void" ] || { echo "hy2-speed: void attempts (not counted):"; sed 's/^/    /' "$W/void"; }

if [ -n "$NOV" ]; then
    echo "hy2-speed: NO VERDICT — $NOV"; exit 3
fi
BAD=0
pair() {
    c=$1; l=$2; lo=$3; hi=$4; f=${5:-}
    if ! ran "$c"; then echo "    $c $l %: not run"; return 0; fi
    o=$(st "$c" "$l" ours); x=$(st "$c" "$l" xray)
    [ -n "$o" ] && [ -n "$x" ] || { echo "    $c $l %: no numbers"; BAD=1; return 0; }
    set -- $o; om=$2; set -- $x; xm=$2
    if awk -v a="$om" -v b="$xm" -v lo="$lo" -v hi="$hi" 'BEGIN { r = a / b; exit !(r >= lo && r <= hi) }'; then vr=holds; else vr=FAILS; BAD=1; fi
    echo "    $c $l %: ours $(mb "$om") / Xray $(mb "$xm") MB/s = $(pct "$om" "$xm") % — $vr"
    if [ "$f" = find ] && [ "$vr" = holds ] && awk -v a="$om" -v b="$xm" 'BEGIN { r = a / b; exit !(r < 0.95 || r > 1.05) }'; then
        echo "    FINDING: $c $l % — our median is $(pct "$om" "$xm") % of Xray's, outside 95-105 %, to investigate"
    fi
}
echo "hy2-speed: P1 (our median at least 90 % and at most 110 % of Xray's)"
for l in 0 1 3; do pair cc-brutal-up $l 0.90 1.10 find; done
for l in 0 3; do pair cc-brutal-down $l 0.90 1.10 find; done
echo "hy2-speed: P2 (each median at least 90 % and at most 110 % of 2,097,152 B/s)"
P2_0=""
for l in 0 3 15; do
    ran cc-brutal-low || { echo "    cc-brutal-low $l %: not run"; continue; }
    for k in ours xray; do
        s=$(st cc-brutal-low $l $k); [ -n "$s" ] || { echo "    cc-brutal-low $l % $k: no numbers"; BAD=1; continue; }
        set -- $s
        if awk -v a="$2" 'BEGIN { r = a / 2097152; exit !(r >= 0.90 && r <= 1.10) }'; then vr=holds; else vr=FAILS; BAD=1; fi
        [ "$l$k" != 0ours ] || P2_0=$vr
        [ "$k$vr" != xrayFAILS ] || NOV="${NOV}Xray's median in cc-brutal-low $l % is outside P2's band: a fault of the stand. "
        echo "    cc-brutal-low $l % $k: $(mb "$2") MB/s = $(pct "$2" 2097152) % — $vr"
    done
done
echo "hy2-speed: P3 (our median at least 85 % and at most 115 % of Xray's)"
pair cc-over-line 0 0.85 1.15
if ran cc-over-line; then
    qd_ours=$(awk '$1 == "cc-over-line" && $3 == "ours" { q += $9 } END { print q + 0 }' "$W/res")
    qd_xray=$(awk '$1 == "cc-over-line" && $3 == "xray" { q += $9 } END { print q + 0 }' "$W/res")
    echo "    queue drops over its runs: ours $qd_ours, Xray $qd_xray"
    if [ "$qd_ours" -eq 0 ] && [ "$qd_xray" -gt 0 ]; then echo "    FINDING: our client shows no queue drops where Xray's shows them, to investigate"; fi
    if [ "$qd_xray" -eq 0 ] && [ "$qd_ours" -gt 0 ]; then echo "    FINDING: Xray's client shows no queue drops where ours shows them, to investigate"; fi
fi
echo "hy2-speed: P4 (a cell fails when our median is under 90 % of Xray's median and our best run is under Xray's median)"
P4=""
for l in 0 1 3; do
    ran cc-bbr-up || { echo "    cc-bbr-up $l %: not run"; continue; }
    o=$(st cc-bbr-up $l ours); x=$(st cc-bbr-up $l xray)
    [ -n "$o" ] && [ -n "$x" ] || { echo "    cc-bbr-up $l %: no numbers"; P4="${P4}v"; continue; }
    set -- $o; omin=$1; om=$2; omax=$3; set -- $x
    if [ $((om * 100)) -lt $(($2 * 90)) ] && [ "$omax" -lt "$2" ]; then vr=FAILS; P4="$P4$l"; else vr=holds; fi
    echo "    cc-bbr-up $l %: ours $(mb "$omin") / $(mb "$om") / $(mb "$omax"), Xray $(mb "$1") / $(mb "$2") / $(mb "$3") MB/s (min / median / max), median $(pct "$om" "$2") % — $vr"
done
case "$P4" in
*v*) echo "    a cell has no numbers: P4 cannot be evaluated"; NOV="${NOV}P4 has a cell without numbers. " ;;
*1*|*3*) echo "    a cell fails at 1 % or 3 %: Xray's BBR is ported" ;;
0) echo "    the 0 % cell alone fails: first a defect to fix, once; the port if it remains" ;;
"") ran cc-bbr-up && echo "    no failing cell: the BBR that ignores loss stays (the line's deep queue never filled, so shallow buffers were not measured)" ;;
esac
echo "hy2-speed: P5 (cwnd above 64 MiB at the end of an up run is a finding; down runs not judged)"
while read -r c l m cw; do
    f=""
    if [ "$m" = up ]; then
        [ "$cw" -le 67108864 ] || f=" — FINDING: cwnd above 64 MiB"
        [ "$cw" -ge 0 ] || f=" — no stats line"
    else f=" (not judged)"; fi
    echo "    $c $l % $m: cwnd $cw$f"
done < "$W/probe"
echo "hy2-speed: recorded only"
for r in "cc-reno-up 1 ours" "cc-reno-up 1 xray" "cc-brutal-up 3 ours" "cc-bbr-up 3 ours" "cc-brutal-down 0 ours-nodown" "cc-brutal-down 3 ours-nodown"; do
    set -- $r; s=$(st "$1" "$2" "$3"); [ -n "$s" ] || continue
    set -- $r $s
    echo "    $1 $2 % $3: min / median / max $(mb "$4") / $(mb "$5") / $(mb "$6") MB/s$( [ "$1$3" = cc-reno-upxray ] && echo " (Xray's Reno known by the absence of its Brutal and BBR debug lines)")"
done

med() { sort -n | awk '{ a[NR] = $1 } END { if (NR) printf "%s", (NR % 2 ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2) }'; }
for c in cc-hop-brutal cc-hop-bbr cc-shallow; do
    for l in 0 1; do
        o=$(st "$c" "$l" ours); x=$(st "$c" "$l" xray); [ -n "$o" ] && [ -n "$x" ] || continue
        set -- $o; om=$2; set -- $x; xm=$2
        echo "    $c $l %: ours $(mb "$om") / Xray $(mb "$xm") MB/s (medians of $REC_RUNS runs) = $(pct "$om" "$xm") %"
        [ "$c" = cc-shallow ] || continue
        for k in ours xray; do
            cm=$(awk -v k="$k" '$1 == "cc-shallow" && $3 == k && $17 >= 0 { print $17 }' "$W/res" | med)
            rr=$(awk -v k="$k" '$1 == "cc-shallow" && $3 == k && $16 > 0 { printf "%.4f\n", $15 / $16 }' "$W/res" | med)
            echo "      $k: the CUBIC flow beside it $(awk -v b="${cm:-0}" -v d="$DUR" 'BEGIN { printf "%.3f", b / d / 1e6 }') MB/s (median);" \
                "UDP bytes sent over bytes delivered $rr (median; runs: $(awk -v k="$k" '$1 == "cc-shallow" && $3 == k && $16 > 0 { printf "%.3f ", $15 / $16 }' "$W/res"))"
        done
    done
done
for z in 65536 1048576; do
    [ -s "$W/fresh" ] || break
    o=$(awk -v z="$z" '$1 == z && $2 == "ours" { print $4 }' "$W/fresh" | med); x=$(awk -v z="$z" '$1 == z && $2 == "xray" { print $4 }' "$W/fresh" | med)
    echo "    cc-fresh $z B: ours $(awk -v z="$z" '$1 == z && $2 == "ours" { printf "%s ", $4 }' "$W/fresh")(median ${o:-none} s);" \
        "Xray $(awk -v z="$z" '$1 == z && $2 == "xray" { printf "%s ", $4 }' "$W/fresh")(median ${x:-none} s)$( [ -n "$o" ] && [ -n "$x" ] && echo "; ours / Xray $(pct "$o" "$x") %")"
done

if [ -n "$NOV" ]; then echo "hy2-speed: NO VERDICT — $NOV"; exit 3; fi
if [ -n "$NV" ]; then
    if [ "$P2_0" = FAILS ]; then echo "hy2-speed: non-vacuity — P2 fails at 0 % with our client on BBR, as required"; exit 0; fi
    echo "hy2-speed: non-vacuity — P2 did NOT fail at 0 % with our client on BBR: the stand cannot tell the controllers apart"; exit 1
fi
[ "$BAD" -eq 0 ] || { echo "hy2-speed: FAILED (P1, P2 or P3)"; exit 1; }
echo "hy2-speed: P1, P2 and P3 hold"
