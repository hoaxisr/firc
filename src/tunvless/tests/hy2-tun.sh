#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

usage() {
    cat <<EOF
usage: sh tests/hy2-tun.sh [-h] [case...]

Runs the real tunvless with Hysteria2 nodes against Xray-core's own Hysteria2 inbound in network
namespaces: the TUN device, redirected sockets, inbounds, failover and the pool.

  XRAY=<binary>     Xray-core 26.10.21 or later (default: xray in PATH)
  TUNVLESS=<path>   the binary (default ./out/tunvless)
  CASES="..."       the cases to run, or as arguments (default: all)
  KEEP=<dir>        copy the work directory (configs, logs) there at the end
  HOP_DUR=<s>       seconds of load in the hop cases (default 45; shorter is not binding)
  HOP_COST_DUR=<s>  seconds per run of hy2-tun-hop-cost (default 30)
  HOP_COST_RUNS=<n> runs per link of hy2-tun-hop-cost (default 5)

Needs root, ip netns, python3, openssl; without one of them, or without Xray, it prints SKIPPED
and exits 0. A case skipped inside a run (nft missing) is named and the run exits 2; a failed
case exits 1.

cases: $ALL_CASES
EOF
}

ALL_CASES="hy2-tun-probe hy2-tun-tcp hy2-tun-ktcp hy2-tun-udp hy2-tun-socks hy2-tun-upload-stop hy2-tun-idle
           hy2-tun-node-death hy2-tun-mixed hy2-tun-obfs-wrong hy2-tun-rss hy2-tun-many hy2-tun-streams
           hy2-tun-slow hy2-tun-threads hy2-tun-silent hy2-tun-halfclose hy2-tun-concurrent hy2-tun-first16k hy2-tun-slowdial
           hy2-tun-hop hy2-tun-hop-delay hy2-tun-hop-remote hy2-tun-hop-local hy2-tun-hop-dead hy2-tun-hop-newport hy2-tun-hop-nofd
           hy2-tun-hop-cost"
case "${1:-}" in -h|--help) usage; exit 0 ;; esac
CASES="${*:-${CASES:-$ALL_CASES}}"

BIN="${TUNVLESS:-./out/tunvless}"
XRAY="${XRAY:-$(command -v xray 2>/dev/null || true)}"
HDUR="${HOP_DUR:-45}"; CDUR="${HOP_COST_DUR:-30}"; CRUNS="${HOP_COST_RUNS:-5}"

[ "$(id -u)" = 0 ] || { echo "hy2-tun: SKIPPED — needs root (ip netns). Not a failure."; exit 0; }
for t in ip ss timeout; do
    command -v "$t" >/dev/null 2>&1 || { echo "hy2-tun: SKIPPED — no $t. Not a failure."; exit 0; }
done
command -v python3 >/dev/null 2>&1 || { echo "hy2-tun: SKIPPED — needs python3. Not a failure."; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "hy2-tun: SKIPPED — needs openssl. Not a failure."; exit 0; }
[ -n "$XRAY" ] && [ -x "$XRAY" ] || { echo "hy2-tun: SKIPPED — no Xray-core (XRAY=/path/to/xray). Not a failure."; exit 0; }
XV=$("$XRAY" version 2>/dev/null | awk 'NR == 1 { print $2 }')
printf '%s\n' "$XV" | awk -F. '{ v = $1 * 10000 + $2 * 100 + $3; exit !(NF >= 3 && v >= 261021) }' ||
    { echo "hy2-tun: SKIPPED — Xray $XV is older than 26.10.21. Not a failure."; exit 0; }
[ -x "$BIN" ] || { echo "hy2-tun: no binary $BIN (make)"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
XRAY="$(cd "$(dirname "$XRAY")" && pwd)/$(basename "$XRAY")"
ip netns add "hy2t-probe-$$" 2>/dev/null || { echo "hy2-tun: SKIPPED — ip netns unavailable. Not a failure."; exit 0; }
ip netns delete "hy2t-probe-$$"
NFT=""; command -v nft >/dev/null 2>&1 && NFT=1
PRL=""; command -v prlimit >/dev/null 2>&1 && PRL=1
TC=""; command -v tc >/dev/null 2>&1 && TC=1

NSC="h2tc$$"; NSS="h2ts$$"
S_IP=10.95.0.1; C_IP=10.95.0.2; TARGET=203.0.113.9
rnd() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
SNI=hy2.test; PW="pw-$(rnd 8)"; OBFS="ob-$(rnd 8)"
P_BASE=18443; P_OBFS=18444; P_D1=18446; P_D2=18447; P_STR=18448; P_SIL=18449; P_V=18450
UUID=$(cat /proc/sys/kernel/random/uuid); SID=$(rnd 8); MASK=mask.hy2.test
W="$(mktemp -d)"
TPID=""
cleanup() {
    exec 7>&- 2>/dev/null || true
    [ -z "${SMP:-}" ] || kill "$SMP" 2>/dev/null || true
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
since() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.1f", b - a }'; }
wait_ss() {
    i=0
    while [ $i -lt 80 ]; do
        ip netns exec "$1" ss "$2" 2>/dev/null | grep -qF "$3" && return 0
        sleep 0.25; i=$((i + 1))
    done
    return 1
}

echo "hy2-tun: server — $("$XRAY" version 2>/dev/null | head -1)"

ip netns add "$NSC"; ip netns add "$NSS"
ip -n "$NSC" link set lo up; ip -n "$NSS" link set lo up
ip link add htc0 netns "$NSC" type veth peer name hts0 netns "$NSS"
ip -n "$NSC" addr add "$C_IP/24" dev htc0
ip -n "$NSS" addr add "$S_IP/24" dev hts0
ip -n "$NSC" link set htc0 up; ip -n "$NSS" link set hts0 up
for a in "$TARGET" 1.1.1.1 8.8.8.8; do ip -n "$NSS" addr add "$a/32" dev lo; done
i=10; while [ $i -le 29 ]; do ip -n "$NSS" addr add "203.0.113.$i/32" dev lo; i=$((i + 1)); done

printf '%s\n' '[ca]' 'basicConstraints=critical,CA:TRUE' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' \
    '[leaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
    'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' "subjectAltName=DNS:$SNI" > "$W/x509.cnf"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout "$W/ca.key" \
    -out "$W/ca.pem" -subj "/CN=hy2 test ca" -config "$W/x509.cnf" -extensions ca >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/leaf.key" \
    -subj "/CN=$SNI" -out "$W/leaf.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/leaf.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -set_serial 2 -days 2 \
    -extfile "$W/x509.cnf" -extensions leaf -out "$W/leaf.pem" >/dev/null 2>&1
openssl verify -CAfile "$W/ca.pem" "$W/leaf.pem" >/dev/null || { echo "hy2-tun: the test certificate does not verify"; exit 1; }
PIN=$(openssl x509 -in "$W/leaf.pem" -outform der | openssl dgst -sha256 -r | awk '{ print $1 }')
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$W/mask.key" -out "$W/mask.pem" -subj "/CN=$MASK" -addext "subjectAltName=DNS:$MASK" >/dev/null 2>&1
"$XRAY" x25519 > "$W/keys.txt" 2>&1
PRIV=$(awk '/^PrivateKey:/ {print $2}' "$W/keys.txt")
PUB=$(awk '/PublicKey/ {print $NF}' "$W/keys.txt")
[ -n "$PRIV" ] && [ -n "$PUB" ] || { echo "hy2-tun: xray x25519 gave no keys"; exit 1; }

cat > "$W/targets.py" <<'PY'
import socket, sys, threading, time
def pat(n):
    return bytes((i * 31 + 7) % 251 for i in range(n))
BIG = pat(1048576)
MID = pat(1572864)
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
def upstop(c):
    try:
        got = 0
        while got < 65536:
            d = c.recv(65536 - got)
            if not d:
                break
            got += len(d)
        c.sendall(BIG)
        c.shutdown(socket.SHUT_WR)
        time.sleep(2)
    except OSError:
        pass
    c.close()
def half(c):
    try:
        got = 0
        while got < 1024:
            d = c.recv(1024 - got)
            if not d:
                break
            got += len(d)
        body = pat(102400)
        step = (len(body) + 14) // 15
        for i in range(15):
            c.sendall(body[i * step:(i + 1) * step])
            time.sleep(0.2)
    except OSError:
        pass
    c.close()
def mid(c):
    try:
        c.sendall(MID)
    except OSError:
        pass
    c.close()
def source(c):
    b = bytes(65536)
    try:
        while True:
            c.sendall(b)
    except OSError:
        pass
    c.close()
def tcp(ip, port, fn):
    s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(128)
    while True:
        c, _ = s.accept()
        threading.Thread(target=fn, args=(c,), daemon=True).start()
def udp(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(d, a)
for a in (("0.0.0.0", 7000, echo), ("::1", 7000, echo), ("0.0.0.0", 7005, upstop), ("0.0.0.0", 7006, mid), ("0.0.0.0", 7008, half), ("0.0.0.0", 7009, source)):
    threading.Thread(target=tcp, args=a, daemon=True).start()
threading.Thread(target=udp, args=(sys.argv[1], 7000), daemon=True).start()
while True:
    time.sleep(3600)
PY

cat > "$W/cli.py" <<'PY'
import os, socket, struct, sys, threading, time
def pat(n):
    return bytes((i * 31 + 7) % 251 for i in range(n))
def recvn(s, k):
    b = b""
    while len(b) < k:
        d = s.recv(k - len(b))
        if not d:
            raise OSError("EOF after %d of %d" % (len(b), k))
        b += d
    return b
def pump(s, n):
    data = os.urandom(n)
    err = []
    def tx():
        try:
            s.sendall(data)
        except OSError as e:
            err.append(e)
    t = threading.Thread(target=tx)
    t.start()
    got = recvn(s, n)
    t.join()
    if err:
        raise err[0]
    if got != data:
        raise OSError("data differs")
def socks(ip, port, host, tport, cmd=1):
    s = socket.create_connection((ip, port), 10)
    s.settimeout(30)
    s.sendall(b"\x05\x01\x00")
    if recvn(s, 2) != b"\x05\x00":
        raise OSError("method refused")
    try:
        a = b"\x01" + socket.inet_aton(host)
    except OSError:
        a = b"\x03" + bytes([len(host)]) + host.encode()
    s.sendall(b"\x05" + bytes([cmd]) + b"\x00" + a + struct.pack(">H", tport))
    r = recvn(s, 10)
    if r[1] != 0:
        raise OSError("SOCKS reply %d" % r[1])
    return s, socket.inet_ntoa(r[4:8]), struct.unpack(">H", r[8:10])[0]
m = sys.argv[1]
a = sys.argv[2:]
if m == "echo":
    host, port, n, k = a[0], int(a[1]), int(a[2]), int(a[3])
    ok = [0]; bad = []; lat = []
    lk = threading.Lock()
    def one(i):
        t0 = time.monotonic()
        try:
            s = socket.create_connection((host, port), 20)
            s.settimeout(30)
            pump(s, n)
            s.close()
            with lk:
                ok[0] += 1
                lat.append(time.monotonic() - t0)
        except Exception as e:
            with lk:
                bad.append("%d: %r" % (i, e))
    ts = [threading.Thread(target=one, args=(i,)) for i in range(k)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    print("echo %d of %d, slowest %.2f s %s" % (ok[0], k, max(lat) if lat else -1, bad[:3]))
    sys.exit(0 if ok[0] == k else 1)
if m == "udp":
    host, port, n, k = a[0], int(a[1]), int(a[2]), int(a[3])
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    got = 0
    for i in range(k):
        d = os.urandom(n)
        u.sendto(d, (host, port))
        try:
            while True:
                r, _ = u.recvfrom(65535)
                if r == d:
                    got += 1
                    break
        except socket.timeout:
            pass
    print("udp %d B: %d of %d" % (n, got, k))
    sys.exit(0 if got == k else 1)
if m == "udpempty":
    host, port = a[0], int(a[1])
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(3)
    u.sendto(b"", (host, port))
    d = os.urandom(100)
    u.sendto(d, (host, port))
    try:
        while True:
            r, _ = u.recvfrom(65535)
            if r == d:
                print("after an empty datagram: echoed")
                sys.exit(0)
    except socket.timeout:
        print("after an empty datagram: no echo")
        sys.exit(1)
if m == "socks":
    ip, port, host, tport, n = a[0], int(a[1]), a[2], int(a[3]), int(a[4])
    s, _, _ = socks(ip, port, host, tport)
    pump(s, n)
    print("socks CONNECT %s: %d intact" % (host, n))
if m == "http":
    ip, port, host, tport, n = a[0], int(a[1]), a[2], int(a[3]), int(a[4])
    s = socket.create_connection((ip, port), 10)
    s.settimeout(30)
    s.sendall(b"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host.encode(), tport, host.encode(), tport))
    h = b""
    while b"\r\n\r\n" not in h:
        d = s.recv(1)
        if not d:
            raise OSError("EOF in the CONNECT reply")
        h += d
    if b" 200" not in h.split(b"\r\n", 1)[0]:
        raise OSError("CONNECT reply %r" % h.split(b"\r\n", 1)[0])
    pump(s, n)
    print("http CONNECT %s: %d intact" % (host, n))
if m == "assoc":
    ip, port, host, tport, n, k = a[0], int(a[1]), a[2], int(a[3]), int(a[4]), int(a[5])
    s, bip, bport = socks(ip, port, "0.0.0.0", 0, 3)
    if bip == "0.0.0.0":
        bip = ip
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    hdr = b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack(">H", tport)
    got = 0
    for i in range(k):
        d = os.urandom(n)
        u.sendto(hdr + d, (bip, bport))
        try:
            while True:
                r, _ = u.recvfrom(65535)
                if r[10:] == d:
                    got += 1
                    break
        except socket.timeout:
            pass
    print("socks UDP %d B: %d of %d" % (n, got, k))
    sys.exit(0 if got == k else 1)
if m == "upstop":
    host, port = a[0], int(a[1])
    s = socket.create_connection((host, port), 20)
    s.settimeout(30)
    e = socket.create_connection((host, 7000), 20)
    e.settimeout(10)
    txerr = []
    def tx():
        try:
            s.sendall(os.urandom(4 << 20))
        except OSError as x:
            txerr.append(repr(x))
    eo = [0, 0]
    stop = threading.Event()
    def side():
        while not stop.is_set():
            try:
                pump(e, 1000)
                eo[0] += 1
            except Exception:
                eo[1] += 1
                return
            time.sleep(0.1)
    t = threading.Thread(target=tx, daemon=True)
    t.start()
    st = threading.Thread(target=side)
    st.start()
    got = b""
    end = "none"
    try:
        while True:
            d = s.recv(65536)
            if not d:
                end = "FIN"
                break
            got += d
    except OSError as x:
        end = "error %r" % x
    time.sleep(2)
    stop.set()
    st.join()
    print("upload-stop: got %d, %s, data %s, sender %s, parallel echoes %d ok %d failed" % (
        len(got), end, "intact" if got == pat(1048576) else "differs", txerr[0] if txerr else "blocked or done",
        eo[0], eo[1]))
    sys.exit(0 if got == pat(1048576) and end == "FIN" and eo[0] > 0 and eo[1] == 0 else 1)
if m == "idle":
    host, port, secs = a[0], int(a[1]), float(a[2])
    s = socket.create_connection((host, port), 20)
    s.settimeout(30)
    pump(s, 1000)
    print("first ok", flush=True)
    time.sleep(secs)
    try:
        pump(s, 1000)
        print("second ok", flush=True)
    except Exception as x:
        print("second failed %r" % x, flush=True)
        sys.exit(1)
    s.close()
if m == "hold":
    host, port, n, secs = a[0], int(a[1]), int(a[2]), float(a[3])
    ss = []
    for i in range(n):
        s = socket.create_connection((host, port), 10)
        s.sendall(b"GET /big/100 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        ss.append(s)
    print("held %d" % n, flush=True)
    time.sleep(secs)
if m == "slow":
    host, port, k, rate = a[0], int(a[1]), int(a[2]), float(a[3])
    want = pat(1572864)
    ok = [0]; bad = []
    lk = threading.Lock()
    def one(i):
        try:
            s = socket.create_connection((host, port), 20)
            s.settimeout(30)
            got = b""
            t0 = time.monotonic()
            while True:
                d = s.recv(16384)
                if not d:
                    break
                got += d
                ahead = len(got) / rate - (time.monotonic() - t0)
                if ahead > 0:
                    time.sleep(ahead)
            with lk:
                if got == want:
                    ok[0] += 1
                else:
                    bad.append("%d: got %d" % (i, len(got)))
        except Exception as e:
            with lk:
                bad.append("%d: %r" % (i, e))
    ts = [threading.Thread(target=one, args=(i,)) for i in range(k)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    print("slow readers: %d of %d intact %s" % (ok[0], k, bad[:3]))
    sys.exit(0 if ok[0] == k else 1)
if m == "halfclose":
    host, port = a[0], int(a[1])
    s = socket.create_connection((host, port), 20)
    s.settimeout(10)
    s.sendall(os.urandom(1024))
    s.shutdown(socket.SHUT_WR)
    t0 = time.time()
    got = b""
    end = "none"
    last = t0
    try:
        while True:
            d = s.recv(65536)
            if not d:
                end = "EOF"
                break
            got += d
            last = time.time()
    except OSError as x:
        end = "error %r" % x
    ok = got == pat(102400) and end == "EOF"
    print("halfclose got %d %s %s, last byte %.2f s and end %.2f s after the shutdown" % (
        len(got), end, "intact" if ok else "differs", last - t0, time.time() - t0))
    sys.exit(0 if ok else 1)
if m == "concurrent":
    host, port, k, secs, cap = a[0], int(a[1]), int(a[2]), int(a[3]), int(a[4])
    t0 = time.monotonic()
    lk = threading.Lock()
    seen = {}
    bad = []
    done = [0]
    def one(i):
        try:
            s = socket.create_connection((host, port), 20)
            s.settimeout(30)
            for j in range(secs):
                d = os.urandom(1024)
                s.sendall(d)
                if recvn(s, 1024) != d:
                    raise OSError("data differs")
                with lk:
                    seen.setdefault(int(time.monotonic() - t0), set()).add(i)
                time.sleep(max(0.0, j + 1 - (time.monotonic() - t0)))
            s.close()
            with lk:
                done[0] += 1
        except Exception as e:
            with lk:
                bad.append("%d: %r" % (i, e))
    ts = [threading.Thread(target=one, args=(i,)) for i in range(k)]
    for t in ts:
        t.start()
        time.sleep(0.03)
    for t in ts:
        t.join()
    most = max((len(v) for v in seen.values()), default=0)
    print("concurrent: most echoing in one second %d of %d, %d complete; per second %s; %s" % (
        most, k, done[0], [len(seen.get(x, ())) for x in range(max(seen, default=0) + 1)], bad[:3]))
    sys.exit(0 if done[0] == k and not bad and (most <= cap if cap else most == k) else 1)
if m == "soak":
    host, port, dur, k = a[0], int(a[1]), float(a[2]), int(a[3])
    via = (a[4], int(a[5])) if len(a) > 5 else None
    n = 262144
    lk = threading.Lock()
    res = []
    def one(i):
        r = [0, 0.0, None]
        last = time.monotonic()
        try:
            if via:
                s, _, _ = socks(via[0], via[1], host, port)
            else:
                s = socket.create_connection((host, port), 20)
            s.settimeout(30)
            end = time.monotonic() + dur
            while time.monotonic() < end:
                data = os.urandom(n)
                err = []
                def tx():
                    try:
                        s.sendall(data)
                    except OSError as e:
                        err.append(e)
                t = threading.Thread(target=tx)
                t.start()
                b = bytearray()
                while len(b) < n:
                    d = s.recv(n - len(b))
                    if not d:
                        raise OSError("EOF after %d of %d" % (len(b), n))
                    t1 = time.monotonic()
                    r[1] = max(r[1], t1 - last)
                    last = t1
                    b += d
                t.join()
                if err:
                    raise err[0]
                if bytes(b) != data:
                    raise OSError("data differs")
                r[0] += 1
            s.close()
        except Exception as e:
            r[2] = "%d: %r after %d rounds" % (i, e, r[0])
        with lk:
            res.append(r)
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(k)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    bad = [x[2] for x in res if x[2]]
    print("soak: %d of %d flows intact, %.1f MB each way in %.1f s, longest receive gap %.2f s counted from the connect %s" % (
        k - len(bad), k, sum(x[0] for x in res) * n / 1e6, time.monotonic() - t0, max(x[1] for x in res), bad[:3]))
    sys.exit(0 if not bad else 1)
if m == "watch":
    host, port, secs = a[0], int(a[1]), float(a[2])
    t0 = time.time()
    last = t0
    end = "alive"
    try:
        s = socket.create_connection((host, port), 20)
        s.settimeout(60)
        while time.time() - t0 < secs:
            pump(s, 1000)
            last = time.time()
            time.sleep(0.2)
    except Exception as e:
        end = "%r" % e
    print("watch %.3f %.3f %.3f %s" % (t0, last, time.time(), end), flush=True)
if m == "down":
    host, port, dur = a[0], int(a[1]), float(a[2])
    s = socket.create_connection((host, port), 20)
    s.settimeout(dur + 15)
    n = 0
    t0 = None
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
if m == "fail":
    host, port = a[0], int(a[1])
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), 30)
        s.settimeout(30)
        pump(s, 1000)
        print("silent: echoed after %.1f s" % (time.monotonic() - t0))
    except Exception as e:
        print("silent: failed after %.1f s: %r" % (time.monotonic() - t0, e))
PY

bg_in "$NSS" "$W/targets.log" python3 "$W/targets.py" "$TARGET"
bg_in "$NSS" "$W/load-target.log" python3 tests/grpc-target.py "$TARGET" 8080
bg_in "$NSS" "$W/probe1.log" python3 tests/grpc-target.py 1.1.1.1 80
bg_in "$NSS" "$W/probe2.log" python3 tests/grpc-target.py 8.8.8.8 80
bg_in "$NSS" "$W/mask.log" openssl s_server -accept "$S_IP:8443" -cert "$W/mask.pem" -key "$W/mask.key" \
    -tls1_3 -alpn h2,http/1.1 -www -quiet
wait_ss "$NSS" -ltn ":7006" && wait_ss "$NSS" -lun "$TARGET:7000" && wait_ss "$NSS" -ltn "$TARGET:8080" &&
    wait_ss "$NSS" -ltn "8.8.8.8:80" && wait_ss "$NSS" -ltn "$S_IP:8443" ||
    { echo "hy2-tun: the targets did not start:"; cat "$W/targets.log"; exit 1; }

TLS="\"security\":\"tls\",\"tlsSettings\":{\"certificates\":[{\"certificateFile\":\"$W/leaf.pem\",\"keyFile\":\"$W/leaf.key\"}]}"
HS="\"hysteriaSettings\":{\"version\":2,\"auth\":\"$PW\"}"
inb() {
    printf '{"tag":"%s","listen":"%s","port":%s,"protocol":"hysteria","settings":{"version":2,"clients":[{"auth":"%s"}]},"streamSettings":{"network":"hysteria",%s,%s%s}}' \
        "$1" "$S_IP" "$2" "$PW" "$TLS" "$HS" "${3:+,$3}"
}
OUTB='"routing":{"rules":[{"inboundTag":["b","o","s","v"],"outboundTag":"direct"}]},"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["203.0.113.0/24","1.1.1.1/32","8.8.8.8/32","127.0.0.1/32","::1/128"]}]}}]'
VIN="{\"tag\":\"v\",\"listen\":\"$S_IP\",\"port\":$P_V,\"protocol\":\"vless\",\"settings\":{\"clients\":[{\"id\":\"$UUID\"}],\"decryption\":\"none\"},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"dest\":\"$S_IP:8443\",\"xver\":0,\"serverNames\":[\"$MASK\"],\"privateKey\":\"$PRIV\",\"shortIds\":[\"$SID\"]}}}"
cat > "$W/xray.json" <<JSON
{"log":{"loglevel":"warning","access":"$W/access.log"},
 "inbounds":[$(inb b $P_BASE),
   $(inb o $P_OBFS "\"finalmask\":{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":\"$OBFS\"}}]}"),
   $(inb s $P_STR "\"finalmask\":{\"quicParams\":{\"maxIncomingStreams\":8}}"),$VIN],
 $OUTB}
JSON
for d in 1 2; do
    eval p=\$P_D$d
    printf '{"log":{"loglevel":"warning"},"inbounds":[%s],%s}\n' "$(inb d$d "$p")" "$OUTB" > "$W/xray-d$d.json"
done
for f in xray xray-d1 xray-d2; do
    "$XRAY" run -test -c "$W/$f.json" > "$W/$f-test.log" 2>&1 || { echo "hy2-tun: Xray refuses $f.json:"; tail -5 "$W/$f-test.log"; exit 1; }
done
bg_in "$NSS" "$W/xray.log" "$XRAY" run -c "$W/xray.json"
XPID=$!
for l in "$S_IP:$P_BASE " "$S_IP:$P_OBFS " "$S_IP:$P_STR "; do
    wait_ss "$NSS" -lun "$l" || { echo "hy2-tun: Xray did not start ($l):"; tail -5 "$W/xray.log"; exit 1; }
done
wait_ss "$NSS" -ltn "$S_IP:$P_V " || { echo "hy2-tun: Xray did not start (VLESS):"; tail -5 "$W/xray.log"; exit 1; }
DPID1=""; DPID2=""
d_up() {
    bg_in "$NSS" "$W/xray-d$1.log" "$XRAY" run -c "$W/xray-d$1.json"
    eval DPID$1=$!
    eval p=\$P_D$1
    wait_ss "$NSS" -lun "$S_IP:$p "
}
d_kill() { eval p=\$DPID$1; [ -z "$p" ] || { kill -9 "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; }; eval DPID$1=""; }

hy() { printf 'hysteria2://%s@%s:%s?sni=%s%s#%s' "$PW" "$S_IP" "$1" "$SNI" "${3:-}" "$2"; }
L_BASE=$(hy $P_BASE B)
L_OBFS=$(hy $P_OBFS O "&obfs=salamander&obfs-password=$OBFS")
L_BAD=$(hy $P_OBFS X "&obfs=salamander&obfs-password=not-$OBFS")
L_V="vless://$UUID@$S_IP:$P_V?encryption=none&type=tcp&security=reality&sni=$MASK&pbk=$PUB&sid=$SID&fp=chrome#V"

cli() { ip netns exec "$NSC" timeout -k 2 "$1" python3 "$W/cli.py" "$2" "$TARGET" "$3" ${4:+"$4"} ${5:+"$5"}; }
qconns() { ip netns exec "$NSC" ss -Hun state established "( dport = :${1:-$P_BASE} )" 2>/dev/null | wc -l; }
qports() { ip netns exec "$NSC" ss -Hun state established "( dport = :${1:-$P_BASE} )" 2>/dev/null | awk '{ print $3 }' | sort | tr '\n' ' '; }
rss() { awk '/^VmRSS:/ { print $2 }' "/proc/$TPID/status" 2>/dev/null || echo 0; }
evwait() {
    i=0; lim=$(awk -v s="${2:-15}" 'BEGIN { print int(s * 5) }')
    while [ $i -lt "$lim" ]; do
        tail -n "+${3:-1}" "$W/kev" | grep -qF "$1" && return 0
        kill -0 "$TPID" 2>/dev/null || return 1
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
tun_up() {
    rm -f "$W/kin"; mkfifo "$W/kin"; : > "$W/kev"
    TLOG="$W/tun-$MODE.log"
    ip netns exec "$NSC" env $TENV "$BIN" --control --ca "$W/ca.pem" -d vl -a 198.19.0.1/32 \
        --interval 3600 $TARGS < "$W/kin" > "$W/kev" 2> "$TLOG" &
    TPID=$!
    exec 7> "$W/kin"
    for l in "$@"; do printf '%s\n' "$l" >&7; done
    echo >&7
    evwait '"ready"' 20 || { echo "    no ready event:"; tail -5 "$TLOG"; return 1; }
    ip netns exec "$NSC" ip route replace 203.0.113.0/24 dev vl
    i=0; while [ $i -lt 50 ] && [ "$(ip netns exec "$NSC" ss -Hun state established dst "$S_IP" | wc -l)" -gt 0 ]; do
        sleep 0.2; i=$((i + 1)); done
}
tun_down() {
    exec 7>&- 2>/dev/null || true
    [ -z "$TPID" ] || { kill "$TPID" 2>/dev/null || true; wait "$TPID" 2>/dev/null || true; }
    TPID=""
    ip netns exec "$NSC" ip link delete vl 2>/dev/null || true
}
clean_log() {
    if grep -E 'does not answer|answers again|did not open|refused the data' "$TLOG" > "$W/bad.txt"; then
        echo "    the log says:"; sed 's/^/        /' "$W/bad.txt" | head -5; return 1
    fi
}
one_conn() {
    c=$(qconns "${2:-$P_BASE}")
    echo "    QUIC connections $1: $c ($(qports "${2:-$P_BASE}"))"
    [ "$c" -eq 1 ]
}
load() {
    ip netns exec "$NSC" timeout -k 2 $(($2 + 30)) python3 tests/grpc-load.py --target "$1" --dur "$2" $3 \
        > "$W/load-$MODE.log" 2>&1 & LP=$!
}
R_IDLE=""; R_LOAD=""; R_AFTER=""
tcp_body() {
    TARGS=""; tun_up "$L_BASE" || return 1
    R_IDLE=$(rss)
    r=0
    o=$(cli 90 echo 7000 4194304 1) || r=1; echo "    $o"
    load "$TARGET:8080" 30 "--report 10"
    peak=0; cmax=0; cmin=99
    while kill -0 "$LP" 2>/dev/null; do
        v=$(rss); [ "$v" -le "$peak" ] || peak=$v
        c=$(qconns); [ "$c" -le "$cmax" ] || cmax=$c; [ "$c" -ge "$cmin" ] || cmin=$c
        echo "$(date +%s) $(qports)" >> "$W/qs-$MODE.txt"
        sleep 1
    done
    wait "$LP" || r=1
    sed 's/^/    /' "$W/load-$MODE.log" | tail -4
    R_LOAD=$peak
    sleep 5
    R_AFTER=$(rss)
    echo "    QUIC connections over the load: least $cmin, most $cmax"
    [ "$cmin" -eq 1 ] && [ "$cmax" -eq 1 ] || r=1
    clean_log || r=1
    return $r
}

HOP_PORTS=$(seq 20000 20009)
L_HOP=$(hy 20000-20009 H "&hop=5-5")
L_ONE=$(hy 20000 P)
TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)
cat > "$W/pb.py" <<'PY'
import sys
from fractions import Fraction
from math import comb
d, n = int(sys.argv[1]), 10
def exact(i):
    return comb(n, i) * sum(Fraction((-1) ** j * comb(i, j)) * Fraction(i - j, n) ** d for j in range(i + 1))
def under(c):
    return sum((exact(i) for i in range(1, c)), Fraction(0))
m = 1
while m < n and under(m + 1) < Fraction(1, 10 ** 6):
    m += 1
print(m, "%.3g" % float(under(m)), "%.3g" % float(under(m + 1)) if m < n else "-")
PY
hop_pre() { for p in $HOP_PORTS; do echo "add rule ip hop pre udp dport $p counter redirect to :$P_BASE"; done | ip netns exec "$NSS" nft -f -; }
hop_nft() {
    { echo "table ip hop {"; echo "chain cnt { type filter hook prerouting priority -300;"
      for p in $HOP_PORTS $P_BASE; do echo "udp dport $p counter"; done
      echo "}"; echo "chain pre { type nat hook prerouting priority -100; }"; echo "}"; } | ip netns exec "$NSS" nft -f -
    hop_pre
    ip netns exec "$NSC" nft -f - <<NFT
table ip hopc { set t { type ipv4_addr . inet_service . inet_service; flags dynamic; }; chain o { type filter hook output priority 0; ip daddr $S_IP meta l4proto udp ct state new add @t { ip daddr . udp sport . udp dport }; }
  set np { typeof ip saddr . udp sport . udp dport; flags dynamic; counter; size 65535; }
  chain i { type filter hook input priority 0; ip saddr $S_IP meta l4proto udp socket transparent 0 accept; ip saddr $S_IP meta l4proto udp add @np { ip saddr . udp sport . udp dport }; }; }
NFT
}
hop_nft_down() {
    ip netns exec "$NSS" nft delete table ip hop 2>/dev/null || true
    for t in hopc hopb; do ip netns exec "$NSC" nft delete table ip $t 2>/dev/null || true; done
    ip netns exec "$NSS" nft delete table inet hopdrop 2>/dev/null || true
}
nftcnt() { ip netns exec "$NSS" nft list chain ip hop cnt | awk '/counter packets/ { for (i = 1; i <= NF; i++) if ($i == "packets") printf "%s ", $(i + 1) }'; }
hop_flush() { ip netns exec "$NSC" nft flush set ip hopc t; ip netns exec "$NSC" nft flush set ip hopc np; }
np_own() {
    ip netns exec "$NSC" nft list set ip hopc t | tr -d '\n' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' | tr ',' '\n' | awk 'NF { print $3 }' > "$W/own.txt"
    ip netns exec "$NSC" nft list set ip hopc np | tr -d '\n' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' | tr ',' '\n' > "$W/np.txt"
    awk 'NR == FNR { own[$1] = 1; next }
        NF { n = 0; for (i = 1; i <= NF; i++) if ($i == "packets") n = $(i + 1); if ($5 in own) { o += n; ot = ot " " $3 ">" $5 } else { f += n; ft = ft " " $3 ">" $5 } }
        END { printf "OWN=%d FOR=%d OTU=\"%s\" FTU=\"%s\"\n", o, f, ot, ft }' "$W/own.txt" "$W/np.txt"
}
ctset() { ip netns exec "$NSC" nft list set ip hopc t | tr -d '\n' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' | tr ',' '\n' | grep -c '[0-9]' || true; }
snmp() {
    ip netns exec "$NSC" awk '$1 == "Udp:" || $1 == "Icmp:" { if (h[$1]) { for (i = 2; i <= NF; i++) v[$1 h[$1, i]] = $i } else { h[$1] = 1; for (i = 2; i <= NF; i++) h[$1, i] = $i } }
        END { print v["Udp:NoPorts"] + 0, v["Icmp:OutDestUnreachs"] + 0 }' /proc/net/snmp
}
tcpc() {
    ip netns exec "$NSC" awk '$1 == "Tcp:" || $1 == "TcpExt:" { if (h[$1]) { for (i = 2; i <= NF; i++) v[h[$1, i]] = $i } else { h[$1] = 1; for (i = 2; i <= NF; i++) h[$1, i] = $i } }
        END { print v["RetransSegs"] + 0, v["TCPTimeouts"] + 0, v["TCPWinProbe"] + 0 }' /proc/net/snmp /proc/net/netstat
}
fdn() { ls "/proc/$1/fd" 2>/dev/null | wc -l; }
qany() { ip netns exec "$NSC" ss -Hun state established dst "$S_IP" 2>/dev/null | wc -l; }
lports() { ip netns exec "$NSC" ss -Hun state established dst "$S_IP" 2>/dev/null | awk '{ n = split($3, l, ":"); print l[n] }' | sort -u | tr '\n' ' '; }
socks_of() {
    if [ "$1" = ours ]; then
        ip netns exec "$NSC" ss -Hun state established dst "$S_IP" | awk '{ n = split($3, l, ":"); m = split($4, p, ":"); printf "%s%s>%s", (NR > 1 ? "," : ""), l[n], p[m] } END { if (!NR) printf "-" }'
    else
        ip netns exec "$NSC" ss -Huan | awk '{ n = split($4, l, ":"); printf "%s%s>x", (NR > 1 ? "," : ""), l[n] } END { if (!NR) printf "-" }'
    fi
}
SMP=""
sampler() {
    rm -f "$W/sstop"; : > "$3"
    ( i=0
      while [ ! -e "$W/sstop" ] && [ $i -lt 400 ]; do
          echo "$(now) $(nftcnt) $(snmp) $(ctset) $(fdn "$2") $(socks_of "$1")" >> "$3"
          sleep 1; i=$((i + 1))
      done ) &
    SMP=$!
    sleep 1.5
}
sampler_stop() { : > "$W/sstop"; [ -z "$SMP" ] || wait "$SMP" 2>/dev/null || true; SMP=""; }
hop_sum() {
    awk '{ if (NR == 1) for (i = 2; i <= 16; i++) b[i] = $i
          if (NR > 1) {
              best = 0; bi = 0
              for (i = 2; i <= 12; i++) { d = $i - p[i]; if (d > best) { best = d; bi = i } }
              if (bi && bi != cur) { if (cur) { h++; seq = seq " " (cur == 12 ? "real" : cur + 19998) ">" (bi == 12 ? "real" : bi + 19998) } cur = bi }
              np[h] += $13 - p[13]; od[h] += $14 - p[14]
          }
          for (i = 2; i <= 16; i++) p[i] = $i
          if ($16 > fm) fm = $16
          if ($17 != "-") { n = split($17, tk, ","); for (j = 1; j <= n; j++) { split(tk[j], lr, ">")
              if (!(lr[1] in lp)) { lp[lr[1]] = 1; nl++; ll = ll " " lr[1] }
              if (!(tk[j] in tu)) { tu[tk[j]] = 1; nt++ } } } }
        END {
            for (i = 2; i <= 11; i++) { c = p[i] - b[i]; pc = pc " " c; if (c > 0) hit++ }
            for (k = 1; k <= h; k++) { per = per " " np[k] "/" od[k] }
            printf "HIT=%d HOPS=%d NLP=%d NTU=%d CT=%d NP=%d OD=%d NP0=%d OD0=%d REAL=%d FDMAX=%d\n", hit, h, nl, nt, p[15] - b[15], p[13] - b[13], p[14] - b[14], np[0], od[0], p[12] - b[12], fm
            printf "PCS=\"%s\" LPS=\"%s\" PER=\"%s\" SEQ=\"%s\"\n", pc, ll, per, seq }' "$1"
}
hop_print() {
    echo "    $1: packets to 20000-20009:$PCS, to the real port $REAL; $HIT of 10 ports hit; hops seen $HOPS:$SEQ"
    echo "    $1: local ports $NLP:$LPS; (local, remote) pairs $NTU; conntrack entries made in the client namespace $CT"
    echo "    $1: Udp NoPorts / Icmp OutDestUnreachs $NP / $OD in all, $NP0 / $OD0 before the first hop, after each hop:${PER:- none}"
    echo "    $1: descriptors at most $FDMAX"
}
icmp_ctl() {
    set -- $(snmp)
    ip netns exec "$NSS" python3 -c 'import socket, sys; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", (sys.argv[1], 9))' "$C_IP"
    sleep 0.5
    set -- "$@" $(snmp)
    c=$(ip netns exec "$NSC" nft list set ip hopc np | tr -d '\n' | grep -c '\. 9 counter packets [1-9]' || true)
    echo "    control: one datagram from the server to a closed client port moved Udp NoPorts by $(($3 - $1)), Icmp OutDestUnreachs by $(($4 - $2)), and was counted by port $( [ "$c" -eq 1 ] && echo yes || echo no)"
    [ $(($3 - $1)) -ge 1 ] && [ $(($4 - $2)) -ge 1 ] && [ "$c" -eq 1 ] || { echo "    the counters do not move"; return 1; }
}
icmp_zero() {
    eval "$(np_own)"
    echo "    $1: datagrams of the server to a local port of this run with no socket: $OWN${OTU:+ (}${OTU# }${OTU:+)}; tolerance zero: the old port stays readable for its linger"
    echo "    $1: and one PING after the hop moves the server within an RTT, so no packet of the server meets a closed port"
    [ "$FOR" -eq 0 ] || echo "    $1: not judged: $FOR to ports this run never held (${FTU# }), the probes of a connection an earlier client left open when it was killed"
    [ "$OWN" -eq 0 ] || { echo "    FINDING: $1 sent port unreachables during the hops"; return 1; }
}
gap_class() { awk -v g="${1:-99}" 'BEGIN { print (g < 2 ? "gap under the 2 s linger" : "a stall of 2 s or more") }'; }
hop_m() {
    k=$(awk -v d="$HDUR" 'BEGIN { print int((d - 0.5) / 5) }')
    set -- $(python3 "$W/pb.py" $((k + 1)))
    M=$1
    echo "    bound: hops every 5 s from the link's start make $k hops in $HDUR s, $((k + 1)) uniform draws over 10 ports;" \
        "the chance that fewer than $M distinct ports are hit is $2 (under 1e-6), fewer than $((M + 1)) $3; at least $M must be hit$( [ "$M" -ge 2 ] || echo " — NOT binding, the run is too short")"
}
soak_gap() { printf '%s\n' "$1" | sed -n 's/.*longest receive gap \([0-9.]*\) s.*/\1/p'; }
fd_back() {
    t0=$(now); i=0; lim=$(($2 * 5))
    while [ $i -lt "$lim" ]; do
        [ "$(fdn "$TPID")" -eq "$1" ] && [ "$(qany)" -eq 0 ] && break
        sleep 0.2; i=$((i + 1))
    done
    f=$(fdn "$TPID"); echo "    descriptors of tunvless: $1 before the link, $f after $(since "$t0") s more (QUIC sockets $(qany))"
    [ "$f" -eq "$1" ]
}
ready_lines() {
    n=$(grep -c 'link ready' "$TLOG" || true)
    grep 'link ready\|port hop failed\|link cut' "$TLOG" | sed 's/^/    log: /' | head -8
    [ "$n" -eq "${1:-1}" ] || { echo "    $n ready lines, not ${1:-1}"; return 1; }
}
xout() {
    printf '{"tag":"X","protocol":"hysteria","settings":{"version":2,"address":"%s","port":%s},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"%s","pinnedPeerCertSha256":"%s"},"hysteriaSettings":{"version":2,"auth":"%s"},"finalmask":{"udp":[{"type":"udphop","settings":{"mode":"%s","remotePorts":"20000-20009","interval":5}}]}}}' \
        "$S_IP" "$2" "$SNI" "$PIN" "$PW" "$1"
}
tun_file() {
    printf '{"outbounds":[%s]}\n' "$(xout "$1" "$2")" > "$W/node-$MODE.json"
    : > "$W/kev"; TLOG="$W/tun-$MODE.log"
    ip netns exec "$NSC" "$BIN" --ca "$W/ca.pem" "$W/node-$MODE.json" -d vl -a 198.19.0.1/32 --interval 3600 > "$TLOG" 2>&1 &
    TPID=$!
    i=0; while [ $i -lt 100 ] && ! ip netns exec "$NSC" ip -o link show vl 2>/dev/null | grep -q ',UP'; do sleep 0.2; i=$((i + 1)); done
    ip netns exec "$NSC" ip route replace 203.0.113.0/24 dev vl 2>/dev/null || { echo "    the device did not come up:"; tail -5 "$TLOG"; return 1; }
    i=0; while [ $i -lt 100 ] && ! grep -q 'info\]: active: ' "$TLOG"; do sleep 0.2; i=$((i + 1)); done
    grep -q 'info\]: active: ' "$TLOG" || { echo "    no active node within 20 s:"; tail -5 "$TLOG"; return 1; }
    i=0; while [ $i -lt 50 ] && [ "$(qany)" -gt 0 ]; do sleep 0.2; i=$((i + 1)); done
}
CPID=""
xc_run() {
    printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"%s","port":1082,"protocol":"socks","settings":{"udp":false}}],"outbounds":[%s]}\n' \
        "$C_IP" "$(xout "$1" "$2")" > "$W/xc-$MODE.json"
    "$XRAY" run -test -c "$W/xc-$MODE.json" > "$W/xc-test.log" 2>&1 || { echo "    Xray refuses the client config:"; tail -3 "$W/xc-test.log"; return 1; }
    bg_in "$NSC" "$W/xc-$MODE.log" "$XRAY" run -c "$W/xc-$MODE.json"
    CPID=$!
    wait_ss "$NSC" -ltn "$C_IP:1082 " || { echo "    the Xray client did not start:"; tail -3 "$W/xc-$MODE.log"; return 1; }
}
xc_down() { [ -z "$CPID" ] || { kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true; }; CPID=""; }
soak_xc() { ip netns exec "$NSC" timeout -k 2 $((HDUR + 40)) python3 "$W/cli.py" soak "$TARGET" 7000 "$HDUR" 2 "$C_IP" 1082; }
cpu_of() { sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{ print $12 + $13 }'; }
watch_end() { awk -v td="$2" '{ printf "%.1f", $4 - td }' "$1"; }

hop_run() {
    tun_up "$L_HOP" || return 1
    r=0; hop_m; FDB=$(fdn "$TPID")
    icmp_ctl || r=1
    hop_flush
    sampler ours "$TPID" "$W/smp-$MODE.txt"
    o=$(cli $((HDUR + 40)) soak 7000 "$HDUR" 2) || r=1; echo "    $o"
    sampler_stop
    eval "$(hop_sum "$W/smp-$MODE.txt")"; hop_print ours
    [ "$HIT" -ge "$M" ] || { echo "    fewer than $M ports hit"; r=1; }
    [ "$NLP" -ge 3 ] || { echo "    the local port took fewer than 3 values"; r=1; }
    g=$(soak_gap "$o"); awk -v g="${g:-99}" 'BEGIN { exit !(g < 2) }' || { echo "    a receive stall of ${g:-?} s, longer than the 2 s linger"; r=1; }
    icmp_zero ours || r=1
    ready_lines || r=1
    fd_back "$FDB" 45 || r=1
    clean_log || r=1
    return $r
}

run_case() {
    TARGS=""; TENV=""; TLOG=""
    case "$MODE" in
    hy2-tun-probe)
        ip netns exec "$NSC" timeout -k 2 30 "$BIN" --probe --ca "$W/ca.pem" "$L_BASE" "$L_OBFS" > "$W/probe.out" 2>&1 || true
        sed 's/^/    /' "$W/probe.out"
        [ "$(grep -cE '	ok	handshake [0-9]+ ms, first byte [0-9]+ ms$' "$W/probe.out")" -eq 2 ] ;;
    hy2-tun-tcp) tcp_body ;;
    hy2-tun-ktcp)
        TARGS="--tcp-port 3600 --tcp-pool 198.18.0.0/15"; tun_up "$L_BASE" || return 1
        printf 'map\n198.18.0.5 %s\n\n' "$TARGET" >&7
        evwait '"type":"map","count":1' 10 || { echo "    no map event"; return 1; }
        ip netns exec "$NSC" ip route replace 198.18.0.0/15 dev vl
        ip netns exec "$NSC" nft -f - <<NFT
table ip h2redir { chain out { type nat hook output priority -100; policy accept; ip daddr 198.18.0.0/15 tcp dport { 7000, 8080 } counter redirect to :3600; }; }
NFT
        r=0
        o=$(ip netns exec "$NSC" timeout -k 2 90 python3 "$W/cli.py" echo 198.18.0.5 7000 4194304 1) || r=1; echo "    $o"
        load 198.18.0.5:8080 20 "--report 10"
        sleep 5; one_conn "under the load" || r=1
        wait "$LP" || r=1
        sed 's/^/    /' "$W/load-$MODE.log" | tail -3
        n=$(ip netns exec "$NSC" nft list table ip h2redir | sed -n 's/.*packets \([0-9]*\) .*/\1/p')
        echo "    redirected connections: $n"
        [ "${n:-0}" -ge 2 ] || r=1
        grep -q '"type":"bytes"' "$W/kev" && echo "    a bytes event: $(grep '"type":"bytes"' "$W/kev" | tail -1)" ||
            { echo "    no bytes event"; r=1; }
        one_conn "after the load" || r=1
        ip netns exec "$NSC" nft delete table ip h2redir
        clean_log || r=1
        return $r ;;
    hy2-tun-udp)
        tun_up "$L_BASE" || return 1
        r=0
        o=$(cli 60 udp 7000 100 50) || r=1; echo "    $o"
        o=$(cli 60 udp 7000 3000 20) || r=1; echo "    $o"
        o=$(cli 10 udpempty 7000) || r=1; echo "    $o"
        return $r ;;
    hy2-tun-socks)
        tun_up "$L_BASE" || return 1
        printf 'inbounds\n%s:1081 - - %s\n\n' "$C_IP" "$L_BASE" >&7
        evwait '"type":"inbound","port":1081,"state":"up"' 10 || { echo "    the inbound did not come up"; return 1; }
        r=0
        s() { o=$(ip netns exec "$NSC" timeout -k 2 60 python3 "$W/cli.py" "$1" "$C_IP" 1081 "$2" "$3" "$4" ${5:+"$5"} 2>&1) || r=1; echo "    $o" | tail -1; }
        s socks "$TARGET" 7000 1048576
        s http "$TARGET" 7000 1048576
        s socks localhost 7000 1048576
        s assoc "$TARGET" 7000 100 20
        return $r ;;
    hy2-tun-upload-stop)
        tun_up "$L_BASE" || return 1
        r=0
        o=$(cli 60 upstop 7005) || r=1; echo "    $o"
        return $r ;;
    hy2-tun-idle)
        tun_up "$L_BASE" || return 1
        r=0
        ip netns exec "$NSC" timeout -k 2 120 python3 "$W/cli.py" idle "$TARGET" 7000 70 > "$W/idle.out" 2>&1 & IP_=$!
        i=0; while [ $i -lt 100 ] && ! grep -q 'first ok' "$W/idle.out"; do sleep 0.2; i=$((i + 1)); done
        grep -q 'first ok' "$W/idle.out" || { echo "    the first echo failed: $(cat "$W/idle.out")"; return 1; }
        p0=$(qports); one_conn "before the silence" || r=1
        wait "$IP_" || r=1
        echo "    $(tr '\n' ' ' < "$W/idle.out")"
        p1=$(qports); echo "    QUIC connections after the silence: $p1"
        [ -n "$p0" ] && [ "$p0" = "$p1" ] || { echo "    the connection changed: $p0 -> $p1"; r=1; }
        t0=$(now); i=0
        while [ $i -lt 175 ] && [ "$(qconns)" -gt 0 ]; do sleep 0.2; i=$((i + 1)); done
        g=$(since "$t0"); c=$(qconns)
        echo "    QUIC connections ${g} s after the last flow closed: $c"
        [ "$c" -eq 0 ] || r=1
        t0=$(now)
        o=$(cli 30 echo 7000 1000 1) || r=1
        echo "    a new flow after that: $o, in $(since "$t0") s"
        clean_log || r=1
        return $r ;;
    hy2-tun-node-death)
        d_up 1 && d_up 2 || { echo "    the node servers did not start"; return 1; }
        TARGS="-A 1"; tun_up "$(hy $P_D1 D1)" "$(hy $P_D2 D2)" || return 1
        r=0
        evwait '"type":"active","nodes":["D1"]' 15 || { echo "    D1 is not active:"; cat "$W/kev"; return 1; }
        o=$(cli 30 echo 7000 1048576 1) || r=1; echo "    through D1: $o"
        load "$TARGET:8080" 60 "--down 2 --up 1 --rate 5 --report 60"
        sleep 3
        n0=$(wc -l < "$W/kev"); t0=$(now)
        d_kill 1
        evwait '"type":"node_down","node":"D1"' 25 $((n0 + 1)) && echo "    node_down D1 after $(since "$t0") s" || r=1
        evwait '"type":"active","nodes":["D2"]' 25 $((n0 + 1)) && g=$(since "$t0") && echo "    D2 active after $g s" || { r=1; g=99; }
        awk -v g="$g" 'BEGIN { exit !(g <= 20) }' || { echo "    later than 20 s after the kill"; r=1; }
        o=$(cli 30 echo 7000 1048576 1) || r=1; echo "    a new flow: $o"
        kill "$LP" 2>/dev/null || true; wait "$LP" 2>/dev/null || true
        d_up 1 || { echo "    D1 did not restart"; return 1; }
        load "$TARGET:8080" 60 "--down 2 --up 0 --rate 0 --report 60"
        sleep 3
        n0=$(wc -l < "$W/kev"); t0=$(now)
        d_kill 2
        evwait '"type":"node_up","node":"D1"' 30 $((n0 + 1)) && echo "    node_up D1 after $(since "$t0") s" || r=1
        evwait '"type":"active","nodes":["D1"]' 30 $((n0 + 1)) && echo "    D1 active again after $(since "$t0") s" || r=1
        o=$(cli 30 echo 7000 1048576 1) || r=1; echo "    a new flow: $o"
        kill "$LP" 2>/dev/null || true; wait "$LP" 2>/dev/null || true
        [ "$r" -eq 0 ] || sed 's/^/    ev: /' "$W/kev"
        d_kill 1
        return $r ;;
    hy2-tun-mixed)
        printf '%s\n' "$L_V" "$L_BASE" "$L_OBFS" > "$W/sub.txt"
        : > "$W/kev"; TLOG="$W/tun-$MODE.log"
        ip netns exec "$NSC" "$BIN" --ca "$W/ca.pem" "$W/sub.txt" -d vl -a 198.19.0.1/32 -A 3 --by site \
            --interval 3600 > "$TLOG" 2>&1 &
        TPID=$!
        i=0; while [ $i -lt 150 ] && [ "$(grep -c 'active node [0-9] of 3\|chose ' "$TLOG")" -lt 3 ]; do sleep 0.2; i=$((i + 1)); done
        grep 'active node\|chose ' "$TLOG" | sed 's/^/    /'
        [ "$(grep -c 'active node [0-9] of 3\|chose ' "$TLOG")" -ge 3 ] || { echo "    not three active nodes"; tail -5 "$TLOG"; return 1; }
        ip netns exec "$NSC" ip route replace 203.0.113.0/24 dev vl
        : > "$W/access.log"
        r=0
        MP=""
        for i in $(seq 10 29); do
            ip netns exec "$NSC" timeout -k 2 30 python3 "$W/cli.py" echo "203.0.113.$i" 7000 65536 1 > "$W/m$i.out" 2>&1 &
            MP="$MP $!"
        done
        for p in $MP; do wait "$p" || r=1; done
        [ "$(cat "$W"/m*.out | grep -c 'echo 1 of 1')" -eq 20 ] || r=1
        echo "    $(cat "$W"/m*.out | grep -c 'echo 1 of 1') of 20 sites echoed"
        sleep 1
        for t in v b o; do
            c=$(grep -cE "accepted tcp:203\.0\.113\.(1[0-9]|2[0-9]):7000 \[$t " "$W/access.log" || true)
            echo "    flows through inbound $t: $c"
            [ "$c" -ge 1 ] || r=1
        done
        return $r ;;
    hy2-tun-obfs-wrong)
        printf '%s\n' "$L_BAD" > "$W/bad.txt"
        TLOG="$W/tun-$MODE.log"; t0=$(now); rc=0
        ip netns exec "$NSC" timeout -k 2 30 "$BIN" --ca "$W/ca.pem" --no-retry "$W/bad.txt" -d vl -a 198.19.0.1/32 \
            > "$TLOG" 2>&1 || rc=$?
        g=$(since "$t0")
        sed 's/^/    /' "$TLOG"
        echo "    exit $rc after $g s"
        [ "$rc" -eq 1 ] && grep -q '^tunvless\[info\]: X — .' "$TLOG" && grep -q 'no node answered' "$TLOG" &&
            awk -v g="$g" 'BEGIN { exit !(g <= 10) }' ;;
    hy2-tun-rss)
        [ -n "$R_AFTER" ] || { tcp_body > "$W/rss-run.log" 2>&1 || { cat "$W/rss-run.log"; return 1; }; }
        echo "    VmRSS of tunvless: idle $R_IDLE kB, at the load of hy2-tun-tcp (most) $R_LOAD kB, 5 s after it $R_AFTER kB"
        [ "${R_IDLE:-0}" -gt 0 ] && [ "${R_LOAD:-0}" -gt 0 ] && [ "${R_AFTER:-0}" -gt 0 ] ;;
    hy2-tun-many)
        tun_up "$L_BASE" || return 1
        r=0
        o=$(cli 90 echo 7000 262144 40) || r=1; echo "    $o"
        one_conn "after 40 flows at once" || r=1
        load "$TARGET:8080" 15 "--down 0 --up 10 --rate 0 --report 5"
        wait "$LP" || r=1
        sed 's/^/    /' "$W/load-$MODE.log" | tail -2
        one_conn "after 10 uploads at once" || r=1
        clean_log || r=1
        return $r ;;
    hy2-tun-streams)
        tun_up "$(hy $P_STR S)" || return 1
        r=0
        o=$(cli 90 echo 7000 65536 30) || r=1; echo "    $o"
        one_conn "after 30 flows on 8 streams" "$P_STR" || r=1
        return $r ;;
    hy2-tun-slow)
        tun_up "$L_BASE" || return 1
        r=0; r0=$(rss)
        ip netns exec "$NSC" timeout -k 2 60 python3 "$W/cli.py" hold "$TARGET" 8080 3 25 > "$W/hold.out" 2>&1 & HP=$!
        i=0; while [ $i -lt 50 ] && ! grep -q held "$W/hold.out"; do sleep 0.2; i=$((i + 1)); done
        sleep 2
        t0=$(now)
        o=$(cli 20 echo 7000 1048576 1) || r=1; echo "    beside 3 unread downloads: $o, in $(since "$t0") s"
        ip netns exec "$NSC" timeout -k 2 60 python3 "$W/cli.py" slow "$TARGET" 7006 10 100000 > "$W/slow.out" 2>&1 & SP=$!
        peak=0
        while kill -0 "$SP" 2>/dev/null; do v=$(rss); [ "$v" -le "$peak" ] || peak=$v; sleep 1; done
        wait "$SP" || r=1
        echo "    $(cat "$W/slow.out")"
        wait "$HP" || true
        echo "    VmRSS: before $r0 kB, most $peak kB, after $(rss) kB"
        clean_log || r=1
        return $r ;;
    hy2-tun-threads)
        TENV="STEER_TUN_THREADS=4"; tun_up "$L_BASE" || return 1
        r=0
        o=$(cli 90 echo 7000 262144 40) || r=1; echo "    $o"
        c=$(qconns); echo "    QUIC connections with 4 loop threads: $c"
        [ "$c" -ge 1 ] && [ "$c" -le 4 ] || r=1
        clean_log || r=1
        return $r ;;
    # catches a half-close that ends the download: the reply after the client's FIN must arrive whole
    hy2-tun-halfclose)
        tun_up "$L_BASE" || return 1
        o=$(cli 30 halfclose 7008); rc=$?; echo "    $o"
        [ "$rc" -eq 0 ] ;;
    # catches flows over a node's stream limit being lost
    hy2-tun-concurrent)
        rc=0
        tun_up "$L_BASE" || return 1
        ip netns exec "$NSC" timeout -k 2 120 python3 "$W/cli.py" concurrent "$TARGET" 7000 24 12 0 > "$W/conc.out" 2>&1 || rc=1
        echo "    default limit: $(cat "$W/conc.out")"
        tun_down
        tun_up "$(hy $P_STR S)" || return 1
        ip netns exec "$NSC" timeout -k 2 120 python3 "$W/cli.py" concurrent "$TARGET" 7000 24 12 8 > "$W/conc.out" 2>&1 & CP=$!
        sleep 6
        one_conn "6 s into the 24 flows on 8 streams" "$P_STR" || rc=1
        wait "$CP" || rc=1
        echo "    8 streams: $(cat "$W/conc.out")"
        [ "$rc" -eq 0 ] ;;
    # catches a first flight past the early buffer on a fresh link: the client times out before the link is up
    hy2-tun-first16k)
        tun_up "$L_BASE" || return 1
        r=0; q=$(qany); set -- $(tcpc)
        o=$(cli 30 echo 7000 16384 1) || r=1; echo "    $o"
        set -- "$@" $(tcpc)
        echo "    QUIC links before the flow $q; TCP retransmitted segments $(($4 - $1)), timeouts $(($5 - $2))"
        [ "$q" -eq 0 ] && [ $(($5 - $2)) -eq 0 ] || r=1
        return $r ;;
    # catches a flow offered more window than the early buffer while the node is slow to answer: the client loses segments
    hy2-tun-slowdial)
        tun_up "$L_BASE" || return 1
        ip netns exec "$NSS" tc qdisc replace dev hts0 root netem delay 1500ms limit 1000
        r=0; q=$(qany); set -- $(tcpc); t0=$(now)
        o=$(cli 60 echo 7000 65536 1) || r=1; echo "    $o, in $(since "$t0") s"
        set -- "$@" $(tcpc)
        ip netns exec "$NSS" tc qdisc del dev hts0 root 2>/dev/null || true
        echo "    every datagram of the server 1.5 s late; QUIC links before the flow $q; TCP retransmitted segments $(($4 - $1)), timeouts $(($5 - $2)), zero-window probes $(($6 - $3))"
        [ "$q" -eq 0 ] && [ $(($4 - $1)) -eq 0 ] && [ $(($5 - $2)) -eq 0 ] || r=1
        [ $(($6 - $3)) -ge 1 ] || { echo "    the client never sat at a zero window"; r=1; }
        clean_log || r=1
        return $r ;;
    hy2-tun-silent)
        ip netns exec "$NSS" nft -f - <<NFT
table inet h2sil { chain in { type filter hook input priority -300; policy accept; udp dport $P_SIL drop; }; }
NFT
        tun_up "$(hy $P_SIL Q)" || return 1
        o=$(cli 40 fail 7000); echo "    $o"
        ip netns exec "$NSS" nft delete table inet h2sil
        g=$(printf '%s\n' "$o" | sed -n 's/^silent: failed after \([0-9.]*\) s.*/\1/p')
        [ -n "$g" ] && awk -v g="$g" 'BEGIN { exit !(g >= 7 && g <= 10) }' ;;
    # catches a link that never hops or a hop that cuts or stalls a flow, leaks a descriptor or repeats the ready line
    hy2-tun-hop) hop_run ;;
    # catches a hop that closes the old port at once: on a 20 ms line the server's packets in flight meet a closed port
    hy2-tun-hop-delay)
        ip netns exec "$NSC" tc qdisc replace dev htc0 root netem delay 20ms limit 1000
        ip netns exec "$NSS" tc qdisc replace dev hts0 root netem delay 20ms limit 1000
        echo "    line: 20 ms each way"
        r=0; hop_run || r=1
        ip netns exec "$NSC" tc qdisc del dev htc0 root 2>/dev/null || true
        ip netns exec "$NSS" tc qdisc del dev hts0 root 2>/dev/null || true
        return $r ;;
    # compares REMOTE-only hops behind a DNAT range with Xray's own client on the same outbound: both work through the source remap
    hy2-tun-hop-remote)
        tun_file intervalRemote "$P_BASE" || return 1
        r=0; hop_m; FDB=$(fdn "$TPID")
        icmp_ctl || r=1
        echo "    the loads differ in entry path: ours through the TUN device, Xray's through its SOCKS inbound"
        hop_flush
        sampler ours "$TPID" "$W/smp-$MODE.txt"
        o=$(cli $((HDUR + 40)) soak 7000 "$HDUR" 2); oi=$?; echo "    ours: $o"
        sampler_stop
        eval "$(hop_sum "$W/smp-$MODE.txt")"; hop_print ours
        [ "$HIT" -ge "$M" ] || { echo "    fewer than $M ports hit"; r=1; }
        [ "$NLP" -eq 1 ] || { echo "    our local port took $NLP values"; r=1; }
        icmp_zero ours || r=1
        oo="intact $([ "$oi" -eq 0 ] && echo yes || echo no), $([ "$HIT" -ge "$M" ] && echo hopped || echo "not hopped"), $NLP local port, $(gap_class "$(soak_gap "$o")")"
        oc="$NP/$OD"
        ready_lines || r=1
        fd_back "$FDB" 45 || r=1
        tun_down
        xc_run intervalRemote "$P_BASE" || return 1
        hop_flush
        sampler xray "$CPID" "$W/smp-$MODE-x.txt"
        o=$(soak_xc); xi=$?; echo "    Xray: $o"
        sampler_stop
        eval "$(hop_sum "$W/smp-$MODE-x.txt")"; hop_print xray
        xc_down
        xo="intact $([ "$xi" -eq 0 ] && echo yes || echo no), $([ "$HIT" -ge "$M" ] && echo hopped || echo "not hopped"), $NLP local port, $(gap_class "$(soak_gap "$o")")"
        echo "    outcome: ours $oo, NoPorts/OutDestUnreachs $oc; Xray's $xo, NoPorts/OutDestUnreachs $NP/$OD"
        [ "$oi" -eq 0 ] && [ "$xi" -eq 0 ] || { echo "    not both intact: no equal outcome"; r=1; }
        [ "$oo" = "$xo" ] || { echo "    FINDING: our outcome differs from Xray's own client's"; r=1; }
        eval "$(np_own)"
        [ "$OWN" -eq 0 ] || echo "    recorded: Xray's own client drew $OWN port unreachables on its own ports during its hops ($OTU); our case is not judged on it"
        return $r ;;
    # catches a local hop that moves the remote port or loses data: every packet to the real port, new local ports
    hy2-tun-hop-local)
        tun_file intervalLocal "$P_BASE" || return 1
        r=0; FDB=$(fdn "$TPID")
        hop_flush
        sampler ours "$TPID" "$W/smp-$MODE.txt"
        o=$(cli $((HDUR + 40)) soak 7000 "$HDUR" 2) || r=1; echo "    $o"
        sampler_stop
        eval "$(hop_sum "$W/smp-$MODE.txt")"; hop_print ours
        [ "$HIT" -eq 0 ] && [ "$REAL" -gt 0 ] || { echo "    packets went to a hop port"; r=1; }
        [ "$NLP" -ge 2 ] || { echo "    the local port did not change"; r=1; }
        ready_lines || r=1
        fd_back "$FDB" 45 || r=1
        return $r ;;
    # shows a hopping link whose server goes silent at once is cut 15-20 s after the drop and gives its descriptors back
    hy2-tun-hop-dead)
        tun_up "$L_HOP" || return 1
        r=0; FDB=$(fdn "$TPID")
        echo "    variant: at 10 s the redirect is deleted and everything between server and client dropped at the same moment, so"
        echo "    no authenticated packet arrives after the drop: the cut is due 15 s after the last one, plus the re-arm of up to 5 s"
        sampler ours "$TPID" "$W/smp-$MODE.txt"
        ip netns exec "$NSC" timeout -k 2 100 python3 "$W/cli.py" watch "$TARGET" 7000 90 > "$W/watch.out" 2>&1 & WP=$!
        sleep 8.5
        : > "$W/sstop"
        td=$(now)
        ip netns exec "$NSS" nft flush chain ip hop pre
        ip netns exec "$NSS" nft -f - <<NFT
table inet hopdrop { chain i { type filter hook prerouting priority -400; ip saddr $C_IP drop; }; chain o { type filter hook output priority -400; ip daddr $C_IP drop; }; }
NFT
        sampler_stop
        eval "$(hop_sum "$W/smp-$MODE.txt")"
        echo "    before the drop: hops seen $HOPS:$SEQ; local ports $NLP:$LPS"
        [ "$HOPS" -ge 1 ] && [ "$NLP" -ge 2 ] || { echo "    the link did not hop before the drop"; r=1; }
        wait "$WP" || true
        c=$(watch_end "$W/watch.out" "$td")
        echo "    the flow: $(cut -d' ' -f5- "$W/watch.out"); it ended $c s after the drop"
        echo "    bound: 15 s after the last authenticated packet, which is at most one 0.2 s echo period before the drop, less 0.1 s"
        echo "    for the timers of the loop and the watch: from 14.7 s; at most 5 s more for the re-arm and the same 0.3 s: to 20.3 s"
        awk -v c="$c" 'BEGIN { exit !(c >= 14.7 && c <= 20.3) }' || { echo "    not 14.7-20.3 s after the drop"; r=1; }
        ready_lines || r=1
        fd_back "$FDB" "$(awk -v t="$td" -v n="$(now)" 'BEGIN { d = int(35 - (n - t)); print (d > 0 ? d : 0) }')" || { echo "    not within 35 s of the drop"; r=1; }
        n0=$(wc -l < "$W/kev"); t0=$(now)
        hop_pre; ip netns exec "$NSS" nft delete table inet hopdrop
        evwait '"type":"active","nodes":["H"]' 40 $((n0 + 1)) && echo "    H active again $(since "$t0") s after the rules came back" ||
            { echo "    H not active again within 40 s"; r=1; }
        o=$(cli 40 echo 7000 1000 1) || r=1; echo "    a new flow after that: $o"
        return $r ;;
    # catches a link that hangs when every new source port is dropped: the liveness rule cuts it and a new flow dials
    hy2-tun-hop-newport)
        tun_up "$L_HOP" || return 1
        r=0
        ip netns exec "$NSC" nft -f - <<NFT
table ip hopb { set first { type inet_service; size 1; flags dynamic; }; chain o { type filter hook output priority 10; ip daddr $S_IP udp sport @first accept; ip daddr $S_IP meta l4proto udp add @first { udp sport } accept; ip daddr $S_IP meta l4proto udp drop; }; }
NFT
        echo "    expected: the first hop 5 s after the link starts, the old socket read for its 2 s linger, the cut 15 s after"
        echo "    the last packet plus up to 5 s: 20 to 27 s after the flow starts"
        ip netns exec "$NSC" timeout -k 2 100 python3 "$W/cli.py" watch "$TARGET" 7000 90 > "$W/watch.out" 2>&1
        set -- $(cat "$W/watch.out")
        c=$(awk -v a="$2" -v b="$4" 'BEGIN { printf "%.1f", b - a }')
        echo "    the flow: $(cut -d' ' -f5- "$W/watch.out"); it ended $c s after it started; source ports let through: $(ip netns exec "$NSC" nft list set ip hopb first | tr -d '\n' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p')"
        awk -v c="$c" 'BEGIN { exit !(c >= 19 && c <= 28) }' || { echo "    not 20-27 s after its start (1 s allowed for the dial)"; r=1; }
        ready_lines || r=1
        ip netns exec "$NSC" nft delete table ip hopb
        o=$(cli 40 echo 7000 1000 1) || r=1; echo "    a new flow without the filter: $o"
        return $r ;;
    # catches a hop whose socket cannot be made: one warning per link, the flow stays on its port, hops resume after
    hy2-tun-hop-nofd)
        tun_up "$L_HOP" || return 1
        r=0
        ip netns exec "$NSC" timeout -k 2 80 python3 "$W/cli.py" soak "$TARGET" 7000 36 1 > "$W/soak.out" 2>&1 & SP=$!
        i=0; while [ $i -lt 100 ] && [ "$(qany)" -ne 1 ]; do sleep 0.1; i=$((i + 1)); done
        sleep 3
        i=0; while [ $i -lt 100 ] && [ "$(qany)" -ne 1 ]; do sleep 0.1; i=$((i + 1)); done
        set -- $(prlimit --pid "$TPID" --nofile --noheadings --output SOFT,HARD)
        s0=$1; hd=$2
        lim=$(ls "/proc/$TPID/fd" | sort -n | awk 'BEGIN { e = 0 } $1 == e { e++ } END { print e }')
        p0=$(lports)
        prlimit --pid "$TPID" --nofile="$lim:$hd"
        echo "    descriptors held $(fdn "$TPID"), soft limit $s0 -> $lim (the lowest free number) for 12 s; local port $p0"
        sleep 12
        p1=$(lports); nf=$(grep -c 'port hop failed, staying on' "$TLOG" || true)
        prlimit --pid "$TPID" --nofile="$s0:$hd"
        sleep 11
        p2=$(lports)
        wait "$SP" || r=1
        echo "    $(cat "$W/soak.out")"
        echo "    local ports: before $p0, at the end of the limit $p1, 11 s after it $p2; hop-failure lines $nf"
        ready_lines || r=1
        [ "$nf" -eq 1 ] && [ "$(grep -c 'port hop failed, staying on' "$TLOG")" -eq 1 ] || { echo "    not one hop-failure line"; r=1; }
        [ "$p1" = "$p0" ] || { echo "    the local port moved while no socket could be made"; r=1; }
        [ -n "$p2" ] && [ "$p2" != "$p0" ] || { echo "    no hop after the limit was lifted"; r=1; }
        return $r ;;
    # records the CPU a hopping link costs per MB against one port on a 40 Mbit/s line with a 50 ms RTT
    hy2-tun-hop-cost)
        ip netns exec "$NSC" tc qdisc replace dev htc0 root netem delay 25ms rate 40mbit limit 1000
        ip netns exec "$NSS" tc qdisc replace dev hts0 root netem delay 25ms rate 40mbit limit 1000
        : > "$W/cost"; r=0; TENV="TUNVLESS_NO_BATCH=1"
        k=1
        while [ $k -le "$CRUNS" ]; do
            for kind in plain hop; do
                if [ $kind = hop ]; then l=$L_HOP; else l=$L_ONE; fi
                tun_up "$l" || { r=1; tun_down; continue; }
                grep -qxF 'tunvless[info]: UDP batching off' "$TLOG" || { echo "    the client does not say UDP batching off"; r=1; }
                n0=$(nftcnt); c0=$(cpu_of "$TPID")
                o=$(cli $((CDUR + 40)) down 7009 "$CDUR") || r=1
                c1=$(cpu_of "$TPID"); n1=$(nftcnt)
                ph=$(awk -v a="$n0" -v b="$n1" 'BEGIN { split(a, x, " "); split(b, y, " "); for (i = 1; i <= 10; i++) h += y[i] > x[i]; print h }')
                b=$(printf '%s\n' "$o" | awk '/^down [0-9]+$/ { print $2 }')
                if [ -n "$b" ]; then
                    awk -v k="$kind" -v b="$b" -v c0="$c0" -v c1="$c1" -v t="$TCK" -v d="$CDUR" \
                        'BEGIN { s = (c1 - c0) / t; printf "%s %.4f %.3f %.2f\n", k, s / (b / 1e6), b / d / 1e6, s }' >> "$W/cost"
                    echo "    run $k $kind: $(tail -1 "$W/cost" | awk '{ print $2 " CPU-s/MB, " $3 " MB/s, " $4 " CPU-s" }'), $ph ports used, $(grep -c 'link ready' "$TLOG") ready line"
                else echo "    run $k $kind: no count ($o)"; r=1; fi
                tun_down
            done
            k=$((k + 1))
        done
        ip netns exec "$NSC" tc qdisc del dev htc0 root 2>/dev/null || true
        ip netns exec "$NSS" tc qdisc del dev hts0 root 2>/dev/null || true
        for kind in plain hop; do
            awk -v k="$kind" '$1 == k { print $2 }' "$W/cost" | sort -n | awk -v k="$kind" '{ a[NR] = $1 } END { if (NR) printf "%s %s %s %s\n", k, a[1], (NR % 2 ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2), a[NR] }'
        done > "$W/cost-sum"
        while read -r kind lo md hi; do echo "    $kind: CPU-s/MB min $lo, median $md, max $hi over $CRUNS runs of $CDUR s"; done < "$W/cost-sum"
        set -- $(tr '\n' ' ' < "$W/cost-sum")
        [ $# -eq 8 ] || return 1
        if awk -v pm="$3" -v hm="$7" -v pmax="$4" -v hmin="$6" 'BEGIN { exit !(hm > pm * 1.03 && hmin > pmax) }'; then
            echo "    the hopping median is more than 3 % above the plain one and the ranges do not overlap: report it"
        else echo "    the hopping median is within 3 % of the plain one, or the ranges overlap"; fi
        return $r ;;
    *) echo "hy2-tun: unknown case $MODE"; exit 2 ;;
    esac
}

FAIL=0; SKIPPED=""
for MODE in $CASES; do
    echo "hy2-tun: case $MODE"
    case "$MODE" in hy2-tun-ktcp|hy2-tun-silent|hy2-tun-hop*)
        [ -n "$NFT" ] || { echo "hy2-tun: case $MODE — SKIPPED (no nft; not passed)"; SKIPPED="$SKIPPED $MODE"; continue; } ;;
    esac
    case "$MODE" in hy2-tun-hop-nofd)
        [ -n "$PRL" ] || { echo "hy2-tun: case $MODE — SKIPPED (no prlimit; not passed)"; SKIPPED="$SKIPPED $MODE"; continue; } ;;
    esac
    case "$MODE" in hy2-tun-hop-cost|hy2-tun-hop-delay|hy2-tun-slowdial)
        [ -n "$TC" ] && ip netns exec "$NSC" tc qdisc replace dev htc0 root netem delay 1ms 2>/dev/null &&
            ip netns exec "$NSC" tc qdisc del dev htc0 root 2>/dev/null ||
            { echo "hy2-tun: case $MODE — SKIPPED (no tc netem; not passed)"; SKIPPED="$SKIPPED $MODE"; continue; } ;;
    esac
    case "$MODE" in hy2-tun-hop*) hop_nft ;; esac
    [ "$HDUR$CDUR$CRUNS" = 45305 ] || case "$MODE" in hy2-tun-hop*) echo "hy2-tun: HOP_DUR=$HDUR HOP_COST_DUR=$CDUR HOP_COST_RUNS=$CRUNS — NOT binding" ;; esac
    if run_case; then echo "hy2-tun: case $MODE — ok"; else
        FAIL=1; echo "hy2-tun: case $MODE — FAIL"
        [ -z "${TLOG:-}" ] || [ ! -f "$TLOG" ] || tail -8 "$TLOG" | sed 's/^/    log: /'
    fi
    tun_down; xc_down; sampler_stop; hop_nft_down
    kill -0 "$XPID" 2>/dev/null || { echo "hy2-tun: the Xray server died:"; tail -20 "$W/xray.log"; exit 1; }
done

[ "$FAIL" -eq 0 ] || { echo "hy2-tun: FAILED"; exit 1; }
[ -z "$SKIPPED" ] || { echo "hy2-tun: SKIPPED, not passed:$SKIPPED"; exit 2; }
echo "hy2-tun: all checks passed"
