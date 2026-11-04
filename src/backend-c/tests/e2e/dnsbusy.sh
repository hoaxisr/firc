#!/bin/sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BE=$(cd "$HERE/../.." && pwd)
SAN=address,undefined,float-cast-overflow

if [ "${FIRC_DNSBUSY_E2E_INNER:-}" != 1 ]; then
    make -s -C "$BE" BUILD=sanitize OPT="-O1 -g -fsanitize=$SAN -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=$SAN" build/sanitize/fircd >/dev/null || exit 1
    T=$(mktemp -d)
    mkdir -p "$T/up" "$T/work"
    FIRC_DNSBUSY_E2E_INNER=1 unshare -Urmn sh -c "mount -t tmpfs tmpfs /run && \
        mount -t overlay overlay -o lowerdir=/etc,upperdir=$T/up,workdir=$T/work /etc && \
        exec sh '$HERE/dnsbusy.sh'"
    rc=$?
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
    exit $rc
fi

FIRCD=$BE/build/sanitize/fircd
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
SOCK=/run/firc/firc.sock
W=$(mktemp -d)
export FIRC_TUNNELS_CACHE_DIR="$W/cache" FIRC_UPDATE_DIR="$W/update" FIRC_HWID_PATH="$W/hwid"
G=0000db01
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${FP:-}" ] && kill "$FP" 2>/dev/null && wait "$FP" 2>/dev/null
    [ -n "${SQ:-}" ] && kill "$SQ" 2>/dev/null
    [ -n "${ST:-}" ] && kill "$ST" 2>/dev/null
    [ -n "${UP:-}" ] && kill "$UP" 2>/dev/null
    ip netns pids dbc 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del dbc 2>/dev/null
    if [ "$fail" != 0 ]; then echo "--- fircd log (tail)"; tail -n 60 "$W/fircd.log" 2>/dev/null; fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

cat > "$W/db.py" <<'PY'
import os, socket, struct, sys, time

def upstream(port, name, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", int(port)))
    while True:
        q, peer = s.recvfrom(1500)
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode())
            i += 1 + q[i]
        hit = ".".join(labels).lower() == name and q[i + 1:i + 3] == b"\x00\x01"
        head = q[:2] + b"\x81\x80" + q[4:6] + (b"\x00\x01" if hit else b"\x00\x00") + b"\x00" * 4
        body = q[12:i + 5]
        if hit:
            body += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(addr)
        s.sendto(head + body, peer)

def squat(port, answer):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("::", int(port)))
    while True:
        q, peer = s.recvfrom(1500)
        i = 12
        while q[i]:
            i += 1 + q[i]
        head = q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01" + b"\x00" * 4
        body = q[12:i + 5] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(answer)
        s.sendto(head + body, peer)

def squat_tcp(port):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.bind(("::", int(port)))
    s.listen(1)
    while True:
        time.sleep(60)

def q(server, port, name):
    pkt = os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    pkt += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(pkt, (server, int(port)))
    try:
        a, _ = s.recvfrom(1500)
    except OSError:
        print("no answer")
        return
    count = struct.unpack(">H", a[6:8])[0]
    i = 12
    while a[i]:
        i += 1 + a[i]
    i += 5
    for _ in range(count):
        i += 2 if a[i] & 0xC0 == 0xC0 else a[i] + 1
        t, _, _, ln = struct.unpack(">HHIH", a[i:i + 10])
        i += 10
        if t == 1 and ln == 4:
            print(socket.inet_ntoa(a[i:i + 4]))
            return
        i += ln
    print("no address")

def field(path):
    d = json.load(sys.stdin)
    for k in path.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    print("null" if d is None else str(d).lower() if isinstance(d, bool) else d)

if __name__ == "__main__":
    import json
    {"upstream": upstream, "squat": squat, "squat_tcp": squat_tcp, "q": q, "field": field}[sys.argv[1]](*sys.argv[2:])
PY

ip link set lo up
ip netns add dbc
ip link add lan type veth peer name c0 netns dbc
ip addr add 10.80.0.1/24 dev lan
ip link set lan up
ip netns exec dbc ip link set lo up
ip netns exec dbc ip addr add 10.80.0.2/24 dev c0
ip netns exec dbc ip link set c0 up
python3 "$W/db.py" upstream 15354 site.test 10.98.0.1 &
UP=$!
python3 "$W/db.py" squat 13553 10.66.66.66 &
SQ=$!

mkdir -p /etc/firc
cat > /etc/firc/firc.conf <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: false
  dnsProxy:
    host: {address: "[::]", port: 13553}
    upstream: {address: 127.0.0.1, port: 15354}
  netfilter:
    iptables: {chainPrefix: FIRC_}
  link: [lan]
EOF
cat > /etc/firc/groups.yaml <<EOF
configVersion: 0.7.0
groups:
  - id: $G
    name: G
    interface: blackhole
    enable: true
    rules:
      - {id: 0000dc01, type: domain, rule: site.test, enable: true}
EOF

wait_for() {
    end=$(($(date +%s%N) + $1 * 1000000000))
    want=$2
    shift 2
    while :; do
        [ "$("$@")" = "$want" ] && return 0
        [ "$(date +%s%N)" -lt "$end" ] || return 1
        sleep 0.2
    done
}
api() { curl -s -m 3 --unix-socket "$SOCK" "http://firc/api/v1/$1" 2>/dev/null | python3 "$W/db.py" field "$2" 2>/dev/null; }
alive() { kill -0 "$FP" 2>/dev/null && echo yes || echo no; }
ask() { ip netns exec dbc python3 "$W/db.py" q 10.80.0.1 "${1:-53}" site.test; }
pool() { case "$(ask)" in 198.18.*) echo fake ;; *) ask ;; esac; }

wait_for 5 yes sh -c "ss -lun | grep -q ':13553 ' && echo yes" || { check "the squatter took the port" yes no; exit 1; }
"$FIRCD" --config /etc/firc/firc.conf > "$W/fircd.log" 2>&1 &
FP=$!

wait_for 30 false api system/settings dnsProxy.listening
check "a busy DNS port: the daemon answers on its socket" false "$(api system/settings dnsProxy.listening)"
check "and keeps running" yes "$(alive)"
check "the port it wanted" 13553 "$(api system/settings dnsProxy.port)"
check "the protocol that failed" udp "$(api system/settings dnsProxy.proto)"
check "the holder's pid" "$SQ" "$(api system/settings dnsProxy.holder.pid)"
check "the holder's name" python3 "$(api system/settings dnsProxy.holder.name)"
check "its own route says the same" "false $SQ" "$(api system/dnsproxy listening) $(api system/dnsproxy holder.pid)"
check "the group is not live" false "$(api groups/$G live)"
check "and says why" dns-down "$(api groups/$G liveReason)"
check "fixture: the squatter answers a LAN query sent to its port" 10.66.66.66 "$(ask 13553)"
check "no port-53 redirect: a LAN query to 53 reaches nobody" "no answer" "$(ask)"
check "the log names the holder" 1 "$(grep -c "DNS proxy cannot listen: \[::\]:13553/udp: address already in use by python3 (pid $SQ)" "$W/fircd.log")"
sleep 11
check "the same failure again is not logged again" 0 "$(grep -c "still cannot listen" "$W/fircd.log")"

python3 "$W/db.py" squat_tcp 13553 &
ST=$!
wait_for 5 yes sh -c "ss -ltn | grep -q ':13553 ' && echo yes"
kill "$SQ"
wait "$SQ" 2>/dev/null
SQ=
wait_for 15 tcp api system/settings dnsProxy.proto
check "a new failure: now the TCP socket" tcp "$(api system/settings dnsProxy.proto)"
check "with its holder" "$ST" "$(api system/settings dnsProxy.holder.pid)"
check "logged once" 1 "$(grep -c "DNS proxy still cannot listen: \[::\]:13553/tcp: address already in use by python3 (pid $ST)" "$W/fircd.log")"
check "still degraded" false "$(api system/settings dnsProxy.listening)"

kill "$ST"
wait "$ST" 2>/dev/null
ST=
wait_for 15 true api system/settings dnsProxy.listening
check "freed: the proxy listens without a restart" true "$(api system/settings dnsProxy.listening)"
check "the same daemon" yes "$(alive)"
check "no holder any more" null "$(api system/settings dnsProxy.holder)"
check "and its own route" "true null" "$(api system/dnsproxy listening) $(api system/dnsproxy holder)"
wait_for 10 true api "groups/$G" live
check "the group is live again" true "$(api groups/$G live)"
wait_for 10 fake pool
check "the redirect is back: a LAN query to 53 gets a fake address" fake "$(pool)"

kill "$FP"
wait "$FP"
rc=$?
FP=
check "a clean stop" 0 "$rc"
check "no sanitizer report" 0 "$(grep -c 'ERROR: AddressSanitizer\|runtime error:' "$W/fircd.log")"

echo "dnsbusy: $pass passed, $fail failed"
[ "$fail" = 0 ]
