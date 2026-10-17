#!/bin/sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BE=$(cd "$HERE/../.." && pwd)
SAN=address,undefined,float-cast-overflow

if [ "${FIRC_IFC_E2E_INNER:-}" != 1 ]; then
    make -s -C "$BE" BUILD=sanitize OPT="-O1 -g -fsanitize=$SAN -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=$SAN" build/sanitize/fircd >/dev/null || exit 1
    T=$(mktemp -d)
    mkdir -p "$T/up" "$T/work"
    FIRC_IFC_E2E_INNER=1 unshare -Urmn sh -c "mount -t tmpfs tmpfs /run && \
        mount -t overlay overlay -o lowerdir=/etc,upperdir=$T/up,workdir=$T/work /etc && \
        exec sh '$HERE/ifcheck.sh'"
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
G=0000ac01 H=0000ac02
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${FP:-}" ] && kill "$FP" 2>/dev/null && wait "$FP" 2>/dev/null
    [ -n "${DNS:-}" ] && kill "$DNS" 2>/dev/null
    for n in ic0 ic1 icw ik0 ik1 ik2 icc; do
        ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del $n 2>/dev/null
    done
    if [ "$fail" != 0 ]; then echo "--- fircd log (tail)"; tail -n 80 "$W/fircd.log" 2>/dev/null; fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

cat > "$W/ic.py" <<'PY'
import os, socket, struct, sys, threading, time, http.server

def dns(port, *pairs):
    names = dict(p.split("=") for p in pairs)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", int(port)))
    while True:
        q, peer = s.recvfrom(1500)
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode())
            i += 1 + q[i]
        addr = names.get(".".join(labels).lower())
        qtype = q[i + 1:i + 3]
        addr = addr if qtype == b"\x00\x01" else None
        known = ".".join(labels).lower() in names
        head = q[:2] + (b"\x81\x80" if known else b"\x81\x83") + q[4:6] + (b"\x00\x01" if addr else b"\x00\x00") + b"\x00" * 4
        body = q[12:i + 5]
        if addr:
            body += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(addr)
        s.sendto(head + body, peer)

def serve(side, flag, hits, reqs, slow):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path == "/generate_204":
                with open(reqs, "a") as f:
                    f.write("req\n")
                if os.path.exists(slow):
                    time.sleep(60)
                self.send_response(204 if os.path.exists(flag) else 503)
                self.end_headers()
                return
            with open(hits, "a") as f:
                f.write("hit\n")
            body = side.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    def echo():
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 7))
        srv.listen(8)
        def one(c):
            try:
                while True:
                    d = c.recv(64)
                    if not d:
                        break
                    c.sendall(d)
            except OSError:
                pass
            c.close()
        while True:
            c, _ = srv.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=echo, daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()

def q(server, port, name):
    pkt = os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    pkt += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(pkt, (server, int(port)))
    a, _ = s.recvfrom(1500)
    count = struct.unpack(">H", a[6:8])[0]
    i = 12
    while a[i]:
        i += 1 + a[i]
    i += 5
    for _ in range(count):
        if a[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while a[i]:
                i += 1 + a[i]
            i += 1
        t, _, _, ln = struct.unpack(">HHIH", a[i:i + 10])
        i += 10
        if t == 1 and ln == 4:
            print(socket.inet_ntoa(a[i:i + 4]))
            return
        i += ln

def hold(addr, out):
    c = socket.create_connection((addr, 7), timeout=5)
    try:
        while True:
            c.sendall(b"x")
            if c.recv(1) != b"x":
                raise OSError("closed")
            time.sleep(0.5)
    except OSError:
        with open(out, "a") as f:
            f.write("reset %d\n" % int(time.time()))

if __name__ == "__main__":
    {"dns": dns, "serve": serve, "q": q, "hold": hold}[sys.argv[1]](*sys.argv[2:])
PY

NS() { ip netns exec "$@"; }
ip link set lo up
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
uplink() {
    ip netns add "$2"
    ip link add "$1" type veth peer name p0 netns "$2"
    ip addr add "$3/24" dev "$1"
    ip link set "$1" up
    NS "$2" ip link set lo up
    NS "$2" sysctl -qw net.ipv4.conf.all.rp_filter=0
    NS "$2" ip addr add "$4/24" dev p0
    NS "$2" ip link set p0 up
    NS "$2" ip route add default via "$3"
    NS "$2" ip addr add 10.99.0.1/32 dev lo
    NS "$2" ip addr add 10.98.0.1/32 dev lo
    touch "$W/ok-$2"
    NS "$2" python3 "$W/ic.py" serve "$2" "$W/ok-$2" "$W/hits-$2" "$W/req-$2" "$W/slow" > "$W/srv-$2.log" 2>&1 &
}
uplink up0 ic0 10.71.0.2 10.71.0.1
uplink up1 ic1 10.72.0.2 10.72.0.1
uplink wan icw 10.73.0.2 10.73.0.1
uplink lk0 ik0 10.74.0.2 10.74.0.1
uplink lk1 ik1 10.75.0.2 10.75.0.1
uplink lk2 ik2 10.76.0.2 10.76.0.1
ip route add default via 10.73.0.1 dev wan
ip route add default via 10.71.0.1 dev up0 metric 100
ip route add default via 10.72.0.1 dev up1 metric 200
sysctl -qw net.ipv6.conf.lk0.disable_ipv6=1
ip route add default via 10.75.0.1 dev lk1 metric 400
ip route add default via 10.76.0.1 dev lk2 metric 500
ip netns add icc
ip link add lan type veth peer name c0 netns icc
ip addr add 10.70.0.1/24 dev lan
ip link set lan up
NS icc ip link set lo up
NS icc ip addr add 10.70.0.2/24 dev c0
NS icc ip link set c0 up
NS icc ip route add default via 10.70.0.1
python3 "$W/ic.py" dns 15353 check.test=10.99.0.1 site.test=10.98.0.1 h.test=10.98.0.1 &
DNS=$!

conf() {
    cat > /etc/firc/firc.conf <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: false
  dnsProxy:
    host: {address: "10.70.0.1", port: 13598}
    upstream: {address: 127.0.0.1, port: 15353}
    disableRemap53: true
  netfilter:
    iptables: {chainPrefix: FIRC_}
  link: [lan]
  check: {url: "http://check.test/generate_204", interval: 10s, timeout: $1}
EOF
}
mkdir -p /etc/firc
conf 2s
cat > /etc/firc/groups.yaml <<EOF
configVersion: 0.7.0
groups:
  - id: $G
    name: G
    interface: [up0, up1]
    enable: true
    rules:
      - {id: 0000ad01, type: domain, rule: site.test, enable: true}
  - id: $H
    name: H
    interface: [lk0, lk1, lk2]
    enable: true
    rules:
      - {id: 0000ad02, type: domain, rule: h.test, enable: true}
EOF
"$FIRCD" --config /etc/firc/firc.conf > "$W/fircd.log" 2>&1 &
FP=$!

group() {
    curl -s --unix-socket "$SOCK" "http://firc/api/v1/groups/$1" 2>/dev/null | python3 -c "$2" 2>/dev/null
}
active() { group "$1" 'import json, sys; print(json.load(sys.stdin).get("active", ""))'; }
states() {
    group "$1" 'import json, sys; print(" ".join(e["name"] + ":" + e["state"] for e in json.load(sys.stdin).get("interfaces", [])))'
}
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
journal() {
    s=0
    : > "$W/ev"
    while :; do
        curl -s --unix-socket "$SOCK" "http://firc/api/v1/system/events?since=$s" > "$W/page" 2>/dev/null || return
        cat "$W/page" >> "$W/ev"
        r=$(python3 -c 'import json, sys; d = json.load(sys.stdin); print(len(d["events"]), int(d["next"]))' < "$W/page" 2>/dev/null)
        [ "${r%% *}" -ge 1024 ] 2>/dev/null || return 0
        s=${r#* }
    done
}
said() { journal; grep -oF "$1" "$W/ev" | wc -l; }
hits() { cat "$W/hits-$1" 2>/dev/null | wc -l; }
side() { NS icc curl -s -m 3 "http://$1/"; }
group_table() {
    for t in $(ip rule show priority 50 | sed -n 's/.*lookup \([0-9a-z]*\).*/\1/p' | sort -u); do
        ip route show table "$t" | grep -q "dev $1 " && { echo "$t"; return; }
    done
}
via() { ip route show table "$HT" | grep -v '^blackhole' | sed -n 's/.* dev \([a-z0-9]*\) .*/\1/p' | tr '\n' ' ' | sed 's/ $//'; }
rule48() { ip rule show priority 48 | wc -l; }
reqs() { cat "$W"/req-* 2>/dev/null | wc -l; }
resets() { cat "$W/$1.out" 2>/dev/null | grep -c reset; }
alive() {
    s=$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)
    [ -n "$s" ] && [ "$s" != Z ]
}

wait_for 15 up0 active $G
check "the group starts on its first entry" 0 "$?"
wait_for 15 lk0 active $H
check "the three-entry group starts on its first entry" 0 "$?"
F=$(NS icc python3 "$W/ic.py" q 10.70.0.1 13598 site.test)
check "the client gets a fake address" 1 "$(echo "$F" | grep -c '^198\.1[89]\.')"
FH=$(NS icc python3 "$W/ic.py" q 10.70.0.1 13598 h.test)
check "the client gets a fake address for H" 1 "$(echo "$FH" | grep -c '^198\.1[89]\.')"
check "up0's side answers the fake address" ic0 "$(side "$F")"
check "lk0's side answers H's fake address" ik0 "$(side "$FH")"
HT=$(group_table lk0)
check "H's table routes by lk0 alone" lk0 "$(via)"

NS icc python3 "$W/ic.py" hold "$F" "$W/hold1.out" &
sleep 2
rm -f "$W/ok-ic0"
wait_for 30 up1 active $G
check "case 1: a dead up0 moves the group to up1" 0 "$?"
check "case 1: the API says up0 dead and up1 alive" "up0:dead up1:alive" "$(states $G)"
sleep 3
check "case 1: the flow held on up0 was reset by the move" 1 "$(resets hold1)"
before=$(hits ic0)
check "case 1: the fake address is answered from up1's side" ic1 "$(side "$F")"
check "case 1: nothing of the group reaches up0 after the move" "$before" "$(hits ic0)"
check "case 1: no packet of the group left by the WAN" 0 "$(hits icw)"
check "case 1: the move is said" 1 "$(said 'group G moved from up0 to up1')"

NS icc python3 "$W/ic.py" hold "$F" "$W/hold2.out" &
sleep 2
touch "$W/ok-ic0"
t0=$(date +%s)

ip link set lk0 down
wait_for 2 lk1 active $H
check "case 4: lk0 going down moves H to lk1 within 2 s" 0 "$?"
check "case 4: the move off lk0 is said once" 1 "$(said 'group H moved from lk0 to lk1')"
check "case 4: the API says lk0 dead and the others alive" "lk0:dead lk1:alive lk2:alive" "$(states $H)"
wait_for 5 lk1 via
check "case 4: H's table routes by lk1 alone" lk1 "$(via)"
check "case 4: H's fake address is answered from lk1's side" ik1 "$(side "$FH")"

ip route del default table "$HT" dev lk1 metric 10
sleep 1
check "case 5: H's route by lk1 stays gone without an event" "" "$(via)"
ip link set lk1 mtu 1400
wait_for 5 lk1 via
check "case 5: a link-up event on the active lk1 writes its route back" 0 "$?"
ip route del default table "$HT" dev lk1 metric 10
sleep 1
check "case 5: H's route by lk1 is gone again" "" "$(via)"
ip addr add 10.75.0.9/32 dev lk1
wait_for 5 lk1 via
check "case 5: an address change on the active lk1 writes its route back" 0 "$?"
check "case 5: H stays on lk1 through both events" lk1 "$(active $H)"

ip link del lk1
wait_for 10 lk2 active $H
check "case 6: deleting lk1 moves H to lk2" 0 "$?"
check "case 6: the move off lk1 is said once" 1 "$(said 'group H moved from lk1 to lk2')"
check "case 6: the link going down and its removal both reach the daemon" 2 "$(said 'interface down: lk1')"
check "case 6: the API says lk0 and lk1 dead, lk2 alive" "lk0:dead lk1:dead lk2:alive" "$(states $H)"
wait_for 5 lk2 via
check "case 6: H's table routes by lk2 alone" lk2 "$(via)"
check "case 6: H's fake address is answered from lk2's side" ik2 "$(side "$FH")"

left=$((t0 + 100 - $(date +%s)))
[ "$left" -gt 0 ] && sleep "$left"
check "case 2: the hold keeps the group on up1 at 100 s" up1 "$(active $G)"
check "case 2: the held flow is untouched before the move back" 0 "$(resets hold2)"
wait_for 45 up0 active $G
check "case 2: the group is back on up0 after the hold" 0 "$?"
check "case 2: the move back is said once" 1 "$(said 'group G moved back from up1 to up0')"
sleep 3
check "case 2: the held flow was reset once" 1 "$(resets hold2)"
check "case 2: up0's side answers again" ic0 "$(side "$F")"
check "case 2: no packet of the group left by the WAN" 0 "$(hits icw)"

dead_before=$(said 'is dead')
warn_before=$(said 'the interface check fails, even through the WAN')
rm -f "$W/ok-ic0" "$W/ok-ic1" "$W/ok-icw"
sleep 40
check "case 3: a check failing everywhere moves nobody" "up0 lk2" "$(active $G) $(active $H)"
check "case 3: the WARN names the check" yes "$([ "$(said 'the interface check fails, even through the WAN')" -gt "$warn_before" ] && echo yes || echo no)"
check "case 3: no interface is said dead" "$dead_before" "$(said 'is dead')"
check "case 3: no packet of the group left by the WAN" 0 "$(hits icw)"

check "case 7: every checked interface holds its check rule" 5 "$(rule48)"
touch "$W/slow"
conf 20s
kill -HUP "$FP"
sleep 5
check "case 7: a reload keeps both groups where they are" "up0 lk2" "$(active $G) $(active $H)"
n=$(reqs)
i=0
while [ $i -lt 300 ] && [ "$(reqs)" -le "$n" ]; do sleep 0.2; i=$((i + 1)); done
check "case 7: a check is in flight against a host that does not answer" yes "$([ "$(reqs)" -gt "$n" ] && echo yes || echo no)"
sleep 0.5
t1=$(date +%s%N)
kill -TERM "$FP"
i=0
while [ $i -lt 50 ] && alive "$FP"; do sleep 0.1; i=$((i + 1)); done
ms=$((($(date +%s%N) - t1) / 1000000))
stuck=no
if alive "$FP"; then stuck=yes; kill -9 "$FP"; fi
wait "$FP"
rc=$?
FP=
check "case 7: fircd stops within 5 s with a check in flight" "no yes" "$stuck $([ "$ms" -lt 5000 ] && echo yes || echo no)"
check "case 7: fircd exits 0" 0 "$rc"
check "case 7: no sanitizer report in the log" 0 "$(grep -c 'Sanitizer\|runtime error' "$W/fircd.log")"
check "case 7: the stop takes every check rule back" 0 "$(rule48)"

echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
