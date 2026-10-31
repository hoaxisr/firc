#!/bin/sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BE=$(cd "$HERE/../.." && pwd)
SAN=address,undefined,float-cast-overflow

if [ "${FIRC_AL_E2E_INNER:-}" != 1 ]; then
    make -s -C "$BE" BUILD=sanitize OPT="-O1 -g -fsanitize=$SAN -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=$SAN" build/sanitize/fircd >/dev/null || exit 1
    T=$(mktemp -d)
    mkdir -p "$T/up" "$T/work"
    FIRC_AL_E2E_INNER=1 unshare -Urmn sh -c "mount -t tmpfs tmpfs /run && \
        mount -t overlay overlay -o lowerdir=/etc,upperdir=$T/up,workdir=$T/work /etc && \
        exec sh '$HERE/autolist.sh'"
    rc=$?
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
    exit $rc
fi

FIRCD=$BE/build/sanitize/fircd
IPT=iptables-legacy
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
SOCK=/run/firc/firc.sock
W=$(mktemp -d)
export FIRC_TUNNELS_CACHE_DIR="$W/cache" FIRC_UPDATE_DIR="$W/update" FIRC_HWID_PATH="$W/hwid"
G=0000ac01
pass=0 fail=0 J=
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${FP:-}" ] && kill "$FP" 2>/dev/null && wait "$FP" 2>/dev/null
    [ -n "${DNS:-}" ] && kill "$DNS" 2>/dev/null
    for n in alw alt alx alc; do
        ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del $n 2>/dev/null
    done
    echo "--- fircd log (autolist lines)"
    grep -a 'autolist' "$W/fircd.log" 2>/dev/null | tail -n 60
    if [ "$fail" != 0 ]; then echo "--- fircd log (tail)"; tail -n 40 "$W/fircd.log" 2>/dev/null; fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

cat > "$W/al.py" <<'PY'
import json, os, socket, ssl, struct, sys, threading, time, http.server

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
        name = ".".join(labels).lower()
        addr = names.get(name) if q[i + 1:i + 3] == b"\x00\x01" else None
        head = q[:2] + (b"\x81\x80" if name in names else b"\x81\x83") + q[4:6] + (b"\x00\x01" if addr else b"\x00\x00") + b"\x00" * 4
        body = q[12:i + 5]
        if addr:
            body += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(addr)
        s.sendto(head + body, peer)

def serve(side, cert, key):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            host = self.headers.get("Host", "")
            big = self.path in ("/big", "/stall") or "freeze" in host or "frost" in host
            body = (b"x" * 65536) if big else side.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            for i in range(0, len(body), 1024):
                if self.path == "/stall" and i == 16384:
                    time.sleep(20)
                    return
                self.wfile.write(body[i:i + 1024])
                self.wfile.flush()
                time.sleep(0.002)
    class N(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            self.send_response(204)
            self.end_headers()
    plain = http.server.ThreadingHTTPServer(("0.0.0.0", 80), N)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 443), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    srv.serve_forever()

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
        t, _, ttl, ln = struct.unpack(">HHIH", a[i:i + 10])
        i += 10
        if t == 1 and ln == 4:
            print(socket.inet_ntoa(a[i:i + 4]), ttl)
            return
        i += ln

def rules(path):
    g = json.load(open(path))
    for r in g.get("rules", []):
        if r["id"] != "0000ad01":
            print("%s:%s:%s:%s" % (r["rule"], r["type"], r.get("autolist", ""), "on" if r.get("enable") else "off"))

def rule_off(path, name):
    g = json.load(open(path))
    for r in g["rules"]:
        if r["rule"] == name:
            r["enable"] = False
            print(r["id"])
            json.dump(r, open(path + ".rule", "w"))
            return

def st(expr):
    j = json.load(sys.stdin)
    print(eval(expr))

def cand(domain):
    for c in json.load(sys.stdin)["candidates"]:
        if c["domain"] == domain:
            print("%s:%s:%s" % (c["state"], c["why"], c["notes"]))

def cut(host, ip):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=15), server_hostname=host)
    s.sendall(("GET /stall HTTP/1.1\r\nHost: %s\r\n\r\n" % host).encode())
    got = 0
    while got < 16384:
        d = s.recv(4096)
        if not d:
            break
        got += len(d)
    time.sleep(11)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    print(got)

def bydomain(path, name):
    for r in json.load(open(path)).get("rules", []):
        if r["rule"] == name:
            print(r.get("autolistByDomain", False))

def res(host, *fields):
    for r in json.load(sys.stdin)["probes"]["results"]:
        if r["host"] == host:
            print(":".join(str(r[f]) for f in (fields or ("verdict", "why"))))
            return

if __name__ == "__main__":
    {"dns": dns, "serve": serve, "q": q, "rules": rules, "rule_off": rule_off, "st": st, "cand": cand,
     "res": res, "cut": cut, "bydomain": bydomain}[sys.argv[1]](*sys.argv[2:])
PY

openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=stand-ca -days 1 -keyout "$W/ca.key" -out "$W/ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=stand -keyout "$W/key" -out "$W/csr" 2>/dev/null
printf 'subjectAltName=DNS:*.ok.test,DNS:*.drop.test,DNS:*.rst.test,DNS:*.freeze.test,DNS:*.frost.test,DNS:*.late.test,DNS:*.hold.test,DNS:*.small.test,DNS:*.cut.test,DNS:*.many.test,DNS:*.syn.test,DNS:*.nowan.test\n' > "$W/san"
openssl x509 -req -in "$W/csr" -CA "$W/ca" -CAkey "$W/ca.key" -CAcreateserial -days 1 -extfile "$W/san" -out "$W/cert" 2>/dev/null
cat /etc/ssl/certs/ca-certificates.crt "$W/ca" > "$W/bundle"
mount --bind "$W/bundle" "$(readlink -f /etc/ssl/certs/ca-certificates.crt)"

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
    for a in $(seq 1 16); do NS "$2" ip addr add "198.51.100.$a/32" dev lo; done
    NS "$2" python3 "$W/al.py" serve "$2" "$W/cert" "$W/key" > "$W/srv-$2.log" 2>&1 &
}
uplink wan alw 10.73.0.2 10.73.0.1
uplink tun0 alt 10.71.0.2 10.71.0.1
uplink cln alx 10.72.0.2 10.72.0.1
ip route add default via 10.73.0.1 dev wan
ip netns add alc
ip link add lan type veth peer name c0 netns alc
ip addr add 10.70.0.1/24 dev lan
ip link set lan up
NS alc ip link set lo up
NS alc ip addr add 10.70.0.2/24 dev c0
NS alc ip link set c0 up
NS alc ip route add default via 10.70.0.1

dpi() { NS alw $IPT "$@" || echo "DPI rule refused: $*"; }
dpi -A INPUT -p tcp --dport 443 -m string --algo bm --string drop.test -j DROP
dpi -A INPUT -p tcp --dport 443 -m string --algo bm --string rst.test -j REJECT --reject-with tcp-reset
dpi -A INPUT -p tcp --dport 443 -m string --algo bm --string hold.test -j DROP
dpi -A INPUT -p tcp --dport 443 -m string --algo bm --string many.test -j DROP
dpi -A OUTPUT -s 198.51.100.10 -p tcp --sport 443 -m connbytes --connbytes 6144: --connbytes-dir reply --connbytes-mode bytes -j DROP
dpi -A OUTPUT -s 198.51.100.4 -p tcp --sport 443 -m connbytes --connbytes 16384: --connbytes-dir reply --connbytes-mode bytes -j DROP
dpi -A INPUT -d 198.51.100.8 -p tcp --dport 443 -m connbytes --connbytes 2000: --connbytes-dir reply --connbytes-mode bytes -j REJECT --reject-with tcp-reset

python3 "$W/al.py" dns 15353 www.ok.test=198.51.100.1 www.drop.test=198.51.100.2 www.rst.test=198.51.100.3 \
    www.freeze.test=198.51.100.4 www.frost.test=198.51.100.4 www.cut.test=198.51.100.5 a.many.test=198.51.100.6 \
    b.many.test=198.51.100.7 www.late.test=198.51.100.8 www.hold.test=198.51.100.9 \
    www.small.test=198.51.100.10 c.many.test=198.51.100.11 www.syn.test=198.51.100.12 www.nowan.test=198.51.100.13 \
    gen.check.test=198.51.100.15 &
DNS=$!

mkdir -p /etc/firc
cat > /etc/firc/firc.conf <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: false
  dnsProxy:
    host: {address: "10.70.0.1", port: 13598}
    upstream: {address: 127.0.0.1, port: 15353}
    disableRemap53: true
    unmatchedTtl: 5s
  netfilter:
    iptables: {chainPrefix: FIRC_}
  link: [lan]
  check:
    url: http://gen.check.test/generate_204
  autolist:
    enabled: true
    mode: add
    group: "$G"
EOF
cat > /etc/firc/groups.yaml <<EOF
configVersion: 0.7.0
groups:
  - id: $G
    name: A
    interface: tun0
    enable: true
    rules:
      - {id: 0000ad01, type: domain, rule: seed.test, enable: true}
EOF
"$FIRCD" --config /etc/firc/firc.conf > "$W/fircd.log" 2>&1 &
FP=$!

api() { curl -s --unix-socket "$SOCK" "$@" 2>/dev/null; }
al() { api "http://firc/api/v1/system/autolist" | python3 "$W/al.py" "$@" 2>/dev/null; }
status() { al st "j['$1']"; }
added() { api "http://firc/api/v1/groups/$G/rules" > "$W/g.json"; python3 "$W/al.py" rules "$W/g.json" | grep "^$1:" ; }
in_yaml() { grep -c "autolist: $1" /etc/firc/groups.yaml; }
ask() { NS alc python3 "$W/al.py" q 10.70.0.1 13598 "$1"; }
fetch() {
    ip=$(ask "$1" | cut -d' ' -f1)
    c=$(NS alc curl -sk -m "${3:-5}" -o /dev/null -w '%{http_code}' --resolve "$1:443:$ip" "https://$1$2") || c=000
    echo "$(date +%T) $1$2 $c" >> "$W/fetch.log"
    echo "$c"
}
times3() { for i in 1 2 3; do fetch "$1" "$2" 5; done | tr '\n' ' ' > "$W/c.$1${3:-}"; }
stall() {
    ip=$(ask "$1" | cut -d' ' -f1)
    n=$(NS alc curl -sk -m 12 -o /dev/null -w '%{size_download}' --resolve "$1:443:$ip" "https://$1$2")
    rc=$?
    echo "$(date +%T) $1$2 exit $rc after $n bytes" >> "$W/fetch.log"
    if [ "$n" -ge 8192 ] && [ "$n" -le 32768 ]; then n=8-32K; elif [ "$n" -gt 0 ] && [ "$n" -lt 8192 ]; then n=below8K; fi
    echo "$rc:$n" > "$W/s.$1$3"
}
around() {
    c=$(NS alc curl -sk -m 5 -o /dev/null -w '%{http_code}' --resolve "$1:443:$2" "https://$1/") || c=000
    echo "$(date +%T) $1 at $2 without asking $c" >> "$W/fetch.log"
}
probe() {
    api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data "{\"host\":\"$1\"}" \
        "http://firc/api/v1/system/autolist/probe"
}
recheck() { api -w ' %{http_code}' -X POST "http://firc/api/v1/system/autolist/check"; }
setting() {
    api -w ' %{http_code}' -X PUT -H 'Content-Type: application/json' --data "{\"settings\": $1}" \
        "http://firc/api/v1/system/settings" > "$W/set.json"
    code=$(sed 's/.* //' "$W/set.json")
    sed 's/ [0-9]*$//' "$W/set.json" | python3 -c "import json,sys; print('$code', json.load(sys.stdin).get('field'))"
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

wait_for 20 True status running
T0=$(date +%s)
check "the automatic list runs" True "$(status running)"
check "it runs in mode add" add "$(status mode)"
check "its chain hangs off mangle/FORWARD" 1 "$($IPT -t mangle -S FORWARD | grep -c -- '-j FIRC_AUTO')"
check "its six rules are in the kernel" 6 "$($IPT -t mangle -S FIRC_AUTO | grep -c NFLOG)"

check "a probe on request is accepted" 202 "$(probe www.frost.test)"
check "a second request waits its turn" 202 "$(probe www.ok.test)"
J=
for i in 1 2 3; do around www.drop.test 198.51.100.2 & J="$J $!"; done
wait $J
J=
sleep 1
check "a client that never asked firc is counted apart" "10.70.0.2:3" \
    "$(al st "','.join('%s:%s' % (b['client'], b['fails']) for b in j['bypassed'])")"
check "and its failures list nothing" 0 "$(status listed)"
check "nor add anything" "" "$(added drop.test)"

wait_for 30 blocked:freeze al res www.frost.test
check "a requested probe finds a freeze through the WAN" blocked:freeze "$(al res www.frost.test)"
check "and adds its domain" "frost.test:namespace:www.frost.test:on" "$(added frost.test)"
wait_for 20 short al res www.ok.test verdict
check "a requested probe of an open small page says short" short "$(al res www.ok.test verdict)"
OKAT=$(al res www.ok.test at)

check "an unrouted answer lives unmatchedTtl" 5 "$(ask www.drop.test | cut -d' ' -f2)"
times3 www.ok.test / & J="$J $!"
times3 www.drop.test / & J="$J $!"
times3 www.rst.test / & J="$J $!"
times3 www.late.test /big & J="$J $!"
stall www.freeze.test /big 1 & J="$J $!"
stall www.freeze.test /big 2 & J="$J $!"
stall www.small.test /big 1 & J="$J $!"
stall www.small.test /big 2 & J="$J $!"
wait $J
J=
sleep 1
echo "--- fetches"; cat "$W/fetch.log"
echo "--- rule counters"; $IPT -t mangle -L FIRC_AUTO -v -n -x | cut -c1-100
check "an open site answers through the WAN" "200 200 200 " "$(cat "$W/c.www.ok.test")"
check "a dropped site does not" "000 000 000 " "$(cat "$W/c.www.drop.test")"
check "a reset site does not" "000 000 000 " "$(cat "$W/c.www.rst.test")"
check "a site reset after its ServerHello does not" "000 000 000 " "$(cat "$W/c.www.late.test")"
check "a frozen site gives 8-32 KB and stalls" "28:8-32K 28:8-32K" "$(cat "$W/s.www.freeze.test1") $(cat "$W/s.www.freeze.test2")"
check "an open site is not added" "" "$(added ok.test)"
check "a dropped ClientHello adds its domain" "drop.test:namespace:www.drop.test:on" "$(added drop.test)"
check "a reset adds its domain" "rst.test:namespace:www.rst.test:on" "$(added rst.test)"
check "a reset after the ServerHello is not counted" "" "$(added late.test)$(al cand late.test)"
check "the addition reaches groups.yaml" 1 "$(in_yaml www.drop.test)"
check "the status counts the hosts listed" 2 "$(status listed)"
check "two stalls nominate the host with no request" checking:freeze:2 "$(al cand freeze.test)"
check "the nominated host waits in the queue" 1 "$(al st "j['probes']['queued']")"
check "a nominated host is not added before its probe" "" "$(added freeze.test)"
check "a page stalled below 8 KB stalls twice" "28:below8K 28:below8K" "$(cat "$W/s.www.small.test1") $(cat "$W/s.www.small.test2")"
check "a stalled small page is not nominated nor added" ":" "$(al cand small.test):$(added small.test)"

stall www.ok.test /stall 1 & J="$J $!"
stall www.ok.test /stall 2 & J="$J $!"
wait $J
J=
sleep 1
check "an open host stalls twice" "28:8-32K 28:8-32K" "$(cat "$W/s.www.ok.test1") $(cat "$W/s.www.ok.test2")"
check "a cached open host is not queued again" "1:" "$(al st "j['probes']['queued']"):$(al cand ok.test)"

H=$(ask www.hold.test)
HT=$(date +%s)
HELD=${H% *}
check "a client holds a real address that lives unmatchedTtl" "198.51.100.9 5" "$H"
for i in 1 2 3; do NS alc curl -sk -m 3 -o /dev/null --resolve "www.hold.test:443:$HELD" https://www.hold.test/ & J="$J $!"; done
wait $J
J=
wait_for 3 "hold.test:namespace:www.hold.test:on" added hold.test
check "its failures add the domain while the answer is still held" \
    "hold.test:namespace:www.hold.test:on yes" "$(added hold.test) $([ $(($(date +%s) - HT)) -lt 5 ] && echo yes || echo no)"
held=$(NS alc curl -sk -m 3 -o /dev/null -w '%{http_code}' --resolve "www.hold.test:443:$HELD" https://www.hold.test/) || held=000
check "the held real address still goes past the tunnel" 000 "$held"
while [ "$(date +%s)" -lt $((HT + 6)) ]; do sleep 0.2; done
F=$(ask www.hold.test | cut -d' ' -f1)
check "after unmatchedTtl the client is answered a fake address" 1 "$(echo "$F" | grep -c '^198\.1[89]\.')"
check "and reaches the site through the tunnel" 200 "$(fetch www.hold.test /)"

api "http://firc/api/v1/groups/$G/rules" > "$W/g.json"
RID=$(python3 "$W/al.py" rule_off "$W/g.json" drop.test)
api -X PUT -H 'Content-Type: application/json' --data @"$W/g.json.rule" "http://firc/api/v1/groups/$G/rules/$RID" > /dev/null
check "the user switches the added rule off and it becomes the user's" "drop.test:namespace::off" "$(added drop.test)"
times3 www.drop.test / again
check "the site fails again past firc" "000 000 000 " "$(cat "$W/c.www.drop.testagain")"
check "a rule the user switched off stays off" "drop.test:namespace::off" "$(added drop.test)"

check "unmatchedTtl 0 is refused while the list is on" "400 app.autolist.enabled" \
    "$(setting '{"app.dnsProxy.unmatchedTtl": 0}')"
check "and nothing changes" 5 "$(api "http://firc/api/v1/system/settings" | python3 -c "import json,sys; print(json.load(sys.stdin)['settings']['app.dnsProxy.unmatchedTtl'])")"

echo "--- waiting for the probe queue's tick, up to $((T0 + 150 - $(date +%s))) s"
wait_for $((T0 + 150 - $(date +%s))) "freeze.test:namespace:www.freeze.test:on" added freeze.test
check "the router's probe confirms the freeze with no request and adds it" \
    "freeze.test:namespace:www.freeze.test:on" "$(added freeze.test)"
check "its verdict is a freeze" blocked:freeze "$(al res www.freeze.test)"
check "the cached open host was not probed twice" "$OKAT 3" "$(al res www.ok.test at) $(al st "j['probes']['usedHour']")"

before=$(status checkedAt)
check "a check through the WAN runs" 200 "$(recheck | sed 's/.* //')"
wait_for 90 False status checking
check "and ends" yes "$([ "$(status checkedAt)" != "$before" ] && echo yes || echo no)"
check "a site still reset through the WAN stays on" "rst.test:namespace:www.rst.test:on" "$(added rst.test)"
check "a site that still freezes stays on" "freeze.test:namespace:www.freeze.test:on" "$(added freeze.test)"
check "the user's rule is not checked" "drop.test:namespace::off" "$(added drop.test)"

check "the check interface may be set to the group's" "200 None" "$(setting '{"app.autolist.checkInterface": "tun0"}')"
check "but then a check is refused" "409 the check interface belongs to the group" \
    "$(recheck | python3 -c "import json,sys; t=sys.stdin.read(); print(t.rsplit(' ',1)[1], json.loads(t.rsplit(' ',1)[0])['error'])")"
check "and so is a probe" 409 "$(probe www.rst.test)"

check "a clean interface is taken" "200 None" "$(setting '{"app.autolist.checkInterface": "cln"}')"
check "a check through a clean interface runs" 200 "$(recheck | sed 's/.* //')"
wait_for 90 False status checking
check "a site it opens is switched off" "rst.test:namespace:www.rst.test:off" "$(added rst.test)"
check "a frozen site it opens is switched off" "freeze.test:namespace:www.freeze.test:off" "$(added freeze.test)"
check "a site it opens that had a held address is switched off" "hold.test:namespace:www.hold.test:off" "$(added hold.test)"
check "the status counts the switches" 4 "$(status switchedOff)"

check "the default route is taken again" "200 None" "$(setting '{"app.autolist.checkInterface": ""}')"
nflog() { $IPT -t mangle -L FIRC_AUTO -v -n -x | awk "/nflog-group $1( |$)/{print \$1}"; }
RST0=$(nflog 10)
CUT=$(ask www.cut.test | cut -d' ' -f1)
for i in 1 2; do NS alc python3 "$W/al.py" cut www.cut.test "$CUT" > "$W/cut$i" 2>&1 & J="$J $!"; done
wait $J
J=
sleep 1
read16() { [ "$(cat "$1")" -ge 16384 ] 2>/dev/null && echo 16K || cat "$1"; }
check "a client reads 16 KB of a frozen transfer and resets it, twice" "16K 16K" "$(read16 "$W/cut1") $(read16 "$W/cut2")"
check "both close by a client reset" 2 "$(($(nflog 10) - RST0))"
check "two client resets after a stall nominate the host" checking:freeze:2 "$(al cand cut.test)"
check "a requested probe takes the nominated host off the queue" 202 "$(probe www.cut.test)"
wait_for 40 short al res www.cut.test verdict
check "its probe ends" short "$(al res www.cut.test verdict)"

fetch a.many.test / > /dev/null
sleep 1
check "one failure of one host lists nothing" "" "$(added many.test)"
fetch b.many.test / > /dev/null & J="$J $!"
fetch c.many.test / > /dev/null & J="$J $!"
wait $J
J=
many() { added many.test | sed 's/:[abc]\.many\.test:/:host:/'; }
wait_for 3 "many.test:namespace:host:on" many
check "three hosts failing once each list their domain" "many.test:namespace:host:on" "$(many)"
check "and the rule keeps that it was listed by its domain" True "$(python3 "$W/al.py" bydomain "$W/g.json" many.test)"

nocon() {
    dpi -I INPUT 1 -d "$2" -p tcp --syn -j DROP
    check "a probe of $1 is accepted before its clients fail" 202 "$(probe "www.$1")"
    for i in 1 2 3; do fetch "www.$1" / & J="$J $!"; done > /dev/null
    wait $J
    J=
    sleep 1
    check "while it connects the clients' unanswered SYNs nominate $1, not add it" "checking:no-connect:0:" \
        "$(al cand "$1"):$(added "$1")"
    wait_for 50 "$3" al res "www.$1" verdict
}
dpi -I INPUT 1 -d 198.51.100.15 -p tcp --syn -j DROP
nocon nowan.test 198.51.100.13 unknown
check "with the WAN check failing the probe says unknown and nothing is proposed" "unknown::" \
    "$(al res www.nowan.test verdict)::$(al cand nowan.test)$(added nowan.test)"
check "and its result says what the WAN check got" 1 \
    "$(al res www.nowan.test error | grep -c ' · wan gen.check.test: .')"
dpi -D INPUT -d 198.51.100.15 -p tcp --syn -j DROP
nocon syn.test 198.51.100.12 blocked
check "with the WAN check passing the probe confirms the unanswered SYN" blocked:no-connect "$(al res www.syn.test)"
check "and its result says the WAN check answered 204" 1 "$(al res www.syn.test error | grep -c ' · wan gen.check.test: 204$')"
check "and adds its domain" "syn.test:namespace:www.syn.test:on" "$(added syn.test)"

kill -TERM "$FP"
wait "$FP"
rc=$?
FP=
check "fircd exits 0" 0 "$rc"
check "no sanitizer report in the log" 0 "$(grep -c 'Sanitizer\|runtime error' "$W/fircd.log")"
check "the stop takes its chain away" 0 "$($IPT -t mangle -S | grep -c FIRC_AUTO)"
echo "== $pass passed, $fail failed in $(($(date +%s) - T0)) s"
[ "$fail" = 0 ]
