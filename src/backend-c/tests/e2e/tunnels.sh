#!/bin/sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BE=$(cd "$HERE/../.." && pwd)
TV=$(cd "$BE/../tunvless" && pwd)

if [ "${FIRC_TUN_E2E_INNER:-}" != 1 ]; then
    make -s -C "$BE" build/host/fircd >/dev/null || exit 1
    make -s -C "$TV" >/dev/null || exit 1
    T=$(mktemp -d)
    mkdir -p "$T/up" "$T/work"
    FIRC_TUN_E2E_INNER=1 unshare -Urmn sh -c "mount -t tmpfs tmpfs /run && \
        mount -t overlay overlay -o lowerdir=/etc,upperdir=$T/up,workdir=$T/work /etc && \
        exec sh '$HERE/tunnels.sh'"
    rc=$?
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
    exit $rc
fi

N=tfn
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
GW=10.78.0.1 ME=10.78.0.2 A=10.79.0.1 B=10.79.0.2 PORT=10800
SOCK=/run/firc/firc.sock
W=$(mktemp -d)
export FIRC_TUNNELS_CACHE_DIR="$W/cache"
export FIRC_HWID_PATH="$W/hwid"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${FP:-}" ] && kill "$FP" 2>/dev/null && wait "$FP" 2>/dev/null
    for p in ${SRV_A:-} ${SRV_B:-} ${WEB:-} ${STUB:-} ${SQ:-} ${LOC:-}; do kill "$p" 2>/dev/null; done
    for ns in $N ${X:-}; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del "$ns" 2>/dev/null
    done
    if [ "$fail" != 0 ]; then
        echo "--- fircd log (tail)"; tail -n 40 "$W/fircd.log" 2>/dev/null
        echo "--- journal"; cat "$W/ev" 2>/dev/null; echo
    fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

NX() { ip netns exec $N "$@"; }
ip link set lo up
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
ip netns add $N
ip link add v0 type veth peer name v1 netns $N
ip addr add $ME/24 dev v0
ip link set v0 up
ip route add default via $GW
NX ip link set lo up
NX sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
NX ip addr add $GW/24 dev v1
NX ip link set v1 up
NX ip addr add $A/32 dev lo
NX ip addr add $B/32 dev lo

node_up() {
    eval addr=\$$1
    ip netns exec $N python3 "$TV/tests/fake-vless.py" --port $PORT --uuid $UUID --mb 1 --bind "$addr" \
        > "$W/srv-$1.log" 2>&1 &
    eval SRV_$1=\$!
}
node_up A
node_up B

mkdir -p /etc/firc
cat > /etc/firc/firc.conf <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: false
  dnsProxy:
    host:
      address: "127.0.0.1"
      port: 13597
    upstream:
      address: 127.0.0.1
      port: 53
    disableRemap53: true
  netfilter:
    iptables:
      chainPrefix: FIRC_
  link: []
EOF
tunnels() {
    cat > /etc/firc/tunnels.yaml <<EOF
tunnels:
  - id: t0
    device: tunvless0
    enable: true
    uplink: auto
    sources:
      - id: 0000000a
        link: "vless://$UUID@$A:$PORT?security=none&type=tcp#A"
      - id: 0000000b
        link: "vless://$UUID@$B:$PORT?security=none&type=tcp#B"
    active: $1
    interval: 5s
    advanced: { timeout: 3s }
${3:-}
  - id: t1
    device: tunvless1
    enable: true
    uplink: auto
    sources:
      - link: "vless://$UUID@$B:$PORT?security=none&type=tcp#B"
    active: 1
    interval: 5s
    advanced: { timeout: 3s }
EOF
    [ "$2" = with2 ] || return 0
    cat >> /etc/firc/tunnels.yaml <<EOF
  - id: t2
    device: tunvless2
    enable: true
    uplink: tunnel:t0
    sources:
      - link: "vless://$UUID@$B:$PORT?security=none&type=tcp#B"
    active: 1
    interval: 5s
    advanced: { timeout: 3s }
EOF
}
tunnels 1 with2
sleep 1

FIRC_TUNVLESS_BIN="$TV/out/tunvless" "$BE/build/host/fircd" --config /etc/firc/firc.conf > "$W/fircd.log" 2>&1 &
FP=$!

ours() {
    me=$(readlink /proc/self/ns/net)
    for p in /proc/[0-9]*; do
        [ "$(cat "$p/comm" 2>/dev/null)" = tunvless ] || continue
        [ "$(readlink "$p/ns/net" 2>/dev/null)" = "$me" ] || continue
        echo "${p#/proc/} $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
    done
}
tpid() { ours | awk -v d="$1" '{ for (i = 2; i < NF; i++) if ($i == "-d" && $(i + 1) == d) print $1 }'; }
journal() { curl -s --unix-socket "$SOCK" "http://firc/api/v1/system/events?since=0" > "$W/ev" 2>/dev/null; }
count_ev() { journal; grep -oF "$1" "$W/ev" | wc -l; }
wait_ev() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        journal && grep -qF "$1" "$W/ev" && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
wait_link() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        ip link show "$1" >/dev/null 2>&1 && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
rule48() { ip rule show | grep '^48:'; }
table_of() { ip route show table "$TABLE" 2>/dev/null; }
wait_table() {
    i=0
    while [ $i -lt $(($3 * 5)) ]; do
        if [ "$1" = has ]; then table_of | grep -q "$2" && return 0; else table_of | grep -q "$2" || return 0; fi
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
wait_pid() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        p=$(tpid "$1")
        [ -n "$p" ] && { echo "$p"; return 0; }
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
wait_new_pid() {
    i=0
    while [ $i -lt $(($3 * 5)) ]; do
        now=$(tpid "$1")
        [ -n "$now" ] && [ "$now" != "$2" ] && { echo "$now"; return 0; }
        sleep 0.2; i=$((i + 1))
    done
    echo "$now"
    return 1
}

# catches: fircd never starting tunvless for a tunnel in tunnels.yaml
wait_link tunvless0 5
check "tunvless0 appears within 5 s" 0 "$?"
# catches: the journal missing a tunnel's first active node
wait_ev "\"source\":\"tunvless0\",\"message\":\"active A" 15
check "the journal names tunvless0's active node" 0 "$?"
# catches: a tunnel left out when there are several
wait_ev "\"source\":\"tunvless1\",\"message\":\"active B" 15
check "tunvless1 runs beside it" 0 "$?"

# catches: a tunnel uplink written without its rule, or more than one
check "one uplink rule at priority 48" 1 "$(rule48 | wc -l)"
MARK=$(rule48 | sed -n 's/.*fwmark \(0x[0-9a-f]*\)\/0xff0000.*/\1/p')
TABLE=$(rule48 | sed -n 's/.*lookup \([0-9a-z]*\).*/\1/p')
P2=$(wait_pid tunvless2 15)
# catches: tunvless started without the uplink's mark, so it leaves by main
check "tunvless2 runs with -m $MARK" 1 "$(ours | awk -v p="$P2" '$1 == p' | grep -c -- "-m $MARK ")"
# catches: the uplink default never written once tunvless0 is up
wait_table has "dev tunvless0" 10
check "tunvless2's table routes via tunvless0" 0 "$?"
kill -9 "$(tpid tunvless0)"
# catches: a lost uplink device leaving anything but the blackhole
wait_table hasnot "dev tunvless0" 3
check "with tunvless0 gone only the blackhole is left" "0 1 1" \
    "$? $(table_of | grep -c '^blackhole default') $(table_of | wc -l)"
# catches: no refresh on READY or link-up, so the uplink stays closed after a restart
wait_table has "dev tunvless0" 20
check "the default via tunvless0 returns after its restart" 0 "$?"
wait_ev "\"source\":\"tunvless0\",\"message\":\"exited (137), restart in" 5
check "the kill is journalled with its restart" 0 "$?"

kill "$SRV_A"; wait "$SRV_A" 2>/dev/null; SRV_A=
# catches: node_down events not reaching the journal
wait_ev "\"source\":\"tunvless0\",\"message\":\"A does not answer" 15
check "A's failure is journalled within 15 s" 0 "$?"
# catches: the replacement node not journalled
wait_ev "\"source\":\"tunvless0\",\"message\":\"active B" 15
check "B takes over within 15 s" 0 "$?"
journal
# catches: a link (secret) written to the journal
check "no link in the journal" 0 "$(grep -c "vless://\|$UUID" "$W/ev")"

node_up A
P0=$(tpid tunvless0)
STARTS0=$(count_ev "\"source\":\"tunvless0\",\"message\":\"tunvless ")
ACT_A=$(count_ev "\"source\":\"tunvless0\",\"message\":\"active A")
# catches: a start-count check that proves nothing because the journal holds no start line to count
check "the journal holds tunvless0's start line" yes "$([ "$STARTS0" -ge 1 ] && echo yes || echo no)"
tunnels 1 with2 '    exclude: ["0000000b:B"]'
kill -HUP "$FP"
i=0
while [ $i -lt 100 ] && [ "$(count_ev "\"source\":\"tunvless0\",\"message\":\"active A")" -le "$ACT_A" ]; do sleep 0.2; i=$((i + 1)); done
# catches: a node change never reaching the running tunvless, so the excluded node stays active
check "excluding the active node makes A active within 20 s" yes \
    "$([ "$(count_ev "\"source\":\"tunvless0\",\"message\":\"active A")" -gt "$ACT_A" ] && echo yes || echo no)"
# catches: a node change restarting tunvless instead of sending it the new list
check "the node change keeps tunvless0's process" "$P0" "$(tpid tunvless0)"
# catches: a restart hidden behind a reused pid, seen as a second start line
check "no new start of tunvless0 in the journal" "$STARTS0" "$(count_ev "\"source\":\"tunvless0\",\"message\":\"tunvless ")"
kill "$SRV_A"; wait "$SRV_A" 2>/dev/null; SRV_A=

P0=$(tpid tunvless0)
P1=$(tpid tunvless1)
# catches: a reload check that compares nothing
check "both tunnels have a process before the reload" "yes yes" \
    "$([ -n "$P0" ] && echo yes || echo no) $([ -n "$P1" ] && echo yes || echo no)"
tunnels 2 with2
kill -HUP "$FP"
# catches: SIGHUP not reloading tunnels.yaml
NP0=$(wait_new_pid tunvless0 "$P0" 10)
check "the changed tunnel restarts on SIGHUP" 0 "$?"
sleep 1
# catches: every reload restarting every tunnel
check "the unchanged tunnel keeps its process" "$P1" "$(tpid tunvless1)"
# catches: a restart that loses the new setting
check "the restarted tunvless0 runs with -A 2" 1 "$(ours | awk -v p="$NP0" '$1 == p' | grep -c -- '-A 2 ')"

P2=$(wait_pid tunvless2 15)
kill -STOP "$P2"
tunnels 2 no
kill -HUP "$FP"
sleep 2
# catches: a removed tunnel's rule deleted while its tunvless still runs
check "the removed tunnel keeps its rule while its process lives" "yes 1" \
    "$(kill -0 "$P2" 2>/dev/null && echo yes || echo no) $(rule48 | wc -l)"
kill -CONT "$P2"
i=0
while [ $i -lt 50 ] && { kill -0 "$P2" 2>/dev/null || [ -n "$(rule48)" ]; }; do sleep 0.2; i=$((i + 1)); done
# catches: a removed tunnel's rule never released after its process ended
check "its process and rule are gone after the reap" "no 0" \
    "$(kill -0 "$P2" 2>/dev/null && echo yes || echo no) $(rule48 | wc -l)"

kill -TERM "$FP"
wait "$FP"
rc=$?
FP=
# catches: a stop that fails the daemon's exit
check "fircd exits 0 on SIGTERM" 0 "$rc"
# catches: a tunnel device left behind by the daemon's stop
check "tunvless0 and tunvless1 are gone" "no no" \
    "$(ip link show tunvless0 >/dev/null 2>&1 && echo yes || echo no) $(ip link show tunvless1 >/dev/null 2>&1 && echo yes || echo no)"
# catches: an uplink rule outliving fircd
check "no rule at priority 48 is left" 0 "$(rule48 | wc -l)"
# catches: an orphaned tunvless process outliving fircd
check "no tunvless process is left" "" "$(ours)"

tunnels 1 with2
FIRC_TUNVLESS_BIN="$TV/out/tunvless" "$BE/build/host/fircd" --config /etc/firc/firc.conf >> "$W/fircd.log" 2>&1 &
FP=$!
wait_pid tunvless2 15 >/dev/null
wait_link tunvless0 10
OLD_TABLE=$(rule48 | sed -n 's/.*lookup \([0-9a-z]*\).*/\1/p')
# catches: a case that proves nothing because the second daemon never wrote its uplink
check "the second daemon runs three tunnels and one uplink rule" "3 1" "$(ours | wc -l) $(rule48 | wc -l)"
kill -9 "$FP"
wait "$FP" 2>/dev/null
FP=
i=0
while [ $i -lt 10 ] && [ -n "$(ours)" ]; do sleep 0.2; i=$((i + 1)); done
# catches: tunvless outliving a killed fircd (no parent-death signal)
check "tunvless processes are gone within 2 s of kill -9" "" "$(ours)"
# catches: a case that proves nothing because the killed daemon left no rule to sweep
check "the killed daemon's rule is still there" 1 "$(rule48 | wc -l)"
FIRC_TUNVLESS_BIN="$TV/out/tunvless" "$BE/build/host/fircd" --config /etc/firc/firc.conf >> "$W/fircd.log" 2>&1 &
FP=$!
wait_link tunvless0 10
check "the tunnels come back after the restart" 0 "$?"
wait_pid tunvless2 15 >/dev/null
check "tunvless2 comes back after the restart" 0 "$?"
# catches: the start sweep leaving the killed daemon's rule or its table, so a second rule or a new table appears
check "one rule at priority 48, in the table the killed daemon used" "1 $OLD_TABLE" \
    "$(rule48 | wc -l) $(rule48 | sed -n 's/.*lookup \([0-9a-z]*\).*/\1/p')"
kill -TERM "$FP"
wait "$FP"
FP=
check "no tunvless process is left after the second stop" "" "$(ours)"

mkdir -p "$W/www"
printf 'vless://%s@%s:%s?security=none&type=tcp#A\nvless://%s@%s:%s?security=none&type=tcp#B\n' \
    "$UUID" "$A" "$PORT" "$UUID" "$B" "$PORT" > "$W/www/sub"
cat > "$W/sub.py" <<'EOF'
import functools, http.server, sys
class Logged(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        sys.stderr.write("headers X-HWID=%s X-Device-OS=%s\n" % (self.headers.get("X-HWID"), self.headers.get("X-Device-OS")))
        sys.stderr.flush()
        super().do_GET()
server = http.server.ThreadingHTTPServer((sys.argv[1], 8088), functools.partial(Logged, directory=sys.argv[2]))
print("Serving HTTP on %s port 8088" % sys.argv[1], flush=True)
server.serve_forever()
EOF
ip netns exec $N python3 "$W/sub.py" $B "$W/www" > "$W/www.log" 2>&1 &
WEB=$!
i=0
while [ $i -lt 25 ] && ! grep -q "Serving HTTP" "$W/www.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
ip route add prohibit $B/32
cat > /etc/firc/tunnels.yaml <<EOF
tunnels:
  - id: t3
    device: tunvless3
    enable: true
    uplink: iface:v0
    sources:
      - subscription: { name: P, url: "http://$B:8088/sub?token=s3cr3t", interval: 10m }
    active: 1
    interval: 5s
    advanced: { timeout: 3s }
EOF
FIRC_TUNVLESS_BIN="$TV/out/tunvless" "$BE/build/host/fircd" --config /etc/firc/firc.conf >> "$W/fircd.log" 2>&1 &
FP=$!
# catches: a subscription fetched unmarked (main has only a prohibit route to it), or its nodes never handed to tunvless
wait_ev "\"source\":\"tunvless3\",\"message\":\"active B" 20
check "a subscription tunnel reaches its first node" 0 "$?"
# catches: the body not cached, or cached readable by others
check "one cache file, mode 600" "1 600" \
    "$(ls "$W/cache" 2>/dev/null | wc -l) $(stat -c %a "$W/cache"/* 2>/dev/null)"
# catches: no stored id on a router without RCI, or one others can read
check "the stored router id is 16 hex digits, mode 600" "1 600" \
    "$(grep -cx '[0-9a-f]\{16\}' "$W/hwid" 2>/dev/null) $(stat -c %a "$W/hwid" 2>/dev/null)"
HWID=$(cat "$W/hwid" 2>/dev/null)
# catches: the default headers or the stored id missing from the subscription request on the wire
check "the fetch names the router to the provider" 1 \
    "$(grep -q "headers X-HWID=$HWID X-Device-OS=KeeneticOS" "$W/www.log" && echo 1 || echo 0)"
journal
# catches: the subscription URL's token written to the log or the journal
check "the log names the subscription by host, never its token" "1 0 0" \
    "$(grep -c "http://$B/…" "$W/fircd.log") $(grep -c s3cr3t "$W/fircd.log") $(grep -c s3cr3t "$W/ev")"
kill "$WEB"; wait "$WEB" 2>/dev/null; WEB=
kill -TERM "$FP"
wait "$FP"
FP=
FIRC_TUNVLESS_BIN="$TV/out/tunvless" "$BE/build/host/fircd" --config /etc/firc/firc.conf >> "$W/fircd.log" 2>&1 &
FP=$!
# catches: a restart without the provider leaving the tunnel down although the cache holds its nodes
wait_ev "\"source\":\"tunvless3\",\"message\":\"active B" 20
check "with the provider gone the restarted tunnel comes up from the cache" 0 "$?"
# catches: a new id made on each start, which would also key the cache anew and miss it
check "the restart keeps the stored id" "$HWID" "$(cat "$W/hwid" 2>/dev/null)"
i=0
while [ $i -lt 50 ] && ! grep -q "fetch failed" "$W/fircd.log"; do sleep 0.2; i=$((i + 1)); done
# catches: a cache test that proves nothing because the provider still answered
check "the restarted daemon could not fetch" 1 "$(grep -c "tunnel subscription http://$B/…: fetch failed" "$W/fircd.log")"
kill -TERM "$FP"
wait "$FP"
FP=
check "no tunvless process is left after the subscription case" "" "$(ours)"

X=tfl
LAN=10.80.0.1 CL=10.80.0.2 C=10.79.0.3 REAL=10.85.0.9 STUBP=5354 DNSP=13597
LX() { ip netns exec $X "$@"; }
miss=
command -v iptables-legacy >/dev/null && command -v iptables-legacy-save >/dev/null || miss=" iptables-legacy"
iptables-legacy -t nat -N KTCP_PROBE >/dev/null 2>&1
iptables-legacy -t nat -A KTCP_PROBE -p tcp -j REDIRECT --to-ports 3600 >/dev/null 2>&1 || miss="$miss xt_REDIRECT"
iptables-legacy -t nat -A KTCP_PROBE -m addrtype ! --dst-type LOCAL -j RETURN >/dev/null 2>&1 || miss="$miss xt_addrtype"
iptables-legacy -t nat -F KTCP_PROBE >/dev/null 2>&1
iptables-legacy -t nat -X KTCP_PROBE >/dev/null 2>&1
# catches: kernel TCP checks skipped on a host whose kernel lacks the modules a user namespace cannot load
check "the kernel takes REDIRECT and addrtype from a user namespace" "" "$miss"
if [ -n "$miss" ]; then
    echo "kernel TCP e2e cannot run: missing$miss; load on the host: modprobe xt_REDIRECT xt_addrtype"
    echo "tunnels e2e: $pass ok, $fail fail"
    exit 1
fi

cat > "$W/kt.py" <<'EOF'
import errno
import socket
import struct
import sys
import time


def qname(q, i):
    labels = []
    while q[i]:
        labels.append(q[i + 1:i + 1 + q[i]].decode())
        i += 1 + q[i]
    return ".".join(labels).lower(), i + 1


def serve(port, name, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", int(port)))
    raw = socket.inet_aton(addr)
    while True:
        q, peer = s.recvfrom(4096)
        n, end = qname(q, 12)
        hit = n == name and struct.unpack("!H", q[end:end + 2])[0] == 1
        hdr = q[:2] + struct.pack("!HHHHH", 0x8180 if n == name else 0x8183, 1, int(hit), 0, 0)
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + raw if hit else b""
        s.sendto(hdr + q[12:end + 4] + ans, peer)


def q(server, port, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    m = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    m += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s.sendto(m, (server, int(port)))
    r = s.recv(4096)
    _, i = qname(r, 12)
    i += 4
    for _ in range(struct.unpack("!H", r[6:8])[0]):
        i += 2
        t, _, _, ln = struct.unpack("!HHIH", r[i:i + 10])
        i += 10
        if t == 1:
            print(socket.inet_ntoa(r[i:i + 4]))
        i += ln


def conn(host, port, wait, sport="0", started=""):
    t0 = time.monotonic()
    got, kind = b"", "data"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(wait))
    try:
        if int(sport):
            s.bind(("0.0.0.0", int(sport)))
        s.connect((host, int(port)))
        s.sendall(b"GET / HTTP/1.0\r\nHost: t\r\n\r\n")
        while True:
            b = s.recv(65536)
            if not b:
                break
            if started and not got:
                open(started, "w").close()
            got += b
    except ConnectionRefusedError:
        kind = "refused"
    except ConnectionResetError:
        kind = "reset"
    except socket.timeout:
        kind = "timeout"
    except OSError as e:
        kind = "unreach" if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH) else "errno%d" % e.errno
    _, sep, body = got.partition(b"\r\n\r\n")
    if kind == "data" and not got:
        kind = "eof"
    print("%s %d %d" % (kind, len(body) if sep else len(got), (time.monotonic() - t0) * 1000), flush=True)


def listen(port, log):
    s = socket.socket()
    s.bind(("0.0.0.0", int(port)))
    s.listen(16)
    print("listening", flush=True)
    while True:
        c, peer = s.accept()
        c.recv(4096)
        with open(log, "a") as f:
            f.write("%s:%d\n" % peer)
        c.sendall(b"HTTP/1.0 200 OK\r\n\r\nlocal")
        c.close()


def attrs(buf):
    i = 0
    while i + 4 <= len(buf):
        ln, t = struct.unpack("=HH", buf[i:i + 4])
        if ln < 4:
            break
        yield t & 0x3fff, buf[i + 4:i + ln]
        i += (ln + 3) & ~3


def tup(buf):
    out = {}
    for t, v in attrs(buf):
        for t2, v2 in attrs(v):
            if t == 1 and t2 in (1, 2):
                out[t2] = socket.inet_ntoa(v2)
            elif t == 2 and t2 == 1:
                out["p"] = v2[0]
            elif t == 2 and t2 in (2, 3):
                out[t2 + 1] = struct.unpack("!H", v2)[0]
    return out


def ct():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
    s.bind((0, 0))
    s.send(struct.pack("=IHHII", 20, 0x101, 0x301, 1, 0) + struct.pack("=BBH", 2, 0, 0))
    while True:
        data = s.recv(1 << 16)
        i = 0
        while i + 16 <= len(data):
            ln, typ = struct.unpack("=IH", data[i:i + 6])
            if typ == 3:
                return
            if typ == 2:
                sys.exit("conntrack dump refused: %d" % struct.unpack("=i", data[i + 16:i + 20])[0])
            o = r = {}
            for t, v in attrs(data[i + 20:i + ln]):
                if t == 1:
                    o = tup(v)
                elif t == 2:
                    r = tup(v)
            if o.get("p") == 6:
                print("%s:%s>%s:%s reply %s:%s>%s:%s" % (o.get(1), o.get(3), o.get(2), o.get(4),
                                                        r.get(1), r.get(3), r.get(2), r.get(4)))
            i += (ln + 3) & ~3


if __name__ == "__main__":
    {"serve": serve, "q": q, "conn": conn, "listen": listen, "ct": ct}[sys.argv[1]](*sys.argv[2:])
EOF
KT="$W/kt.py"

ip route del prohibit $B/32
sysctl -qw net.ipv4.ip_forward=1
mkdir -p /run/ktsys && mount -t sysfs sysfs /run/ktsys
ip netns add $X
ip link add v2 type veth peer name v3 netns $X
ip addr add $LAN/24 dev v2
ip link set v2 up
LX ip link set lo up
LX sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
LX ip addr add $CL/24 dev v3
LX ip link set v3 up
LX ip route add default via $LAN
NX ip addr add $C/32 dev lo
NX python3 "$TV/tests/fake-vless.py" --port $PORT --uuid $UUID --mb 1 --bind $A --log-dst "$W/dst" \
    > "$W/srv-A.log" 2>&1 &
SRV_A=$!
NX python3 "$TV/tests/fake-vless.py" --port $PORT --uuid $UUID --mb 16 --kbps 256 --bind $C \
    --log-dst "$W/dst-slow" > "$W/srv-C.log" 2>&1 &
python3 "$KT" serve $STUBP dl.test $REAL &
STUB=$!
: > "$W/dst"
: > "$W/dst-slow"

cat > /etc/firc/firc.conf <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: false
  dnsProxy:
    host:
      address: "$LAN"
      port: $DNSP
    upstream:
      address: 127.0.0.1
      port: $STUBP
    disableRemap53: true
  netfilter:
    iptables:
      chainPrefix: FIRC_
  link: [v2]
  logLevel: debug
EOF
groups() {
    {
        echo "configVersion: 0.7.0"
        echo "groups:"
        [ "$1" = without0 ] || cat <<EOF
  - id: 0000aa01
    name: G0
    interface: tunvless0
    enable: true
    rules:
      - { id: 0000ab01, type: domain, rule: dl.test, enable: true }
      - { id: 0000ab02, type: subnet, rule: 10.81.0.0/24, enable: true }
${2:-}
EOF
        cat <<EOF
  - id: 0000aa02
    name: G1
    interface: tunvless1
    enable: true
    rules:
      - { id: 0000ab11, type: subnet, rule: 10.82.0.0/24, enable: true }
EOF
    } > /etc/firc/groups.yaml
}
ktun() {
    cat > /etc/firc/tunnels.yaml <<EOF
tunnels:
  - id: t0
    device: tunvless0
    enable: true
    uplink: auto
    sources:
      - link: "vless://$UUID@$1:$PORT?security=none&type=tcp#N0"
    active: 1
    interval: 5s
    advanced: { timeout: 3s, kernelTcp: $2 }
  - id: t1
    device: tunvless1
    enable: true
    uplink: auto
    sources:
      - link: "vless://$UUID@$A:$PORT?security=none&type=tcp#N1"
    active: 1
    interval: 5s
    advanced: { timeout: 3s, kernelTcp: true }
EOF
}
tstate() {
    curl -s --unix-socket "$SOCK" http://firc/api/v1/tunnels/state 2>/dev/null | python3 -c '
import json, sys
t = [t for t in json.load(sys.stdin)["tunnels"] if t["device"] == sys.argv[1]]
print(" ".join(str(t[0][k]) for k in sys.argv[2:]) if t else "none")' "$@" 2>/dev/null
}
wait_state() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        [ "$(tstate "$1" status tcpPort)" = "$3" ] && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
nat() { iptables-legacy-save -t nat 2>&1; }
wait_redirect() {
    i=0
    while [ $i -lt 50 ]; do
        nat | grep -q -- "-j REDIRECT --to-ports $1\$" && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
rx() { cat "/run/ktsys/class/net/$1/statistics/rx_bytes"; }
seen() { grep -cxF "$2" "$1"; }
lines() { cat "$1" 2>/dev/null | wc -l; }
wait_file() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do
        [ -s "$1" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
JUMP='-A PREROUTING -p tcp -m mark --mark 0x40000000/0x40000000 -m addrtype ! --dst-type LOCAL -j FIRC_REDIR'
DNATJ='-A PREROUTING -d 198.18.0.0/15 -j FIRC_DNAT'

groups with0
ktun $A true
python3 "$KT" listen 3601 "$W/squat" > "$W/squat.out" 2>&1 &
SQ=$!
wait_file "$W/squat.out" 5
FIRC_TUNVLESS_BIN="$TV/out/tunvless" "$BE/build/host/fircd" --config /etc/firc/firc.conf >> "$W/fircd.log" 2>&1 &
FP=$!
wait_state tunvless0 15 "up 3600"
# catches: the READY port never reaching /state, or a port other than 3600+N
check "/state reports tcpPort 3600 for tunvless0" 3600 "$(tstate tunvless0 tcpPort)"
wait_redirect 3600
nat > "$W/nat"
rc=$?
# catches: an unreadable nat table (iptables-save on an nf_tables host) passing the rule checks below as empty
check "iptables-legacy-save reads the nat table firc wrote" "0 1" "$rc $(grep -c '^:FIRC_REDIR ' "$W/nat")"
jl=$(grep -nxF -- "$JUMP" "$W/nat" | cut -d: -f1)
dl=$(grep -nxF -- "$DNATJ" "$W/nat" | cut -d: -f1)
# catches: the REDIR jump missing its local exclusion, or standing after the DNAT jump so DNAT binds the flow first
check "the REDIR jump with addrtype ! LOCAL precedes the DNAT jump" yes \
    "$([ -n "$jl" ] && [ -n "$dl" ] && [ "$jl" -lt "$dl" ] && echo yes || echo "no (jump $jl, dnat $dl)")"
M0=$(iptables-legacy-save -t mangle | sed -n 's|^-A FIRC_0000aa01 -d 10.81.0.0/24 .*--set-xmark \(0x40[0-9a-f]*\)/0x40ff0000$|\1|p')
# catches: a REDIRECT to the wrong port or under another group's mark
check "one REDIRECT, G0's mark to 3600" "1 1" \
    "$(grep -c -- '-j REDIRECT' "$W/nat") $(grep -cxF -- "-A FIRC_REDIR -p tcp -m mark --mark $M0/0x40ff0000 -j REDIRECT --to-ports 3600" "$W/nat")"

F=$(LX python3 "$KT" q $LAN $DNSP dl.test)
# catches: an rx check that proves nothing because the netns's counters cannot be read
check "tunvless0 and tunvless1 have rx counters in this netns" "yes yes" \
    "$([ -r /run/ktsys/class/net/tunvless0/statistics/rx_bytes ] && echo yes || echo no) $([ -r /run/ktsys/class/net/tunvless1/statistics/rx_bytes ] && echo yes || echo no)"
RX0=$(rx tunvless0)
# catches: the map not used, so the node is asked for the fake address instead of the real one
check "a 1 MB download to the fake reaches the node as the real address" "data 1048576 1 0" \
    "$(LX python3 "$KT" conn "$F" 80 10 | cut -d' ' -f1,2) $(seen "$W/dst" "$REAL:80") $(grep -c '^198\.18\.' "$W/dst")"
# catches: a subnet flow sent to the map or reset instead of dialled as it is
check "a 1 MB download to a subnet address reaches the node as it is" "data 1048576 1" \
    "$(LX python3 "$KT" conn 10.81.0.5 80 10 | cut -d' ' -f1,2) $(seen "$W/dst" "10.81.0.5:80")"
RXD=$(($(rx tunvless0) - RX0))
# catches: the flows silently taking the TUN path while the downloads still succeed
check "tunvless0's rx grew by less than 64 KB over 2 MB of downloads ($RXD)" yes "$([ "$RXD" -lt 65536 ] && echo yes || echo no)"
U=${F%.*}.200
r=$(LX python3 "$KT" conn "$U" 80 3)
# catches: an unmapped fake address served, dialled, or left to time out instead of reset
check "an unmapped fake address in G0's chunk is reset within 1 s ($r)" "reset yes" \
    "${r%% *} $([ "${r##* }" -lt 1000 ] && echo yes || echo no)"

P0=$(tpid tunvless0)
kill -STOP "$P0"
kill -9 "$P0"
wait_ev "\"source\":\"tunvless0\",\"message\":\"exited (137), restart in 3 s" 3
inside=$?
r=$(LX python3 "$KT" conn "$F" 80 2)
alive=$(tpid tunvless0)
# catches: the port dropped on exit, so the REDIRECT goes and new TCP leaks to the DNAT/TUN path or times out
check "inside the restart window a new connection is refused at once ($r)" "0 refused yes 1 none" \
    "$inside ${r%% *} $([ "${r##* }" -lt 500 ] && echo yes || echo no) $(nat | grep -c -- "--to-ports 3600") ${alive:-none}"
wait_state tunvless0 15 "up 3600"
# catches: the restarted child taking another port, or fircd forgetting it
check "after the restart tunvless0 is up on 3600 again" "up 3600" "$(tstate tunvless0 status tcpPort)"
# catches: a restarted child with an empty map, or a REDIRECT left pointing at nothing
check "a download through the restarted child works" "data 1048576" "$(LX python3 "$KT" conn "$F" 80 10 | cut -d' ' -f1,2)"

RX1=$(rx tunvless1)
wait_ev "\"source\":\"tunvless1\",\"message\":\"port 3601 is taken, TCP stays on the TUN" 5
# catches: a busy port not journalled
check "a taken 3601 is journalled" 0 "$?"
# catches: a stale or assumed port staged for a child that could not bind it, handing G1's TCP to the squatter
check "tunvless1 reports tcpPort 0 and no REDIRECT is staged for it" "0 0" \
    "$(tstate tunvless1 tcpPort) $(nat | grep -c -- '--to-ports 3601')"
r=$(LX python3 "$KT" conn 10.82.0.5 80 10 | cut -d' ' -f1,2)
RXD=$(($(rx tunvless1) - RX1))
# catches: a group whose tunnel has no port losing TCP instead of keeping the TUN path
check "G1's download works over the TUN and the squatter saw nothing" "data 1048576 yes 0" \
    "$r $([ "$RXD" -ge 1048576 ] && echo yes || echo "no ($RXD)") $(lines "$W/squat")"
kill "$SQ"; wait "$SQ" 2>/dev/null; SQ=

python3 "$KT" listen 8099 "$W/local" > "$W/local.out" 2>&1 &
LOC=$!
wait_file "$W/local.out" 5
groups with0 '      - { id: 0000ab03, type: subnet, rule: 0.0.0.0/0, enable: true }'
kill -HUP "$FP"
i=0
while [ $i -lt 25 ] && [ "$(seen "$W/dst" "10.86.0.4:80")" = 0 ]; do
    LX python3 "$KT" conn 10.86.0.4 80 3 >/dev/null
    sleep 0.2; i=$((i + 1))
done
# catches: a local-exclusion check that proves nothing because 0.0.0.0/0 never took effect
check "with subnet 0.0.0.0/0 an outside address is redirected to the node" 1 "$(seen "$W/dst" "10.86.0.4:80")"
# catches: the jump without addrtype ! LOCAL, so a covered device loses the router's own services to tunvless
check "a connection to the router's own address reaches its listener" "data 5 1" \
    "$(LX python3 "$KT" conn $LAN 8099 3 | cut -d' ' -f1,2) $(lines "$W/local")"
kill "$LOC"; wait "$LOC" 2>/dev/null; LOC=

LX python3 "$KT" conn "$F" 9 10 > "$W/idle" &
i=0
while [ $i -lt 50 ] && [ "$(seen "$W/dst" "$REAL:9")" = 0 ]; do sleep 0.1; i=$((i + 1)); done
kill -TERM "$FP"
wait "$FP"
FP=
wait_file "$W/idle" 3
# catches: a stop that ends an open redirected connection with a FIN, so a cut download without a length looks complete
check "the stop resets an open redirected connection" "1 reset" "$(seen "$W/dst" "$REAL:9") $(cut -d' ' -f1 "$W/idle")"
nat > "$W/nat"
# catches: a stop that leaves the REDIR chain or its jump redirecting into a dead port
check "the SIGTERM stop leaves no FIRC_REDIR" "1 0" "$(grep -c '^\*nat' "$W/nat") $(grep -c FIRC_REDIR "$W/nat")"

groups with0
ktun $C false
: > "$W/dst-slow"
FIRC_TUNVLESS_BIN="$TV/out/tunvless" "$BE/build/host/fircd" --config /etc/firc/firc.conf >> "$W/fircd.log" 2>&1 &
FP=$!
wait_ev "\"source\":\"tunvless0\",\"message\":\"active N0" 15
wait_state tunvless0 15 "up 0"
F=$(LX python3 "$KT" q $LAN $DNSP dl.test)
RX0=$(rx tunvless0)
LX python3 "$KT" conn "$F" 80 30 0 "$W/st1" > "$W/slow1" &
S1=$!
i=0
while [ $i -lt 50 ] && [ ! -e "$W/st1" ]; do sleep 0.1; i=$((i + 1)); done
sleep 1
RXD=$(($(rx tunvless0) - RX0))
# catches: a toggle check that proves nothing because the first flow never took the TUN path
check "with kernelTcp off the open download runs over tunvless0 ($RXD bytes)" "0 yes" \
    "$(nat | grep -c -- '--to-ports 3600') $([ "$RXD" -ge 65536 ] && echo yes || echo no)"
ktun $C true
kill -HUP "$FP"
wait_file "$W/slow1" 10
# catches: a toggle that leaves an open TUN download hanging instead of ending it
check "turning kernelTcp on ends the open TUN download with a reset" reset "$(cut -d' ' -f1 "$W/slow1")"
kill "$S1" 2>/dev/null; wait "$S1" 2>/dev/null
wait_redirect 3600
N0=$(seen "$W/dst-slow" "$REAL:80")
RX0=$(rx tunvless0)
LX python3 "$KT" conn "$F" 80 30 40002 "$W/st2" > "$W/slow2" &
S2=$!
i=0
while [ $i -lt 50 ] && [ ! -e "$W/st2" ]; do sleep 0.1; i=$((i + 1)); done
sleep 1
python3 "$KT" ct > "$W/ct"
RXD=$(($(rx tunvless0) - RX0))
# catches: a toggle that leaves new flows on DNAT, or a flush added to the toggle that kills the new flow
check "after the toggle a new flow is redirected, not DNATed" "1 1 0 yes" \
    "$(($(seen "$W/dst-slow" "$REAL:80") - N0)) $(grep -c "^$CL:40002>$F:80 reply $LAN:3600>$CL:40002\$" "$W/ct") \
$(grep -c "^$CL:40002>.* reply $REAL:" "$W/ct") $([ "$RXD" -lt 32768 ] && echo yes || echo "no ($RXD)")"

N0=$(seen "$W/dst-slow" "$REAL:80")
groups without0
kill -HUP "$FP"
wait_file "$W/slow2" 5
# catches: a withdrawn group's redirected flow kept open on routing it lost
check "removing G0 resets its open redirected download within a pass" reset "$(cut -d' ' -f1 "$W/slow2")"
kill "$S2" 2>/dev/null; wait "$S2" 2>/dev/null
r=$(LX python3 "$KT" conn "$F" 80 3 | cut -d' ' -f1)
# catches: a removed group's REDIRECT left in place, so its fake still reaches the node
check "after the removal a new connection to the fake fails and reaches no node" "no $N0" \
    "$([ "$r" = data ] && echo yes || echo no) $(seen "$W/dst-slow" "$REAL:80")"

groups with0
kill -HUP "$FP"
wait_redirect 3600
kill -9 "$FP"
wait "$FP" 2>/dev/null
FP=
i=0
while [ $i -lt 10 ] && [ -n "$(ours)" ]; do sleep 0.2; i=$((i + 1)); done
# catches: a purge check that proves nothing because the killed daemon left no REDIR behind
check "the killed daemon left FIRC_REDIR and its jump" "1 1" \
    "$(nat | grep -c '^:FIRC_REDIR ') $(nat | grep -cxF -- "$JUMP")"
"$BE/build/host/fircd" --config /etc/firc/firc.conf --purge >> "$W/fircd.log" 2>&1
rc=$?
nat > "$W/nat"
# catches: --purge leaving the REDIR chain or its jump
check "fircd --purge drops FIRC_REDIR and its jump" "0 1 0 0" \
    "$rc $(grep -c '^\*nat' "$W/nat") $(grep -c '^:FIRC_REDIR ' "$W/nat") $(grep -cxF -- "$JUMP" "$W/nat")"

echo "tunnels e2e: $pass ok, $fail fail"
[ "$fail" = 0 ]
