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
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${FP:-}" ] && kill "$FP" 2>/dev/null && wait "$FP" 2>/dev/null
    for p in ${SRV_A:-} ${SRV_B:-} ${WEB:-}; do kill "$p" 2>/dev/null; done
    ip netns pids $N 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $N 2>/dev/null
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
  logLevel: info
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
wait_ev "tunnel tunvless0: active A" 15
check "the journal names tunvless0's active node" 0 "$?"
# catches: a tunnel left out when there are several
wait_ev "tunnel tunvless1: active B" 15
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
wait_ev "tunnel tunvless0: exited (137), restart in" 5
check "the kill is journalled with its restart" 0 "$?"

kill "$SRV_A"; wait "$SRV_A" 2>/dev/null; SRV_A=
# catches: node_down events not reaching the journal
wait_ev "tunnel tunvless0: A does not answer" 15
check "A's failure is journalled within 15 s" 0 "$?"
# catches: the replacement node not journalled
wait_ev "tunnel tunvless0: active B" 15
check "B takes over within 15 s" 0 "$?"
journal
# catches: a link (secret) written to the journal
check "no link in the journal" 0 "$(grep -c "vless://\|$UUID" "$W/ev")"

node_up A
P0=$(tpid tunvless0)
STARTS0=$(count_ev "tunnel tunvless0: tunvless[info]: tunvless ")
ACT_A=$(count_ev "tunnel tunvless0: active A")
# catches: a start-count check that proves nothing because the journal holds no start line to count
check "the journal holds tunvless0's start line" yes "$([ "$STARTS0" -ge 1 ] && echo yes || echo no)"
tunnels 1 with2 '    exclude: ["0000000b:B"]'
kill -HUP "$FP"
i=0
while [ $i -lt 100 ] && [ "$(count_ev "tunnel tunvless0: active A")" -le "$ACT_A" ]; do sleep 0.2; i=$((i + 1)); done
# catches: a node change never reaching the running tunvless, so the excluded node stays active
check "excluding the active node makes A active within 20 s" yes \
    "$([ "$(count_ev "tunnel tunvless0: active A")" -gt "$ACT_A" ] && echo yes || echo no)"
# catches: a node change restarting tunvless instead of sending it the new list
check "the node change keeps tunvless0's process" "$P0" "$(tpid tunvless0)"
# catches: a restart hidden behind a reused pid, seen as a second start line
check "no new start of tunvless0 in the journal" "$STARTS0" "$(count_ev "tunnel tunvless0: tunvless[info]: tunvless ")"
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
ip netns exec $N python3 -m http.server 8088 --bind $B --directory "$W/www" > "$W/www.log" 2>&1 &
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
wait_ev "tunnel tunvless3: active B" 20
check "a subscription tunnel reaches its first node" 0 "$?"
# catches: the body not cached, or cached readable by others
check "one cache file, mode 600" "1 600" \
    "$(ls "$W/cache" 2>/dev/null | wc -l) $(stat -c %a "$W/cache"/* 2>/dev/null)"
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
wait_ev "tunnel tunvless3: active B" 20
check "with the provider gone the restarted tunnel comes up from the cache" 0 "$?"
i=0
while [ $i -lt 50 ] && ! grep -q "fetch failed" "$W/fircd.log"; do sleep 0.2; i=$((i + 1)); done
# catches: a cache test that proves nothing because the provider still answered
check "the restarted daemon could not fetch" 1 "$(grep -c "tunnel subscription http://$B/…: fetch failed" "$W/fircd.log")"
kill -TERM "$FP"
wait "$FP"
FP=
check "no tunvless process is left after the subscription case" "" "$(ours)"

echo "tunnels e2e: $pass ok, $fail fail"
[ "$fail" = 0 ]
