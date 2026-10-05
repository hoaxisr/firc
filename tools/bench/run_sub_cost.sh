#!/bin/sh
set -u

WORK="${WORK:-/tmp/subcost}"
PORT="${PORT:-18399}"
DNS_PORT="${DNS_PORT:-3653}"
DAEMON="${DAEMON:-/opt/bin/fircd}"
SIZES="${SIZES:-10000 50000 100000 313000}"
OUT="${OUT:-$WORK/results.txt}"
SOCK="${SOCK:-/tmp/firc/firc.sock}"
# Without a pause the poller spins and steals CPU from the daemon it times.
if sleep 0.1 2>/dev/null; then POLL_SLEEP=0.1; else POLL_SLEEP=1; fi
CONF="$WORK/conf"
LIST="$WORK/list.txt"
GROUP_ID=5eba1111

cleanup() {
    rm -f "$WORK/probing"
    [ -n "${PROBE_PID:-}" ] && kill "$PROBE_PID" 2>/dev/null
    for _p in ${DNS_WAIT_PID:-} ${API_WAIT_PID:-} ${LIST_WAIT_PID:-}; do
        kill "$_p" 2>/dev/null
    done
    [ -n "${DAEMON_PID:-}" ] && kill -TERM "$DAEMON_PID" 2>/dev/null
    [ -n "${SOCAT_PID:-}" ] && kill "$SOCAT_PID" 2>/dev/null
    sleep 2
    [ -n "${DAEMON_PID:-}" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    return 0
}
trap 'cleanup; exit 130' INT TERM

rm -rf "$WORK"
mkdir -p "$CONF" || exit 1

# ~26-byte distinct lines, so ~313 000 fit the 8 MiB fetch cap.
gen_list() {
    awk -v n="$1" 'BEGIN { for (i = 0; i < n; i++) printf "n%d.ads%d.example.com\n", i, i % 13 }' > "$LIST"
}

cat > "$WORK/serve.sh" <<EOF
#!/bin/sh
printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n'
cat $LIST
EOF
chmod +x "$WORK/serve.sh"

# The installed config, moved off the live daemon's ports and chain prefix.
STOCK_CONF="${STOCK_CONF:-/opt/etc/firc/firc.conf}"
sed -e 's/port: 8080/port: 18080/' \
    -e "s/port: 3553/port: $DNS_PORT/" \
    -e 's/"\[::\]"/"127.0.0.1"/' \
    -e "s/address: '\[::\]'/address: '127.0.0.1'/" \
    -e 's/disableRemap53: false/disableRemap53: true/' \
    -e 's/chainPrefix: FIRC_/chainPrefix: FIRCB_/' \
    -e 's/logLevel: .*/logLevel: debug/' \
    "$STOCK_CONF" > "$CONF/firc.conf" || exit 1
# Anchored, so a word inside a comment cannot satisfy it; without debug there are no stage timings.
grep -q '^[[:space:]]*logLevel: debug' "$CONF/firc.conf" || {
    echo "could not set logLevel: debug in $CONF/firc.conf (from $STOCK_CONF)" >&2
    exit 1
}

# A large interval keeps the ticker from syncing during a measured run.
cat > "$CONF/groups.yaml" <<EOF
configVersion: 0.7.0
groups:
  - id: $GROUP_ID
    name: bench
    interface: nwg0
    enable: true
    rules: []
    list:
      url: 'http://127.0.0.1:$PORT/list.txt'
      interval: 86400
EOF

rss() { awk '/^VmRSS:/ { print $2 }' "/proc/$DAEMON_PID/status" 2>/dev/null; }
hwm() { awk '/^VmHWM:/ { print $2 }' "/proc/$DAEMON_PID/status" 2>/dev/null; }
avail() { awk '/^MemAvailable:/ { print $2 }' /proc/meminfo; }

# Entware's curl lacks Unix sockets and silently hits the firmware's web server, so use socat.
REQ_TIMEOUT="${REQ_TIMEOUT:-7200}"
req() {
    _t0=$(cut -d' ' -f1 /proc/uptime)
    _line=$(printf '%s %s HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n' "$1" "$2" |
        socat -t "$REQ_TIMEOUT" - "UNIX-CONNECT:$SOCK" 2>/dev/null | head -1)
    _t1=$(cut -d' ' -f1 /proc/uptime)
    _code=$(printf '%s' "$_line" | awk '{ print $2 }')
    printf '%s %s' \
        "$(awk -v a="$_t0" -v b="$_t1" 'BEGIN { printf "%.2f", b - a }')" \
        "${_code:--}"
}

probe_start() {
    : > "$WORK/probe.txt"
    : > "$WORK/probing"
    (
        while [ -f "$WORK/probing" ]; do
            req GET /api/v1/system/interfaces
            echo
        done >> "$WORK/probe.txt" 2>/dev/null
    ) &
    PROBE_PID=$!
}

# Stop and read are separate: in a command substitution the probe is not a child and `wait` returns at once.
probe_stop() {
    rm -f "$WORK/probing"
    wait "$PROBE_PID" 2>/dev/null
    PROBE_PID=
}

probe_max() {
    awk 'BEGIN { m = 0 } $1 + 0 > m { m = $1 + 0 } END { printf "%.2f", m }' "$WORK/probe.txt"
}

now_s() { cut -d' ' -f1 /proc/uptime; }
since() { awk -v a="$1" -v b="$(now_s)" 'BEGIN { printf "%.2f", b - a }'; }

# shut-none: a half-closed socket reads as a gone client and ends the event stream after one event.
sync_once() {
    _t0=$(now_s)
    _code=$(printf 'POST /api/v1/groups/%s/list/sync HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n' \
        "$GROUP_ID" | socat -t "$REQ_TIMEOUT" - "UNIX-CONNECT:$SOCK" 2>/dev/null | head -1 |
        awk '{ print $2 }')
    _ev=$(printf 'GET /api/v1/groups/%s/list/sync/events HTTP/1.1\r\nHost: x\r\n\r\n' \
        "$GROUP_ID" | socat -t "$REQ_TIMEOUT" - "UNIX-CONNECT:$SOCK,shut-none" 2>/dev/null |
        awk '/^event: done/ { print "done"; exit } /^event: error/ { print "error"; exit }')
    printf '%s %s %s' "$(since "$_t0")" "${_code:--}" "${_ev:--}"
}

# Sums the debug stage timings of the last changed sync; an unchanged sync prints none.
loop_s() {
    _line=$(grep 'sync applied' "$WORK/daemon.log" 2>/dev/null | tail -1)
    [ -n "$_line" ] || { printf -- '-'; return; }
    printf '%s' "$_line" |
        awk '{ s = 0; for (i = 2; i <= NF; i++) if ($i ~ /^ms/) s += $(i - 1) }
             END { printf "%.2f", s / 1000 }'
}

dns_answer_bytes() {
    printf '\253\315\001\000\000\001\000\000\000\000\000\000\007example\007invalid\000\000\001\000\001' |
        socat -t 0.3 -T 0.6 - "UDP4:127.0.0.1:$DNS_PORT" 2>/dev/null | wc -c
}

sync_nosave() {
    sync_once
}

gen_list 10
socat "TCP-LISTEN:$PORT,reuseaddr,fork,bind=127.0.0.1" "SYSTEM:$WORK/serve.sh" &
SOCAT_PID=$!
sleep 1

"$DAEMON" --config "$CONF/firc.conf" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!

i=0
while [ $i -lt 60 ]; do
    [ "$(req GET /api/v1/system/interfaces | awk '{ print $2 }')" = 200 ] && break
    i=$((i + 1))
    sleep 1
done
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "the daemon did not come up; see $WORK/daemon.log" >&2
    tail -5 "$WORK/daemon.log" >&2
    cleanup
    exit 1
fi

{
    echo "# run_sub_cost.sh -- $(date)"
    echo "# $(uname -sm), $(awk '/^MemTotal:/ { print $2 }' /proc/meminfo) kB total"
    echo "# daemon: $("$DAEMON" --version 2>&1 | head -1)"
    echo "#"
    echo "# lines  bytes    changed_s  unchanged_s  page_s  loop_s  nosave_s  worst_other_req_s probes  VmRSS_kB  VmHWM_kB  MemAvail_kB"
} > "$OUT"

for n in $SIZES; do
    gen_list "$n"
    bytes=$(wc -c < "$LIST")

    probe_start
    set -- $(sync_once)
    t_changed=$1; code_changed=$2; ev_changed=$3
    probe_stop
    stall=$(probe_max)
    probes=$(wc -l < "$WORK/probe.txt")
    t_loop=$(loop_s)

    set -- $(sync_once)
    t_unchanged=$1; code_unchanged=$2; ev_unchanged=$3

    set -- $(req GET "/api/v1/groups/$GROUP_ID/list/rules?offset=100000&limit=50&q=ads7")
    t_page=$1; code_page=$2

    t_nosave=-
    if [ "${DECOMPOSE:-0}" = 1 ]; then
        sed '$d' "$LIST" > "$LIST.tmp" && mv "$LIST.tmp" "$LIST"
        set -- $(sync_nosave)
        t_nosave=$1
    fi

    printf '%8s %8s  %9s  %11s  %9s  %6s  %9s  %17s %6s  %8s  %8s  %11s\n' \
        "$n" "$bytes" "$t_changed" "$t_unchanged" "$t_page" "$t_loop" "$t_nosave" "$stall" "$probes" \
        "$(rss)" "$(hwm)" "$(avail)" >> "$OUT"
    if [ "$code_changed" != "202" ] || [ "$code_unchanged" != "202" ] ||
       [ "$code_page" != "200" ] || [ "$ev_changed" != "done" ] || [ "$ev_unchanged" != "done" ]; then
        echo "  (HTTP $code_changed / $code_unchanged / $code_page, events $ev_changed / $ev_unchanged)" >> "$OUT"
    fi
    tail -1 "$OUT"
done

kill -TERM "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null
rm -f "$WORK/t_dns" "$WORK/t_api" "$WORK/t_list"
start_before=$(now_s)
"$DAEMON" --config "$CONF/firc.conf" > "$WORK/daemon2.log" 2>&1 &
DAEMON_PID=$!

# Also true once the daemon is gone, so the pollers stop.
boot_over() {
    kill -0 "$DAEMON_PID" 2>/dev/null ||
        { echo 1; return; }
    awk -v a="$start_before" -v b="$(now_s)" 'BEGIN { print (b - a > 300) }'
}

(
    while [ "$(boot_over)" = 0 ]; do
        [ "$(dns_answer_bytes)" -gt 0 ] 2>/dev/null && { now_s > "$WORK/t_dns"; break; }
    done
) &
DNS_WAIT_PID=$!
(
    while [ "$(boot_over)" = 0 ]; do
        [ "$(req GET /api/v1/system/interfaces | awk '{ print $2 }')" = 200 ] &&
            { now_s > "$WORK/t_api"; break; }
        sleep "$POLL_SLEEP"
    done
) &
API_WAIT_PID=$!
(
    while [ "$(boot_over)" = 0 ]; do
        grep -q 'sync applied' "$WORK/daemon2.log" 2>/dev/null &&
            { now_s > "$WORK/t_list"; break; }
        sleep 1
    done
) &
LIST_WAIT_PID=$!
wait "$DNS_WAIT_PID" "$API_WAIT_PID" "$LIST_WAIT_PID" 2>/dev/null

boot_at() {
    [ -s "$1" ] || { printf -- '-'; return; }
    awk -v a="$start_before" -v b="$(cat "$1")" 'BEGIN { printf "%.2f", b - a }'
}
{
    echo "#"
    echo "# startup into a list of $(wc -l < "$LIST") lines, fetched:"
    echo "#   $(boot_at "$WORK/t_dns") s to the first answered DNS query (dns_first_s)"
    echo "#   $(boot_at "$WORK/t_api") s to the first answered API request (api_first_s)"
    echo "#   $(boot_at "$WORK/t_list") s to the first list applied (list_s, 1 s resolution)"
    echo "#   VmRSS $(rss) kB, VmHWM $(hwm) kB, MemAvailable $(avail) kB"
    echo "#   groups.yaml: $(wc -c < "$CONF/groups.yaml") bytes"
} >> "$OUT"

cleanup
tail -8 "$OUT"
echo "-> $OUT"
