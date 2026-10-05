#!/bin/sh
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/.build/bench"
BACKEND_C_DIR="$REPO/src/backend-c"
DAEMON="${DAEMON:-$BACKEND_C_DIR/build/host/fircd}"
OUT_DIR="${1:-$REPO/.build/bench/soak-subscriptions}"
DURATION="${DURATION:-90}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-5}"
DNS_PORT=3557
UPSTREAM_PORT=5397
STUB_SUB_PORT=18300
HTTP_PORT=18301
# Own dir: groups.yaml sits next to --config, and a shared dir would mix another script's rules in.
CFG_DIR=/tmp/firc-subscription-fault-soak
mkdir -p "$CFG_DIR"
CFG="$CFG_DIR/firc.conf"

mkdir -p "$OUT_DIR"
RSS_CSV="$OUT_DIR/rss.csv"
echo "sec,rss_kb" > "$RSS_CSV"

pkill -9 -f fircd 2>/dev/null
pkill -9 -x dnsstub 2>/dev/null
pkill -9 -f subscription_fault_stub.py 2>/dev/null
sleep 1

cat > "$CFG" <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: true
    auth:
      enabled: false
    host:
      address: "127.0.0.1"
      port: $HTTP_PORT
    skin: default
  dnsProxy:
    host:
      address: "127.0.0.1"
      port: $DNS_PORT
    upstream:
      address: 127.0.0.1
      port: $UPSTREAM_PORT
    disableRemap53: true
    maxIdleConns: 10
    maxConcurrent: 100
    timeout: 5s
  netfilter:
    iptables:
      chainPrefix: FIRC_
    ipset:
      tablePrefix: firc_
      additionalTTL: 5m0s
    disableIPv4: false
    disableIPv6: false
    startMarkTableIndex: 1298229100
  link: []
  showAllInterfaces: true
  logLevel: info
groups:
  - id: aaaaaaaa
    name: soak-group
    color: "#ffffff"
    interface: eth0
    enable: false
    rules:
      - id: bbbbbbbb
        name: r1
        type: namespace
        rule: fault-soak.example.com
        enable: true
  # A list is part of a group. enable:true is what makes
  # a list due for its timer (firc_sub_is_due); interface:"" keeps the
  # group's ruleset out of the kernel (firc_ruleset_runtime_enabled asks
  # for a usable interface), so no netfilter work is attempted and only
  # the fetch/apply/republish code under test runs.
  - id: 10000001
    name: good-alternating
    interface: ""
    enable: true
    rules: []
    list:
      url: "http://127.0.0.1:$STUB_SUB_PORT/good"
      interval: 4
  - id: 10000002
    name: redirect-loop
    interface: ""
    enable: true
    rules: []
    list:
      url: "http://127.0.0.1:$STUB_SUB_PORT/loopA"
      interval: 4
  - id: 10000003
    name: not-found
    interface: ""
    enable: true
    rules: []
    list:
      url: "http://127.0.0.1:$STUB_SUB_PORT/404"
      interval: 4
  - id: 10000004
    name: oversized
    interface: ""
    enable: true
    rules: []
    list:
      url: "http://127.0.0.1:$STUB_SUB_PORT/big"
      interval: 4
  - id: 10000005
    name: connection-refused
    interface: ""
    enable: true
    rules: []
    list:
      url: "http://127.0.0.1:1/nope"
      interval: 4
EOF

echo "== building bench tools + daemon"
( cd "$REPO/tools/bench" && go build -o "$BIN/dnsstub" ./dnsstub && go build -o "$BIN/dnsload" ./dnsload )
( cd "$BACKEND_C_DIR" && make build/host/fircd >/dev/null )

"$BIN/dnsstub" -listen "127.0.0.1:$UPSTREAM_PORT" -cname 2 >"$OUT_DIR/dnsstub.log" 2>&1 &
STUB_DNS=$!
python3 "$REPO/tools/bench/subscription_fault_stub.py" "$STUB_SUB_PORT" >"$OUT_DIR/stub_sub.log" 2>&1 &
STUB_SUB=$!

# The first list fetch fires at once, so wait until the stub accepts connections.
j=0
while [ "$j" -lt 50 ]; do
    if curl -s -o /dev/null "http://127.0.0.1:$STUB_SUB_PORT/404"; then break; fi
    j=$((j + 1))
    sleep 0.1
done

"$DAEMON" --config "$CFG" >"$OUT_DIR/daemon.log" 2>&1 &
DP=$!
sleep 1

if ! kill -0 "$DP" 2>/dev/null; then
    echo "daemon failed to start:"; cat "$OUT_DIR/daemon.log"
    kill -9 "$STUB_DNS" "$STUB_SUB" 2>/dev/null
    exit 1
fi

"$BIN/dnsload" -server "127.0.0.1:$DNS_PORT" -proto udp -concurrency 10 \
    -duration "${DURATION}s" -ndomains 5000 \
    -pattern 'q%06d.fault-soak.example.com.' >"$OUT_DIR/load_udp.json" 2>&1 &
LOAD=$!

i=0
hup_count=0
while [ "$i" -lt "$DURATION" ]; do
    rss=$(awk '/VmRSS/{print $2}' "/proc/$DP/status" 2>/dev/null || echo 0)
    echo "$i,$rss" >> "$RSS_CSV"
    if ! kill -0 "$DP" 2>/dev/null; then
        echo "daemon died mid-soak at t=${i}s"
        cat "$OUT_DIR/daemon.log"
        kill -9 "$STUB_DNS" "$STUB_SUB" "$LOAD" 2>/dev/null
        exit 1
    fi
    if [ "$i" -gt 0 ] && [ $((i % 20)) -eq 0 ]; then
        kill -HUP "$DP" 2>/dev/null
        hup_count=$((hup_count + 1))
    fi
    sleep "$SAMPLE_INTERVAL"
    i=$((i + SAMPLE_INTERVAL))
done

wait "$LOAD" 2>/dev/null
final_rss=$(awk '/VmRSS/{print $2}' "/proc/$DP/status" 2>/dev/null || echo 0)
final_hwm=$(awk '/VmHWM/{print $2}' "/proc/$DP/status" 2>/dev/null || echo 0)
echo "$DURATION,$final_rss" >> "$RSS_CSV"

alive="no"
kill -0 "$DP" 2>/dev/null && alive="yes"

sync_errors=$(grep -c '": sync failed: ' "$OUT_DIR/daemon.log" 2>/dev/null || echo 0)
reloads=$(grep -c "config reloaded" "$OUT_DIR/daemon.log" 2>/dev/null || echo 0)

kill -TERM "$DP" 2>/dev/null
sleep 1
terminated_cleanly="no"
if ! kill -0 "$DP" 2>/dev/null; then
    terminated_cleanly="yes"
else
    kill -9 "$DP" 2>/dev/null
fi
kill -9 "$STUB_DNS" "$STUB_SUB" 2>/dev/null

{
    echo "duration_sec: $DURATION"
    echo "daemon_alive_at_end_of_soak: $alive"
    echo "daemon_terminated_cleanly_on_sigterm: $terminated_cleanly"
    echo "final_rss_kb: $final_rss"
    echo "peak_rss_kb (VmHWM): $final_hwm"
    echo "sighup_reloads_sent: $hup_count"
    echo "sighup_reloads_logged: $reloads"
    echo "list_fetch_failures_logged (expected: loop/404/oversized/refused, every ~4s each): $sync_errors"
    echo "dns_load: $(cat "$OUT_DIR/load_udp.json" 2>/dev/null)"
} > "$OUT_DIR/summary.txt"

cat "$OUT_DIR/summary.txt"
echo "raw daemon log: $OUT_DIR/daemon.log" >&2
echo "raw rss samples: $RSS_CSV" >&2

if [ "$alive" != "yes" ] || [ "$terminated_cleanly" != "yes" ]; then
    exit 1
fi
exit 0
