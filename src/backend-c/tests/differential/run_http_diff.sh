#!/bin/sh
# HTTP API contract suite: drives fircd through http_contract/contract.py and diffs the trace with golden/.
# Needs root (real iptables and /run/firc) and python3; the config, groups.yaml, tunnels.yaml and logs all stay in out/.
# The bare rm -rf /run/firc drops the pool file a previous run left, which this run would otherwise inherit.
set -eu
rm -rf /run/firc 2>/dev/null || true
DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_C_DIR="$(cd "$DIR/../.." && pwd)"
OUT="$DIR/out"
GOLDEN="$DIR/golden/http_contract.trace"
mkdir -p "$OUT"

SCRATCH_CONFIG="$OUT/http_scratch_config.yaml"
PORT=18095
DNS_PORT=13595
SOCK=/run/firc/firc.sock
PIDFILE=/var/run/firc.pid

C_PID=
cleanup() {
    [ -n "$C_PID" ] && kill "$C_PID" 2>/dev/null || true
    rm -f "$OUT/groups.yaml" "$OUT/tunnels.yaml" "$OUT/hwid"
    rm -rf "$OUT/tunnels-cache" "$OUT/update"
    rm -f "$SOCK" "$PIDFILE"
}
trap cleanup EXIT

cat > "$SCRATCH_CONFIG" <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: true
    host:
      address: "127.0.0.1"
      port: $PORT
  dnsProxy:
    host:
      address: "127.0.0.1"
      port: $DNS_PORT
    upstream:
      address: 127.0.0.1
      port: 53
    disableRemap53: true
    disableDropAAAA: false
    maxIdleConns: 10
    maxConcurrent: 100
    timeout: 5s
  netfilter:
    iptables:
      chainPrefix: FIRC_
    ipset:
      tablePrefix: firc_
      additionalTTL: 1h0m0s
    disableIPv4: false
    disableIPv6: false
    startMarkTableIndex: 1718186595
  link: []
groups: []
EOF

echo "== building C daemon"
( cd "$BACKEND_C_DIR" && make build/host/fircd >/dev/null )
C_BIN="$BACKEND_C_DIR/build/host/fircd"

echo "== a removed level as the output floor is refused"
rc=0
timeout 10 "$C_BIN" --config "$SCRATCH_CONFIG" --output-floor trace > "$OUT/c_floor.log" 2>&1 || rc=$?
if [ "$rc" != 2 ] || ! grep -q '^usage: fircd' "$OUT/c_floor.log"; then
    echo "   --output-floor trace: exit $rc, want 2 and the usage line"
    exit 1
fi

wait_for_port() {
    i=0
    while [ "$i" -lt 50 ]; do
        if curl -s -o /dev/null "http://127.0.0.1:$PORT/api/v1/auth"; then return 0; fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

echo "== running contract against C daemon"
rm -f "$SOCK" "$PIDFILE" "$OUT/groups.yaml" "$OUT/tunnels.yaml"
rm -rf "$OUT/tunnels-cache"
printf '0123456789abcdef\n' > "$OUT/hwid"
FIRC_HWID_PATH="$OUT/hwid" FIRC_TUNNELS_PATH="$OUT/tunnels.yaml" FIRC_TUNNELS_CACHE_DIR="$OUT/tunnels-cache" FIRC_UPDATE_DIR="$OUT/update" \
    FIRC_TUNVLESS_BIN="$BACKEND_C_DIR/tests/unit/fixtures/fake_tunvless.sh" \
    "$C_BIN" --config "$SCRATCH_CONFIG" > "$OUT/c_daemon.log" 2>&1 &
C_PID=$!
if ! wait_for_port; then
    echo "C daemon failed to start:"; cat "$OUT/c_daemon.log"; exit 1
fi
python3 "$DIR/http_contract/contract.py" 127.0.0.1 "$PORT" "$SOCK" > "$OUT/c.trace" 2> "$OUT/c_contract.err"
CONTRACT_STATUS=$?
REPORTED=$(FIRC_SOCK="$SOCK" FIRC_CONF="$SCRATCH_CONFIG" sh "$BACKEND_C_DIR/../../files/entware/_ipk/control/postinst" --report-web 2>&1)
kill "$C_PID" 2>/dev/null || true
wait "$C_PID" 2>/dev/null || true
C_PID=
if [ "$CONTRACT_STATUS" -ne 0 ]; then
    echo "contract run against C failed:"; cat "$OUT/c_contract.err"; exit 1
fi

if [ "$REPORTED" != "firc: WebUI at http://127.0.0.1:$PORT" ]; then
    echo "postinst reported the WebUI wrongly: $REPORTED"; exit 1
fi
echo "   postinst's WebUI address from the running daemon: OK"

echo "== diffing against golden trace"
if diff -u "$GOLDEN" "$OUT/c.trace" > "$OUT/http_contract.diff"; then
    echo "   HTTP contract: OK ($(grep -c '^STEP' "$GOLDEN") steps)"
else
    echo "   HTTP CONTRACT REGRESSION (vs golden/http_contract.trace):"
    cat "$OUT/http_contract.diff"
    exit 1
fi

echo "== starting with the DNS remap on"
REMAP_CONFIG="$OUT/http_remap_config.yaml"
sed 's/disableRemap53: true/disableRemap53: false/' "$SCRATCH_CONFIG" > "$REMAP_CONFIG"
rm -rf /run/firc 2>/dev/null || true
rm -f "$SOCK" "$PIDFILE" "$OUT/groups.yaml" "$OUT/tunnels.yaml"
rm -rf "$OUT/tunnels-cache"
printf '0123456789abcdef\n' > "$OUT/hwid"
FIRC_HWID_PATH="$OUT/hwid" FIRC_TUNNELS_PATH="$OUT/tunnels.yaml" FIRC_TUNNELS_CACHE_DIR="$OUT/tunnels-cache" FIRC_UPDATE_DIR="$OUT/update" \
    FIRC_TUNVLESS_BIN="$BACKEND_C_DIR/tests/unit/fixtures/fake_tunvless.sh" \
    "$C_BIN" --config "$REMAP_CONFIG" > "$OUT/c_remap.log" 2>&1 &
C_PID=$!
if ! wait_for_port; then
    echo "C daemon failed to start with the DNS remap on:"; cat "$OUT/c_remap.log"; exit 1
fi
kill "$C_PID" 2>/dev/null || true
wait "$C_PID" 2>/dev/null || true
C_PID=
echo "   start with the DNS remap on: OK"
