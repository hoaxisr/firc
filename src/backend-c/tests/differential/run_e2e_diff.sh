#!/bin/sh
# Playwright e2e suite against fircd serving a fresh production build of the frontend (out/e2e_skins).
# Needs root, a `make` build of fircd, node/npm, and Chromium installed for Playwright.
# Serves on 5173, the baseURL src/frontend/playwright.config.ts names.
set -eu
rm -rf /run/firc 2>/dev/null || true
DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_C_DIR="$(cd "$DIR/../.." && pwd)"
FRONTEND_DIR="$(cd "$BACKEND_C_DIR/../frontend" && pwd)"
OUT="$DIR/out"
mkdir -p "$OUT"

PORT=5173
DNS_PORT=13599
SKINS_DIR="$OUT/e2e_skins"
SCRATCH_CONFIG="$OUT/e2e_scratch_config.yaml"
rm -f "$OUT/groups.yaml"
SOCK=/run/firc/firc.sock

C_PID=
cleanup() {
    [ -n "$C_PID" ] && kill "$C_PID" 2>/dev/null || true
    [ -n "$C_PID" ] && wait "$C_PID" 2>/dev/null || true
    rm -f "$SOCK"
}
trap cleanup EXIT

cat > "$SCRATCH_CONFIG" <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: true
    auth:
      enabled: false
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
  showAllInterfaces: true
  logLevel: error
groups: []
EOF

echo "== building frontend"
( cd "$FRONTEND_DIR" && npm install --no-audit --no-fund >/dev/null && npm run build >/dev/null )
rm -rf "$SKINS_DIR"
mkdir -p "$SKINS_DIR/default"
cp -r "$FRONTEND_DIR/dist/." "$SKINS_DIR/default/"

echo "== building C daemon"
( cd "$BACKEND_C_DIR" && make build/host/fircd >/dev/null )
C_BIN="$BACKEND_C_DIR/build/host/fircd"

REAL_SKINS_ROOT=/usr/share/firc
REAL_SKINS_BACKUP="$OUT/e2e_real_skins.backup"
rm -rf "$REAL_SKINS_BACKUP"
if [ -d "$REAL_SKINS_ROOT/skins" ]; then
    mv "$REAL_SKINS_ROOT/skins" "$REAL_SKINS_BACKUP"
fi
restore_skins() {
    rm -rf "$REAL_SKINS_ROOT/skins"
    if [ -d "$REAL_SKINS_BACKUP" ]; then
        mv "$REAL_SKINS_BACKUP" "$REAL_SKINS_ROOT/skins"
    fi
    rmdir "$REAL_SKINS_ROOT" 2>/dev/null || true
}
trap 'restore_skins; cleanup' EXIT

mkdir -p "$REAL_SKINS_ROOT/skins"
cp -r "$SKINS_DIR/default" "$REAL_SKINS_ROOT/skins/default"

wait_for_port() {
    i=0
    while [ "$i" -lt 50 ]; do
        if curl -s -o /dev/null "http://localhost:$PORT/"; then return 0; fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

echo "== starting C daemon"
rm -f "$SOCK" /var/run/firc.pid
"$C_BIN" --config "$SCRATCH_CONFIG" > "$OUT/e2e_daemon.log" 2>&1 &
C_PID=$!
if ! wait_for_port; then
    echo "C daemon failed to start:"; cat "$OUT/e2e_daemon.log"; exit 1
fi

echo "== running Playwright e2e suite against fircd"
STATUS=0
( cd "$FRONTEND_DIR" && \
  FIRC_E2E_BASE_URL="http://localhost:$PORT" \
  npx playwright test --config=playwright.c-backend.config.ts ) || STATUS=$?

exit $STATUS
