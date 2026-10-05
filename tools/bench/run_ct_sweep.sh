#!/bin/sh
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BIN:-$REPO/.build/bench}"
RESULTS_DIR="${1:-$REPO/.build/bench/ct-sweep}"
SOCKET="${SOCKET:-/tmp/firc/firc.sock}"
ENTRIES="${ENTRIES:-12000}"  # ctfill's default prefix x ports holds 16 256
PASSES="${PASSES:-20}"
LOAD_SEC="${LOAD_SEC:-30}"
PROXY_PORT="${PROXY_PORT:-3553}"
CONCURRENCY="${CONCURRENCY:-10}"

die() { echo "$*" >&2; exit 1; }
[ -S "$SOCKET" ] || die "no daemon socket at $SOCKET (is fircd running?)"
command -v socat >/dev/null 2>&1 || die "socat is required"
for t in ctfill dnsload; do
    [ -x "$BIN/$t" ] || die "$BIN/$t is missing -- build it for this target first"
done
mkdir -p "$RESULTS_DIR" || die "cannot write $RESULTS_DIR"

ct_count() {
    for p in /proc/sys/net/netfilter/nf_conntrack_count \
             /proc/sys/net/ipv4/netfilter/ip_conntrack_count; do
        [ -r "$p" ] && { cat "$p"; return; }
    done
    echo 0
}

# The daemon answers at once and rebuilds behind it, so passes pile up as on a flapping interface.
poke_hook() {
    body='{"type":"ip6tables-restore","table":"mangle"}'
    len=$(printf "%s" "$body" | wc -c)
    socat - "UNIX-CONNECT:$SOCKET" >/dev/null 2>&1 <<EOF
POST /api/v1/system/hooks/netfilterd HTTP/1.1
Host:
Content-Type: application/json
Content-Length: $len

$body
EOF
}

run_load() {
    "$BIN/dnsload" -mode load -server "127.0.0.1:$PROXY_PORT" \
        -duration "${LOAD_SEC}s" -concurrency "$CONCURRENCY" -label "$1" 2>/dev/null
}

echo "== filling conntrack to ~$ENTRIES entries =="
"$BIN/ctfill" -n "$ENTRIES" -hold 0 > "$RESULTS_DIR/ctfill.json" 2>"$RESULTS_DIR/ctfill.err" &
FILL_PID=$!
sleep 2
# ctfill refuses past nf_conntrack_max; a background refusal must stop the run.
if ! kill -0 "$FILL_PID" 2>/dev/null; then
    die "ctfill exited: $(head -1 "$RESULTS_DIR/ctfill.err" 2>/dev/null)"
fi
i=0
while [ $i -lt 60 ]; do
    now=$(ct_count)
    [ "$now" -ge "$ENTRIES" ] && break
    i=$((i + 1))
    sleep 1
done
BEFORE=$(ct_count)
echo "conntrack entries: $BEFORE"

echo "== baseline: $LOAD_SEC s of load, no rebuild passes =="
run_load quiet > "$RESULTS_DIR/quiet.json"

echo "== under $PASSES rebuild passes =="
(
    n=0
    while [ $n -lt "$PASSES" ]; do
        poke_hook
        n=$((n + 1))
        sleep 1
    done
) &
POKE_PID=$!
run_load under-passes > "$RESULTS_DIR/under-passes.json"
wait $POKE_PID 2>/dev/null

AFTER=$(ct_count)
kill -INT $FILL_PID 2>/dev/null
wait $FILL_PID 2>/dev/null

cat > "$RESULTS_DIR/run.txt" <<EOF
entries_before=$BEFORE
entries_after=$AFTER
passes=$PASSES
load_sec=$LOAD_SEC
concurrency=$CONCURRENCY
EOF

echo
echo "results in $RESULTS_DIR"
echo "  quiet.json        -- p99 with no rebuild passes"
echo "  under-passes.json -- p99 with $PASSES passes underneath"
echo "  run.txt           -- the table size the numbers belong to"
echo
echo "The difference between the two p99s is what a flush costs the loop"
echo "thread, at this table size. A figure without run.txt beside it means"
echo "nothing: the cost is a function of the table, not a constant."
