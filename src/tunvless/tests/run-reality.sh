#!/bin/sh
# The tunnel through a REAL Reality server: our own, with known keys.
#
# tests/run-tunnel.sh uses a fake server without TLS and tests the tunnel loop (TCP synthesis,
# retransmission, threads). It does not test Reality, Vision or VLESS at all, and failures there
# look from outside like "the node died".
#
# Here the server is real (sing-box), with real Reality and Vision, and it LOGS what it did not
# like. That is the only way to tell "we were not recognized" from "recognized, but we did not
# understand the answer": Reality has no negative answer, it silently proxies an unrecognized
# client to the cover site, and both cases look the same from outside.
#
# The two sides MUST be in separate network namespaces: on one host the route to the target
# through the tunnel also applies to the server, its outgoing connection goes back into the
# tunnel, and the test catches its own loop, which looks like a Reality refusal.
#
# Needs sing-box: SINGBOX, default ./build/sing-box.
set -eu
cd "$(dirname "$0")/.."

SB="${SINGBOX:-./build/sing-box}"
BIN="${TUNVLESS:-./out/tunvless}"
MASK="${MASK:-prod.vkimages.io}"          # cover domain: must support TLS 1.3 and h2
TARGET="${TARGET:-205.234.175.175}"       # what to fetch through the tunnel
TPATH="${TPATH:-/1mb.test}"
THOST="${THOST:-cachefly.cachefly.net}"

[ -x "$SB" ] || { echo "no sing-box: $SB (SINGBOX=path)"; exit 2; }
[ -x "$BIN" ] || { echo "no binary: $BIN"; exit 2; }

NS=tunvless-reality
W="$(mktemp -d)"
cleanup() {
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    ip link delete veth-h 2>/dev/null || true
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

ip netns delete "$NS" 2>/dev/null || true
ip link delete veth-h 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip link add veth-h type veth peer name veth-c
ip addr add 10.90.0.1/24 dev veth-h && ip link set veth-h up
ip link set veth-c netns "$NS"
ip netns exec "$NS" ip addr add 10.90.0.2/24 dev veth-c
ip netns exec "$NS" ip link set veth-c up

"$SB" generate reality-keypair > "$W/rk.txt"
PRIV=$(awk '/PrivateKey/{print $2}' "$W/rk.txt")
PUB=$(awk '/PublicKey/{print $2}' "$W/rk.txt")
UUID=$("$SB" generate uuid)
SID=0123456789abcdef

cat > "$W/server.json" <<CFG
{"log":{"level":"trace","timestamp":true},
 "inbounds":[{"type":"vless","tag":"in","listen":"10.90.0.1","listen_port":18443,
   "users":[{"uuid":"$UUID","flow":"xtls-rprx-vision"}],
   "tls":{"enabled":true,"server_name":"$MASK",
     "reality":{"enabled":true,
       "handshake":{"server":"$MASK","server_port":443},
       "private_key":"$PRIV","short_id":["$SID"]}}}],
 "outbounds":[{"type":"direct","tag":"out"}]}
CFG

LINK="vless://$UUID@10.90.0.1:18443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=$MASK&pbk=$PUB&sid=$SID&fp=chrome#local"

"$SB" run -c "$W/server.json" > "$W/srv.log" 2>&1 &
SRV=$!
sleep 2
grep -q "tcp server started" "$W/srv.log" || { echo "server did not start:"; tail -5 "$W/srv.log"; exit 1; }

ip netns exec "$NS" env STEER_TUN_STATS=1 "$BIN" "$LINK" -d vl -r "$TARGET/32" > "$W/tun.log" 2>&1 &
for _ in $(seq 40); do
    ip netns exec "$NS" ip route show "$TARGET/32" 2>/dev/null | grep -q 'dev vl' && break
    sleep 0.2
done
ip netns exec "$NS" ip route show "$TARGET/32" 2>/dev/null | grep -q 'dev vl' ||
    { echo "vl did not come up:"; tail -5 "$W/tun.log"; exit 1; }

echo "  cover $MASK, target $TARGET"
ip netns exec "$NS" curl -s -o "$W/dl.bin" \
    -w "  through the tunnel: code %{http_code}, %{size_download} bytes, %{speed_download} B/s\n" \
    --max-time 30 -H "Host: $THOST" "http://$TARGET$TPATH" || echo "  through the tunnel: FAILED"

echo "  server:"
grep -iE "inbound connection to|Xtls|ERROR|isHandshakeComplete" "$W/srv.log" |
    tail -5 | sed 's/.*\] //; s/^/    /' | cut -c1-150
