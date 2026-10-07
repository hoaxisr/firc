#!/bin/sh
# UDP over a Vision flow against REAL servers: Xray-core (XRAY=/path/to/xray) and sing-box
# (SINGBOX=/path/to/sing-box).
#
# With flow=xtls-rprx-vision UDP does not go as command 2 but as Mux.Cool with XUDP frames over
# the Vision stream (src/proto/vless/vldial.c, the XUDP block): neither Xray-core nor sing-box
# accepts command 2 on such a node. The frame format follows both servers' sources, but only a
# live run shows wire mistakes: the Mux request header carries no port and address, and with
# them sing-box read the extra bytes as stream data and dropped the connection. So this test
# runs the real wire: the client is the VLESS dialer (tests/xudpprobe.c), the server is real,
# with a UDP echo behind it.
#
# The server uses TLS with a self-signed leaf (openssl), and the client pins its fingerprint
# (`pcs`): one more pinning check against a real server. The node is named localhost, not
# 127.0.0.1: link parsing rejects nodes with no peer (127.0.0.0/8), and the test must go through
# the same parsing.
#
# Anything missing is a LOUD skip (echo and exit 0), as in venc.sh: a silent skip reads as a pass.
set -eu
cd "$(dirname "$0")/.."
BUILD=${BUILD:-build}
PROBE="$BUILD/xudpprobe"
[ -x "$PROBE" ] || { echo "xudp: no $PROBE (built by make interop)"; exit 2; }
command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 || {
	echo "xudp: SKIPPED — needs python3 and openssl. Not a failure."; exit 0; }
HAVE_X=0; HAVE_S=0
[ -n "${XRAY:-}" ] && [ -x "$XRAY" ] && HAVE_X=1
[ -n "${SINGBOX:-}" ] && [ -x "$SINGBOX" ] && HAVE_S=1
if [ $HAVE_X = 0 ] && [ $HAVE_S = 0 ]; then
	echo "xudp: SKIPPED — no servers (XRAY=/path/to/xray, SINGBOX=/path/to/sing-box). Not a failure."
	exit 0
fi

W=$(mktemp -d)
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT INT TERM

BASE=$((21000 + $$ % 20000))
ECHO=$((BASE + 1)); XP_VIS=$((BASE + 2)); XP_PLAIN=$((BASE + 3)); SB_VIS=$((BASE + 4))
U=00000000-0000-0000-0000-000000000001

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/k.pem" -out "$W/c.pem" \
	-subj "/CN=test.example" -days 2 -addext "subjectAltName=DNS:test.example" 2>/dev/null
PCS=$(openssl x509 -in "$W/c.pem" -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n')

python3 - "$ECHO" <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(b"echo:" + d, a)
PY
PIDS="$PIDS $!"

if [ $HAVE_X = 1 ]; then
	# finalRules allow: by default freedom does not connect to loopback and private addresses.
	cat > "$W/x.json" <<EOF
{"log": {"loglevel": "warning"},
 "inbounds": [
  {"listen": "127.0.0.1", "port": $XP_VIS, "protocol": "vless",
   "settings": {"clients": [{"id": "$U", "flow": "xtls-rprx-vision"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}},
  {"listen": "127.0.0.1", "port": $XP_PLAIN, "protocol": "vless",
   "settings": {"clients": [{"id": "$U"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}}],
 "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
EOF
	"$XRAY" run -c "$W/x.json" >"$W/x.log" 2>&1 &
	PIDS="$PIDS $!"
	echo "xudp: server — $("$XRAY" version 2>/dev/null | head -1)"
fi
if [ $HAVE_S = 1 ]; then
	cat > "$W/s.json" <<EOF
{"log": {"level": "warn"},
 "inbounds": [{"type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": $SB_VIS,
   "users": [{"uuid": "$U", "flow": "xtls-rprx-vision"}],
   "tls": {"enabled": true, "server_name": "test.example", "certificate_path": "$W/c.pem", "key_path": "$W/k.pem"}}],
 "outbounds": [{"type": "direct", "tag": "d"}]}
EOF
	"$SINGBOX" run -c "$W/s.json" >"$W/s.log" 2>&1 &
	PIDS="$PIDS $!"
	echo "xudp: server — $("$SINGBOX" version 2>/dev/null | head -1)"
fi
sleep 2

FAILS=0
run() { # LABEL PORT FLOW
	name=$1; port=$2; flow=$3
	url="vless://$U@localhost:$port?type=tcp&security=tls&sni=test.example&pcs=$PCS${flow:+&flow=$flow}"
	for mode in single burst; do
		if [ $mode = burst ]; then export BURST=1; else unset BURST || true; fi
		if out=$(timeout 40 "$PROBE" "$url" 127.0.0.1 "$ECHO" 5 2>&1); then
			echo "  ok   $name ($mode)"
		else
			echo "  FAIL $name ($mode)"; echo "$out" | sed 's/^/       /'; FAILS=$((FAILS + 1))
		fi
	done
	unset BURST || true
}
[ $HAVE_X = 1 ] && run "Xray, vision: Mux and XUDP" $XP_VIS xtls-rprx-vision
[ $HAVE_X = 1 ] && run "Xray, no flow: command 2" $XP_PLAIN ""
[ $HAVE_S = 1 ] && run "sing-box, vision: Mux and XUDP" $SB_VIS xtls-rprx-vision

[ $FAILS = 0 ] && echo "xudp: all checks passed" || { echo "xudp: failures: $FAILS"; exit 1; }
