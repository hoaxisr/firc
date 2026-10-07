#!/bin/sh
# End-to-end checks of the client against a REAL Xray-core: VLESS encryption and post-quantum TLS.
#
#   1. VLESS encryption (mlkem768x25519plus): modes native / xorpub / random × X25519 / ML-KEM key
#      × 1rtt / 0rtt. Three connections in one process (from the second on with a 0-RTT ticket,
#      as the trace shows) and 4 MB there and back through an echo server: writes of random
#      length, compared byte by byte.
#   2. Several relays in a chain (X25519 → ML-KEM → X25519) and custom padding from a string.
#   3. REALITY: the client offers the X25519MLKEM768 hybrid and Xray picks it; with mldsa65Seed on
#      the server and pqv in the link the client verifies the ML-DSA-65 signature, and with
#      another key's pqv it refuses. Needs network access and a cover site with a large
#      certificate (VENC_DEST, default www.apple.com: www.microsoft.com has an 8 KB chain, and
#      Xray 26.3.27 breaks the handshake with it even for its own client). Without them this
#      section is SKIPPED loudly and the rest runs.
#
# Why a live server and not a byte comparison: VLESS encryption has no "input → output" vector,
# every handshake is random. The only proof that we speak the same protocol is a live server
# that rejects anything not matching to the bit (AEAD with a BLAKE3 context over all messages).
#
# Xray: XRAY=/path/to/binary or docker with the image XRAY_IMAGE (default
# ghcr.io/xtls/xray-core:latest); with neither, a loud skip (exit 0), not silence. The client is
# $BUILD/vencprobe (built by make interop against a real wolfSSL). Containers and temporary files
# are removed on any exit.
set -eu
cd "$(dirname "$0")/.."
BUILD=${BUILD:-build}
PROBE="$BUILD/vencprobe"
[ -x "$PROBE" ] || { echo "venc: no $PROBE (built by make interop)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "venc: SKIPPED — needs python3"; exit 0; }

IMG=${XRAY_IMAGE:-ghcr.io/xtls/xray-core:latest}
if [ -n "${XRAY:-}" ] && [ -x "$XRAY" ]; then
	MODE=bin
elif command -v docker >/dev/null 2>&1 && docker image inspect "$IMG" >/dev/null 2>&1; then
	MODE=docker
else
	echo "venc: SKIPPED — no Xray-core (XRAY=/path or image $IMG in docker). Not a failure."
	exit 0
fi

W=$(mktemp -d)
# The container reads the configs as another user, and mktemp creates the directory 0700.
chmod 755 "$W"
PIDS=""
CONTS=""
cleanup() {
	for p in $PIDS; do kill "$p" 2>/dev/null || true; done
	for c in $CONTS; do docker rm -f "$c" >/dev/null 2>&1 || true; done
	rm -rf "$W"
}
trap cleanup EXIT INT TERM

xray_cmd() {
	if [ "$MODE" = bin ]; then "$XRAY" "$@"; else docker run --rm "$IMG" "$@"; fi
}
XVER=$(xray_cmd version 2>/dev/null | head -1)
echo "venc: server — $XVER ($MODE)"

BASE=$((20000 + $$ % 20000))
NEXT=$BASE
# Not via $(…): a subshell would lose the counter, and every server would get the same port.
port() { NEXT=$((NEXT + 1)); PORT=$NEXT; }

# The echo server: the one destination Xray's freedom outbound sends the test data to.
port; ECHO=$PORT
python3 - "$ECHO" <<'PY' &
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(64)
def h(c):
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            c.sendall(d)
    finally: c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
PY
PIDS="$PIDS $!"

wait_port() {
	python3 - "$1" <<'PY'
import socket, sys, time
for _ in range(60):
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.2).close(); sys.exit(0)
    except OSError: time.sleep(0.2)
sys.exit(1)
PY
}

# xray_start NAME PORT: the config $W/NAME.json is already written.
xray_start() {
	if [ "$MODE" = bin ]; then
		"$XRAY" run -c "$W/$1.json" >"$W/$1.log" 2>&1 &
		PIDS="$PIDS $!"
		LAST_PID=$!
	else
		c="steer-venc-$$-$1"
		docker run -d --rm --name "$c" --network host -v "$W:/cfg:ro" "$IMG" run -c "/cfg/$1.json" >/dev/null
		CONTS="$CONTS $c"
		LAST_CONT=$c
	fi
	wait_port "$2" || { echo "venc: server $1 did not start"; [ -f "$W/$1.log" ] && tail -5 "$W/$1.log"; return 1; }
}
# The tail of the server log, printed when a check fails: without it "could not decrypt" cannot
# be told from "the server refused for its own reason".
srvlog() {
	if [ "$MODE" = bin ]; then tail -8 "$W/$1.log" 2>/dev/null | sed 's/^/      xray: /'
	else docker logs "steer-venc-$$-$1" 2>&1 | tail -8 | sed 's/^/      xray: /'; fi
}
xray_stop() {
	if [ "$MODE" = bin ]; then kill "$LAST_PID" 2>/dev/null || true; wait "$LAST_PID" 2>/dev/null || true
	else docker rm -f "$LAST_CONT" >/dev/null 2>&1 || true; fi
}

UUID=b831381d-6324-4d53-ad4f-8cda48b30811
OK=0
BAD=0
result() { # NAME CODE
	if [ "$2" -eq 0 ]; then OK=$((OK + 1)); printf '  %-58s ok\n' "$1"
	else BAD=$((BAD + 1)); printf '  %-58s FAIL\n' "$1"; fi
}

# ---- VLESS encryption keys --------------------------------------------------------------------
xray_cmd vlessenc >"$W/vlessenc.txt"
python3 - "$W" <<'PY'
import re, sys
t = open(sys.argv[1] + "/vlessenc.txt").read()
dec = re.findall(r'"decryption": "([^"]+)"', t)
enc = re.findall(r'"encryption": "([^"]+)"', t)
assert len(dec) == 2 and len(enc) == 2, t
for name, i in (("x", 0), ("m", 1)):
    open(sys.argv[1] + "/dec-" + name, "w").write(dec[i])
    open(sys.argv[1] + "/enc-" + name, "w").write(enc[i])
PY

# gen_server NAME PORT DECRYPTION UUID → $W/NAME.json
gen_server() {
	python3 - "$W" "$1" "$2" "$3" "$4" <<'PY'
import json, os, sys
w, name, port, dec, uuid = sys.argv[1:6]
srv = {"log": {"loglevel": "warning"},
       "inbounds": [{"port": int(port), "listen": "127.0.0.1", "protocol": "vless",
                     "settings": {"clients": [{"id": uuid}], "decryption": dec},
                     "streamSettings": {"network": "tcp"}}],
       "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
json.dump(srv, open("%s/%s.json" % (w, name), "w"))
os.chmod("%s/%s.json" % (w, name), 0o644)
PY
}

echo "venc: VLESS encryption — modes × keys × 1rtt/0rtt"
[ "${VENC_ONLY:-}" = reality ] && modes="" || modes="native xorpub random"
for mode in $modes; do
	for kind in x m; do
		for rtt in 1rtt 0rtt; do
			name="e-$mode-$kind-$rtt"
			port; p=$PORT
			dec=$(sed "s/\.native\./.$mode./" "$W/dec-$kind")
			enc=$(sed "s/\.native\.0rtt\./.$mode.$rtt./" "$W/enc-$kind")
			gen_server "$name" "$p" "$dec" "$UUID"
			xray_start "$name" "$p" || { result "$name: server starts" 1; continue; }
			url="vless://$UUID@localhost:$p?encryption=$enc&type=tcp&security=none#$name"
			STEER_VENC_TRACE=1 "$PROBE" bulk "$url" "$ECHO" 1 3 >"$W/$name.probe" 2>&1 && rc=0 || rc=$?
			result "$name: three connections in a row" $rc
			if [ "$rtt" = 0rtt ]; then
				n0=$(grep -c "0-RTT with ticket" "$W/$name.probe" || true)
				[ "$n0" -eq 2 ] && rc=0 || rc=1
				result "$name: connections 2 and 3 use the ticket" $rc
			fi
			"$PROBE" bulk "$url" "$ECHO" 4 >"$W/$name.bulk" 2>&1 && rc=0 || rc=$?
			[ $rc -eq 0 ] || { sed 's/^/      /' "$W/$name.bulk"; srvlog "$name"; }
			result "$name: 4 MB there and back" $rc
			xray_stop
		done
	done
done

echo "venc: relay chain and custom padding"
if [ "${VENC_ONLY:-}" != reality ]; then
port; p=$PORT
xk_d=$(sed 's/.*\.//' "$W/dec-x"); mk_d=$(sed 's/.*\.//' "$W/dec-m")
xk_e=$(sed 's/.*\.//' "$W/enc-x"); mk_e=$(sed 's/.*\.//' "$W/enc-m")
gen_server chain "$p" "mlkem768x25519plus.xorpub.600s.$xk_d.$mk_d.$xk_d" "$UUID"
xray_start chain "$p" && {
	url="vless://$UUID@localhost:$p?encryption=mlkem768x25519plus.xorpub.0rtt.$xk_e.$mk_e.$xk_e&type=tcp&security=none#chain"
	"$PROBE" bulk "$url" "$ECHO" 1 2 >"$W/chain.probe" 2>&1 && rc=0 || rc=$?
	result "three relays X25519 → ML-KEM → X25519, two connections" $rc
	"$PROBE" bulk "$url" "$ECHO" 2 >/dev/null 2>&1 && rc=0 || rc=$?
	result "three relays: 2 MB there and back" $rc
	xray_stop
}
port; p=$PORT
pad="100-100-200.60-10-30.50-0-100"
gen_server pad "$p" "$(sed "s/\.native\.600s\./.random.600s.$pad./" "$W/dec-m")" "$UUID"
xray_start pad "$p" && {
	url="vless://$UUID@localhost:$p?encryption=$(sed "s/\.native\.0rtt\./.random.1rtt.$pad./" "$W/enc-m")&type=tcp&security=none#pad"
	"$PROBE" bulk "$url" "$ECHO" 1 2 >/dev/null 2>&1 && rc=0 || rc=$?
	result "custom padding from a string, two connections" $rc
	xray_stop
}

fi

# A ticket the server forgot (it restarted): the connection with the ticket is rejected, the client
# drops the ticket, and the next connection makes a full handshake and works.
echo "venc: 0-RTT ticket forgotten by the server"
if [ "${VENC_ONLY:-}" != reality ]; then
port; p=$PORT
gen_server stale "$p" "$(sed 's/\.native\./.random./' "$W/dec-m")" "$UUID"
xray_start stale "$p" && {
	url="vless://$UUID@localhost:$p?encryption=$(sed 's/\.native\.0rtt\./.random.0rtt./' "$W/enc-m")&type=tcp&security=none#stale"
	mkdir -p "$W/sync"
	VENC_SYNC="$W/sync" STEER_VENC_TRACE=1 "$PROBE" bulk "$url" "$ECHO" 1 4 >"$W/stale.out" 2>&1 &
	PROBE_PID=$!
	PIDS="$PIDS $PROBE_PID"
	n=1
	while [ "$n" -le 3 ]; do
		i=0
		while [ ! -f "$W/sync/ready.$n" ] && [ "$i" -lt 600 ]; do sleep 0.1; i=$((i + 1)); done
		# restart the server after connection 2 (the first with the ticket), then just go on
		if [ "$n" -eq 2 ]; then xray_stop; xray_start stale "$p" || break; fi
		: > "$W/sync/go.$n"
		n=$((n + 1))
	done
	wait "$PROBE_PID" && rc=0 || rc=$?
	result "after the server restart the last connection works" $rc
	grep -q "rejected the 0-RTT ticket" "$W/stale.out" && rc=0 || rc=1
	result "the rejected ticket is reported" $rc
	[ "$(grep -c 'full handshake' "$W/stale.out")" -ge 2 ] && rc=0 || rc=1
	result "a full handshake after the rejection" $rc
	xray_stop
}
fi

echo "venc: REALITY with the X25519MLKEM768 hybrid and an ML-DSA-65 signature"
DEST=${VENC_DEST:-www.apple.com}
if python3 -c "import socket,sys; socket.create_connection(('$DEST',443),3).close()" 2>/dev/null; then
	xray_cmd x25519 >"$W/x25519.txt"
	PRIV=$(awk '/PrivateKey/{print $2}' "$W/x25519.txt")
	PUB=$(awk '/Password|PublicKey/{print $NF}' "$W/x25519.txt" | head -1)
	xray_cmd mldsa65 >"$W/mldsa.txt"
	SEED=$(awk '/Seed/{print $2}' "$W/mldsa.txt")
	VERIFY=$(awk '/Verify/{print $2}' "$W/mldsa.txt")
	xray_cmd mldsa65 >"$W/mldsa2.txt"
	OTHER=$(awk '/Verify/{print $2}' "$W/mldsa2.txt")
	SID=0123456789abcdef
	for variant in plain mldsa; do
		port; p=$PORT
		python3 - "$W" "reality-$variant" "$p" "$UUID" "$DEST" "$PRIV" "$SID" "$variant" "$SEED" <<'PY'
import json, os, sys
w, name, port, uuid, dest, priv, sid, variant, seed = sys.argv[1:10]
rs = {"show": False, "dest": dest + ":443", "serverNames": [dest], "privateKey": priv, "shortIds": [sid]}
if variant == "mldsa": rs["mldsa65Seed"] = seed
srv = {"log": {"loglevel": "warning"},
       "inbounds": [{"port": int(port), "listen": "127.0.0.1", "protocol": "vless",
                     "settings": {"clients": [{"id": uuid}], "decryption": "none"},
                     "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": rs}}],
       "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
json.dump(srv, open("%s/%s.json" % (w, name), "w"))
os.chmod("%s/%s.json" % (w, name), 0o644)
PY
		xray_start "reality-$variant" "$p" || { result "reality-$variant: server starts" 1; continue; }
		# The first connection to a REALITY server that has just started loses the request:
		# the server accepts the handshake and stays silent (Xray 26.9.9: 7 runs of 10, none
		# with a 0.5 s pause). The port opens before the server is ready, so the pause is
		# here, not in wait_port.
		sleep 1
		base="vless://$UUID@localhost:$p?encryption=none&type=tcp&security=reality&sni=$DEST&pbk=$PUB&sid=$SID&fp=chrome"
		STEER_PQ_TRACE=1 "$PROBE" bulk "$base#r" "$ECHO" 1 >"$W/r-$variant.probe" 2>&1 && rc=0 || rc=$?
		[ $rc -eq 0 ] || { sed 's/^/      /' "$W/r-$variant.probe"; srvlog "reality-$variant"; }
		result "reality ($variant): 1 MB there and back" $rc
		grep -q "X25519MLKEM768" "$W/r-$variant.probe" && rc=0 || rc=1
		result "reality ($variant): the server chose the hybrid" $rc
		if [ "$variant" = mldsa ]; then
			"$PROBE" bulk "$base&pqv=$VERIFY#r" "$ECHO" 1 >/dev/null 2>&1 && rc=0 || rc=$?
			result "reality (mldsa): the right pqv passes" $rc
			"$PROBE" bulk "$base&pqv=$OTHER#r" "$ECHO" 1 >/dev/null 2>&1 && rc=1 || rc=0
			result "reality (mldsa): another key's pqv is refused" $rc
		fi
		xray_stop
	done
else
	echo "  SKIPPED: cover site $DEST:443 unreachable (VENC_DEST=…). Not a failure."
fi

echo
if [ "$BAD" -eq 0 ]; then echo "venc: all checks passed ($OK)"; else echo "venc: FAILED $BAD of $((OK + BAD))"; exit 1; fi
