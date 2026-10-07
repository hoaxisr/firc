#!/bin/sh
# ECH (Encrypted Client Hello) against a REAL server: Xray-core (XRAY=/path/to/xray), built on Go's
# crypto/tls.
#
# The client (vless_probe from tests/vencprobe.c: the same handshake as in production) builds the
# outer Hello with the public name from the ECHConfig and hides the real name in the HPKE payload;
# the server decrypts it, confirms acceptance in ServerHello.random, and the handshake goes on with
# the inner Hello (the transcript switches to it). Without that match the keys differ, so a
# successful handshake itself proves that the HPKE schedule, AAD, padding and the acceptance
# confirmation match the reference.
#
#   accepted: Xray's list (HKDF-SHA256 + AES-128-GCM) and our own list with ChaCha20-Poly1305 only;
#   refused:  a server without ECH and a foreign key both give "server rejected ECH" (TLS13_EECH),
#             not a silent handshake with the name in the clear;
#   unusable: a corrupt list and a "domain+https://…" value (a DNS query) make the node unusable
#             with a stated reason.
# A successful handshake is told from a refusal by the text vencprobe prints. The VLESS probe after
# it needs network access on the server (a request to 1.1.1.1:80) and may fail without it; that is
# neither an ECH refusal nor a failure of this test.
#
# Anything missing is a loud skip (echo and exit 0), as in xudp.sh and venc.sh.
set -eu
cd "$(dirname "$0")/.."
BUILD=${BUILD:-build}
PROBE="$BUILD/vencprobe"
[ -x "$PROBE" ] || { echo "ech: no $PROBE (built by make interop)"; exit 2; }
command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 || {
	echo "ech: SKIPPED — needs python3 and openssl. Not a failure."; exit 0; }
[ -n "${XRAY:-}" ] && [ -x "$XRAY" ] || {
	echo "ech: SKIPPED — no Xray-core (XRAY=/path/to/xray). Not a failure."; exit 0; }

W=$(mktemp -d)
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT INT TERM

BASE=$((23000 + $$ % 20000))
P_ECH=$((BASE + 1)); P_NOECH=$((BASE + 2)); P_CHACHA=$((BASE + 3))
U=00000000-0000-0000-0000-000000000001

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/k.pem" -out "$W/c.pem" \
	-subj "/CN=test.example" -days 2 -addext "subjectAltName=DNS:test.example" 2>/dev/null
PCS=$(openssl x509 -in "$W/c.pem" -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n')

# The list and the server keys from Xray itself: "ECH config list:" and "ECH server keys:", each
# value on the next line.
"$XRAY" tls ech --serverName public.example > "$W/xech.txt" 2>&1
LIST=$(awk '/ECH config list/{getline; print; exit}' "$W/xech.txt")
KEYS=$(awk '/ECH server keys/{getline; print; exit}' "$W/xech.txt")
[ -n "$LIST" ] && [ -n "$KEYS" ] || { echo "ech: xray tls ech produced no keys:"; cat "$W/xech.txt"; exit 1; }

# Our own list with ChaCha20-Poly1305 as the only suite (Xray lists all nine). The private key comes
# from openssl; the server key record is [u16 key length][key][u16 ECHConfig length][ECHConfig].
python3 - "$W" > "$W/chacha.txt" <<'PY'
import base64, struct, subprocess, sys
pem = subprocess.check_output(["openssl", "genpkey", "-algorithm", "X25519"])
priv = subprocess.check_output(["openssl", "pkey", "-outform", "DER"], input=pem)[-32:]
pub = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem)[-32:]
name = b"chacha.example"
body = bytes([9]) + struct.pack(">HH", 0x20, 32) + pub + struct.pack(">H", 4) + struct.pack(">HH", 1, 3)
body += bytes([64, len(name)]) + name + struct.pack(">H", 0)
cfg = struct.pack(">HH", 0xfe0d, len(body)) + body
print(base64.b64encode(struct.pack(">H", len(cfg)) + cfg).decode())
print(base64.b64encode(struct.pack(">H", 32) + priv + struct.pack(">H", len(cfg)) + cfg).decode())
PY
CLIST=$(sed -n 1p "$W/chacha.txt"); CKEYS=$(sed -n 2p "$W/chacha.txt")

cat > "$W/x.json" <<EOF
{"log": {"loglevel": "warning"},
 "inbounds": [
  {"listen": "127.0.0.1", "port": $P_ECH, "protocol": "vless",
   "settings": {"clients": [{"id": "$U"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"echServerKeys": "$KEYS",
     "certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}},
  {"listen": "127.0.0.1", "port": $P_NOECH, "protocol": "vless",
   "settings": {"clients": [{"id": "$U"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
     "certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}},
  {"listen": "127.0.0.1", "port": $P_CHACHA, "protocol": "vless",
   "settings": {"clients": [{"id": "$U"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"echServerKeys": "$CKEYS",
     "certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}}],
 "outbounds": [{"protocol": "freedom"}]}
EOF
"$XRAY" run -c "$W/x.json" >"$W/x.log" 2>&1 &
PIDS="$PIDS $!"
echo "ech: server — $("$XRAY" version 2>/dev/null | head -1)"
sleep 2

urlenc() { printf '%s' "$1" | sed 's/+/%2B/g; s#/#%2F#g; s/=/%3D/g'; }
FAILS=0
# The node is named localhost: link parsing rejects nodes in 127.0.0.0/8 (no peer).
probe() { # LABEL PORT EXPECTED(accepted|refused|unusable) LIST
	name=$1; port=$2; want=$3; lst=$4
	out=$("$PROBE" probe "vless://$U@localhost:$port?type=tcp&security=tls&sni=test.example&pcs=$PCS${lst:+&ech=$(urlenc "$lst")}" 1 2>&1 | tr '\n' ' ') || true
	case "$out" in
		*"rejected ECH"*) got=refused ;;
		*"node unusable"*) got=unusable ;;
		*"ECH:"*|*"did not prove"*|*"corrupt TLS record"*|*"closed by the server"*) got="error ($out)" ;;
		*) got=accepted ;;
	esac
	if [ "$got" = "$want" ]; then echo "  ok   $name"; else echo "  FAIL $name: expected $want, got $got [$out]"; FAILS=$((FAILS + 1)); fi
}
probe "ECH, AES-128-GCM suite (Xray's list)" $P_ECH accepted "$LIST"
probe "ECH, ChaCha20-Poly1305 suite" $P_CHACHA accepted "$CLIST"
probe "no ECH to a server with ECH: a plain handshake" $P_ECH accepted ""
probe "ECH to a server without ECH: refused, no handshake in clear" $P_NOECH refused "$LIST"
probe "ECH with a foreign key: refused" $P_CHACHA refused "$LIST"
probe "corrupt list: node unusable" $P_ECH unusable "AAAA"
probe "DNS record query (domain+https://…): node unusable" $P_ECH unusable "cloudflare-ech.com+https://1.1.1.1/dns-query"

[ $FAILS = 0 ] && echo "ech: all checks passed" || { echo "ech: failures: $FAILS"; exit 1; }
