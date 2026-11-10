#!/bin/sh
# VLESS against a REAL Xray-core, one case per transport setting: the node probe, and load both ways.
#
# tests/grpcmatch.c and tests/h2match.c check frames written by hand. What a gRPC server puts in
# one TLS record depends on how grpc-go flushes and on how fast the target answers, and that is
# where h2_read used to drop the data read in the same call as the end of the stream (RST_STREAM
# after the closing HEADERS). Against Xray 26.3.27 that broke three things: the node probe failed
# on a working node (14 of 30 in gun mode, 21 of 30 in multi), the pool declared the node dead and
# reset every connection, and about 20% of short connections lost the end of the response.
#
# Checks (a failure exits 1, the reason on the last line):
#   1. the node probe (tunvless --probe) 30 times in a row: no failure;
#   2. DUR seconds (default 60) of load through the tunnel: two long flows down, two up and short
#      pages at 10 per second; no page truncated or hung, no long flow broken, no direction stalled
#      for 15 seconds;
#   3. the pool checks the node every 10 seconds (--interval 10): its log must not say that the
#      node does not answer, nor that a flow did not open.
# KEEP=<dir>: copy the work directory there at the end (Xray and tunnel logs, configs).
# CASES: the cases to run, separated by spaces (default: all of them, see case_cfg). Each case is a
# server config (Xray streamSettings) and the matching client link, so a setting the client
# misreads shows up as a probe or load failure against the real server.
#
# The sides live in separate network namespaces: the client (tunvless, its device vl and the load)
# in one; Xray, the Reality cover site and the targets in the other, with 1.1.1.1 and 8.8.8.8
# serving HTTP on :80 as the probe's targets.
#
# Needs root, ip netns, python3, openssl and Xray-core: XRAY=<binary> (or xray in PATH). Without Xray
# or root it is skipped loudly (exit 0). TUNVLESS: the binary (default ./out/tunvless). Not part of
# make test or make e2e: it takes minutes.
set -eu
cd "$(dirname "$0")/.."

BIN="${TUNVLESS:-./out/tunvless}"
DUR="${DUR:-60}"
ALL_CASES="grpc-gun grpc-multi xhttp-auto xhttp-stream-one xhttp-stream-up xhttp-packet-up xhttp-tls
           xhttp-auto-tls xhttp-auto-one xhttp-padding xhttp-host xhttp-path xhttp-up-secs
           xhttp-no-sse xhttp-post-max
           xhttp-sess-header xhttp-sess-cookie xhttp-sess-query xhttp-seq-header xhttp-seq-cookie-key
           xhttp-old-names xhttp-data-header xhttp-data-cookie xhttp-data-cookie-small
           xhttp-obfs-header xhttp-obfs-cookie xhttp-obfs-query xhttp-obfs-qih xhttp-tokenish
           xhttp-method-put xhttp-method-get xhttp-table xhttp-headers xhttp-no-grpc xhttp-max-hdr
           xhttp-neg-obfs xhttp-neg-sess xhttp-neg-data xhttp-reality-firefox xhttp-tls-p384 xhttp-tls-p384-neg xhttp-tls-p384-cache
           v6-carry-tcp v6-carry-xhttp v6-second v6-none v6-noroute
           node6-tcp node6-xhttp node6-name node6-dual
           xhttp-dl-reality-auto xhttp-dl-packet-tls xhttp-dl-none xhttp-dl-extra xhttp-dl-post-main
           xhttp-dl-name xhttp-dl-route xhttp-dl-neg-path xhttp-dl-neg-sess
           xmux-count-one xmux-count-packet xmux-count-up xmux-concurrency xmux-requests xmux-reuse
           xmux-kill xmux-ping xmux-up-parallel xmux-dl xmux-kernel-inbound xmux-stall xmux-post-size
           h2-wire-reality h2-wire-tls h2-credit h2-speed rec-raw rec-vision rec-ws vis-dl vis-dl-tls
           ua-golang ua-edge ua-firefox ua-safari ua-curl ua-empty
           fm-frag-hello-tls fm-frag-hello-reality fm-frag-range fm-frag-loop fm-frag-xhttp
           fm-hc-raw fm-hc-vision fm-hc-xhttp fm-hc-ws fm-hc-neg fm-filter-ok fm-filter-neg
           fm-chain-hf fm-chain-fh fm-dl-same fm-dl-noinherit fm-dl-frag fm-refuse-sudoku fm-refuse-xmc
           vis-up vis-up-tls vis-up-shapes vis-up-tls12 vis-up-ccm8 vis-plain-end vis-wait vis-reshape
           fm-frag-vision-up fm-hc-vision-up"
VCASES="vis-up vis-up-tls vis-up-shapes vis-up-tls12 vis-up-ccm8 vis-plain-end vis-wait vis-reshape fm-frag-vision-up fm-hc-vision-up"
CASES="${CASES:-$ALL_CASES}"
XRAY="${XRAY:-$(command -v xray 2>/dev/null || true)}"

[ "$(id -u)" = 0 ] || { echo "run-xray: SKIPPED — needs root (ip netns). Not a failure."; exit 0; }
command -v ip >/dev/null 2>&1 || { echo "run-xray: SKIPPED — no ip. Not a failure."; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "run-xray: SKIPPED — needs python3. Not a failure."; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "run-xray: SKIPPED — needs openssl. Not a failure."; exit 0; }
[ -n "$XRAY" ] && [ -x "$XRAY" ] || { echo "run-xray: SKIPPED — no Xray-core (XRAY=/path/to/xray). Not a failure."; exit 0; }
[ -x "$BIN" ] || { echo "run-xray: no binary $BIN (make)"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
ip netns add "grpc-probe-$$" 2>/dev/null || { echo "run-xray: SKIPPED — ip netns unavailable. Not a failure."; exit 0; }
ip netns delete "grpc-probe-$$"

NSC="grpcc$$"; NSS="grpcs$$"
S_IP=10.93.0.1; C_IP=10.93.0.2; S_IP2=10.93.0.3; TARGET=203.0.113.9
C_IP6=2001:db8:93::2; S_IP6=2001:db8:93::1
TARGET6=2001:db8:9::9; CHK6A=2606:4700:4700::1111; CHK6B=2001:4860:4860::8888
PORT=18443; MASK=mask.grpc.test; SVC=grpcsvc
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
SID=0123456789abcdef
W="$(mktemp -d)"
PIDS=""
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
    done
    sleep 0.3
    rm -rf "/etc/netns/$NSC" 2>/dev/null || true
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill -9 "$p" 2>/dev/null || true; done
        ip netns delete "$n" 2>/dev/null || true
    done
    [ -n "${KEEP:-}" ] && cp -r "$W/." "$KEEP/" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

bg_in() { ns="$1"; log="$2"; shift 2; ip netns exec "$ns" "$@" > "$log" 2>&1 & PIDS="$PIDS $!"; }

echo "run-xray: server — $("$XRAY" version 2>/dev/null | head -1)"

ip netns add "$NSC"; ip netns add "$NSS"
ip -n "$NSC" link set lo up; ip -n "$NSS" link set lo up
ip link add grc0 netns "$NSC" type veth peer name grs0 netns "$NSS"
ip -n "$NSC" addr add "$C_IP/24" dev grc0
ip -n "$NSS" addr add "$S_IP/24" dev grs0
ip -n "$NSS" addr add "$S_IP2/24" dev grs0
ip -n "$NSC" addr add "$C_IP6/64" dev grc0 nodad
ip -n "$NSS" addr add "$S_IP6/64" dev grs0 nodad
ip -n "$NSC" link set grc0 up; ip -n "$NSS" link set grs0 up
for a in "$TARGET" 1.1.1.1 8.8.8.8; do ip -n "$NSS" addr add "$a/32" dev lo; done
for a in "$TARGET6" "$CHK6A" "$CHK6B"; do ip -n "$NSS" addr add "$a/128" dev lo nodad; done

"$XRAY" x25519 > "$W/keys.txt" 2>&1
PRIV=$(awk '/^PrivateKey:/ {print $2}' "$W/keys.txt")
PUB=$(awk '/PublicKey/ {print $NF}' "$W/keys.txt")
[ -n "$PRIV" ] && [ -n "$PUB" ] || { echo "run-xray: xray x25519 gave no keys:"; cat "$W/keys.txt"; exit 1; }
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$W/mask.key" -out "$W/mask.pem" -subj "/CN=$MASK" -addext "subjectAltName=DNS:$MASK" >/dev/null 2>&1
printf '%s\n' '[ca]' 'basicConstraints=critical,CA:TRUE' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' \
    '[inter]' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign' \
    'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
    '[leaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
    'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' "subjectAltName=DNS:$MASK" > "$W/p384.cnf"
for r in root384 other384; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -sha384 -days 2 -keyout "$W/$r.key" \
        -out "$W/$r.pem" -subj "/CN=$r" -config "$W/p384.cnf" -extensions ca >/dev/null 2>&1
done
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -keyout "$W/inter384.key" \
    -subj "/CN=inter384" -out "$W/inter384.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/inter384.csr" -CA "$W/root384.pem" -CAkey "$W/root384.key" -set_serial 2 -sha384 -days 2 \
    -extfile "$W/p384.cnf" -extensions inter -out "$W/inter384.pem" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/leaf384.key" \
    -subj "/CN=$MASK" -out "$W/leaf384.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/leaf384.csr" -CA "$W/inter384.pem" -CAkey "$W/inter384.key" -set_serial 3 -sha384 -days 2 \
    -extfile "$W/p384.cnf" -extensions leaf -out "$W/leaf384.pem" >/dev/null 2>&1
cat "$W/leaf384.pem" "$W/inter384.pem" > "$W/chain384.pem"
openssl verify -CAfile "$W/root384.pem" -untrusted "$W/inter384.pem" "$W/leaf384.pem" >/dev/null ||
    { echo "run-xray: the P-384 test chain does not verify in OpenSSL"; exit 1; }

# The Reality cover site: any TLS 1.3 server with h2 in ALPN.
bg_in "$NSS" "$W/mask.log" openssl s_server -accept "$S_IP:8443" -cert "$W/mask.pem" -key "$W/mask.key" \
    -tls1_3 -alpn h2,http/1.1 -www -quiet
# The target, and the targets of the node probe.
is_v() { case " $VCASES " in *" $1 "*) return 0 ;; esac; return 1; }
TPID=""; OPID=""; VPID=""; OWANT=""; NOLD=""; NNEW=""
for m in $CASES; do if is_v "$m"; then NNEW=1; else NOLD=1; fi; done
[ -z "$NOLD" ] || { bg_in "$NSS" "$W/target.log" python3 tests/grpc-target.py "$TARGET" 8080; TPID=$!; }
case " $CASES " in *" vis-dl"*|*" fm-hc-vision "*) OWANT=1; bg_in "$NSS" "$W/origin.log" python3 tests/vision-origin.py "$TARGET" 8443 "$W/mask.pem" "$W/mask.key" 0; OPID=$! ;; esac
if [ -n "$NNEW" ]; then
    printf '%s\n' 'openssl_conf = c' '[c]' 'ssl_conf = s' '[s]' 'system_default = d' '[d]' 'CipherString = DEFAULT@SECLEVEL=0' > "$W/ccm8.cnf"
    bg_in "$NSS" "$W/vorigin.log" python3 tests/vision-origin.py "$TARGET" 9443 "$W/mask.pem" "$W/mask.key" 0
    bg_in "$NSS" "$W/vorigin12.log" python3 tests/vision-origin.py "$TARGET" 9444 "$W/mask.pem" "$W/mask.key" 0 1.2
    bg_in "$NSS" "$W/ccm8.log" env OPENSSL_CONF="$W/ccm8.cnf" openssl s_server -accept "$TARGET:8445" -cert "$W/mask.pem" \
        -key "$W/mask.key" -tls1_3 -ciphersuites TLS_AES_128_CCM_8_SHA256 -www -quiet
fi
bg_in "$NSS" "$W/probe1.log" python3 tests/grpc-target.py 1.1.1.1 80
bg_in "$NSS" "$W/probe2.log" python3 tests/grpc-target.py 8.8.8.8 80
bg_in "$NSS" "$W/target6.log" python3 tests/grpc-target.py "$TARGET6" 8080
bg_in "$NSS" "$W/probe1-6.log" python3 tests/grpc-target.py "$CHK6A" 80 log-host
bg_in "$NSS" "$W/probe2-6.log" python3 tests/grpc-target.py "$CHK6B" 80 log-host
bg_in "$NSS" "$W/echo6.log" python3 -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("2001:db8:9::9", 9000))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d, a)'
# A counter of SYNs to the node, printed only (skipped without nft).
if command -v nft >/dev/null 2>&1; then
    ip netns exec "$NSS" nft -f - >/dev/null 2>&1 <<NFT || true
table inet grpccnt { chain in { type filter hook input priority -300; policy accept;
    iifname "grs0" tcp dport $PORT tcp flags & (syn | ack) == syn counter comment "syn"; }; }
NFT
fi
DLNFT=""
if command -v nft >/dev/null 2>&1; then
    ip netns exec "$NSS" nft -f - >/dev/null 2>&1 <<NFT && DLNFT=1 || true
table inet dlcnt {
    chain in { type filter hook input priority -300; policy accept;
        iifname "grs0" ip daddr $S_IP tcp dport $PORT counter comment "in1"
        iifname "grs0" ip daddr $S_IP2 tcp dport $PORT counter comment "in2"
        iifname "grs0" ip daddr $S_IP tcp dport $PORT tcp flags & (syn | ack) == syn counter comment "syn1"
        iifname "grs0" ip daddr $S_IP2 tcp dport $PORT tcp flags & (syn | ack) == syn counter comment "syn2"; }
    chain out { type filter hook output priority -300; policy accept;
        oifname "grs0" ip saddr $S_IP tcp sport $PORT counter comment "out1"
        oifname "grs0" ip saddr $S_IP2 tcp sport $PORT counter comment "out2"; }
}
NFT
fi

FAIL=0; SKIPPED=""
# One case: NET (streamSettings without security), SEC (reality | tls), Q (the link's transport
# parameters) and TUN_ARGS (extra client flags). Defaults are Xray's own.
enc() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
xh() { XP="{\"path\":\"/xp/\",\"mode\":\"$1\",$2}"; Q="type=xhttp&path=%2Fxp%2F&mode=$1&extra=$(enc "{$2}")"; }
dl() { DL=1; SEC=$1; XM=$2; LM=$3; SX=$4; MX=$4; BX=$4; }
dl_cfg() {
    XP="{\"path\":\"/xp/\"${XM:+,\"mode\":\"$XM\"}${SX:+,$SX}}"
    case "$SEC" in
    reality) BS="\"security\":\"reality\",\"realitySettings\":{\"serverName\":\"$MASK\",\"publicKey\":\"$PUB\",\"shortId\":\"$SID\",\"fingerprint\":\"chrome\"}" ;;
    tls)     BS="\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$MASK\"}" ;;
    *)       BS='"security":"none"' ;;
    esac
    BLK="{\"address\":\"$DH\",\"port\":${DPORT:-$PORT},\"network\":\"xhttp\",$BS,\"xhttpSettings\":{\"path\":\"$BP\"${BX:+,$BX}}${BFM:+,\"finalmask\":$BFM}}"
    XBS=$BS; [ "$SEC" != tls ] || XBS="\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$MASK\",\"alpn\":[\"h2\"],\"fingerprint\":\"chrome\",\"certificates\":[{\"certificateFile\":\"$W/mask.pem\",\"usage\":\"verify\"}]}"
    XBLK="{\"address\":\"$DH\",\"port\":${DPORT:-$PORT},\"network\":\"xhttp\",$XBS,\"xhttpSettings\":{\"path\":\"$BP\"${BX:+,$BX}}${BFM:+,\"finalmask\":$BFM}}"
    Q="type=xhttp&path=%2Fxp%2F${LM:+&mode=$LM}&extra=$(enc "{${MX:+$MX,}\"downloadSettings\":$BLK}")"
}
HCJ='{"type":"header-custom","settings":{"clients":[[{"packet":"GET / HTTP/1.1\r\n\r\n","type":"str"}]],"servers":[[{"packet":"HTTP/1.1 200 OK\r\n\r\n","type":"str"}]]}}'
HCX='{"type":"header-custom","settings":{"clients":[[{"packet":"GET /x HTTP/1.1\r\n\r\n","type":"str"}]],"servers":[[{"packet":"HTTP/1.1 200 OK\r\n\r\n","type":"str"}]]}}'
HCH=474554202f20485454502f312e310d0a0d0a
FR10='{"type":"fragment","settings":{"packets":"tlshello","length":10}}'
fmtls() { SEC=tls; TUN_ARGS="--ca $W/mask.pem"; XALPN=${1:-http/1.1}; }
fmraw() { NET='"network":"tcp"'; Q="type=tcp"; XCNET="$NET"; }
fmfrag() { fmraw; CFM="{\"tcp\":[{\"type\":\"fragment\",\"settings\":$1}]}"; LPORT=18444; TAPLENS=1; }
fmxh() { XP="{\"path\":\"/xp/\",\"mode\":\"$1\"}"; Q="type=xhttp&path=%2Fxp%2F&mode=$1"; }
neg() { EXPECT=fail; XP="{\"path\":\"/xp/\",\"mode\":\"packet-up\",$1}"; Q="type=xhttp&path=%2Fxp%2F&mode=packet-up"; }
case_cfg() {
    SLOG="${XLOG:-warning}"
    SEC=reality; TUN_ARGS=""; TUN_ENV=""; FP=chrome; SCERT=mask; SKEY=mask; EXPECT=ok; V6=""; NODE=v4; XMODE=""; XMUX=""; KEYLOG=""; LPORT=""; TAPCAP=1048576
    XCNET=""; FLOW=""; XALPN=h2; DL=""; DH="$S_IP2"; BP=/xp/
    CFM=""; SFM=""; BFM=""; DPORT=""; TAPLENS=""; TAP2=""
    XP='{"path":"/xp/"}'
    case "$1" in
    grpc-gun|grpc-multi)
        m=${1#grpc-}; multi=false; [ "$m" = multi ] && multi=true
        NET="\"network\":\"grpc\",\"grpcSettings\":{\"serviceName\":\"$SVC\",\"multiMode\":$multi}"
        Q="type=grpc&serviceName=$SVC&mode=$m" ;;
    xhttp-auto)        Q="type=xhttp&path=%2Fxp%2F" ;;
    xhttp-reality-firefox) FP=firefox; Q="type=xhttp&path=%2Fxp%2F" ;;
    xhttp-tls-p384)    SEC=tls; TUN_ENV="SSL_CERT_FILE=$W/root384.pem"; SCERT=chain384; SKEY=leaf384
                       Q="type=xhttp&path=%2Fxp%2F&mode=stream-up" ;;
    xhttp-tls-p384-neg) SEC=tls; TUN_ENV="SSL_CERT_FILE=$W/other384.pem"; SCERT=chain384; SKEY=leaf384
                       Q="type=xhttp&path=%2Fxp%2F&mode=stream-up"; EXPECT=fail ;;
    xhttp-tls-p384-cache) SEC=tls; TUN_ENV="SSL_CERT_FILE=$W/root384.pem STEER_CHAIN_TRACE=1"; SCERT=chain384; SKEY=leaf384
                       Q="type=xhttp&path=%2Fxp%2F&mode=stream-up" ;;
    xhttp-stream-one|xhttp-stream-up|xhttp-packet-up)
                       Q="type=xhttp&path=%2Fxp%2F&mode=${1#xhttp-}" ;;
    # TLS instead of Reality: the client verifies the server's certificate against --ca.
    xhttp-tls)         SEC=tls; TUN_ARGS="--ca $W/mask.pem"; Q="type=xhttp&path=%2Fxp%2F&mode=stream-up" ;;
    # auto resolves as in Xray's client: packet-up over TLS, stream-one with Reality. A server
    # set to one mode refuses the others with 400 (hub.go), so a wrong guess fails here.
    xhttp-auto-tls)    SEC=tls; TUN_ARGS="--ca $W/mask.pem"; XP='{"path":"/xp/","mode":"packet-up"}'
                       Q="type=xhttp&path=%2Fxp%2F" ;;
    xhttp-auto-one)    XP='{"path":"/xp/","mode":"stream-one"}'; Q="type=xhttp&path=%2Fxp%2F" ;;
    # The server checks the padding length against its own range: the link carries it in extra.
    xhttp-padding)     XP='{"path":"/xp/","xPaddingBytes":"20-40"}'
                       Q="type=xhttp&path=%2Fxp%2F&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%2220-40%22%7D" ;;
    # host set on the server: requests must name it.
    xhttp-host)        XP='{"path":"/xp/","host":"cdn.xhttp.test"}'
                       Q="type=xhttp&path=%2Fxp%2F&mode=stream-up&host=cdn.xhttp.test" ;;
    # A path without the trailing slash, as panels write it.
    xhttp-path)        XP='{"path":"/a/b"}'; Q="type=xhttp&path=%2Fa%2Fb&mode=packet-up" ;;
    # stream-up: the server writes padding into the upload's response every 1-2 s.
    xhttp-up-secs)     XP='{"path":"/xp/","scStreamUpServerSecs":"1-2"}'
                       Q="type=xhttp&path=%2Fxp%2F&mode=stream-up" ;;
    xhttp-no-sse)      XP='{"path":"/xp/","noSSEHeader":true}'; Q="type=xhttp&path=%2Fxp%2F&mode=packet-up" ;;
    # packet-up: the server limits each POST body; the link says how much.
    xhttp-post-max)    XP='{"path":"/xp/","scMaxEachPostBytes":4096}'
                       Q="type=xhttp&path=%2Fxp%2F&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A4096%7D" ;;
    xhttp-sess-header)       xh stream-up '"sessionIDPlacement":"header"' ;;
    xhttp-sess-cookie)       xh packet-up '"sessionIDPlacement":"cookie"' ;;
    xhttp-sess-query)        xh packet-up '"sessionIDPlacement":"query","sessionIDKey":"sid"' ;;
    xhttp-seq-header)        xh packet-up '"seqPlacement":"header"' ;;
    xhttp-seq-cookie-key)    xh packet-up '"seqPlacement":"cookie","seqKey":"sq"' ;;
    xhttp-old-names)         XP='{"path":"/xp/","mode":"packet-up","sessionIDPlacement":"header","sessionIDKey":"X-Sid"}'
                             Q="type=xhttp&path=%2Fxp%2F&mode=packet-up&extra=$(enc '{"sessionPlacement":"query","sessionKey":"old","sessionIDPlacement":"header","sessionIDKey":"X-Sid"}')" ;;
    xhttp-data-header)       xh packet-up '"uplinkDataPlacement":"header"' ;;
    xhttp-data-cookie)       xh packet-up '"uplinkDataPlacement":"cookie"' ;;
    xhttp-data-cookie-small) xh packet-up '"uplinkDataPlacement":"cookie","uplinkChunkSize":64' ;;
    xhttp-obfs-header)       xh packet-up '"xPaddingObfsMode":true,"xPaddingPlacement":"header"' ;;
    xhttp-obfs-cookie)       xh packet-up '"xPaddingObfsMode":true,"xPaddingPlacement":"cookie","xPaddingKey":"pad"' ;;
    xhttp-obfs-query)        xh packet-up '"xPaddingObfsMode":true,"xPaddingPlacement":"query","xPaddingKey":"pq"' ;;
    xhttp-obfs-qih)          xh packet-up '"xPaddingObfsMode":true,"xPaddingPlacement":"queryInHeader","xPaddingHeader":"X-Ref"' ;;
    xhttp-tokenish)          xh packet-up '"xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingMethod":"tokenish","xPaddingBytes":"50-60"' ;;
    xhttp-method-put)        xh stream-one '"uplinkHTTPMethod":"PUT"' ;;
    xhttp-method-get)        xh packet-up '"uplinkHTTPMethod":"GET"' ;;
    xhttp-table)             xh packet-up '"sessionIDTable":"Base62","sessionIDLength":12' ;;
    xhttp-headers)           xh packet-up '"headers":{"X-Custom":"v1","User-Agent":"tv-test"}' ;;
    xhttp-no-grpc)           xh stream-up '"noGRPCHeader":true' ;;
    xhttp-max-hdr)           xh packet-up '"uplinkDataPlacement":"header","serverMaxHeaderBytes":4096,"scMinPostsIntervalMs":"10-50"' ;;
    v6-carry-tcp)      V6=carry; NET='"network":"tcp"'; Q="type=tcp" ;;
    v6-second)         V6=second; NET='"network":"tcp"'; Q="type=tcp" ;;
    v6-none)           V6=none; NET='"network":"tcp"'; Q="type=tcp" ;;
    v6-noroute)        V6=noroute; NET='"network":"tcp"'; Q="type=tcp" ;;
    v6-carry-xhttp)    V6=carry; Q="type=xhttp&path=%2Fxp%2F&mode=packet-up" ;;
    node6-tcp)         NODE=v6; NET='"network":"tcp"'; Q="type=tcp" ;;
    node6-name)        NODE=name6; NET='"network":"tcp"'; Q="type=tcp" ;;
    node6-dual)        NODE=dual; NET='"network":"tcp"'; Q="type=tcp" ;;
    node6-xhttp)       NODE=v6; Q="type=xhttp&path=%2Fxp%2F&mode=packet-up" ;;
    xhttp-neg-obfs)          neg '"xPaddingObfsMode":true,"xPaddingPlacement":"cookie"' ;;
    xhttp-neg-sess)          neg '"sessionIDPlacement":"header"' ;;
    xhttp-neg-data)          neg '"uplinkDataPlacement":"cookie"' ;;
    # One inbound on two addresses: the GET goes to $S_IP2 (downloadSettings), the POSTs to $S_IP.
    xhttp-dl-reality-auto)   dl reality stream-up "" "" ;;
    xhttp-dl-packet-tls)     dl tls packet-up packet-up ""; TUN_ARGS="--ca $W/mask.pem" ;;
    xhttp-dl-none)           dl none packet-up packet-up '"sessionIDPlacement":"query"' ;;
    xhttp-dl-extra)          dl reality packet-up packet-up '"sessionIDPlacement":"header","xPaddingObfsMode":true,"xPaddingPlacement":"cookie","xPaddingKey":"pad"' ;;
    xhttp-dl-post-main)      dl reality packet-up packet-up '"uplinkDataPlacement":"body"'; BX='"uplinkDataPlacement":"cookie"' ;;
    xhttp-dl-name)           dl reality packet-up packet-up ""; DH=dl.test ;;
    xhttp-dl-route)          dl reality packet-up packet-up ""; TUN_ARGS="--route 10.93.0.2/31" ;;
    xhttp-dl-neg-path)       dl none packet-up packet-up '"sessionIDPlacement":"query"'; EXPECT=fail; BP=/wrong/ ;;
    xhttp-dl-neg-sess)       dl none packet-up packet-up '"sessionIDPlacement":"query"'; EXPECT=fail; BX='"sessionIDPlacement":"header"' ;;
    xmux-count-one|xmux-idle|xmux-stall|xmux-kernel-inbound) xm stream-one "" ;;
    xmux-count-packet)       SEC=tls; TUN_ARGS="--ca $W/mask.pem"; xm packet-up "" ;;
    xmux-count-up)           SEC=tls; TUN_ARGS="--ca $W/mask.pem"; xm stream-up "" ;;
    xmux-post-size)          SEC=tls; TUN_ARGS="--ca $W/mask.pem"; xm packet-up ""; KEYLOG=1; TAPCAP=4294967296 ;;
    xmux-concurrency)        xm stream-one '{"maxConcurrency":4}' ;;
    xmux-requests)           xm stream-one '{"maxConnections":1,"hMaxRequestTimes":5}' ;;
    xmux-reuse)              xm stream-one '{"cMaxReuseTimes":3}' ;;
    xmux-kill|xmux-up-parallel) xm stream-one '{"maxConnections":1}' ;;
    xmux-ping)               SEC=none; xm stream-one '{"hKeepAlivePeriod":2}' ;;
    xmux-dl)                 dl reality stream-up "" "" ;;
    h2-wire-reality|h2-credit) xm stream-one ""; KEYLOG=1 ;;
    h2-wire-tls)             SEC=tls; TUN_ARGS="--ca $W/mask.pem"; xm packet-up ""; KEYLOG=1 ;;
    h2-speed)                xm stream-one "" ;;
    ua-golang)               ua '{"User-Agent":"golang"}' ;;
    ua-edge)                 ua '{"User-Agent":"edge"}' ;;
    ua-firefox)              ua '{"User-Agent":"firefox","DNT":"0"}' ;;
    ua-safari)               ua '{"User-Agent":"safari"}' ;;
    ua-curl)                 ua '{"User-Agent":"curl"}' ;;
    ua-empty)                ua '{"User-Agent":""}' ;;
    rec-raw)                 NET='"network":"tcp"'; Q="type=tcp"; XCNET="$NET"; KEYLOG=1 ;;
    rec-vision)              NET='"network":"tcp"'; Q="type=tcp&flow=xtls-rprx-vision"; XCNET="$NET"
                             FLOW=xtls-rprx-vision; KEYLOG=1 ;;
    vis-dl)                  NET='"network":"tcp"'; Q="type=tcp&flow=xtls-rprx-vision"; XCNET="$NET"
                             FLOW=xtls-rprx-vision ;;
    vis-dl-tls)              SEC=tls; TUN_ARGS="--ca $W/mask.pem"; XALPN=http/1.1; NET='"network":"tcp"'; Q="type=tcp&flow=xtls-rprx-vision"; XCNET="$NET"
                             FLOW=xtls-rprx-vision ;;
    rec-ws)                  SEC=tls; TUN_ARGS="--ca $W/mask.pem"; NET='"network":"ws","wsSettings":{"path":"/ws"}'
                             Q="type=ws&path=%2Fws"; XCNET="$NET"; XALPN=http/1.1; KEYLOG=1 ;;
    fm-frag-hello-tls)       fmtls; fmfrag '{"packets":"tlshello","length":"10-20"}' ;;
    fm-frag-hello-reality)   fmfrag '{"packets":"tlshello","length":"10-20"}' ;;
    fm-frag-range)           fmfrag '{"packets":"1-1","length":100,"delay":20}' ;;
    fm-frag-loop)            fmfrag '{"packets":"3-3","length":200,"delay":200}' ;;
    fm-frag-xhttp)           fmfrag '{"packets":"2-4","length":50,"delay":20}'; fmxh stream-up ;;
    fm-hc-raw)               fmtls; fmraw; CFM="{\"tcp\":[$HCJ]}"; SFM=$CFM; LPORT=18444 ;;
    fm-hc-vision)            fmtls; fmraw; Q="type=tcp&flow=xtls-rprx-vision"; FLOW=xtls-rprx-vision; CFM="{\"tcp\":[$HCJ]}"; SFM=$CFM ;;
    fm-hc-xhttp)             fmtls h2; fmxh stream-up; CFM="{\"tcp\":[$HCJ]}"; SFM=$CFM; LPORT=18444 ;;
    fm-hc-ws)                fmtls; NET='"network":"ws","wsSettings":{"path":"/ws"}'
                             Q="type=ws&path=%2Fws"; XCNET="$NET"; CFM="{\"tcp\":[$HCJ]}"; SFM=$CFM; LPORT=18444 ;;
    fm-hc-neg)               fmtls; fmraw; CFM="{\"tcp\":[$HCX]}"; SFM="{\"tcp\":[$HCJ]}"; EXPECT=fail ;;
    fm-filter-ok)            fmraw; SFM="{\"tcp\":[{\"type\":\"filter\",\"settings\":{\"allowedSourceIPs\":[\"$C_IP/32\"]}}]}"; CFM=$SFM ;;
    fm-filter-neg)           fmraw; SFM='{"tcp":[{"type":"filter","settings":{"allowedSourceIPs":["10.255.255.1/32"]}}]}'; EXPECT=fail ;;
    fm-chain-hf)             fmtls; fmraw; CFM="{\"tcp\":[$HCJ,$FR10]}"; SFM="{\"tcp\":[$HCJ]}"; LPORT=18444 ;;
    fm-chain-fh)             fmtls; fmraw; CFM="{\"tcp\":[$FR10,$HCJ]}"; SFM="{\"tcp\":[$HCJ]}"; LPORT=18444 ;;
    fm-dl-same)              fmtls h2; dl tls packet-up packet-up ""; CFM="{\"tcp\":[$HCJ]}"; SFM=$CFM; BFM=$CFM ;;
    fm-dl-noinherit)         fmtls h2; dl tls packet-up packet-up ""; CFM="{\"tcp\":[$HCJ]}"; SFM=$CFM; EXPECT=fail ;;
    fm-dl-frag)              dl reality packet-up packet-up ""; BFM="{\"tcp\":[$FR10]}"; LPORT=18444; DPORT=18444; TAP2=1 ;;
    vis-up|vis-up-shapes|vis-up-tls12|vis-up-ccm8|vis-plain-end|vis-wait|vis-reshape) fmraw; vcfg ;;
    vis-up-tls)              fmtls; fmraw; vcfg ;;
    fm-frag-vision-up)       fmfrag '{"packets":"1-3","length":"10-20"}'; vcfg ;;
    fm-hc-vision-up)         fmtls; fmraw; CFM="{\"tcp\":[$HCJ]}"; SFM=$CFM; vcfg ;;
    fm-refuse-sudoku)        fmraw; CFM='{"tcp":[{"type":"sudoku","settings":{"password":"p"}}]}'; SFM=$CFM ;;
    fm-refuse-xmc)           fmtls; fmraw; CFM='{"tcp":[{"type":"xmc","settings":{"password":"p","profiles":[{"username":"Steve_1","uuid":"00112233-4455-6677-8899-aabbccddeeff","texturesValue":"v","texturesSignature":"s"}]}}]}'; SFM=$CFM ;;
    *) echo "run-xray: unknown case $1"; exit 2 ;;
    esac
    [ -z "$DL" ] || dl_cfg
    case "$1" in xhttp-*|xmux-*|h2-*|ua-*|v6-carry-xhttp|node6-xhttp|fm-*xhttp|fm-dl-*) NET="\"network\":\"xhttp\",\"xhttpSettings\":$XP" ;; esac
    case "$1" in
    fm-*xhttp) XCNET="$NET" ;;
    fm-dl-*)   XCNET="\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/xp/\",\"mode\":\"$XM\",\"downloadSettings\":$XBLK}" ;;
    esac
    [ -z "$SFM" ] || NET="$NET,\"finalmask\":$SFM"
    [ -z "$CFM" ] || { Q="$Q&fm=$(enc "$CFM")"; XCNET="$XCNET,\"finalmask\":$CFM"; }
    FJ=""; [ -z "$FLOW" ] || FJ=",\"flow\":\"$FLOW\""
    KL=""; [ -z "$KEYLOG" ] || { KL=",\"masterKeyLog\":\"$W/keys.log\""; LPORT=18444; }
    if [ "$SEC" = none ]; then
        SECJ='"security":"none"'; LSEC="security=none"
    elif [ "$SEC" = reality ]; then
        SECJ="\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"dest\":\"$S_IP:8443\",\"xver\":0,\"serverNames\":[\"$MASK\"],\"privateKey\":\"$PRIV\",\"shortIds\":[\"$SID\"]$KL}"
        LSEC="security=reality&sni=$MASK&pbk=$PUB&sid=$SID&fp=$FP"
    else
        SECJ="\"security\":\"tls\",\"tlsSettings\":{\"alpn\":[\"h2\",\"http/1.1\"],\"certificates\":[{\"certificateFile\":\"$W/$SCERT.pem\",\"keyFile\":\"$W/$SKEY.key\"}]$KL}"
        LSEC="security=tls&sni=$MASK&alpn=$(enc "$XALPN")&fp=$FP"
    fi
}

v6_routes_clean() {
    addrs=$(ip netns exec "$NSC" ip -6 addr show dev vl scope global 2>/dev/null | awk '$1 == "inet6" { print $2 }')
    na=$(printf '%s' "$addrs" | grep -c . || true)
    own=""
    if [ "$na" -gt 1 ]; then
        echo "run-xray: FAIL — vl holds $na global IPv6 addresses, at most one is expected:"; printf '%s\n' "$addrs" | sed 's/^/    /'
        return 1
    fi
    if [ "$na" -eq 1 ]; then
        case "$addrs" in
        */128) own=${addrs%/128} ;;
        *) echo "run-xray: FAIL — the device address is not a /128: $addrs"; return 1 ;;
        esac
    fi
    rt=$(ip netns exec "$NSC" ip -6 route show table all | awk '!(/^(local|anycast|multicast) / && / table local /)')
    bad=$(printf '%s\n' "$rt" | awk -v own="$own" -v t6="${1:+$TARGET6}" '
        /^([a-z]+ )?(default|::\/0)( |$)/ { print; next }
        / dev vl( |$)/ {
            if (index($0, "fe80::/64 dev vl proto kernel ") == 1) next
            if (own != "" && index($0, own " dev vl proto kernel ") == 1) next
            if (t6 != "" && index($0, t6 " dev vl ") == 1) next
            print
        }')
    rl=$(ip netns exec "$NSC" ip -6 rule show | awk '$1 != "0:" && $1 != "32766:"')
    if [ -n "$bad" ] || [ -n "$rl" ]; then
        echo "run-xray: FAIL — IPv6 routes or rules outside the expected set:"
        printf '%s\n' "$rt" | sed 's/^/    route /'; ip netns exec "$NSC" ip -6 rule show | sed 's/^/    rule /'
        return 1
    fi
    echo "run-xray: IPv6 routes clean"
}

dl_snap() {
    ip netns exec "$NSS" nft list table inet dlcnt 2>/dev/null | awk '
        { for (i = 1; i < NF; i++) { if ($i == "packets") p = $(i + 1); if ($i == "bytes") b = $(i + 1) } }
        NF > 1 && $(NF - 1) == "comment" { k = $NF; gsub(/"/, "", k); v[k] = k ~ /^syn/ ? p : b }
        END { printf "%.0f %.0f %.0f %.0f %.0f %.0f\n", v["in1"], v["in2"], v["out1"], v["out2"], v["syn1"], v["syn2"] }'
}
dl_delta() { printf '%s %s\n' "$1" "$2" | awk '{ for (i = 1; i <= 6; i++) printf "%.0f ", $(i + 6) - $i; print "" }'; }
dl_load() {
    a=$(dl_snap)
    ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TARGET:8080" --dur 10 \
        --down "$1" --up "$2" --rate 0 --report 5 || return 1
    read -r din1 din2 dout1 dout2 _ _ <<EOF
$(dl_delta "$a" "$(dl_snap)")
EOF
}
dl_checks() {
    r=0
    if dl_load 0 2; then
        echo "run-xray: upload only: into $S_IP $din1 bytes, into $S_IP2 $din2 bytes"
        [ "$din1" -gt 0 ] && [ $((din2 * 20)) -lt "$din1" ] || {
            echo "run-xray: FAIL — the upload did not go to $S_IP (into $S_IP2 must be under 1/20)"; r=1; }
    else r=1; fi
    if dl_load 2 0; then
        echo "run-xray: download only: out of $S_IP $dout1 bytes, out of $S_IP2 $dout2 bytes"
        [ "$dout2" -gt $((dout1 * 20)) ] || {
            echo "run-xray: FAIL — the download did not come from $S_IP2 (over 20 times $S_IP)"; r=1; }
    else r=1; fi
    read -r _ _ _ _ dsyn1 dsyn2 <<EOF
$(dl_delta "$D0" "$(dl_snap)")
EOF
    echo "run-xray: TCP connections to $S_IP: $dsyn1, to $S_IP2: $dsyn2"
    [ "$dsyn1" -gt 0 ] && [ "$dsyn2" -gt 0 ] || { echo "run-xray: FAIL — not both addresses were connected to"; r=1; }
    return $r
}

etc_writable() { mkdir -p /etc/netns 2>/dev/null && : > /etc/netns/.w 2>/dev/null && rm -f /etc/netns/.w; }

srv_v6() {
    for a in "$TARGET6" "$CHK6A" "$CHK6B"; do ip -n "$NSS" addr "$1" "$a/128" dev lo nodad; done
    ip -n "$NSS" addr "$1" "$S_IP6/64" dev grs0 nodad
}

ua() { SEC=tls; TUN_ARGS="--ca $W/mask.pem"; KEYLOG=1; XMODE=packet-up
    Q="type=xhttp&path=%2Fxp%2F&mode=packet-up&extra=$(enc "{\"headers\":$1}")"
    XCNET="\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/xp/\",\"mode\":\"packet-up\",\"headers\":$1}"; }
xm() { XMODE=$1; XMUX=$2; Q="type=xhttp&path=%2Fxp%2F&mode=$1${2:+&extra=$(enc "{\"xmux\":$2}")}"; }
sub_write() { printf '%s\n' "vless://$UUID@$HOST:${LPORT:-$PORT}?encryption=none&$Q&$LSEC#$MODE" > "$W/sub.txt"; }
est() { ip netns exec "$NSS" ss -Htn state established "( sport = :$PORT )" | wc -l; }
est_samp() {
    i=0; : > "$2"
    while [ "$i" -lt "$1" ]; do
        echo "$i - -" >> "$2"
        ip netns exec "$NSS" ss -Htn state established "( sport = :$PORT )" | awk -v i="$i" '{ print i, $3, $4 }' >> "$2"
        i=$((i + 1)); sleep 0.5
    done
}
est_stat() {
    awk -v a="${2:-}" '$2 == "-" { s[$1] += 0; next } { gsub(/\[::ffff:|\]/, "", $2) } a == "" || index($2, a ":") == 1 { s[$1]++; p[$3] = 1 }
        END { mn = -1; mx = 0; for (k in s) { if (mn < 0 || s[k] < mn) mn = s[k]; if (s[k] > mx) mx = s[k] }
              d = 0; for (k in p) d++; print mn, mx, d }' "$1"
}
nft_val() { ip netns exec "$NSS" nft list table inet "$1" 2>/dev/null | sed -n "s/.*$2 \([0-9]*\) .*comment \"$3\".*/\1/p"; }
syns() { nft_val grpccnt packets syn; }
want() {
    if [ "$2" -"$3" "$4" ] 2>/dev/null; then echo "run-xray: $1: $2 (expected $3 $4)"
    else echo "run-xray: FAIL — $1: ${2:-none}, expected $3 $4"; XR=1; fi
}
tun_up() {
    ip netns exec "$NSC" env ${TUN_TRACE:+STEER_TUN_TRACE=1} "$1" $TUN_ARGS "$W/sub.txt" -d vl -n 0 --interval 3600 > "$W/tun-$MODE-$2.log" 2>&1 &
    SPID=$!; PIDS="$PIDS $SPID"
    for _ in $(seq 60); do ip netns exec "$NSC" ip link show vl >/dev/null 2>&1 && break; sleep 0.25; done
    ip netns exec "$NSC" ip link show vl >/dev/null 2>&1 || {
        echo "run-xray: FAIL — the tunnel vl did not come up:"; tail -8 "$W/tun-$MODE-$2.log"; return 1; }
    ip netns exec "$NSC" ip route replace "$TARGET/32" dev vl
    TGT="$TARGET:8080"
    sleep 2
}
tun_down() {
    [ -z "$SPID" ] || { kill "$SPID" 2>/dev/null || true; wait "$SPID" 2>/dev/null || true; }
    SPID=""
    ip netns exec "$NSC" ip link delete vl 2>/dev/null || true
}
xc_up() {
    case "$SEC" in
    reality) CS="\"security\":\"reality\",\"realitySettings\":{\"serverName\":\"$MASK\",\"publicKey\":\"$PUB\",\"shortId\":\"$SID\",\"fingerprint\":\"chrome\"}" ;;
    tls)     CS="\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$MASK\",\"alpn\":[\"$XALPN\"],\"fingerprint\":\"chrome\",\"certificates\":[{\"certificateFile\":\"$W/mask.pem\",\"usage\":\"verify\"}]}" ;;
    *)       CS='"security":"none"' ;;
    esac
    XMJ=""; [ -z "$XMUX" ] || XMJ=",\"xmux\":$XMUX"
    XN=${XCNET:-"\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/xp/\",\"mode\":\"$XMODE\"$XMJ}"}
    cat > "$W/xc-$MODE.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":18080,"protocol":"dokodemo-door","settings":{"address":"$TARGET","port":${XC_TPORT:-8080},"network":"tcp"}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"$S_IP","port":${LPORT:-$PORT},"users":[{"id":"$UUID","encryption":"none"$FJ}]}]},
   "streamSettings":{$XN,$CS}}]}
JSON
    ip netns exec "$NSC" "$XRAY" run -c "$W/xc-$MODE.json" > "$W/xc-$MODE.log" 2>&1 &
    CPID=$!; PIDS="$PIDS $CPID"
    for _ in $(seq 40); do ip netns exec "$NSC" ss -ltn 2>/dev/null | grep -q "127.0.0.1:18080 " && break; sleep 0.25; done
    ip netns exec "$NSC" ss -ltn 2>/dev/null | grep -q "127.0.0.1:18080 " || {
        echo "run-xray: FAIL — the Xray client did not start:"; tail -5 "$W/xc-$MODE.log"; return 1; }
    TGT=127.0.0.1:18080
    sleep 1
}
xc_down() { [ -z "$CPID" ] || { kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true; }; CPID=""; }
lrun() {
    lg=$1; shift
    r=0; ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TGT" "$@" > "$W/load-$MODE-$lg.log" 2>&1 || r=1
    sed 's/^/    /' "$W/load-$MODE-$lg.log"
    return $r
}
lres() { sed -n "s/^RESULT: pages \([0-9]*\) ok \/ \([0-9]*\) failed; \([0-9]*\) MB down, \([0-9]*\) MB up;.*/\\$2/p" "$W/load-$MODE-$1.log"; }
xcount() {
    s0=$(syns)
    ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TGT" --dur "$2" --down "$3" --up "$4" --rate "${5:-0}" \
        --report 10 > "$W/load-$MODE-$1.log" 2>&1 &
    LPID=$!; PIDS="$PIDS $LPID"
    sleep 3
    est_samp "$(awk -v d="$2" 'BEGIN { n = int((d - 4) * 2); print (n > 0 ? n : 1) }')" "$W/est-$MODE-$1"
    lr=0; wait "$LPID" || lr=1; LPID=""
    sed 's/^/    /' "$W/load-$MODE-$1.log"
    CNT="$(est_stat "$W/est-$MODE-$1") $(($(syns) - s0))"
    [ "$lr" -eq 0 ] || { echo "run-xray: FAIL — the load failed ($1)"; XR=1; }
}
rss() { awk '/^VmRSS:/ { print $2 }' "/proc/$SPID/status"; }
cpu() { sed 's/.*) //' "/proc/$SPID/stat" | awk '{ print $12 + $13 }'; }
evwait() { i=0; while [ $i -lt 75 ] && ! grep -qF "$1" "$W/kev"; do sleep 0.2; i=$((i + 1)); done; grep -qF "$1" "$W/kev"; }
socks_load() {
    ip netns exec "$NSC" python3 -c '
import socket, struct, sys, threading, time
ip, port, tgt, n, dur = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
got = [0] * n
bad = []
def recvn(s, k):
    b = b""
    while len(b) < k:
        d = s.recv(k - len(b))
        if not d:
            raise OSError("EOF in the SOCKS reply")
        b += d
    return b
def run(i):
    try:
        s = socket.create_connection((ip, port), 10)
        s.settimeout(30)
        s.sendall(b"\x05\x01\x00")
        if recvn(s, 2) != b"\x05\x00":
            raise OSError("method refused")
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(tgt) + struct.pack(">H", 8080))
        if recvn(s, 10)[1] != 0:
            raise OSError("CONNECT refused")
        s.sendall(b"GET /big/100000 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        end = time.time() + dur
        while time.time() < end:
            d = s.recv(1 << 20)
            if not d:
                raise OSError("EOF")
            got[i] += len(d)
    except Exception as e:
        bad.append("%d: %s" % (i, e))
ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
for t in ts:
    t.start()
for t in ts:
    t.join()
print("socks: %d flows, %.0f MB, least %d bytes, broken %d %s" % (n, sum(got) / 1e6, min(got), len(bad), bad[:3]))
sys.exit(1 if bad or min(got) == 0 else 0)
' "$C_IP" 1081 "$TARGET" 5 "$1"
}
hold_load() {
    ip netns exec "$NSC" python3 -c '
import socket, sys, time
ss = []
for i in range(int(sys.argv[2])):
    s = socket.create_connection((sys.argv[1], 8080), 10)
    s.sendall(b"GET /big/100000 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
    ss.append(s)
time.sleep(float(sys.argv[3]))
print("holders: %d connections held unread" % len(ss))
' "$TARGET" 20 "$1"
}
tap_up() {
    TAPD="$W/tap-$MODE-$1"
    ip netns exec "$NSS" python3 tests/tlstap.py --listen "$S_IP:$LPORT" --to "$S_IP:$PORT" --dir "$TAPD" \
        --cap "$TAPCAP" ${TAPLENS:+--lens} > "$W/tap-$MODE-$1.log" 2>&1 &
    RPID=$!; PIDS="$PIDS $RPID"
    for _ in $(seq 40); do ip netns exec "$NSS" ss -ltn | grep -q "$S_IP:$LPORT " && break; sleep 0.25; done
    ip netns exec "$NSS" ss -ltn | grep -q "$S_IP:$LPORT " || { echo "run-xray: FAIL — the relay did not start"; return 1; }
}
tap_down() { [ -z "$RPID" ] || { kill "$RPID" 2>/dev/null || true; wait "$RPID" 2>/dev/null || true; }; RPID=""; }
tap_conns() { ls "$1" 2>/dev/null | sed -n 's/\.c2s$//p' | sort -n; }
h2t() { "$H2TAP" "$1" "$W/keys.log" "$2/$3.c2s" "$2/$3.s2c" ${4:+"$4"}; }
tap_check() {
    nc=0; NA=0
    for n in $(tap_conns "$1"); do
        nc=$((nc + 1))
        o=$(h2t check "$1" "$n" 2>&1) && r=0 || r=$?
        f=$(h2t first "$1" "$n" 2>/dev/null) || f=?
        a=$(h2t afterack "$1" "$n" 2>/dev/null) || a=?
        hb=$(h2t dump "$1" "$n" 2>/dev/null | grep -o '\[hb=[0-9a-f]*' | sed 's/\[hb=//' | tr '\n' ' ') || hb=
        u=$(h2t ramp-units "$1" "$n" 2>&1) && ru=0 || ru=$?
        echo "run-xray: $2 connection $n: $o; $f; blocks start $hb; first after the ACK $a; ramp-units $u"
        [ "$r" -eq 0 ] || { echo "run-xray: FAIL — $2 connection $n: h2tap check exit $r"; XR=1; }
        [ "$ru" -eq 0 ] || { echo "run-xray: FAIL — $2 connection $n: h2tap ramp-units exit $ru"; XR=1; }
        [ "$a" = none ] || NA=$((NA + 1))
        [ -n "${3:-}" ] || continue
        [ "$f" = "$3" ] || { echo "run-xray: FAIL — $2 connection $n: $f, expected $3"; XR=1; }
        [ "$a" = none ] || [ "$a" = 3fe11f ] || { echo "run-xray: FAIL — $2 connection $n: the first block after the ACK starts $a, expected 3fe11f"; XR=1; }
    done
    want "$2 connections through the tap" "$nc" ge 1
}
tap_names() { for n in $(tap_conns "$1"); do h2t names "$1" "$n" "$2" 2>/dev/null && return 0; done; echo none; }
up200() {
    ip netns exec "$NSC" python3 -c '
import socket, sys
h, p = sys.argv[1].rsplit(":", 1)
s = socket.create_connection((h, int(p)), 20)
s.settimeout(30)
s.sendall(b"POST /up HTTP/1.1\r\nHost: t\r\nContent-Length: 200000\r\nConnection: close\r\n\r\n" + b"u" * 200000)
r = b""
while True:
    d = s.recv(65536)
    if not d:
        break
    r += d
print("upload: %s" % r.split(b"\r\n\r\n", 1)[-1].decode())
sys.exit(0 if r.endswith(b"ok 200000") else 1)' "$TGT"
}
inb_up() {
    rm -f "$W/kin"; mkfifo "$W/kin"; : > "$W/kev"
    ip netns exec "$NSC" "$BIN" $TUN_ARGS --control -d vl -A 1 --interval 3600 --tcp-port 3600 \
        --tcp-pool 198.18.0.0/15 < "$W/kin" > "$W/kev" 2> "$W/tun-$MODE-$1.log" &
    SPID=$!; PIDS="$PIDS $SPID"
    exec 7> "$W/kin"
    cat "$W/sub.txt" >&7; echo >&7
    evwait '"ready"' || { echo "run-xray: FAIL — no ready event:"; tail -5 "$W/tun-$MODE-$1.log"; exec 7>&-; return 1; }
    printf 'inbounds\n%s:1081 - - %s\n\n' "$C_IP" "$(cat "$W/sub.txt")" >&7
    evwait '"type":"inbound","port":1081,"state":"up"' || {
        echo "run-xray: FAIL — the inbound on $C_IP:1081 did not come up"; exec 7>&-; return 1; }
}
rec_drive() {
    ip netns exec "$NSC" timeout 40 python3 -c '
import socket, struct, sys, time
kind, host, port, pat, tgt = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
s = socket.create_connection((host, port), 30)
s.settimeout(30)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
def recvn(k):
    b = b""
    while len(b) < k:
        d = s.recv(k - len(b))
        if not d:
            raise OSError("EOF in the SOCKS reply")
        b += d
    return b
if kind == "socks":
    s.sendall(b"\x05\x01\x00")
    if recvn(2) != b"\x05\x00":
        raise OSError("method refused")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(tgt) + struct.pack(">H", 8080))
    if recvn(10)[1] != 0:
        raise OSError("CONNECT refused")
total = 49152 if pat == "first8k" else 2000
fmt = b"POST /up HTTP/1.1\r\nHost: t\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
cl = total - len(fmt % 0)
while len(fmt % cl) + cl != total:
    cl = total - len(fmt % cl)
msg = fmt % cl + b"u" * cl
if pat == "first8k":
    s.sendall(msg[:8192])
    time.sleep(1)
    for i in range(1, 6):
        s.sendall(msg[8192 * i:8192 * (i + 1)])
        time.sleep(0.1)
else:
    s.sendall(msg)
r = b""
while True:
    d = s.recv(65536)
    if not d:
        break
    r += d
print("drive %s %s: %s" % (kind, pat, r.split(b"\r\n\r\n", 1)[-1].decode()))
sys.exit(0 if r.endswith(b"ok %d" % cl) else 1)' "$1" "$2" "$3" "$4" "$TARGET"
}
rec_conn() {
    best=""; bs=-1; hits=""; rc=0
    for n in $(tap_conns "$1"); do
        if [ "${2:-}" = largest ]; then
            sz=$(wc -c < "$1/$n.c2s"); [ "$sz" -le "$bs" ] || { bs=$sz; best=$n; }
            continue
        fi
        o=$(h2t has "$1" "$n" "POST /up" 2>&1) && r=0 || r=$?
        case "$r" in
        0) hits="$hits $n"; best=$n ;;
        1) ;;
        *) echo "run-xray: FAIL — connection $n: h2tap has exit $r: $o" >&2; rc=1 ;;
        esac
    done
    [ "${hits# * }" = "$hits" ] || { echo "run-xray: FAIL — POST /up in more than one connection:$hits" >&2; rc=1; }
    [ -n "$best" ] || { echo "run-xray: FAIL — no tap connection for the drive" >&2; rc=1; }
    [ "$rc" -eq 0 ] || return 1
    echo "$best"
}
same() {
    if [ "$2" = "$3" ]; then echo "run-xray: $1: $2"
    else echo "run-xray: FAIL — $1: ${2:-none}, expected $3"; XR=1; fi
}
rec_run() {
    tap_down; tap_up "$1" || return 1
    if [ "$1" = t ]; then inb_up t || return 1; rec_drive socks "$C_IP" 1081 "$2" && dr=0 || dr=$?; exec 7>&-
    else xc_up || return 1; rec_drive plain 127.0.0.1 18080 "$2" && dr=0 || dr=$?; fi
    [ "$dr" -eq 0 ] || { echo "run-xray: FAIL — the drive failed ($1)"; XR=1; }
    sleep 0.5; tun_down; xc_down; sleep 0.5; tap_down
}
rec_case() {
    p=first8k; [ "$1" = rec-vision ] && p=first
    rec_run t "$p" || return 1
    rec_run x "$p" || return 1
    how=""; [ "$1" = rec-ws ] && how=largest
    for c in t x; do
        d="$W/tap-$MODE-$c"; l=""
        if ! n=$(rec_conn "$d" $how); then echo "run-xray: FAIL — $c: no single tap connection for the drive"; XR=1
        else
            l=$(h2t lens "$d" "$n" 10 2>&1) || { echo "run-xray: FAIL — $c connection $n: h2tap lens: $l"; XR=1; }
            r=$(h2t ramp "$d" "$n" 2>&1) || { echo "run-xray: FAIL — $c connection $n: $r"; XR=1; }
            echo "run-xray: $c connection $n: lens $l; ramp $r"
            [ -z "$how" ] || want "$c connection $n, plaintext bytes" \
                "$(h2t lens "$d" "$n" | tr ' ' '\n' | awk '{ t += $1 } END { print t + 0 }')" ge 49152
        fi
        eval "L_$c=\$l"
    done
    case "$1" in
    rec-raw)
        e="1186 2372 3558 1076 26 7116 1076 8192 8192 8192"
        same "Xray records 0-9" "$L_x" "$e"
        same "tunvless records 0-9" "$L_t" "$e"
        tap_down; tap_up u || return 1
        tun_up "$BIN" u || return 1
        up200 || { echo "run-xray: FAIL — the upload through vl"; XR=1; }
        sleep 0.5; tun_down; sleep 0.5; tap_down
        d="$W/tap-$MODE-u"
        n=$(rec_conn "$d" largest) || { echo "run-xray: FAIL — no tap connection for the TUN upload"; return 1; }
        r=$(h2t ramp "$d" "$n" 2>&1) || { echo "run-xray: FAIL — TUN connection $n: $r"; XR=1; }
        set -- $(h2t lens "$d" "$n" | tr ' ' '\n' | awk '$1 > m { m = $1 } $1 == 8192 { k++ } END { print NR, m + 0, k + 0 }')
        echo "run-xray: TUN connection $n: $r; records $1, longest $2, of 8192 B $3"
        want "longest TUN record" "$2" le 8192
        want "TUN records of 8192 B" "$3" ge 1 ;;
    rec-vision)
        same "Xray record 0" "${L_x%% *}" 1186
        same "tunvless record 0" "${L_t%% *}" 1186 ;;
    rec-ws)
        e="2372 1732 4104 32 4104 4104 4104 4104 4104"
        for c in x t; do
            eval "l=\$L_$c"
            want "$c record 0, the upgrade" "${l%% *}" le 1186
            same "$c records 1-9" "${l#* }" "$e"
        done ;;
    esac
    return $XR
}
h2_load() {
    case "$MODE" in
    h2-wire-reality) lrun "$1" --dur 3 --down 0 --up 0 --rate 1 ;;
    h2-wire-tls|ua-*) lrun "$1" --dur 3 --down 0 --up 0 --rate 1 && up200 ;;
    h2-credit)       lrun "$1" --dur 5 --down 1 --up 0 --rate 0 --report 5 ;;
    xmux-post-size)  lrun "$1" --dur 4 --down 0 --up 2 --rate 0 --report 1 ;;
    esac
}
h2_run() {
    tap_down; tap_up "$1" || return 1
    if [ "$1" = t ]; then tun_up "$BIN" t || return 1; else xc_up || return 1; fi
    h2_load "$1" || { echo "run-xray: FAIL — the load failed ($1)"; XR=1; }
    sleep 1
    tun_down; xc_down; sleep 0.5; tap_down
}
tap_fields() { for n in $(tap_conns "$1"); do h2t fields "$1" "$n" "$2" 2>/dev/null && return 0; done; return 1; }
fl_names() { sed 's/: .*//' "$1" | sort | tr '\n' ' '; }
fl_vals() { sed -n "s/^$2: //p" "$1" | sort | tr '\n' '|'; }
ua_case() {
    case "$1" in ua-golang) tail=3 ;; *) tail=2 ;; esac
    for me in GET POST; do
        for c in t x; do
            tap_fields "$W/tap-$MODE-$c" "$me" > "$W/f-$c-$me" || { echo "run-xray: FAIL — no $me block ($c)"; XR=1; : > "$W/f-$c-$me"; }
            echo "run-xray: $me fields, $c:"; sed 's/^/run-xray:   /' "$W/f-$c-$me" | cut -c1-160
        done
        same "$me names" "$(fl_names "$W/f-t-$me")" "$(fl_names "$W/f-x-$me")"
        [ -s "$W/f-x-$me" ] || { echo "run-xray: FAIL — empty $me block"; XR=1; }
        if [ "$me" = POST ]; then
            for c in t x; do
                same "last names of the POST ($c)" "$(sed 's/: .*//' "$W/f-$c-POST" | tail -n "$tail" | tr '\n' ' ')" \
                    "$(if [ "$tail" = 3 ]; then echo 'content-length accept-encoding user-agent '; else echo 'content-length accept-encoding '; fi)"
            done
        fi
        for f in user-agent accept-language priority dnt accept cache-control pragma sec-fetch-mode sec-fetch-dest sec-fetch-site sec-ch-ua-mobile sec-ch-ua-platform; do
            for c in t x; do
                v=$(fl_vals "$W/f-$c-$me" $f); [ "$f" != user-agent ] || v=$(echo "$v" | sed 's/[0-9][0-9]*/N/g')
                eval "V_$c=\$v"
            done
            same "$me $f" "$V_t" "$V_x"
        done
        for c in t x; do
            eval "B_$c=\$(sed -n 's/^sec-ch-ua: //p' \"$W/f-$c-$me\" | grep -o '\"Google Chrome\"\\|\"Microsoft Edge\"\\|\"Chromium\"' | sort | tr '\\n' ' ')"
        done
        same "$me sec-ch-ua brands" "$B_t" "$B_x"
        for c in t x; do
            u=$(fl_vals "$W/f-$c-$me" user-agent); d=$(fl_vals "$W/f-$c-$me" dnt)
            case "$1" in
            ua-golang) same "$me user-agent ($c)" "$u" "Go-http-client/2.0|" ;;
            ua-empty) same "$me user-agent ($c)" "$u" "" ;;
            ua-firefox) same "$me dnt ($c)" "$d" "0|1|" ;;
            esac
        done
    done
    return $XR
}
xmux_case() {
    m=$1; XR=0
    case "$m" in
    xmux-count-one|xmux-concurrency)
        tun_up "$BIN" t || return 1
        xcount t 20 20 0; set -- $CNT
        w=3; [ "$m" = xmux-concurrency ] && w=5
        want "connections at once, least over the load (most $2, distinct $3)" "$1" eq "$w"
        want "TCP connections opened during the load" "$4" eq "$w" ;;
    xmux-count-packet|xmux-count-up)
        tun_up "$BIN" t || return 1
        xcount t 60 20 2; T="$CNT $(lres t 4)"; TC=$(cpu); TR=$(rss); tun_down
        xc_up || return 1
        xcount x 60 20 2; X="$CNT $(lres x 4)"; xc_down
        set -- $T $X
        echo "run-xray: connections     least most distinct SYN   MB up"
        echo "run-xray:   tunvless      $1 $2 $3 $4   $5"
        echo "run-xray:   Xray client   $6 $7 $8 $9   ${10}"
        want "tunvless most at once against Xray's most" "$2" le "$7"
        want "tunvless least at once against Xray's least" "$1" le "$6"
        if [ "$m" = xmux-count-packet ]; then
            want "tunvless MB up, percent of Xray's" "$((${5%%.*} * 100 / (${10%%.*} + 1)))" ge 90
            echo "run-xray: tunvless: CPU ticks $TC, VmRSS $TR KiB, MB up per 1000 ticks $((${5%%.*} * 1000 / (TC + 1)))"
            if [ -x "${TUNVLESS_BASE:-}" ]; then
                tun_up "$TUNVLESS_BASE" b || return 1
                xcount b 60 20 2; ub=$(lres b 4); BC=$(cpu); BR=$(rss); tun_down
                echo "run-xray: base: MB up ${ub:-?}, CPU ticks $BC, VmRSS $BR KiB, MB up per 1000 ticks $((${ub:-0} * 1000 / (BC + 1)))"
            fi
        fi ;;
    xmux-requests|xmux-reuse)
        tun_up "$BIN" t || return 1
        d=5; w=2; [ "$m" = xmux-reuse ] && { d=5.5; w=3; }
        xcount t "$d" 0 0 2; set -- $CNT
        echo "run-xray: pages: $(lres t 1) ok, $(lres t 2) failed"
        want "TCP connections opened during the pages" "$4" eq "$w" ;;
    xmux-kill)
        tun_up "$BIN" t || return 1
        s0=$(syns); a0=$(wc -l < "$W/xray-access-$MODE.log")
        ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TGT" --dur 12 --down 5 --up 0 --rate 0 \
            --report 30 > "$W/load-$MODE-k.log" 2>&1 &
        LPID=$!; PIDS="$PIDS $LPID"
        sleep 4
        want "connections before the reset" "$(est)" eq 1
        cport=$(ip netns exec "$NSS" ss -Htn state established "( sport = :$PORT )" | awk '{ sub(/.*:/, "", $4); print $4; exit }')
        ip netns exec "$NSS" nft -f - <<NFT
table inet xkill { chain in { type filter hook input priority -300; policy accept; tcp dport $PORT tcp sport $cport reject with tcp reset; }; }
NFT
        sleep 1
        ip netns exec "$NSS" nft delete table inet xkill
        wait "$LPID" || true; LPID=""
        sed 's/^/    /' "$W/load-$MODE-k.log"
        want "long flows broken by the reset" "$(sed -n 's/.*long flows broke (\([0-9]*\)).*/\1/p' "$W/load-$MODE-k.log")" eq 5
        lrun p --dur 2 --down 0 --up 0 --rate 1 || XR=1
        want "pages after the reset" "$(lres p 1)" eq 1
        sy=$(($(syns) - s0))
        ck=$(tail -n +$((a0 + 1)) "$W/xray-access-$MODE.log" | grep -cE 'accepted tcp:(1\.1\.1\.1|8\.8\.8\.8|\[[0-9a-f:]*\]):80 ' || true)
        want "node checks the reset brought" "$ck" ge 2
        want "TCP connections opened for flows ($sy in all, less the checks)" "$((sy - ck))" eq 2 ;;
    xmux-ping)
        for ka in 2 -1; do
            xm stream-one "{\"hKeepAlivePeriod\":$ka}"; sub_write
            tun_up "$BIN" "k$ka" || return 1
            lrun "p$ka" --dur 2 --down 0 --up 0 --rate 1 || XR=1
            sleep 0.5; p0=$(nft_val dlcnt packets in1); sleep 10; p1=$(nft_val dlcnt packets in1)
            tun_down
            if [ "$ka" = 2 ]; then want "packets to the node in 10 s idle, hKeepAlivePeriod 2" "$((p1 - p0))" ge 4
            else want "packets to the node in 10 s idle, hKeepAlivePeriod -1" "$((p1 - p0))" eq 0; fi
        done ;;
    xmux-idle)
        tun_up "$BIN" t || return 1
        lrun p1 --dur 2 --down 0 --up 0 --rate 1 || XR=1
        want "connections after the page" "$(est)" eq 1
        sleep 288
        want "connections after about 289 s idle" "$(est)" eq 1
        sleep 17
        want "connections after about 306 s idle" "$(est)" eq 0
        s0=$(syns)
        lrun p2 --dur 2 --down 0 --up 0 --rate 1 || XR=1
        want "TCP connections opened by the next page" "$(($(syns) - s0))" eq 1 ;;
    xmux-up-parallel)
        for b in base cur; do
            bin=$BIN; [ "$b" = base ] && bin=$TUNVLESS_BASE
            tun_up "$bin" "$b" || return 1
            lrun "$b" --dur 20 --down 0 --up 5 --rate 0 --report 5 --stall 5 --each || XR=1
            tun_down
        done
        ub=$(lres base 4); uc=$(lres cur 4)
        echo "run-xray: uploaded: 2f17e46 ${ub:-?} MB, this build ${uc:-?} MB"
        want "upload, percent of 2f17e46" "$((${uc:-0} * 100 / (${ub:-0} + 1)))" ge 80 ;;
    xmux-dl)
        tun_up "$BIN" t || return 1
        xcount t 20 20 0
        set -- $(est_stat "$W/est-$MODE-t" "$S_IP") $(est_stat "$W/est-$MODE-t" "$S_IP2")
        want "connections at once to $S_IP, least (most $2, distinct $3)" "$1" eq 3
        want "connections at once to $S_IP2, least (most $5, distinct $6)" "$4" eq 3 ;;
    xmux-kernel-inbound)
        inb_up k || return 1
        printf 'map\n198.18.0.5 %s\n\n' "$TARGET" >&7
        evwait '"type":"map","count":1' || XR=1
        ip netns exec "$NSC" ip route replace "$TARGET/32" dev vl
        ip netns exec "$NSC" ip route replace 198.18.0.0/15 dev vl
        ip netns exec "$NSC" nft -f - <<NFT
table ip xredir { chain out { type nat hook output priority -100; policy accept; ip daddr 198.18.0.0/15 tcp dport 8080 counter redirect to :3600; }; }
NFT
        TGT="$TARGET:8080"; sleep 1
        ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TGT" --dur 20 --down 10 --up 0 --rate 0 \
            --report 10 > "$W/load-$MODE-tun.log" 2>&1 & P1=$!
        ip netns exec "$NSC" python3 tests/grpc-load.py --target 198.18.0.5:8080 --dur 20 --down 5 --up 0 --rate 0 \
            --report 10 > "$W/load-$MODE-redir.log" 2>&1 & P2=$!
        socks_load 20 > "$W/load-$MODE-socks.log" 2>&1 & P3=$!
        PIDS="$PIDS $P1 $P2 $P3"
        sleep 3
        est_samp 32 "$W/est-$MODE-k"
        wait "$P1" || XR=1; wait "$P2" || XR=1; wait "$P3" || XR=1
        for f in tun redir socks; do echo "run-xray: $f:"; sed 's/^/    /' "$W/load-$MODE-$f.log"; done
        exec 7>&-
        set -- $(est_stat "$W/est-$MODE-k")
        want "connections at once, least over the load (most $2, distinct $3)" "$1" eq 3
        want "redirected connections" "$(ip netns exec "$NSC" nft list table ip xredir | sed -n 's/.*packets \([0-9]*\) .*/\1/p')" eq 5
        grep -q '"type":"bytes"' "$W/kev" && echo "run-xray: tunvless reported redirected bytes" || {
            echo "run-xray: FAIL — no bytes event for the redirected flows"; XR=1; } ;;
    ua-*)
        h2_run t || return 1
        h2_run x || return 1
        tap_check "$W/tap-$MODE-t" tunvless
        tap_check "$W/tap-$MODE-x" "Xray client"
        ua_case "$m" ;;
    rec-raw|rec-vision|rec-ws) rec_case "$m" || XR=1 ;;
    vis-dl|vis-dl-tls)
        N=${VN:-200}
        vloop() {
            ok=0; bad=0; i=0
            while [ $i -lt "$N" ]; do
                case $((i % 6)) in 0) qs="bytes=3000000" ;; 1) qs="bytes=3000000&chunk=1400" ;;
                2) qs="bytes=200000&delay=0.05" ;; 3) qs="bytes=3000000&first=6000&gap=0.03" ;;
                4) qs="bytes=3000000&first=3000&gap=0.03" ;; *) qs="bytes=3000000&first=7900" ;; esac
                e=$(ip netns exec "$NSC" curl -sS -k --tlsv1.3 -m 15 -o /dev/null "https://$1/__down?$qs" 2>&1) && ok=$((ok + 1)) || {
                    bad=$((bad + 1)); echo "    $2 #$i $qs: $e"; }
                i=$((i + 1))
            done
            echo "run-xray: $2: $ok ok, $bad failed of $N"
            want "$2 failures of $N" "$bad" eq 0
        }
        TUN_TRACE=1 tun_up "$BIN" t || return 1
        vloop "$TARGET:8443" tunvless
        tun_down
        want "tunvless switches to direct copy" "$(grep -c 'server switched to direct copy' "$W/tun-$MODE-t.log")" ge 1
        XC_TPORT=8443 xc_up || return 1
        vloop "127.0.0.1:18080" "Xray client"
        xc_down ;;
    xmux-post-size)
        h2_run t || return 1
        h2_run x || return 1
        for c in t x; do
            d="$W/tap-$MODE-$c"; : > "$W/posts-$c"
            for n in $(tap_conns "$d"); do h2t posts "$d" "$n" >> "$W/posts-$c" 2>/dev/null || true; done
            set -- $(awk '{ p = $1; sub(/\?.*/, "", p); sub(/.*\//, "", p) } p ~ /^[0-9]+$/ && p + 0 >= 8 && $2 ~ /^[0-9]+$/ { print $2 }' "$W/posts-$c" |
                sort -n | awk '{ a[NR] = $1 } END { if (!NR) { print 0, 0, 0; exit } m = int((NR + 1) / 2); q = int((NR + 9) / 10); print NR, a[m], a[q] }')
            echo "run-xray: $c POSTs $(wc -l < "$W/posts-$c"), after the ramp $1, median $2, p10 $3"
            eval "md_$c=$2 pt_$c=$3"
        done
        want "tunvless median POST, percent of Xray's $md_x" "$((md_t * 100 / (md_x > 0 ? md_x : 1)))" ge 90
        want "tunvless p10 POST, percent of its median $md_t" "$((pt_t * 100 / (md_t > 0 ? md_t : 1)))" ge 50 ;;
    h2-wire-reality|h2-wire-tls)
        tap_down; tap_up q || return 1
        out=$(probe); tap_down
        is_ok "$out" || { echo "run-xray: FAIL — the probe through the tap: $out"; XR=1; }
        h2_run t || return 1
        h2_run x || return 1
        tap_check "$W/tap-$MODE-q" "tunvless probe"
        tap_check "$W/tap-$MODE-t" tunvless headers-first
        [ "$m" != h2-wire-tls ] || want "tunvless connections with a block after the ACK" "$NA" ge 1
        tap_check "$W/tap-$MODE-x" "Xray client"
        ms=POST; [ "$m" = h2-wire-tls ] && ms="GET POST"
        for me in $ms; do
            nt=$(tap_names "$W/tap-$MODE-t" "$me"); nx=$(tap_names "$W/tap-$MODE-x" "$me")
            echo "run-xray: $me names, tunvless:    $nt"
            echo "run-xray: $me names, Xray client: $nx"
            [ "$nt" != none ] && [ "$nt" = "$nx" ] || { echo "run-xray: FAIL — the $me names differ"; XR=1; }
        done
        if [ "$m" = h2-wire-tls ]; then
            for c in t x; do
                case " $(tap_names "$W/tap-$MODE-$c" POST) " in *" content-length "*) ;;
                *) echo "run-xray: FAIL — no content-length in the first POST ($c)"; XR=1 ;; esac
            done
        fi ;;
    h2-credit)
        h2_run t || return 1
        h2_run x || return 1
        tap_check "$W/tap-$MODE-t" tunvless
        tap_check "$W/tap-$MODE-x" "Xray client"
        for c in t x; do
            pa=0; l0=0; ls=0
            for n in $(tap_conns "$W/tap-$MODE-$c"); do
                w=$(h2t wu "$W/tap-$MODE-$c" "$n" 2>&1) || { echo "run-xray: FAIL — $c connection $n: h2tap wu: $w"; XR=1; continue; }
                set -- $w
                pa=$((pa + $2)); l0=$((l0 + $4)); ls=$((ls + $6))
            done
            mb=$(lres "$c" 3); d=${mb:-0}; [ "$d" -gt 0 ] || d=1
            echo "run-xray: $c: ${mb:-?} MB down, pairs $pa, lone0 $l0, lonestream $ls, pairs per MB $((pa / d))"
            eval "pm_$c=$((pa * 1000 / d)) ls_$c=$ls"
        done
        want "tunvless pairs per 1000 MB against Xray's $pm_x (x/1.5)" "$pm_t" ge "$((pm_x * 2 / 3))"
        want "tunvless pairs per 1000 MB against Xray's $pm_x (x*1.5)" "$pm_t" le "$((pm_x * 3 / 2))"
        want "tunvless lone stream WINDOW_UPDATEs" "$ls_t" eq 0 ;;
    h2-speed)
        for b in base cur; do
            bin=$BIN; [ "$b" = base ] && bin=$TUNVLESS_BASE
            tun_up "$bin" "$b" || return 1
            lrun "$b" --dur 20 --down 2 --up 2 --rate 0 --report 5 || XR=1
            tun_down
        done
        for k in 3 4; do
            vb=$(lres base $k); vc=$(lres cur $k); d=down; [ $k = 4 ] && d=up
            echo "run-xray: MB $d: base ${vb:-?}, this build ${vc:-?}"
            want "MB $d, percent of the base" "$((${vc:-0} * 100 / (${vb:-0} + 1)))" ge 80
        done ;;
    xmux-stall)
        tun_up "$BIN" t || return 1
        lrun w --dur 3 --down 0 --up 0 --rate 20 --report 10 || XR=1
        sleep 2
        r0=$(rss); o0=$(nft_val dlcnt bytes out1); c0=$(cpu)
        hold_load 10 > "$W/load-$MODE-hold.log" 2>&1 & HP=$!; PIDS="$PIDS $HP"
        mx=$r0; i=0
        while [ $i -lt 20 ]; do r=$(rss); [ "$r" -le "$mx" ] || mx=$r; i=$((i + 1)); sleep 0.5; done
        o1=$(nft_val dlcnt bytes out1); c1=$(cpu)
        wait "$HP" || XR=1; sed 's/^/    /' "$W/load-$MODE-hold.log"
        want "CPU time of tunvless while 20 flows are not read, ticks" "$((c1 - c0))" le 100
        want "VmRSS growth while 20 flows are not read, KiB (from $r0)" "$((mx - r0))" le 36864
        want "VmRSS growth while 20 flows are not read, KiB (from $r0)" "$((mx - r0))" ge 24576
        want "bytes the node sent meanwhile" "$((o1 - o0))" ge 33554432 ;;
    esac
    if grep -E "does not answer|answers again|did not open|refused the data" "$W"/tun-"$MODE"-*.log 2>/dev/null | head -3 | grep .; then
        echo "run-xray: FAIL — the pool declared the node dead, a flow did not open, or data was refused"; XR=1
    fi
    return $XR
}

tap2_up() {
    ip netns exec "$NSS" python3 tests/tlstap.py --listen "$S_IP2:$LPORT" --to "$S_IP2:$PORT" --dir "$W/tap2-$MODE-$1" \
        ${TAPLENS:+--lens} > "$W/tap2-$MODE-$1.log" 2>&1 &
    R2PID=$!; PIDS="$PIDS $R2PID"
    for _ in $(seq 40); do ip netns exec "$NSS" ss -ltn | grep -q "$S_IP2:$LPORT " && break; sleep 0.25; done
    ip netns exec "$NSS" ss -ltn | grep -q "$S_IP2:$LPORT " || { echo "run-xray: FAIL — the second relay did not start"; return 1; }
}
tap2_down() { [ -z "${R2PID:-}" ] || { kill "$R2PID" 2>/dev/null || true; wait "$R2PID" 2>/dev/null || true; }; R2PID=""; }
fmpy() {
    python3 -c '
import os, sys
mode, d, a = sys.argv[1], sys.argv[2], sys.argv[3:]
def recs(b, off):
    r = []
    while off + 5 <= len(b):
        n = b[off + 3] << 8 | b[off + 4]
        r.append((b[off], off, n))
        off += 5 + n
    return r
def spans(n):
    r, o = [], 0
    with open(os.path.join(d, "%d.lens" % n)) as f:
        for l in f:
            t, k = l.split()
            r.append((o, o + int(k), float(t)))
            o += int(k)
    return r
def hello(b, off, lo, hi, one=False):
    if len(b) < off + 9 or b[off] != 22 or b[off + 5] != 1:
        return "no handshake record at %d" % off
    need = 4 + (b[off + 6] << 16 | b[off + 7] << 8 | b[off + 8])
    got, ls = 0, []
    while got < need:
        if len(b) < off + 5 or b[off] != 22:
            return "the hello ends after %d of %d bytes" % (got, need)
        n = b[off + 3] << 8 | b[off + 4]
        ls.append(n); got += n; off += 5 + n
    if got != need:
        return "records carry %d bytes, the hello %d" % (got, need)
    if any(not lo <= x <= hi for x in ls[:-1]) or not 1 <= ls[-1] <= hi or one and len(ls) != 1:
        return "bodies %s" % ls
    return "ok: hello %d B in %d records, bodies %d..%d, last %d" % (need, len(ls), min(ls), max(ls), ls[-1])
def check(n, b):
    if mode == "head":
        h = bytes.fromhex(a[0])
        return "ok: starts with the header" if b.startswith(h) else "starts %s" % b[:len(h)].hex()
    if mode == "hello":
        return hello(b, int(a[2]), int(a[0]), int(a[1]))
    if mode == "uncut":
        return hello(b, int(a[0]), 1, 1 << 30, True)
    r = recs(b, 0)
    if mode == "range":
        m = int(a[0]); h = 5 + r[0][2]
        cov = [s for s in spans(n) if s[0] < h]
        k = sum(1 for s in cov if s[1] - s[0] <= m)
        w = h // m - 2
        return "%s: hello %d B in %d recvs, %d of them <= %d B (expected >= %d)" % ("ok" if k >= w else "bad", h, len(cov), k, m, w)
    if mode == "xh":
        m, k = int(a[0]), int(a[1])
        if len(r) < k:
            return "skip: %d records" % len(r)
        s0, e = r[0][1] + 5 + r[0][2], min(len(b), r[k - 1][1] + 5 + r[k - 1][2])
        cov = [s for s in spans(n) if s[0] < e and s[1] > s0]
        big = [s[1] - s[0] for s in cov if s[1] - s[0] > m]
        ok = cov and cov[0][0] == s0 and not big and len(cov) >= -(-(e - s0) // m)
        return "%s: records 2-%d (%d B from %d) in %d recvs: %s" % ("ok" if ok else "bad", k, e - s0, s0, len(cov), [s[1] - s[0] for s in cov])
    if mode == "loop":
        m = int(a[0])
        if len(r) < 4:
            return "skip: %d records" % len(r)
        o, n4 = r[3][1], 5 + r[3][2]
        if n4 < 1000:
            return "skip: record 4 is %d B" % n4
        cov = [s for s in spans(n) if s[0] < o + n4 and s[1] > o]
        sz = [s[1] - s[0] for s in cov]
        gaps = [cov[i + 1][2] - cov[i][2] for i in range(len(cov) - 1)]
        tot = cov[-1][2] - cov[0][2]
        ok = cov[0][0] == o and len(cov) >= 5 and max(sz) <= m and min(gaps) >= 0.18 and tot >= 0.8
        return "%s: record 4 of %d B in %d recvs %s, gaps %s ms, %.0f ms in all" % ("ok" if ok else "bad", n4, len(cov), sz, [round(g * 1000) for g in gaps], tot * 1000)
    return "unknown mode"
cs = sorted(int(f[:-4]) for f in os.listdir(d) if f.endswith(".c2s")) if os.path.isdir(d) else []
bad, good = 0, 0
for n in cs:
    b = open(os.path.join(d, "%d.c2s" % n), "rb").read()
    if not b:
        print("run-xray:   connection %d: empty" % n)
        continue
    try:
        v = check(n, b)
    except (IndexError, ValueError, OSError) as e:
        v = "unreadable: %s" % e
    print("run-xray:   connection %d: %s" % (n, v))
    if v.startswith("ok"):
        good += 1
    elif not v.startswith("skip"):
        bad += 1
sys.exit(1 if bad or not good else 0)
' "$@"
}
fm_loop_drive() {
    ip netns exec "$NSC" timeout 40 python3 -c '
import socket, sys, threading, time
host, port = sys.argv[1], int(sys.argv[2])
res = {}
def conn():
    s = socket.create_connection((host, port), 30)
    s.settimeout(30)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s
def readall(s):
    r = b""
    while True:
        d = s.recv(65536)
        if not d:
            return r
        r += d
def fa():
    try:
        fmt = b"POST /up HTTP/1.1\r\nHost: t\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
        cl = 1000 - len(fmt % 0)
        while len(fmt % cl) + cl != 1000:
            cl = 1000 - len(fmt % cl)
        s = conn()
        s.sendall(fmt % cl + b"u" * cl)
        res["a"] = readall(s).endswith(b"ok %d" % cl)
    except OSError as e:
        res["a"] = "%s" % e
def fb():
    try:
        t0 = time.monotonic()
        s = conn()
        s.sendall(b"GET /pg/0 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        d = s.recv(65536)
        res["bt"] = (time.monotonic() - t0) * 1000
        res["b"] = (d + readall(s)).startswith(b"HTTP/1.1 200 OK")
    except OSError as e:
        res["b"] = "%s" % e
ta = threading.Thread(target=fa)
ta.start()
time.sleep(0.05)
tb = threading.Thread(target=fb)
tb.start()
ta.join()
tb.join()
bt = res.get("bt", 1e9)
print("run-xray: flow A (1000 B): %s; flow B: %s, reply %.0f ms after its connect began (expected < 150)" % (res.get("a"), res.get("b"), bt))
sys.exit(0 if res.get("a") is True and res.get("b") is True and bt < 150 else 1)' "$1" "$2"
}
fm_vis() {
    ok=0; i=0
    for qs in bytes=3000000 "bytes=3000000&chunk=1400" "bytes=200000&delay=0.05" "bytes=3000000&first=6000&gap=0.03" "bytes=3000000&first=7900" bytes=100000; do
        e=$(ip netns exec "$NSC" curl -sS -k --tlsv1.3 -m 15 -o /dev/null "https://$1/__down?$qs" 2>&1) && ok=$((ok + 1)) || echo "    #$i $qs: $e"
        i=$((i + 1))
    done
    echo "run-xray: $ok of $i downloads ok"
    [ "$ok" -eq "$i" ]
}
fm_drive() {
    h=$TARGET; p=8080; [ "$1" = x ] && { h=127.0.0.1; p=18080; }
    case "$MODE" in
    fm-frag-loop) fm_loop_drive "$h" "$p" ;;
    fm-hc-vision) [ "$1" = t ] && p=8443; fm_vis "$h:$p" ;;
    *) rec_drive plain "$h" "$p" first ;;
    esac
}
fm_taps() { tap_down; tap2_down; [ -z "$LPORT" ] || tap_up "$1" || return 1; [ -z "$TAP2" ] || tap2_up "$1"; }
fm_run() {
    fm_taps "$1" || return 1
    O=fail
    if [ "$1" = t ] && [ "$EXPECT" = fail ]; then
        O=fail
        for _ in 1 2 3; do out=$(probe); echo "run-xray: probe: $out"; ! is_ok "$out" || O=ok; done
    elif [ "$1" = t ]; then
        if [ "$MODE" = fm-hc-vision ]; then TUN_TRACE=1 tun_up "$BIN" t || return 1; else tun_up "$BIN" t || return 1; fi
        ! fm_drive t || O=ok
    else
        if [ "$MODE" = fm-hc-vision ]; then XC_TPORT=8443 xc_up || return 1; else xc_up || return 1; fi
        ! fm_drive x || O=ok
    fi
    sleep 0.5; tun_down; xc_down; sleep 0.5; tap_down; tap2_down
    eval "O_$1=\$O"
}
fm_warm() {
    fm_taps w || return 1
    for _ in $(seq 12); do out=$(probe); is_ok "$out" && break; sleep 1; done
    echo "run-xray: warm-up probe: $out"
    tap_down; tap2_down
}
fm_refuse() {
    kind=${MODE#fm-refuse-}
    if [ -z "${FMX:-}" ]; then
        s0=$(nft_val dlcnt packets syn1)
        rm -f "$W/kin"; mkfifo "$W/kin"; : > "$W/kev"
        ip netns exec "$NSC" "$BIN" --control -d vl -A 1 --interval 3600 < "$W/kin" > "$W/kev" 2> "$W/tun-$MODE-t.log" &
        SPID=$!; PIDS="$PIDS $SPID"
        exec 7> "$W/kin"
        cat "$W/sub.txt" >&7; echo >&7
        txt="link cannot be used: finalmask: $kind is not supported yet"
        i=0; while [ $i -lt 25 ] && ! grep -qF "$txt" "$W/tun-$MODE-t.log"; do sleep 0.2; i=$((i + 1)); done
        out=$(probe); echo "run-xray: probe: $out"
        sleep 2; exec 7>&-; tun_down
        if grep -F "$txt" "$W/tun-$MODE-t.log"; then echo "run-xray: tunvless refused the link"
        else echo "run-xray: FAIL — no '$txt' in the log:"; tail -5 "$W/tun-$MODE-t.log"; XR=1; fi
        ! is_ok "$out" || { echo "run-xray: FAIL — the probe passed on a refused link"; XR=1; }
        want "TCP connections from tunvless to $S_IP" "$(($(nft_val dlcnt packets syn1) - s0))" eq 0
    fi
    xc_up || return 1
    O=fail; for _ in 1 2 3; do rec_drive plain 127.0.0.1 18080 first && { O=ok; break; }; sleep 1; done
    xc_down
    same "Xray client with $kind" "$O" ok
}
fm_case() {
    XR=0; O_t=skip; O_x=skip; R2PID=""
    case "$MODE" in fm-refuse-*) fm_refuse; return $XR ;; esac
    [ "$EXPECT" = fail ] || fm_warm || return 1
    for c in t x; do
        [ "$c" = t ] && [ -n "${FMX:-}" ] && continue
        a=$(dl_snap)
        fm_run "$c" || return 1
        if [ -n "$DL" ] && [ "$EXPECT" = fail ]; then
            read -r _ _ _ _ _ s2 <<EOF
$(dl_delta "$a" "$(dl_snap)")
EOF
            want "$c: TCP connections to the download address $S_IP2" "$s2" gt 0
        fi
    done
    echo "run-xray: outcome: tunvless $O_t, Xray client $O_x"
    for c in t x; do
        eval "o=\$O_$c"
        [ "$o" != skip ] || continue
        if [ "$EXPECT" = fail ]; then same "$c refused" "$o" fail
        elif [ "$MODE" != fm-frag-hello-reality ]; then same "$c data" "$o" ok; fi
    done
    [ "$MODE" != fm-frag-hello-reality ] || [ -n "${FMX:-}" ] || same "tunvless outcome, as Xray's client" "$O_t" "$O_x"
    [ "$EXPECT" = ok ] || return $XR
    for c in t x; do
        eval "o=\$O_$c"
        [ "$o" = ok ] || continue
        d="$W/tap-$MODE-$c"
        echo "run-xray: $c taps:"
        case "$MODE" in
        fm-frag-hello-*)   fmpy hello "$d" 10 19 0 ;;
        fm-frag-range)     fmpy range "$d" 100 ;;
        fm-frag-loop)      fmpy loop "$d" 200 ;;
        fm-frag-xhttp)     fmpy xh "$d" 50 5 ;;
        fm-hc-raw|fm-hc-xhttp|fm-hc-ws) fmpy head "$d" "$HCH" ;;
        fm-chain-hf)       fmpy head "$d" "$HCH" && fmpy uncut "$d" 18 ;;
        fm-chain-fh)       fmpy head "$d" "$HCH" && fmpy hello "$d" 10 10 18 ;;
        fm-dl-frag)        fmpy hello "$W/tap2-$MODE-$c" 10 10 0 && fmpy uncut "$d" 0 ;;
        *) echo "run-xray:   none" ;;
        esac || { echo "run-xray: FAIL — $c: the tap does not show the mask"; XR=1; }
    done
    [ "$MODE" != fm-hc-vision ] || [ -n "${FMX:-}" ] ||
        want "tunvless switches to direct copy" "$(grep -c 'server switched to direct copy' "$W/tun-$MODE-t.log")" ge 1
    if grep -E "does not answer|answers again|did not open|refused the data" "$W"/tun-"$MODE"-*.log 2>/dev/null | head -3 | grep .; then
        echo "run-xray: FAIL — the pool declared the node dead, a flow did not open, or data was refused"; XR=1
    fi
    return $XR
}

vcfg() { Q="$Q&flow=xtls-rprx-vision"; FLOW=xtls-rprx-vision; LPORT=18444; TAPCAP=4294967296; SLOG=debug; }
pstop() { eval "p=\$$1"; [ -z "$p" ] || { kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; }; eval "$1=''"; }
lwait() {
    for _ in $(seq 40); do ip netns exec "$NSS" ss -ltn | grep -q "$1 " && return 0; sleep 0.25; done
    echo "run-xray: FAIL — nothing listens on $1"; return 1
}
v_own() {
    pstop TPID; pstop OPID
    [ -n "$VPID" ] || { bg_in "$NSS" "$W/vtargets.log" python3 tests/vtargets.py "$TARGET"; VPID=$!; }
    lwait "$TARGET:8080"; lwait "$TARGET:2222"; lwait "$TARGET:9443"; lwait "$TARGET:9444"; lwait "$TARGET:8445"
}
o_own() {
    pstop VPID
    [ -z "$NOLD" ] || [ -n "$TPID" ] || { bg_in "$NSS" "$W/target.log" python3 tests/grpc-target.py "$TARGET" 8080; TPID=$!; lwait "$TARGET:8080"; }
    [ -z "$OWANT" ] || [ -n "$OPID" ] || {
        bg_in "$NSS" "$W/origin.log" python3 tests/vision-origin.py "$TARGET" 8443 "$W/mask.pem" "$W/mask.key" 0; OPID=$!
        lwait "$TARGET:8443"; }
}
OT1=""; OT2=""
votap_up() {
    bg_in "$NSS" "$W/otap-$MODE-$1.log" python3 tests/tlstap.py --listen "$TARGET:8443" --to "$TARGET:9443" --dir "$W/otap-$MODE-$1"; OT1=$!
    bg_in "$NSS" "$W/otap12-$MODE-$1.log" python3 tests/tlstap.py --listen "$TARGET:8444" --to "$TARGET:9444" --dir "$W/otap12-$MODE-$1"; OT2=$!
    lwait "$TARGET:8443" && lwait "$TARGET:8444"
}
votap_down() { pstop OT1; pstop OT2; }
vxc_up() {
    case "$SEC" in
    reality) CS="\"security\":\"reality\",\"realitySettings\":{\"serverName\":\"$MASK\",\"publicKey\":\"$PUB\",\"shortId\":\"$SID\",\"fingerprint\":\"chrome\"}" ;;
    *)       CS="\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$MASK\",\"alpn\":[\"$XALPN\"],\"fingerprint\":\"chrome\",\"certificates\":[{\"certificateFile\":\"$W/mask.pem\",\"usage\":\"verify\"}]}" ;;
    esac
    IN=""; i=0
    for tp in 8080 2222 8443 8444 8445; do
        IN="$IN${IN:+,}{\"listen\":\"127.0.0.1\",\"port\":$((18080 + i)),\"protocol\":\"dokodemo-door\",\"settings\":{\"address\":\"$TARGET\",\"port\":$tp,\"network\":\"tcp\"}}"
        i=$((i + 1))
    done
    cat > "$W/xc-$MODE.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[$IN],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"$S_IP","port":$LPORT,"users":[{"id":"$UUID","encryption":"none"$FJ}]}]},
   "streamSettings":{$XCNET,$CS}}]}
JSON
    ip netns exec "$NSC" "$XRAY" run -c "$W/xc-$MODE.json" > "$W/xc-$MODE-$1.log" 2>&1 &
    CPID=$!; PIDS="$PIDS $CPID"
    for _ in $(seq 40); do ip netns exec "$NSC" ss -ltn 2>/dev/null | grep -q "127.0.0.1:18084 " && break; sleep 0.25; done
    ip netns exec "$NSC" ss -ltn 2>/dev/null | grep -q "127.0.0.1:18084 " || {
        echo "run-xray: FAIL — the Xray client did not start:"; tail -5 "$W/xc-$MODE-$1.log"; return 1; }
    sleep 1
}
vhost() { if [ "$C" = t ]; then echo "$TARGET"; else echo 127.0.0.1; fi; }
vport() {
    [ "$C" = t ] && { echo "$1"; return; }
    case "$1" in 8080) echo 18080 ;; 2222) echo 18081 ;; 8443) echo 18082 ;; 8444) echo 18083 ;; 8445) echo 18084 ;; esac
}
vframes() {
    awk -v p="$2" '
        NR == FNR { if (/received request for tcp:/ && $NF ~ (":" p "$")) { n++; id = $4 } next }
        n == 1 && $4 == id && /Xtls Unpadding new block, content / { printf "%s%s/%s/%s", s, $(NF - 4), $(NF - 2), $NF; s = " " }
        END { print ""; if (n != 1) { print "vframes: " n + 0 " sessions name port " p > "/dev/stderr"; exit 1 } }' "$1" "$1"
}
vreq_ms() {
    python3 -c '
import re, sys, time
port, t0 = sys.argv[2], float(sys.argv[3])
hits = [l for l in open(sys.argv[1]) if re.search(r"received request for tcp:\S+:%s$" % port, l.rstrip())]
if len(hits) != 1:
    sys.exit("vreq_ms: %d sessions name port %s" % (len(hits), port))
d, t = hits[0].split()[:2]
e = time.mktime(time.strptime(d + " " + t[:8], "%Y/%m/%d %H:%M:%S")) + float("0" + t[8:])
print(int(round((e - t0) * 1000)))' "$@"
}
fld() { printf '%s\n' "$1" | tr ' ' '\n' | awk -F/ -v k="$2" 'NF { printf "%s%s", s, $k; s = " " } END { print "" }'; }
fsum() { printf '%s\n' "$1" | tr ' ' '\n' | awk -F/ 'NF { t += $1 } END { print t + 0 }'; }
fbad() {
    printf '%s\n' "$1" | tr ' ' '\n' | awk -F/ -v e="$2" 'NF { n++; f = n == 1 ? 16 : 0
        if (e == "pad" && $2 >= 256 || e == "cut" && $1 >= 8171 || e == "cap" && f + 5 + $1 + $2 > 8192) b++ }
        END { print n ? b + 0 : "none" }'
}
rx() {
    if printf '%s\n' "$2" | grep -Eqx "$3"; then echo "run-xray: $1: $2 (matches $3)"
    else echo "run-xray: FAIL — $1: ${2:-none}, expected to match $3"; XR=1; fi
}
vcn() { if [ "$C" = t ]; then echo tunvless; else echo "Xray client"; fi; }
vgo() {
    G=$1; shift
    tap_up "$C-$G" || return 1
    votap_up "$C-$G" || return 1
    if [ "$C" = t ]; then TUN_TRACE=1 tun_up "$BIN" "$G" || return 1; else vxc_up "$G" || return 1; fi
    mk=$(wc -l < "$W/xray-$MODE.log")
    "$@" > "$W/drv-$MODE-$C-$G.log" 2>&1 && vr=0 || vr=$?
    sed 's/^/    /' "$W/drv-$MODE-$C-$G.log"
    if [ "$vr" -eq 0 ]; then echo "run-xray: $(vcn) $G: the drive passed (answer checked)"
    else echo "run-xray: FAIL — $(vcn) $G: the drive failed ($vr)"; XR=1; fi
    if [ "$C" = t ] && [ -n "${VPROBE:-}" ]; then
        sleep 1; mp=$(wc -l < "$W/xray-$MODE.log")
        echo "run-xray: probe: $(probe)"
        sleep 1; tail -n +$((mp + 1)) "$W/xray-$MODE.log" > "$W/slog-$MODE-$C-probe"
    fi
    sleep 1
    tun_down; xc_down; sleep 0.5; tap_down; votap_down
    tail -n +$((mk + 1)) "$W/xray-$MODE.log" > "$W/slog-$MODE-$C-$G"
    VL="$W/slog-$MODE-$C-$G"; VCC=""; VOC=""
    n=$(rec_conn "$W/tap-$MODE-$C-$G" largest) && VCC="$W/tap-$MODE-$C-$G/$n.c2s"
    for d in "$W/otap-$MODE-$C-$G" "$W/otap12-$MODE-$C-$G"; do
        k=$(ls "$d" 2>/dev/null | grep -c '\.c2s$' || true)
        [ "$k" -eq 0 ] || { VOC=$(ls "$d"/*.c2s | head -1); [ "$k" -eq 1 ] || { echo "run-xray: FAIL — $k origin connections in $d"; XR=1; }; }
    done
    VF=$(vframes "$VL" "$VP") || { echo "run-xray: FAIL — $(vcn) $G: no single session for port $VP"; XR=1; }
    echo "run-xray: $(vcn) $G: frames $VF"
}
dcurl() {
    f=$1; p=$2; shift 2
    h=$(ip netns exec "$NSC" timeout 120 curl -sS -k -m 100 "$@" -T - "https://$(vhost):$(vport "$p")/up" < "$f") || return 1
    echo "answered $h, local $(sha256sum < "$f" | cut -c1-64)"
    [ "$h" = "$(sha256sum < "$f" | cut -c1-64)" ]
}
ddrive() { ip netns exec "$NSC" timeout 60 python3 tests/vdrive.py "$1" "$(vhost)" "$(vport "$2")" "$3" "$4" ${5:-} ${6:-}; }
dshape() { ip netns exec "$NSC" timeout 60 python3 tests/vshapes.py "$1" "$(vhost)" "$(vport 8443)" "$MASK" "$W/mask.pem" 1000000; }
vtail() {
    [ -n "$VCC" ] && [ -n "$VOC" ] || { echo "run-xray: FAIL — $(vcn) $G: no client or origin capture"; XR=1; return; }
    o=$(python3 tests/vtail.py "$VCC" "$VOC" "$1" ${2:-}) && r=0 || r=1
    echo "run-xray: $(vcn) $G: $o"
    [ "$r" -eq 0 ] || { echo "run-xray: FAIL — $(vcn) $G: vtail.py ${2:-}exit 1"; XR=1; }
}
vconn() { python3 -c 'import sys; print(sys.argv[1].split("connect=")[1].split()[0])' "$(cat "$W/drv-$MODE-$C-$G.log")"; }
vshape_check() {
    [ -n "$VOC" ] || { echo "run-xray: FAIL — $(vcn) $G: no origin capture"; XR=1; return; }
    set -- $(python3 tests/vrecs.py "$VOC") 0 0 0 0 0
    case "$G" in
    split)  e="$(($1 + 5)) $(($2 + $3 + 10)) $(($4 + 5))"; k="0 0 2" ;;
    joined) e="$(($1 + 5)) $(($2 + $3 + $4 + 15)) $(($5 + 5))"; k="0 0 2" ;;
    nocss)  e="$(($1 + 5)) $(($2 + 5))"; k="0 2" ;;
    esac
    echo "run-xray: $(vcn) $G: origin records $1 $2 $3 $4 ${5:-}"
    same "$(vcn) $G commands" "$(fld "$VF" 3)" "$k"
    same "$(vcn) $G contents" "$(fld "$VF" 1)" "$e"
    s=$(fsum "$VF")
    vtail "$s"
    want "$(vcn) $G origin bytes after S" "$(($(wc -c < "$VOC") - s))" ge 1000000
    eval "SK_${C}_$G=\"\$(fld \"\$VF\" 3)\" SC_${C}_$G=\"\$(fld \"\$VF\" 1)\""
}
v_up_check() {
    rx "$(vcn) commands" "$(fld "$VF" 3)" '0( 0)+ 2'
    s=$(fsum "$VF")
    vtail "$s"
    [ -z "$VOC" ] || want "$(vcn) origin bytes after S" "$(($(wc -c < "$VOC") - s))" ge 3000000
    [ "$C" != t ] || want "tunvless traces the client switch" "$(grep -c 'client switched to direct copy' "$W/tun-$MODE-$G.log")" ge 1
}
vapp() { [ -n "$VCC" ] && python3 tests/vrecs.py "$VCC" --after-handshake || true; }
v_case() {
    XR=0
    tap_up w || return 1
    warm=0; for _ in $(seq 12); do out=$(probe); is_ok "$out" && { warm=1; break; }; sleep 1; done
    tap_down
    [ "$warm" -eq 1 ] || { echo "run-xray: FAIL — the node did not answer the probe within a minute: $out"; return 1; }
    case "$MODE" in
    vis-up-ccm8)
        e=$(ip netns exec "$NSS" env OPENSSL_CONF="$W/ccm8.cnf" timeout 20 curl -sS -k --tlsv1.3 --tls13-ciphers TLS_AES_128_CCM_8_SHA256 \
            -o /dev/null -w '%{http_code}' "https://$TARGET:8445/" 2>&1) || e="$e failed"
        [ "$e" = 200 ] || { echo "run-xray: FAIL — no CCM_8 on this host: $e"; return 1; }
        echo "run-xray: CCM_8 directly in the server namespace: $e" ;;
    vis-up|vis-up-tls|vis-up-tls12) head -c "$([ "$MODE" = vis-up-tls12 ] && echo 1000000 || echo 3000000)" /dev/urandom > "$W/up-$MODE.bin" ;;
    esac
    for C in t x; do
        case "$MODE" in
        vis-up|vis-up-tls)
            VP=8443; vgo up dcurl "$W/up-$MODE.bin" 8443 --tlsv1.3 || return 1
            v_up_check ;;
        vis-up-tls12)
            VP=8444; vgo up dcurl "$W/up-$MODE.bin" 8444 --tls-max 1.2 || return 1
            rx "$(vcn) commands" "$(fld "$VF" 3)" '0( 0)+ 1'
            want "$(vcn) frames with command 2" "$(fld "$VF" 3 | tr ' ' '\n' | grep -c '^2$')" eq 0
            vtail "$(fsum "$VF")" --not ;;
        vis-up-ccm8)
            VP=8445
            vgo get sh -c 'ip netns exec "$0" env OPENSSL_CONF="$1" timeout 30 curl -sS -k -m 20 --tlsv1.3 --tls13-ciphers TLS_AES_128_CCM_8_SHA256 -o /dev/null -w "status %{http_code}\n" "$2" | tee /dev/stderr | grep -qx "status 200"' \
                "$NSC" "$W/ccm8.cnf" "https://$(vhost):$(vport 8445)/" || return 1
            rx "$(vcn) commands" "$(fld "$VF" 3)" '0( 0)+ 1'
            want "$(vcn) frames with command 2" "$(fld "$VF" 3 | tr ' ' '\n' | grep -c '^2$')" eq 0 ;;
        vis-up-shapes)
            for m in split joined nocss; do VP=8443; vgo "$m" dshape "$m" || return 1; vshape_check; done ;;
        fm-frag-vision-up|fm-hc-vision-up)
            VP=8443; vgo split dshape split || return 1; vshape_check ;;
        vis-plain-end)
            VP=8080; VPROBE=1 vgo plain ddrive plain 8080 0 1000 10 50 || return 1
            same "$(vcn) frames" "$(printf '%s\n' "$VF" | sed 's|/[0-9]*/|/P/|g')" "100/P/0 100/P/0 100/P/0 100/P/0 100/P/0 100/P/0 100/P/1"
            want "$(vcn) frames with padding of 256 B or more" "$(fbad "$VF" pad)" eq 0
            if [ "$C" = t ]; then
                PF=$(vframes "$W/slog-$MODE-t-probe" 80) || { echo "run-xray: FAIL — no single probe session"; XR=1; }
                echo "run-xray: tunvless probe: frames $PF"
                same "tunvless probe commands" "$(fld "$PF" 3)" 0
                want "tunvless probe frames with padding of 256 B or more" "$(fbad "$PF" pad)" eq 0
            fi ;;
        vis-wait)
            VP=2222; vgo greet ddrive greet 2222 0 8192 || return 1
            want "$(vcn) greet: ms to the request" "$(vreq_ms "$VL" 2222 "$(vconn)")" ge 500
            want "$(vcn) greet: ms to the request" "$(vreq_ms "$VL" 2222 "$(vconn)")" le 800
            a=$(vapp); echo "run-xray: $(vcn) greet: records after the handshake $(echo "$a" | cut -c1-60)"
            same "$(vcn) greet: first record after the handshake" "${a%% *}" 61
            want "$(vcn) greet: frames with content 0" "$(fld "$VF" 1 | tr ' ' '\n' | grep -c '^0$')" eq 0
            VP=8080; vgo w700 ddrive plain 8080 700 2000 || return 1
            want "$(vcn) 700: ms to the request" "$(vreq_ms "$VL" 8080 "$(vconn)")" ge 500
            want "$(vcn) 700: ms to the request" "$(vreq_ms "$VL" 8080 "$(vconn)")" le 800
            a=$(vapp); echo "run-xray: $(vcn) 700: records after the handshake $(echo "$a" | cut -c1-60)"
            set -- $a 0 0
            pp=$(fld "$VF" 2 | cut -d' ' -f1)
            same "$(vcn) 700: first two records after the handshake" "$1 $2" "61 $((2038 + ${pp:-0}))"
            same "$(vcn) 700: frames" "$(printf '%s\n' "$VF" | sed 's|/[0-9]*/|/P/|g')" "2000/P/0"
            vgo w300 ddrive plain 8080 300 2000 || return 1
            want "$(vcn) 300: ms to the request" "$(vreq_ms "$VL" 8080 "$(vconn)")" ge 300
            want "$(vcn) 300: ms to the request" "$(vreq_ms "$VL" 8080 "$(vconn)")" le 550
            a=$(vapp); echo "run-xray: $(vcn) 300: records after the handshake $(echo "$a" | cut -c1-60)"
            want "$(vcn) 300: records after the handshake" "$(echo "$a" | wc -w)" ge 1
            want "$(vcn) 300: records of 61 B after the handshake" "$(echo "$a" | tr ' ' '\n' | grep -c '^61$')" eq 0 ;;
        vis-reshape)
            for g in "g8k greet 2222 0 8192" "p0 plain 8080 0 8192" "p150 plain 8080 150 8192" "g20k greet 2222 0 20000"; do
                set -- $g; VP=$3
                vgo "$1" ddrive "$2" "$3" "$4" "$5" || return 1
                case "$1" in
                g20k)
                    same "$(vcn) $1 contents in all" "$(fsum "$VF")" 20000
                    want "$(vcn) $1 frames with content of 8171 B or more" "$(fbad "$VF" cut)" eq 0
                    rx "$(vcn) $1 commands" "$(fld "$VF" 3)" '0( 0)*' ;;
                g8k|p0|p150)
                    same "$(vcn) $1 contents" "$(fld "$VF" 1)" "4096 4096"
                    same "$(vcn) $1 commands" "$(fld "$VF" 3)" "0 0" ;;
                esac
                case "$1" in p0|p150)
                    a=$(vapp); set -- "$1" $a
                    same "$(vcn) $1 first four records after the handshake" "$2 $3 $4 $5" "1203 2389 3575 1093" ;;
                esac
                want "$(vcn) $1 frames over 8192 B" "$(fbad "$VF" cap)" eq 0
            done ;;
        esac
    done
    case "$MODE" in
    vis-up-shapes|fm-frag-vision-up|fm-hc-vision-up)
        ms="split"; [ "$MODE" = vis-up-shapes ] && ms="split joined nocss"
        for m in $ms; do
            eval "a=\$SK_t_$m b=\$SK_x_$m c=\$SC_t_$m d=\$SC_x_$m"
            same "$m commands, tunvless as Xray's client" "$a" "$b"
            same "$m contents, tunvless as Xray's client" "$c" "$d"
        done ;;
    esac
    return $XR
}
for MODE in $CASES; do
    rm -rf "/etc/netns/$NSC" 2>/dev/null || true
    srv_v6 replace
    SYN0=$(syns)
    case_cfg "$MODE"
    echo "run-xray: ==== case $MODE ===="
    HOST="$S_IP"
    case "$NODE" in
    v6)    HOST="[$S_IP6]" ;;
    name6) HOST=node6.test ;;
    dual)  HOST=node46.test ;;
    esac
    case "$NODE" in
    name6|dual)
        if ! etc_writable; then
            echo "run-xray: case $MODE — SKIPPED (no writable /etc for the hosts file; not passed)"
            SKIPPED="$SKIPPED $MODE"; continue
        fi
        mkdir -p "/etc/netns/$NSC"
        if [ "$NODE" = name6 ]; then printf '%s node6.test\n' "$S_IP6" > "/etc/netns/$NSC/hosts"
        else
            printf '%s node46.test\n%s node46.test\n' "$S_IP" "$S_IP6" > "/etc/netns/$NSC/hosts"
            printf 'precedence ::/0 100\nprecedence ::ffff:0:0/96 10\n' > "/etc/netns/$NSC/gai.conf"
        fi ;;
    esac
    if [ "$MODE" = xmux-up-parallel ] && [ ! -x "${TUNVLESS_BASE:-}" ]; then
        echo "run-xray: case $MODE — SKIPPED (no TUNVLESS_BASE binary; not passed)"
        SKIPPED="$SKIPPED $MODE"; continue
    fi
    case "$MODE" in h2-*|rec-*|ua-*|xmux-post-size)
        if [ ! -x "${H2TAP:-}" ]; then
            echo "run-xray: case $MODE — SKIPPED (no H2TAP binary; not passed)"
            SKIPPED="$SKIPPED $MODE"; continue
        fi ;;
    esac
    if [ "$MODE" = h2-speed ] && [ ! -x "${TUNVLESS_BASE:-}" ]; then
        echo "run-xray: case $MODE — SKIPPED (no TUNVLESS_BASE binary; not passed)"
        SKIPPED="$SKIPPED $MODE"; continue
    fi
    case "$MODE" in xmux-*)
        if [ -z "$DLNFT" ]; then
            echo "run-xray: case $MODE — SKIPPED (no nft counters in the server namespace; not passed)"
            SKIPPED="$SKIPPED $MODE"; continue
        fi ;;
    esac
    case "$MODE" in fm-refuse-*)
        if [ -z "$DLNFT" ]; then
            echo "run-xray: case $MODE — SKIPPED (no nft counters in the server namespace; not passed)"
            SKIPPED="$SKIPPED $MODE"; continue
        fi ;;
    esac
    if [ -n "$DL" ] && [ -z "$DLNFT" ]; then
        echo "run-xray: case $MODE — SKIPPED (no nft counters in the server namespace; not passed)"
        SKIPPED="$SKIPPED $MODE"; continue
    fi
    if [ "$DH" = dl.test ]; then
        if ! etc_writable; then
            echo "run-xray: case $MODE — SKIPPED (no writable /etc for the hosts file; not passed)"
            SKIPPED="$SKIPPED $MODE"; continue
        fi
        mkdir -p "/etc/netns/$NSC"; printf '%s dl.test\n' "$S_IP2" > "/etc/netns/$NSC/hosts"
    fi
    INB1="\"port\":$PORT,\"protocol\":\"vless\",\"settings\":{\"clients\":[{\"id\":\"$UUID\"$FJ}],\"decryption\":\"none\"},\"streamSettings\":{$NET,$SECJ}"
    case "$NODE" in
    v6|name6) INB="{\"listen\":\"$S_IP6\",$INB1}" ;;
    dual)     INB="{\"listen\":\"$S_IP\",$INB1},{\"listen\":\"$S_IP6\",$INB1}" ;;
    *)        INB="{\"listen\":\"$S_IP\",$INB1}" ;;
    esac
    [ -z "$DL" ] || INB="{\"listen\":\"0.0.0.0\",$INB1}"
    FR="{\"action\":\"allow\",\"ip\":[\"$TARGET/32\"]}"
    case "$V6" in
    carry|noroute)
            FR="$FR,{\"action\":\"allow\",\"ip\":[\"$TARGET6/128\",\"$CHK6A/128\",\"$CHK6B/128\"]}" ;;
    none)   FR="$FR,{\"action\":\"allow\",\"ip\":[\"$TARGET6/128\"]},{\"action\":\"block\",\"ip\":[\"$CHK6A/128\",\"$CHK6B/128\"]}" ;;
    second) FR="$FR,{\"action\":\"allow\",\"ip\":[\"$TARGET6/128\",\"$CHK6B/128\"]},{\"action\":\"block\",\"ip\":[\"$CHK6A/128\"]}" ;;
    esac
    if [ "$V6" = noroute ]; then
        srv_v6 del
        if ip netns exec "$NSS" ip -6 route get "$CHK6A" >/dev/null 2>&1 || ip netns exec "$NSS" ip -6 route get "$CHK6B" >/dev/null 2>&1; then
            echo "run-xray: FAIL — the server namespace still routes IPv6:"; ip -n "$NSS" -6 route show table all | sed 's/^/    /'
            FAIL=1; echo "run-xray: case $MODE — FAIL"; continue
        fi
        echo "run-xray: the server namespace has no IPv6 route to the check targets"
    fi
    cat > "$W/xray.json" <<JSON
{"log":{"loglevel":"$SLOG","access":"$W/xray-access-$MODE.log"},
 "inbounds":[$INB],
 "outbounds":[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[$FR]}}]}
JSON
    ip netns exec "$NSS" "$XRAY" run -c "$W/xray.json" > "$W/xray-$MODE.log" 2>&1 &
    XPID=$!; PIDS="$PIDS $XPID"
    for _ in $(seq 40); do ip netns exec "$NSS" ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.25; done
    ip netns exec "$NSS" ss -ltn 2>/dev/null | grep -q ":$PORT " || { echo "run-xray: Xray did not start:"; tail -5 "$W/xray-$MODE.log"; exit 1; }
    [ -z "$DL" ] || D0=$(dl_snap)
    RPID=""; [ -z "$KEYLOG" ] || tap_up p || { FAIL=1; kill "$XPID" 2>/dev/null || true; continue; }

    sub_write
    if is_v "$MODE"; then v_own; else o_own; fi
    probe() { ip netns exec "$NSC" env $TUN_ENV "$BIN" --probe --timeout 5 $TUN_ARGS "$W/sub.txt" 2>&1 || true; }
    is_ok() { printf '%s' "$1" | awk -F '\t' '$3 == "ok" { f = 1 } END { exit !f }'; }
    if is_v "$MODE"; then
        SPID=""; CPID=""; LPID=""
        rc=0; v_case || rc=1
        tun_down; xc_down; tap_down; votap_down
        kill "$XPID" 2>/dev/null || true
        sleep 0.5
        if [ "$rc" -ne 0 ]; then FAIL=1; echo "run-xray: case $MODE — FAIL"; else echo "run-xray: case $MODE — ok"; fi
        continue
    fi
    case "$MODE" in fm-*)
        SPID=""; CPID=""; LPID=""
        rc=0; fm_case || rc=1
        tun_down; xc_down; tap_down; tap2_down
        kill "$XPID" 2>/dev/null || true
        sleep 0.5
        if [ "$rc" -ne 0 ]; then FAIL=1; echo "run-xray: case $MODE — FAIL"; else echo "run-xray: case $MODE — ok"; fi
        continue ;;
    esac

    # Warm-up: the very first connection to a freshly started Xray with Reality can be slow (and
    # openssl s_server as the cover site even more), so failures are counted only after the first
    # answer, waited for up to a minute. That is the test bed, not the client.
    warm=0
    for _ in $(seq 12); do
        out=$(probe)
        if is_ok "$out"; then warm=1; break; fi
        sleep 1
    done
    if [ "$EXPECT" = fail ]; then
        kill "$XPID" 2>/dev/null || true; sleep 0.5
        [ -z "$DL" ] || read -r _ _ _ _ _ dsyn2 <<EOF
$(dl_delta "$D0" "$(dl_snap)")
EOF
        if [ "$warm" -eq 1 ]; then
            echo "run-xray: FAIL — the server accepted a request it must refuse: $out"; FAIL=1
            echo "run-xray: case $MODE — FAIL"
        elif [ "$MODE" = xhttp-tls-p384-neg ] && ! openssl x509 -in "$W/leaf384.pem" -noout -checkhost "$MASK" | grep -q 'does match'; then
            echo "run-xray: FAIL — the leaf does not name $MASK, so the refusal proves nothing about the chain"; FAIL=1
            echo "run-xray: case $MODE — FAIL"
        elif [ "$MODE" = xhttp-tls-p384-neg ] && ! printf '%s' "$out" | grep -q 'does not chain to a root'; then
            echo "run-xray: FAIL — refused, but not for the chain: $out"; FAIL=1
            echo "run-xray: case $MODE — FAIL"
        elif [ -n "$DL" ] && [ "$dsyn2" -eq 0 ]; then
            echo "run-xray: FAIL — refused before the GET reached $S_IP2: $out"; FAIL=1
            echo "run-xray: case $MODE — FAIL"
        elif [ -n "$DL" ] && ! printf '%s' "$out" | grep -q 'server answered 4'; then
            echo "run-xray: FAIL — refused, but not by the server: $out"; FAIL=1
            echo "run-xray: case $MODE — FAIL"
        else
            echo "run-xray: refused as expected: $out"; echo "run-xray: case $MODE — ok"
        fi
        continue
    fi
    [ "$warm" -eq 1 ] || { echo "run-xray: FAIL — the node did not answer the probe within a minute: $out"; FAIL=1; tap_down; kill "$XPID" 2>/dev/null || true; continue; }
    case "$MODE" in xmux-*|h2-*|rec-*|vis-*|ua-*)
        SPID=""; CPID=""; LPID=""
        rc=0; xmux_case "$MODE" || rc=1
        tun_down; xc_down; tap_down
        kill "$XPID" 2>/dev/null || true
        sleep 0.5
        if [ "$rc" -ne 0 ]; then FAIL=1; echo "run-xray: case $MODE — FAIL"; else echo "run-xray: case $MODE — ok"; fi
        continue ;;
    esac

    # 1. The node probe, 30 times.
    ok=0; bad=0
    for i in $(seq 30); do
        out=$(probe)
        if is_ok "$out"; then ok=$((ok + 1)); else
            bad=$((bad + 1)); LAST="$out"
            echo "run-xray:   probe $i: $out"
        fi
    done
    echo "run-xray: node probe: ok $ok, failed $bad"
    if [ "$bad" -ne 0 ]; then
        echo "run-xray: FAIL — the probe fails on a working node: $LAST"
        FAIL=1; kill "$XPID" 2>/dev/null || true; continue
    fi

    # 2-3. The tunnel and the load. The pool checks the node every 10 s instead of every minute,
    # so a false "dead" (two failures in a row) shows up within the run.
    mark1=$(wc -l < "$W/probe1-6.log"); mark2=$(wc -l < "$W/probe2-6.log"); markx=$(wc -l < "$W/xray-access-$MODE.log")
    ip netns exec "$NSC" env $TUN_ENV "$BIN" $TUN_ARGS "$W/sub.txt" -d vl -n 0 --interval 10 > "$W/tun-$MODE.log" 2>&1 &
    SPID=$!; PIDS="$PIDS $SPID"
    for _ in $(seq 60); do ip netns exec "$NSC" ip link show vl >/dev/null 2>&1 && break; sleep 0.25; done
    ip netns exec "$NSC" ip link show vl >/dev/null 2>&1 || {
        echo "run-xray: FAIL — the tunnel vl did not come up:"; tail -8 "$W/tun-$MODE.log"; FAIL=1
        kill "$SPID" "$XPID" 2>/dev/null || true; continue; }
    ip netns exec "$NSC" ip route replace "$TARGET/32" dev vl
    [ "$DH" != dl.test ] || : > "/etc/netns/$NSC/hosts"
    rc=0
    [ "$NODE" = v4 ] || v6_routes_clean || rc=1
    if [ -n "$V6" ]; then
        seen() { tail -n +$(($2 + 1)) "$1"; }
        v6addr() { ip netns exec "$NSC" ip -6 addr show dev vl 2>/dev/null | grep -c 'inet6 2001:db8::' || true; }
        got6=0
        for _ in $(seq 120); do
            [ "$(v6addr)" -gt 0 ] && { got6=1; break; }
            sleep 0.25
        done
        v6_routes_clean || rc=1
        if [ "$V6" = none ] || [ "$V6" = noroute ]; then
            if [ "$got6" -eq 1 ]; then echo "run-xray: FAIL — the device got an IPv6 address on a node that reaches no IPv6 check"; rc=1
            else echo "run-xray: no IPv6 address on vl after 30 s, as expected"; fi
            tried=$(seen "$W/xray-access-$MODE.log" "$markx" | grep -n "accepted tcp:\[$CHK6A\]:80" | head -1)
            if [ -z "$tried" ]; then echo "run-xray: FAIL — Xray saw no attempt to [$CHK6A]:80"; rc=1
            else echo "run-xray: Xray saw the check go to [$CHK6A]:80"; fi
            if [ "$V6" = noroute ]; then
                xl=$(seen "$W/xray-access-$MODE.log" "$markx")
                n1=$(printf '%s\n' "$xl" | grep -n "accepted tcp:\[$CHK6A\]:80" | head -1 | cut -d: -f1)
                n2=$(printf '%s\n' "$xl" | grep -n "accepted tcp:\[$CHK6B\]:80" | head -1 | cut -d: -f1)
                if [ -n "$n1" ] && [ -n "$n2" ] && [ "$n1" -lt "$n2" ]; then
                    echo "run-xray: Xray saw [$CHK6A]:80 tried (line $n1), then [$CHK6B]:80 (line $n2)"
                else echo "run-xray: FAIL — the unroutable first target did not lead to the second (lines '$n1' '$n2')"; rc=1; fi
            fi
            reached="$(seen "$W/probe1-6.log" "$mark1")$(seen "$W/probe2-6.log" "$mark2")"
            [ -z "$reached" ] || { echo "run-xray: FAIL — a blocked IPv6 check target was reached:"; printf '%s\n' "$reached"; rc=1; }
        elif [ "$got6" -ne 1 ]; then
            echo "run-xray: FAIL — no 2001:db8:: address on vl within 30 s:"; tail -8 "$W/tun-$MODE.log"; rc=1
        else
            echo "run-xray: IPv6 address on vl: $(ip netns exec "$NSC" ip -6 addr show dev vl | sed -n 's/.*inet6 \(2001:db8::[^ ]*\).*/\1/p')"
            ip netns exec "$NSC" ip -6 route replace "$TARGET6/128" dev vl
            ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TARGET6:8080" --dur 20 \
                --down 2 --up 2 --rate 10 --report 10 || rc=1
            ip netns exec "$NSC" python3 -c '
import os, socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(3)
for size in (1, 200, 1200):
    p = os.urandom(size)
    for _ in range(5):
        s.sendto(p, ("2001:db8:9::9", 9000))
        try:
            d = s.recv(65535)
        except socket.timeout:
            continue
        break
    else:
        print("udp6 %d bytes: no answer" % size); sys.exit(1)
    if d != p:
        print("udp6 %d bytes: wrong content" % size); sys.exit(1)
    print("udp6 %d bytes: echoed" % size)' || rc=1
            case "$V6" in
            carry)  want="$(seen "$W/probe1-6.log" "$mark1")"; other="$(seen "$W/probe2-6.log" "$mark2")"; host="[$CHK6A]" ;;
            second) want="$(seen "$W/probe2-6.log" "$mark2")"; other="$(seen "$W/probe1-6.log" "$mark1")"; host="[$CHK6B]" ;;
            esac
            if [ "$(printf '%s\n' "$want" | sort -u)" = "host $host" ]; then echo "run-xray: the IPv6 check sent Host: $host"
            else echo "run-xray: FAIL — the IPv6 check did not send exactly Host: $host to its target:"; printf '%s\n' "$want"; rc=1; fi
            if [ "$V6" = second ]; then
                xl=$(seen "$W/xray-access-$MODE.log" "$markx")
                n1=$(printf '%s\n' "$xl" | grep -n "accepted tcp:\[$CHK6A\]:80" | head -1 | cut -d: -f1)
                n2=$(printf '%s\n' "$xl" | grep -n "accepted tcp:\[$CHK6B\]:80" | head -1 | cut -d: -f1)
                if [ -n "$n1" ] && [ -n "$n2" ] && [ "$n1" -lt "$n2" ]; then
                    echo "run-xray: Xray saw [$CHK6A]:80 tried (line $n1) before [$CHK6B]:80 (line $n2)"
                else echo "run-xray: FAIL — Xray did not see [$CHK6A]:80 tried before [$CHK6B]:80 (lines '$n1' '$n2')"; rc=1; fi
            fi
            [ -z "$other" ] || { echo "run-xray: FAIL — the other IPv6 check target was reached:"; printf '%s\n' "$other"; rc=1; }
        fi
    fi
    echo "run-xray: tunnel up, load for $DUR s (two flows down, two up, 10 pages/s)"

    ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TARGET:8080" --dur "$DUR" \
        --down 2 --up 2 --rate 10 --report 10 || rc=1

    # The node declared dead (its connections reset) or a flow to it that did not open.
    # ... or the node refused uploaded data (xhttp: 413 over scMaxEachPostBytes, 400 on padding).
    bad_log=$(grep -E "does not answer|answers again|did not open|refused the data" "$W/tun-$MODE.log" || true)
    if [ -n "$bad_log" ]; then
        echo "run-xray: FAIL — the pool declared the node dead, a flow did not open, or data was refused:"
        printf '%s\n' "$bad_log" | head -5 | sed 's/^/    /'
        rc=1
    fi
    if [ -n "$DL" ]; then
        dl_checks || rc=1
        if grep -q "does not resolve" "$W/tun-$MODE.log"; then
            echo "run-xray: FAIL — a name did not resolve:"; grep "does not resolve" "$W/tun-$MODE.log" | head -3; rc=1
        fi
        case "$TUN_ARGS" in
        *--route*)
            if grep -qF "server $S_IP2 keeps its route outside the tunnel" "$W/tun-$MODE.log"; then
                echo "run-xray: server $S_IP2 keeps its route outside the tunnel"
            else echo "run-xray: FAIL — the download address did not keep its route"; rc=1; fi ;;
        esac
    fi
    if [ "$NODE" != v4 ]; then
        n4=$(grep -Fc "from $C_IP:" "$W/xray-access-$MODE.log" || true)
        n6=$(grep -Fc "from [$C_IP6]:" "$W/xray-access-$MODE.log" || true)
        echo "run-xray: Xray accepted from $C_IP: $n4, from [$C_IP6]: $n6"
        if [ "$NODE" = dual ]; then
            [ "$n4" -gt 0 ] && [ "$n6" -eq 0 ] || { echo "run-xray: FAIL — a dual-stack node must be reached over IPv4 only"; rc=1; }
        else
            [ "$n6" -gt 0 ] && [ "$n4" -eq 0 ] || { echo "run-xray: FAIL — the node must be reached over IPv6 only"; rc=1; }
        fi
    fi
    if command -v nft >/dev/null 2>&1; then
        syns=$(ip netns exec "$NSS" nft list chain inet grpccnt in 2>/dev/null | sed -n 's/.*packets \([0-9]*\) .*comment "syn".*/\1/p')
        [ -n "$syns" ] && echo "run-xray: TCP connections to the node in this case: $((syns - ${SYN0:-0}))"
    fi
    if [ "$NODE" != v4 ] || [ -n "$V6" ]; then
        case "$V6" in carry|second) v6_routes_clean target || rc=1 ;; *) v6_routes_clean || rc=1 ;; esac
    fi
    if [ "$MODE" = xhttp-tls-p384-cache ]; then
        nv=$(grep -c 'chain: .* verified, cached until' "$W/tun-$MODE.log" || true)
        nh=$(grep -c 'chain: .* from the cache' "$W/tun-$MODE.log" || true)
        echo "run-xray: chain verified $nv, from the cache $nh"
        [ "$nv" -eq 1 ] || { echo "run-xray: FAIL — the chain was verified $nv times, not once"; rc=1; }
        [ "$nh" -ge 1 ] || { echo "run-xray: FAIL — no handshake took the chain from the cache"; rc=1; }
    fi
    kill "$SPID" 2>/dev/null || true
    sleep 0.5
    ip netns exec "$NSC" ip link delete vl 2>/dev/null || true
    kill "$XPID" 2>/dev/null || true
    sleep 0.5
    if [ "$rc" -ne 0 ]; then FAIL=1; echo "run-xray: case $MODE — FAIL"; else echo "run-xray: case $MODE — ok"; fi
done

[ "$FAIL" -eq 0 ] || { echo "run-xray: FAILED"; exit 1; }
[ -z "$SKIPPED" ] || { echo "run-xray: SKIPPED, not passed:$SKIPPED"; exit 2; }
echo "run-xray: all checks passed"
