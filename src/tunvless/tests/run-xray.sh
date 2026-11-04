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
           xhttp-neg-obfs xhttp-neg-sess xhttp-neg-data
           v6-carry-tcp v6-carry-xhttp v6-second v6-none v6-noroute
           node6-tcp node6-xhttp node6-name node6-dual
           xhttp-dl-reality-auto xhttp-dl-packet-tls xhttp-dl-none xhttp-dl-extra xhttp-dl-post-main
           xhttp-dl-name xhttp-dl-route xhttp-dl-neg-path xhttp-dl-neg-sess
           xmux-count-one xmux-count-packet xmux-count-up xmux-concurrency xmux-requests xmux-reuse
           xmux-kill xmux-ping xmux-up-parallel xmux-dl xmux-kernel-inbound xmux-stall
           h2-wire-reality h2-wire-tls h2-credit h2-speed"
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

# The Reality cover site: any TLS 1.3 server with h2 in ALPN.
bg_in "$NSS" "$W/mask.log" openssl s_server -accept "$S_IP:8443" -cert "$W/mask.pem" -key "$W/mask.key" \
    -tls1_3 -alpn h2,http/1.1 -www -quiet
# The target, and the targets of the node probe.
bg_in "$NSS" "$W/target.log" python3 tests/grpc-target.py "$TARGET" 8080
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
    BLK="{\"address\":\"$DH\",\"port\":$PORT,\"network\":\"xhttp\",$BS,\"xhttpSettings\":{\"path\":\"$BP\"${BX:+,$BX}}}"
    Q="type=xhttp&path=%2Fxp%2F${LM:+&mode=$LM}&extra=$(enc "{${MX:+$MX,}\"downloadSettings\":$BLK}")"
}
neg() { EXPECT=fail; XP="{\"path\":\"/xp/\",\"mode\":\"packet-up\",$1}"; Q="type=xhttp&path=%2Fxp%2F&mode=packet-up"; }
case_cfg() {
    SEC=reality; TUN_ARGS=""; EXPECT=ok; V6=""; NODE=v4; XMODE=""; XMUX=""; KEYLOG=""; LPORT=""
    DL=""; DH="$S_IP2"; BP=/xp/
    XP='{"path":"/xp/"}'
    case "$1" in
    grpc-gun|grpc-multi)
        m=${1#grpc-}; multi=false; [ "$m" = multi ] && multi=true
        NET="\"network\":\"grpc\",\"grpcSettings\":{\"serviceName\":\"$SVC\",\"multiMode\":$multi}"
        Q="type=grpc&serviceName=$SVC&mode=$m" ;;
    xhttp-auto)        Q="type=xhttp&path=%2Fxp%2F" ;;
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
    xmux-concurrency)        xm stream-one '{"maxConcurrency":4}' ;;
    xmux-requests)           xm stream-one '{"maxConnections":1,"hMaxRequestTimes":5}' ;;
    xmux-reuse)              xm stream-one '{"cMaxReuseTimes":3}' ;;
    xmux-kill|xmux-up-parallel) xm stream-one '{"maxConnections":1}' ;;
    xmux-ping)               SEC=none; xm stream-one '{"hKeepAlivePeriod":2}' ;;
    xmux-dl)                 dl reality stream-up "" "" ;;
    h2-wire-reality|h2-credit) xm stream-one ""; KEYLOG=1 ;;
    h2-wire-tls)             SEC=tls; TUN_ARGS="--ca $W/mask.pem"; xm packet-up ""; KEYLOG=1 ;;
    h2-speed)                xm stream-one "" ;;
    *) echo "run-xray: unknown case $1"; exit 2 ;;
    esac
    [ -z "$DL" ] || dl_cfg
    case "$1" in xhttp-*|xmux-*|h2-*|v6-carry-xhttp|node6-xhttp) NET="\"network\":\"xhttp\",\"xhttpSettings\":$XP" ;; esac
    KL=""; [ -z "$KEYLOG" ] || { KL=",\"masterKeyLog\":\"$W/keys.log\""; LPORT=18444; }
    if [ "$SEC" = none ]; then
        SECJ='"security":"none"'; LSEC="security=none"
    elif [ "$SEC" = reality ]; then
        SECJ="\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"dest\":\"$S_IP:8443\",\"xver\":0,\"serverNames\":[\"$MASK\"],\"privateKey\":\"$PRIV\",\"shortIds\":[\"$SID\"]$KL}"
        LSEC="security=reality&sni=$MASK&pbk=$PUB&sid=$SID&fp=chrome"
    else
        SECJ="\"security\":\"tls\",\"tlsSettings\":{\"alpn\":[\"h2\",\"http/1.1\"],\"certificates\":[{\"certificateFile\":\"$W/mask.pem\",\"keyFile\":\"$W/mask.key\"}]$KL}"
        LSEC="security=tls&sni=$MASK&alpn=h2&fp=chrome"
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
    ip netns exec "$NSC" "$1" $TUN_ARGS "$W/sub.txt" -d vl -n 0 --interval 3600 > "$W/tun-$MODE-$2.log" 2>&1 &
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
    tls)     CS="\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"$MASK\",\"alpn\":[\"h2\"],\"fingerprint\":\"chrome\",\"certificates\":[{\"certificateFile\":\"$W/mask.pem\",\"usage\":\"verify\"}]}" ;;
    *)       CS='"security":"none"' ;;
    esac
    XMJ=""; [ -z "$XMUX" ] || XMJ=",\"xmux\":$XMUX"
    cat > "$W/xc-$MODE.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":18080,"protocol":"dokodemo-door","settings":{"address":"$TARGET","port":8080,"network":"tcp"}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"$S_IP","port":${LPORT:-$PORT},"users":[{"id":"$UUID","encryption":"none"}]}]},
   "streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/xp/","mode":"$XMODE"$XMJ},$CS}}]}
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
        > "$W/tap-$MODE-$1.log" 2>&1 &
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
        echo "run-xray: $2 connection $n: $o; $f; blocks start $hb; first after the ACK $a"
        [ "$r" -eq 0 ] || { echo "run-xray: FAIL — $2 connection $n: h2tap check exit $r"; XR=1; }
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
h2_load() {
    case "$MODE" in
    h2-wire-reality) lrun "$1" --dur 3 --down 0 --up 0 --rate 1 ;;
    h2-wire-tls)     lrun "$1" --dur 3 --down 0 --up 0 --rate 1 && up200 ;;
    h2-credit)       lrun "$1" --dur 5 --down 1 --up 0 --rate 0 --report 5 ;;
    esac
}
h2_run() {
    tap_down; tap_up "$1" || return 1
    if [ "$1" = t ]; then tun_up "$BIN" t || return 1; else xc_up || return 1; fi
    h2_load "$1" || { echo "run-xray: FAIL — the load failed ($1)"; XR=1; }
    sleep 1
    tun_down; xc_down; sleep 0.5; tap_down
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
        xcount t 60 20 2; T="$CNT $(lres t 4)"; tun_down
        xc_up || return 1
        xcount x 60 20 2; X="$CNT $(lres x 4)"; xc_down
        set -- $T $X
        echo "run-xray: connections     least most distinct SYN   MB up"
        echo "run-xray:   tunvless      $1 $2 $3 $4   $5"
        echo "run-xray:   Xray client   $6 $7 $8 $9   ${10}"
        want "tunvless most at once against Xray's most" "$2" le "$7"
        want "tunvless least at once against Xray's least" "$1" le "$6" ;;
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
        rm -f "$W/kin"; mkfifo "$W/kin"; : > "$W/kev"
        ip netns exec "$NSC" "$BIN" $TUN_ARGS --control -d vl -A 1 --interval 3600 --tcp-port 3600 \
            --tcp-pool 198.18.0.0/15 < "$W/kin" > "$W/kev" 2> "$W/tun-$MODE-k.log" &
        SPID=$!; PIDS="$PIDS $SPID"
        exec 7> "$W/kin"
        cat "$W/sub.txt" >&7; echo >&7
        evwait '"ready"' || { echo "run-xray: FAIL — no ready event:"; tail -5 "$W/tun-$MODE-k.log"; exec 7>&-; return 1; }
        printf 'inbounds\n%s:1081 - - %s\n\n' "$C_IP" "$(cat "$W/sub.txt")" >&7
        printf 'map\n198.18.0.5 %s\n\n' "$TARGET" >&7
        evwait '"type":"inbound","port":1081,"state":"up"' || XR=1
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
        echo "run-xray: CPU time of tunvless while 20 flows are not read: $((c1 - c0)) ticks"
        want "VmRSS growth while 20 flows are not read, KiB (from $r0)" "$((mx - r0))" le 36864
        want "VmRSS growth while 20 flows are not read, KiB (from $r0)" "$((mx - r0))" ge 24576
        want "bytes the node sent meanwhile" "$((o1 - o0))" ge 33554432 ;;
    esac
    if grep -E "does not answer|answers again|did not open|refused the data" "$W"/tun-"$MODE"-*.log 2>/dev/null | head -3 | grep .; then
        echo "run-xray: FAIL — the pool declared the node dead, a flow did not open, or data was refused"; XR=1
    fi
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
    case "$MODE" in h2-*)
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
    INB1="\"port\":$PORT,\"protocol\":\"vless\",\"settings\":{\"clients\":[{\"id\":\"$UUID\"}],\"decryption\":\"none\"},\"streamSettings\":{$NET,$SECJ}"
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
{"log":{"loglevel":"warning","access":"$W/xray-access-$MODE.log"},
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
    probe() { ip netns exec "$NSC" "$BIN" --probe --timeout 5 $TUN_ARGS "$W/sub.txt" 2>&1 || true; }
    is_ok() { printf '%s' "$1" | awk -F '\t' '$3 == "ok" { f = 1 } END { exit !f }'; }

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
    case "$MODE" in xmux-*|h2-*)
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
    ip netns exec "$NSC" "$BIN" $TUN_ARGS "$W/sub.txt" -d vl -n 0 --interval 10 > "$W/tun-$MODE.log" 2>&1 &
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
