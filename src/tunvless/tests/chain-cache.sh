#!/bin/sh
set -u
skip() { echo "chain-cache: $1 — skipped"; exit 0; }
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || skip "no binary $BIN (make)"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"; export TUNVLESS="$BIN"
HERE="$(cd "$(dirname "$0")" && pwd)"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
for t in ip python3 nsenter unshare openssl awk sha256sum date; do command -v $t >/dev/null 2>&1 || skip "no $t"; done
python3 -c 'import ssl' 2>/dev/null || skip "python3 has no ssl"
if [ "${CHAIN_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "needs root"
    unshare -nm true 2>/dev/null || skip "unshare -nm unavailable"
    CHAIN_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "cannot mount a private /sys"
ip link set lo up
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
DST=203.0.113.7
tmp="$(mktemp -d)"
CPID="" NODE="" TUN="" LOG=""
cleanup() {
    exec 8>&- 2>/dev/null
    kill $NODE $TUN $CPID 2>/dev/null
    if [ "$fail" != 0 ] && [ -n "$LOG" ]; then echo "--- tunnel (tail)"; tail -n 15 "$LOG" 2>/dev/null; fi
    if [ "${CHAIN_KEEP:-}" = 1 ]; then echo "work dir: $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

unshare -n sleep 1800 & CPID=$!
sleep 0.3
C() { nsenter -t "$CPID" -n "$@"; }
ip link add p0 type veth peer name c0
ip link set c0 netns "$CPID"
ip addr add 10.77.1.1/24 dev p0
ip link set p0 up
C ip link set lo up
C ip addr add 10.77.1.2/24 dev c0
C ip link set c0 up
C ip route add default via 10.77.1.1
ip addr add 10.77.0.1/32 dev lo

die() { echo "FAIL $1"; echo "chain-cache: $pass ok, $((fail + 1)) fail"; fail=$((fail + 1)); exit 1; }
q() { "$@" >"$tmp/openssl.err" 2>&1 || { cat "$tmp/openssl.err"; die "openssl: $*"; }; }
SER=100
printf '%s\n' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign' > "$tmp/ca.ext"
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:node.test' > "$tmp/leaf.ext"
mkdir "$tmp/ca"
: > "$tmp/ca/index.txt"
echo 1000 > "$tmp/ca/serial"
printf '%s\n' '[ca]' 'default_ca=d' '[d]' "dir=$tmp/ca" "database=$tmp/ca/index.txt" "new_certs_dir=$tmp/ca" \
    "serial=$tmp/ca/serial" 'default_md=sha384' 'policy=pol' 'copy_extensions=none' 'unique_subject=no' \
    '[pol]' 'commonName=supplied' > "$tmp/ca.cnf"
root() {
    q openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -days 2 -sha384 \
        -keyout "$tmp/$1.key" -out "$tmp/$1.pem" -subj "/CN=chain $1" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
}
inter() {
    SER=$((SER + 1))
    q openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -keyout "$tmp/$1.key" \
        -out "$tmp/$1.csr" -subj "/CN=chain $1"
    q openssl x509 -req -in "$tmp/$1.csr" -CA "$tmp/$2.pem" -CAkey "$tmp/$2.key" -set_serial $SER -sha384 -days 2 \
        -extfile "$tmp/ca.ext" -out "$tmp/$1.pem"
}
csr() {
    q openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$tmp/$1.key" \
        -out "$tmp/$1.csr" -subj "/CN=node.test"
}
chain() { [ -s "$tmp/$1.pem" ] || die "openssl did not issue $1"; cat "$tmp/$1.pem" "$tmp/$2.pem" > "$tmp/$1.chain"; }
leaf() {
    SER=$((SER + 1))
    csr "$1"
    q openssl x509 -req -in "$tmp/$1.csr" -CA "$tmp/$2.pem" -CAkey "$tmp/$2.key" -set_serial $SER -sha384 -days 2 \
        -extfile "$tmp/leaf.ext" -out "$tmp/$1.pem"
    chain "$1" "$2"
}
leaf_until() {
    csr "$1"
    q openssl ca -batch -config "$tmp/ca.cnf" -cert "$tmp/$2.pem" -keyfile "$tmp/$2.key" -in "$tmp/$1.csr" \
        -out "$tmp/$1.pem" -startdate "$(date -u +%Y%m%d%H%M%SZ)" -enddate "$3" -extfile "$tmp/leaf.ext" -notext
    chain "$1" "$2"
}
root rootA; inter interA rootA; root rootB; inter interB rootB
leaf leafA interA
leaf leaf2 interA
leaf leafB interB
cat "$tmp/leafA.chain" "$tmp/rootA.pem" > "$tmp/leafA.full"

node_start() {
    python3 "$HERE/sigpipe-node.py" --bind 10.77.0.1 --port 10443 --uuid "$UUID" --tls "$tmp/$1" "$tmp/$2.key" \
        >"$tmp/node.out" 2>"$tmp/node.err" & NODE=$!
    wait_for 'grep -q ready "$tmp/node.out"' 10
}
node_stop() { kill $NODE 2>/dev/null; wait $NODE 2>/dev/null; NODE=""; : > "$tmp/node.out"; }
LINK="vless://$UUID@10.77.0.1:10443?encryption=none&type=tcp&security=tls&sni=node.test"
tun_start() {
    LOG="$tmp/t-$1.log"
    env SSL_CERT_FILE="$tmp/$2.pem" STEER_CHAIN_TRACE=1 "$BIN" "$LINK#$1" -d vlt -a 198.51.100.1/32 -r $DST/32 \
        >"$LOG" 2>&1 & TUN=$!
    wait_for 'ip route show $DST/32 | grep -q vlt' 20
}
tun_stop() { kill $TUN 2>/dev/null; wait $TUN 2>/dev/null; TUN=""; ip link del vlt 2>/dev/null; }
T() { grep -c "chain: node.test $1" "$LOG"; }
ping_() { C timeout 20 python3 "$HERE/sigpipe-client.py" $DST --ping >/dev/null 2>&1; }
pings() { n=0; for _ in $(seq "$1"); do ping_ && n=$((n + 1)); done; echo "$n"; }

# catches: no cache (a verification per handshake) or a cache that never hits
node_start leafA.chain leafA
tun_start real rootA
check "real chain: 10 pings pass" 10 "$(pings 10)"
check "real chain: verified once" 1 "$(T 'verified, cached')"
check "real chain: at least 9 hits" 1 "$([ "$(T 'from the cache')" -ge 9 ] && echo 1 || echo 0)"
check "real chain: nothing refused" 0 "$(T refused)"
tun_stop; node_stop

# catches: a changed certificate on the same host taken from the cache, or another root accepted
node_start leafA.chain leafA
tun_start rotate rootA
check "rotate: 3 pings pass" 3 "$(pings 3)"
node_stop; node_start leaf2.chain leaf2; sleep 3
check "rotate: 3 pings pass with a new leaf" 3 "$(pings 3)"
check "rotate: the new leaf verified" 2 "$(T 'verified, cached')"
node_stop; node_start leafB.chain leafB; sleep 3
check "rotate: a leaf under another root fails" 0 "$(pings 1)"
check "rotate: refused for the chain" 1 "$([ "$(grep -c 'does not chain to a root' "$LOG")" -ge 1 ] && echo 1 || echo 0)"
check "rotate: refused in the trace" 1 "$([ "$(T refused)" -ge 1 ] && echo 1 || echo 0)"
check "rotate: still two verified" 2 "$(T 'verified, cached')"
tun_stop; node_stop

# catches: a cached chain that keeps passing after its leaf expired
na=$(( $(date -u +%s) + 40 ))
leaf_until leafX interA "$(date -u -d "@$na" +%Y%m%d%H%M%SZ)"
openssl x509 -in "$tmp/leafX.pem" -noout -checkend 30 >/dev/null 2>&1 || die "leafX expires too early"
openssl x509 -in "$tmp/leafX.pem" -noout -checkend 45 >/dev/null 2>&1 && die "leafX does not expire within 45 s"
node_start leafX.chain leafX
tun_start expired rootA
check "expired: 2 pings pass" 2 "$(pings 2)"
check "expired: verified once" 1 "$(T 'verified, cached')"
check "expired: a hit" 1 "$([ "$(T 'from the cache')" -ge 1 ] && echo 1 || echo 0)"
wait_for '[ "$(date -u +%s)" -gt "$na" ]' 60
hits=$(T 'from the cache')
sleep 3
check "expired: a ping after notAfter fails" 0 "$(pings 1)"
check "expired: refused for the chain" 1 "$([ "$(grep -c 'does not chain to a root' "$LOG")" -ge 1 ] && echo 1 || echo 0)"
check "expired: refused in the trace" 1 "$([ "$(T refused)" -ge 1 ] && echo 1 || echo 0)"
check "expired: no hit after notAfter" "$hits" "$(T 'from the cache')"
tun_stop; node_stop

# catches: pcs or the anchor kind left out of the key, so a link without the pin hits the pinned entry
PCS=$(openssl x509 -in "$tmp/rootA.pem" -outform DER | sha256sum | cut -d' ' -f1)
node_start leafA.full leafA
LOG="$tmp/t-pin.log"
mkfifo "$tmp/in"
env SSL_CERT_FILE="$tmp/rootB.pem" STEER_CHAIN_TRACE=1 "$BIN" --control -d vlt -a 198.51.100.1/32 -r $DST/32 \
    <"$tmp/in" >"$tmp/ev" 2>"$LOG" & TUN=$!
exec 8>"$tmp/in"
printf '%s\n\n' "$LINK&pcs=$PCS#pin" >&8
wait_for 'ip route show $DST/32 | grep -q vlt' 20
check "pin: 2 pings pass with pcs" 2 "$(pings 2)"
check "pin: verified once" 1 "$(T 'verified, cached')"
printf 'nodes\n%s\n\n' "$LINK#nopin" >&8
wait_for '[ "$(grep -c "\"type\":\"nodes\"" "$tmp/ev")" -ge 1 ]' 10
sleep 3
check "pin: the same chain without pcs fails" 0 "$(pings 1)"
check "pin: refused in the trace" 1 "$([ "$(T refused)" -ge 1 ] && echo 1 || echo 0)"
printf 'nodes\n%s\n\n' "$LINK&pcs=$PCS#pin" >&8
wait_for '[ "$(grep -c "\"type\":\"nodes\"" "$tmp/ev")" -ge 2 ]' 10
check "pin: pcs back, a ping passes" 1 "$(n=0; for _ in 1 2 3 4 5 6; do ping_ && { n=1; break; }; sleep 2; done; echo $n)"
exec 8>&-
tun_stop; node_stop

echo "chain-cache: $pass ok, $fail fail"
[ "$fail" = 0 ]
