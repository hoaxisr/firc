#!/bin/sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BE=$(cd "$HERE/../.." && pwd)
SAN=address,undefined,float-cast-overflow

if [ "${FIRC_LINK_E2E_INNER:-}" != 1 ]; then
    make -s -C "$BE" BUILD=sanitize OPT="-O1 -g -fsanitize=$SAN -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=$SAN" build/sanitize/fircd >/dev/null || exit 1
    T=$(mktemp -d)
    mkdir -p "$T/up" "$T/work"
    FIRC_LINK_E2E_INNER=1 unshare -Urmn sh -c "mount -t tmpfs tmpfs /run && \
        mount -t overlay overlay -o lowerdir=/etc,upperdir=$T/up,workdir=$T/work /etc && \
        exec sh '$HERE/linkaddr.sh'"
    rc=$?
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
    exit $rc
fi

FIRCD=$BE/build/sanitize/fircd
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
W=$(mktemp -d)
export FIRC_TUNNELS_CACHE_DIR="$W/cache" FIRC_UPDATE_DIR="$W/update" FIRC_HWID_PATH="$W/hwid"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${FP:-}" ] && kill "$FP" 2>/dev/null && wait "$FP" 2>/dev/null
    if [ "$fail" != 0 ]; then echo "--- fircd log (tail)"; tail -n 60 "$W/fircd.log" 2>/dev/null; fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

rules() { iptables-legacy-save -t nat 2>/dev/null | grep -c -- "-A FIRC_DNSOR -d $1/32"; }
wait_rules() {
    i=0
    while [ "$i" -lt 100 ]; do
        [ "$(rules "$1")" = "$2" ] && break
        i=$((i + 1))
        sleep 0.1
    done
    rules "$1"
}

ip link set lo up
ip link add lan0 type dummy
ip addr add 10.70.0.1/24 dev lan0
ip link set lan0 up
ip link add late0 type dummy
ip link set late0 up

mkdir -p /etc/firc
cat > /etc/firc/firc.conf <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: false
  dnsProxy:
    host: {address: "10.70.0.1", port: 13598}
    upstream: {address: 127.0.0.1, port: 15353}
  netfilter:
    iptables: {chainPrefix: FIRC_}
  link: [lan0, late0, gone0]
EOF
cat > /etc/firc/groups.yaml <<EOF
configVersion: 0.7.0
groups: []
EOF
"$FIRCD" --config /etc/firc/firc.conf > "$W/fircd.log" 2>&1 &
FP=$!

check "the listed LAN is redirected though gone0 does not exist" 2 "$(wait_rules 10.70.0.1 2)"
kill -0 "$FP" 2>/dev/null
check "fircd runs" 0 $?
check "the missing interface is named once" 1 "$(grep -c 'link gone0 has no address' "$W/fircd.log")"
check "an interface without an address has no rule" 0 "$(rules 10.71.0.1)"

ip addr add 10.71.0.1/24 dev late0
check "an address set after start is redirected" 2 "$(wait_rules 10.71.0.1 2)"

ip addr add 10.72.0.1/24 dev late0
ip addr del 10.71.0.1/24 dev late0
check "a new address is redirected" 2 "$(wait_rules 10.72.0.1 2)"
check "the old address is not" 0 "$(wait_rules 10.71.0.1 0)"

ip link del late0
check "a deleted interface leaves no rule" 0 "$(wait_rules 10.72.0.1 0)"
check "a deleted interface is named once" 1 "$(grep -c 'link late0 has no address' "$W/fircd.log")"
check "the other LAN keeps its rules" 2 "$(rules 10.70.0.1)"

kill "$FP"
wait "$FP"
check "fircd stops cleanly" 0 $?
FP=

echo "pass=$pass fail=$fail"
[ "$fail" = 0 ]
