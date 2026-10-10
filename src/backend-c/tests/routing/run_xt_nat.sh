#!/bin/sh
set -eu

HELPER=${FIRC_ROUTECHECK:?set FIRC_ROUTECHECK to the firc-routecheck binary}
FAM=${1:?usage: run_xt_nat.sh v4|v6}

if [ -z "${FIRC_ROUTING_INSIDE:-}" ]; then
    if [ "$(id -u)" = 0 ]; then
        exec env FIRC_ROUTING_INSIDE=1 unshare -mn sh "$0" "$@"
    fi
    exec env FIRC_ROUTING_INSIDE=1 unshare -Urmn sh "$0" "$@"
fi

fail() {
    echo "FAIL ($FAM): $*" >&2
    exit 1
}

case $FAM in
v4)
    SAVE=${IPT_LEGACY_SAVE:-iptables-legacy-save}
    PRE='-A PREROUTING -d 198.18.0.0/15 -j FIRC_DNAT'
    D1='-A FIRC_DNAT -d 198.18.0.1/32 -j DNAT --to-destination 9.9.9.9'
    D2='-A FIRC_DNAT -d 198.18.0.2/32 -j DNAT --to-destination 9.9.9.8'
    NAME=ipv4
    ;;
v6)
    SAVE=${IP6T_LEGACY_SAVE:-ip6tables-legacy-save}
    PRE='-A PREROUTING -d fd37:9a00::/48 -j FIRC_DNAT'
    D1='-A FIRC_DNAT -d fd37:9a00::1/128 -j DNAT --to-destination 2001:db8::9'
    D2='-A FIRC_DNAT -d fd37:9a00::2/128 -j DNAT --to-destination 2001:db8::8'
    NAME=ipv6
    ;;
*) fail "no family $FAM" ;;
esac

command -v "$SAVE" >/dev/null || fail "$SAVE is not installed"
mount -t tmpfs tmpfs /run
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

"$HELPER" xtnat write "$FAM" 2>"$T/w1" || fail "the first write failed: $(cat "$T/w1")"
"$HELPER" xtdump nat "$FAM" > "$T/nat" || fail "the table cannot be read back"
for want in "$PRE" '-A POSTROUTING -j FIRC_g1' "$D1" "$D2" \
    '-A FIRC_g1 -o tun0 -m mark --mark 0x10000/0xff0000 -j MASQUERADE'; do
    grep -qxF -- "$want" "$T/nat" || fail "not in the kernel: $want"
done
"$SAVE" -t nat > "$T/save" || fail "$SAVE cannot read the table firc wrote"
grep -qxF ':FIRC_DNAT - [0:0]' "$T/save" || fail "$SAVE does not see FIRC_DNAT"
grep -qxF ':FIRC_g1 - [0:0]' "$T/save" || fail "$SAVE does not see FIRC_g1"

"$HELPER" xtnat write "$FAM" 2>"$T/w2" || fail "the second write failed: $(cat "$T/w2")"
grep -q "x_tables $NAME nat: unchanged" "$T/w2" || fail "an unchanged table was written again"

python3 -c 'import socket, sys, time; s = socket.socket(socket.AF_UNIX); s.bind("\0xtables"); open(sys.argv[1], "w").close(); time.sleep(3)' "$T/held" &
HOLDER=$!
n=0
until [ -e "$T/held" ]; do
    n=$((n + 1))
    [ "$n" -le 200 ] || fail "the lock holder never bound @xtables"
    sleep 0.01
done
start=$(date +%s%N)
rc=0
"$HELPER" xtnat sweep "$FAM" 2>/dev/null || rc=$?
waited=$(( ($(date +%s%N) - start) / 1000000 ))
kill "$HOLDER" 2>/dev/null || true
wait "$HOLDER" 2>/dev/null || true
[ "$rc" = 4 ] || fail "a held xtables lock answered $rc, not 4 (again)"
[ "$waited" -ge 200 ] && [ "$waited" -lt 1500 ] || fail "waited $waited ms for the xtables lock"
"$HELPER" xtdump nat "$FAM" | grep -qxF -- "$D1" || fail "a sweep that lost the lock wrote anyway"

"$HELPER" xtnat sweep "$FAM" 2>"$T/s" || fail "the sweep failed: $(cat "$T/s")"
"$HELPER" xtdump nat "$FAM" > "$T/swept" || fail "the swept table cannot be read back"
if grep -q FIRC_ "$T/swept"; then fail "the sweep left a chain or a jump of ours"; fi
if "$SAVE" -t nat | grep -q FIRC_; then fail "$SAVE still sees a chain of ours"; fi

"$HELPER" xtnat probe "$FAM" || fail "this kernel lacks a nat extension firc writes"
echo "x_tables nat $FAM: OK"
