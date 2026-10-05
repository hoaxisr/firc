#!/bin/sh
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BACKEND="$REPO/src/backend-c"
BIN="${BIN:-$REPO/.build/bench/nflog_family}"
GROUP="${GROUP:-42}"
SECONDS_TO_WAIT="${SECONDS_TO_WAIT:-10}"
CC="${CC:-cc}"

mkdir -p "$(dirname "$BIN")" || exit 1

$CC -O1 -g -I"$BACKEND/include" -I"$BACKEND/src" \
    -o "$BIN" \
    "$REPO/tools/bench/nflog_family.c" \
    "$BACKEND/src/tap/nflog_sock.c" \
    "$BACKEND/src/tap/nflog.c" \
    "$BACKEND/src/netlink/nlattr_iter.c" \
    "$BACKEND/src/util/err.c" \
    "$BACKEND/src/logging/log.c" || exit 1

unshare -Urmn sh -c "
    set -e
    ip link set lo up
    iptables  -t mangle -A OUTPUT -p icmp   -j NFLOG --nflog-group $GROUP --nflog-threshold 1
    ip6tables -t mangle -A OUTPUT -p icmpv6 -j NFLOG --nflog-group $GROUP --nflog-threshold 1
    '$BIN' $GROUP $SECONDS_TO_WAIT &
    reader=\$!
    sleep 1
    ping -c 3 -i 0.2 -W 1 127.0.0.1 > /dev/null 2>&1 || true
    ping -6 -c 3 -i 0.2 -W 1 ::1     > /dev/null 2>&1 || true
    wait \$reader
"
rc=$?
case $rc in
    0) echo "one group carried both families" ;;
    1) echo "one family only -- see the counts above" ;;
    2) echo "nothing arrived: the rules or the bind did not take" ;;
    *) echo "the reader could not start (rc=$rc)" ;;
esac
exit $rc
