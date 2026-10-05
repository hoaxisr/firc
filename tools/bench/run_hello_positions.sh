#!/bin/sh
set -u

WAN="${WAN:-$(ip route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1); exit }')}"
DURATION="${DURATION:-2700}"
POOL="${POOL:-198.18.0.0/15}"
MAXPOS="${MAXPOS:-12}"
OUT="${OUT:-/tmp/hello-positions.txt}"
CHAIN=FIRCPROBE
IPT="${IPT:-iptables}"
WORK_ACC="${WORK_ACC:-/tmp/hello-positions.acc}"
WORK_CUR="$WORK_ACC.cur"

[ -n "$WAN" ] || { echo "no default route: set WAN=<iface>" >&2; exit 1; }

# The last position is an open-ended bucket.
rule_args() { # $1 = hex, $2 = connbytes spec
    echo "-o $WAN -p tcp --dport 443 --tcp-flags SYN,ACK ACK ! -d $POOL" \
         "-m length --length 100:" \
         "-m connbytes --connbytes $2 --connbytes-dir original --connbytes-mode packets" \
         "-m string --algo bm --hex-string $1 --from 40 --to 84"
}

install_chain() {
    $IPT -t mangle -N "$CHAIN" 2>/dev/null
    $IPT -t mangle -F "$CHAIN"
    for hex in '|160301|' '|160303|'; do
        p=1
        while [ "$p" -lt "$MAXPOS" ]; do
            # shellcheck disable=SC2046
            $IPT -t mangle -A "$CHAIN" $(rule_args "$hex" "$p:$p") || return 1
            p=$((p + 1))
        done
        # shellcheck disable=SC2046
        $IPT -t mangle -A "$CHAIN" $(rule_args "$hex" "$MAXPOS:") || return 1
    done
    $IPT -t mangle -C FORWARD -j "$CHAIN" 2>/dev/null ||
        $IPT -t mangle -I FORWARD 1 -j "$CHAIN"
}

remove_chain() {
    while $IPT -t mangle -D FORWARD -j "$CHAIN" 2>/dev/null; do :; done
    $IPT -t mangle -F "$CHAIN" 2>/dev/null
    $IPT -t mangle -X "$CHAIN" 2>/dev/null
    return 0
}

trap 'remove_chain; exit 130' INT TERM

remove_chain
install_chain || { echo "could not install the counting chain (xt_string? xt_connbytes?)" >&2; remove_chain; exit 1; }

start=$(cut -d' ' -f1 /proc/uptime)
lost=0
checks=0
: > "$WORK_ACC"

# A firmware rewrite drops the chain and its counters, so bank the last reading before reinstalling.
snapshot() {
    $IPT -t mangle -L "$CHAIN" -v -n -x 2>/dev/null | awk 'NR > 2 && NF > 0 { print $1 }'
}

bank() { # adds $1 (a snapshot) to the accumulator
    printf '%s\n' "$1" > "$WORK_CUR"
    awk 'NR == FNR { a[FNR] = $1; n = FNR; next }
         { b[FNR] = $1; m = FNR }
         END { k = (n > m ? n : m); for (i = 1; i <= k; i++) print (a[i] + 0) + (b[i] + 0) }' \
        "$WORK_ACC" "$WORK_CUR" > "$WORK_ACC.new" 2>/dev/null
    mv "$WORK_ACC.new" "$WORK_ACC"
}

while :; do
    sleep 60
    checks=$((checks + 1))
    snap=$(snapshot)
    if ! $IPT -t mangle -C FORWARD -j "$CHAIN" 2>/dev/null; then
        lost=$((lost + 1))
        bank "$snap"
        install_chain
    fi
    now=$(cut -d' ' -f1 /proc/uptime)
    [ "$(awk -v a="$start" -v b="$now" -v d="$DURATION" 'BEGIN { print (b - a >= d) }')" = 1 ] && break
done
end=$(cut -d' ' -f1 /proc/uptime)
bank "$(snapshot)"

counts=$(cat "$WORK_ACC")

{
    echo "# run_hello_positions.sh -- $(date)"
    echo "# $(uname -srm), wan=$WAN, pool=$POOL"
    echo "# $(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.0f", (b - a) / 60 }') minutes, chain checked $checks times, missing at $lost of them"
    echo "#"
    printf '%-26s' 'position:'
    p=1
    while [ "$p" -lt "$MAXPOS" ]; do printf '%5s' "$p"; p=$((p + 1)); done
    printf '%7s\n' "$MAXPOS+"
    echo "$counts" | awk -v m="$MAXPOS" '
        { c[NR] = $1 }
        END {
            for (r = 0; r < 2; r++) {
                printf "%-26s", (r == 0 ? "ClientHello |160301|:" : "later handshake |160303|:")
                total = 0
                for (i = 1; i <= m; i++) {
                    v = c[r * m + i] + 0
                    total += v
                    printf (i < m ? "%5d" : "%7d"), v
                }
                printf "   total %d\n", total
            }
        }'
} | tee "$OUT"

remove_chain
echo "-> $OUT"
