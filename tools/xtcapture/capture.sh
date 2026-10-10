#!/bin/sh
set -eu
usage() { echo "usage: capture.sh [--dry] SBIN_DIR FIXTURE_DIR OUT_DIR v4|v6" >&2; exit 2; }

only() {
    [ $# -eq 1 ] && [ -f "$1" ] || { echo "want exactly one capture, got: $*" >&2; return 1; }
    printf '%s\n' "$1"
}

tools() {
    case $FAM in v4) R=iptables-restore S=iptables-save ;; v6) R=ip6tables-restore S=ip6tables-save ;; *) usage ;; esac
}

keep() {
    rep=$(only "$T"/*-replace.bin) || { rm -rf "$T"; exit 1; }
    cnt=$(only "$T"/*-counters.bin) || { rm -rf "$T"; exit 1; }
    cp "$rep" "$OUT/$NAME.$FAM.replace.bin"
    cp "$cnt" "$OUT/$NAME.$FAM.counters.bin"
}

if [ "${1:-}" = --one ]; then
    shift
    SBIN=$1 FX=$2 OUT=$3 FAM=$4 SHIM=$5 XTDUMP=$6 NAME=$7
    shift 7
    tools
    for base in "$@"; do "$SBIN/$R" --noflush < "$FX/$base.$FAM.rules"; done
    "$XTDUMP" "$FAM" nat "$OUT/$NAME.$FAM.seed.bin" > /dev/null
    T=$(mktemp -d)
    XTCAPTURE_DIR=$T LD_PRELOAD=$SHIM "$SBIN/$R" --noflush < "$FX/$NAME.$FAM.rules"
    keep
    "$SBIN/$S" -t nat | grep -v '^#' > "$OUT/$NAME.$FAM.save.txt"
    rm -rf "$T"
    exit 0
fi

if [ "${1:-}" = --one-dry ]; then
    shift
    SBIN=$1 FX=$2 OUT=$3 FAM=$4 SHIM=$5 NAME=$6
    tools
    SEED=$FX/$NAME.$FAM.seed.bin
    [ -s "$SEED" ] || { echo "no $SEED" >&2; exit 1; }
    T=$(mktemp -d)
    XTC_DRY=1 XTC_SEED=$SEED XTCAPTURE_DIR=$T LD_PRELOAD=$SHIM "$SBIN/$S" -t nat > /dev/null
    [ -f "$T/dry-answered" ] || { echo "$SBIN/$S did not load $SHIM: refusing to run $R" >&2; rm -rf "$T"; exit 1; }
    rm -f "$T/dry-answered"
    XTC_DRY=1 XTC_SEED=$SEED XTCAPTURE_DIR=$T LD_PRELOAD=$SHIM "$SBIN/$R" --noflush < "$FX/$NAME.$FAM.rules"
    keep
    XTC_DRY=1 XTC_SEED=$OUT/$NAME.$FAM.replace.bin LD_PRELOAD=$SHIM "$SBIN/$S" -t nat | grep -v '^#' > "$OUT/$NAME.$FAM.save.txt"
    rm -rf "$T"
    exit 0
fi

DRY=0
if [ "${1:-}" = --dry ]; then DRY=1; shift; fi
[ $# -eq 4 ] || usage
SBIN=$(cd "$1" && pwd)
FX=$(cd "$2" && pwd)
mkdir -p "$3"
OUT=$(cd "$3" && pwd)
FAM=$4
tools
HERE=$(cd "$(dirname "$0")" && pwd)
SELF=$HERE/$(basename "$0")
SHIM=${XTCAPTURE_SHIM:-$HERE/shim.so}
XTDUMP=${XTCAPTURE_XTDUMP:-$(dirname "$SHIM")/xtdump}
[ -f "$SHIM" ] || { echo "no $SHIM: run build-tools.sh first" >&2; exit 1; }
[ "$DRY" = 1 ] || [ -x "$XTDUMP" ] || { echo "no $XTDUMP: run build-tools.sh first" >&2; exit 1; }

while read -r name bases; do
    [ -n "$name" ] || continue
    if [ "$DRY" = 1 ]; then
        sh "$SELF" --one-dry "$SBIN" "$FX" "$OUT" "$FAM" "$SHIM" "$name"
    elif [ "$(id -u)" = 0 ]; then
        unshare -mn sh -c 'mount -t tmpfs tmpfs /run && exec sh "$@"' sh "$SELF" --one "$SBIN" "$FX" "$OUT" "$FAM" "$SHIM" "$XTDUMP" "$name" $bases
    else
        unshare -Urmn sh -c 'mount -t tmpfs tmpfs /run && exec sh "$@"' sh "$SELF" --one "$SBIN" "$FX" "$OUT" "$FAM" "$SHIM" "$XTDUMP" "$name" $bases
    fi
    echo "captured $name.$FAM"
done < "$FX/FIXTURES"
