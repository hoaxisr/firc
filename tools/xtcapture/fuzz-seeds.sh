#!/bin/sh
set -eu
[ $# -eq 2 ] || { echo "usage: fuzz-seeds.sh FIXTURE_DIR SEED_DIR" >&2; exit 2; }
FX=$1
OUT=$2
mkdir -p "$OUT"
for f in "$FX"/*.replace.bin; do
    base=$(basename "$f" .replace.bin)
    case $base in *.v6) fam='\001' ;; *) fam='\000' ;; esac
    size=$(od -An -t u4 -j 40 -N 4 "$f" | tr -d ' ')
    [ "$size" -le 1500 ] || continue
    {
        printf "$fam"
        dd if="$f" bs=1 skip=32 count=4 2>/dev/null
        dd if="$f" bs=1 skip=44 count=40 2>/dev/null
        dd if="$f" bs=1 skip=36 count=8 2>/dev/null
        dd if="$f" bs=1 skip=96 2>/dev/null
    } > "$OUT/$base"
done
