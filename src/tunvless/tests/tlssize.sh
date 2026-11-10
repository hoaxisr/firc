#!/bin/sh
set -u
BIN="${1:-}"
RE="${2:-readelf}"
MAX="${TLS_MAX:-20480}"
[ -n "$BIN" ] || { echo "usage: tlssize.sh <binary> [readelf]"; exit 2; }
ph=$("$RE" -lW "$BIN" 2>&1) || { echo "tlssize: $RE cannot read $BIN"; exit 1; }
row=$(printf '%s\n' "$ph" | awk '$1 == "TLS" { print $6; exit }')
if [ -z "$row" ]; then
    syms=$("$RE" -sW "$BIN" 2>&1) || { echo "tlssize: $RE cannot read the symbols of $BIN"; exit 1; }
    n=$(printf '%s\n' "$syms" | awk '$4 == "TLS" { c++ } END { print c + 0 }')
    [ "$n" = 0 ] || { echo "tlssize: no TLS segment, but $n TLS symbols in $BIN"; exit 1; }
    row=0x0
fi
case "$row" in 0x*) ;; *) echo "tlssize: unreadable MemSiz '$row'"; exit 1 ;; esac
mem=$(printf '%d' "$row" 2>/dev/null) || { echo "tlssize: unreadable MemSiz '$row'"; exit 1; }
echo "PT_TLS memsz $mem (max $MAX)"
[ "$mem" -le "$MAX" ]
