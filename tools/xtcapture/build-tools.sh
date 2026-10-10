#!/bin/sh
set -eu
[ $# -eq 2 ] || { echo "usage: build-tools.sh CC OUT_DIR" >&2; exit 2; }
CC=$1
OUT=$2
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
"$CC" -O2 -shared -fPIC -o "$OUT/shim.so" "$HERE/shim.c" -ldl
"$CC" -O2 -o "$OUT/lockwatch" "$HERE/lockwatch.c"
"$CC" -O2 -o "$OUT/xtdump" "$HERE/xtdump.c"
