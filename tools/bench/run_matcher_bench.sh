#!/bin/sh
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BACKEND="$REPO/src/backend-c"
BIN="${BIN:-$REPO/.build/bench/matcherbench}"
SIZES="${SIZES:-5000 10000 20000 40000 80000}"
CC="${CC:-cc}"

mkdir -p "$(dirname "$BIN")" || exit 1
$CC -O2 -I"$BACKEND/include" -I"$BACKEND/src" -o "$BIN" \
    "$REPO/tools/bench/matcherbench.c" \
    "$BACKEND/src/rules/match.c" \
    "$BACKEND/src/rules/wildcard.c" \
    "$BACKEND/src/util/err.c" \
    "$BACKEND/src/logging/log.c" \
    $(pkg-config --cflags --libs libpcre2-8 2>/dev/null || echo -lpcre2-8) || exit 1

echo "# $(uname -sm), $($CC --version | head -1)"
for borrow in 0 1; do
    for shape in 0 1; do
        for n in $SIZES; do "$BIN" "$n" "$shape" "$borrow"; done
    done
done
