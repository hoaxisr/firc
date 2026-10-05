#!/bin/sh
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BACKEND="${BACKEND:-$REPO/src/backend-c}"  # another tree's, to run the same bench against it
BIN="${BIN:-$REPO/.build/bench/devselbench}"
SIZES="${SIZES:-8 50 128 250 1000}"
LAYOUTS="${LAYOUTS:-spread lan24}"
ITERS="${ITERS:-2000000}"
CC="${CC:-cc}"

mkdir -p "$(dirname "$BIN")" || exit 1
$CC -O2 -std=c11 -D_GNU_SOURCE -I"$BACKEND/include" -I"$BACKEND/src" -o "$BIN" \
    "$REPO/tools/bench/devselbench.c" \
    "$BACKEND/src/interfaces/keenetic_policy.c" \
    "$BACKEND/src/interfaces/keenetic_rci.c" \
    "$BACKEND/src/rules/devices.c" \
    "$BACKEND/src/fakeip/addr.c" \
    "$BACKEND/src/util/err.c" \
    "$BACKEND/src/logging/log.c" \
    "$BACKEND/src/logging/events.c" \
    "$BACKEND/src/util/rand.c" \
    $(pkg-config --cflags --libs libcjson libcurl 2>/dev/null || echo -lcjson -lcurl) -lpthread || exit 1

echo "# $(uname -sm), $($CC --version | head -1)"
for layout in $LAYOUTS; do
    for n in $SIZES; do "$BIN" "$n" "$ITERS" "$layout" || exit 1; done
done
