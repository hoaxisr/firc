#!/bin/sh
set -u

: "${CROSS_COMPILE:?CROSS_COMPILE names the toolchain prefix, e.g. mips-openwrt-linux-gnu-}"
: "${SYSROOT:?SYSROOT names the SDK target staging dir holding opt/include and opt/lib}"
QEMU=${QEMU:-qemu-mips-static}

case $CROSS_COMPILE in
*/*)
    PATH=$(dirname "$CROSS_COMPILE"):$PATH
    CROSS_COMPILE=$(basename "$CROSS_COMPILE")
    ;;
esac
export PATH
export STAGING_DIR="${STAGING_DIR:-$(dirname "$SYSROOT")}"

backend=$(cd "$(dirname "$0")/../../src/backend-c" && pwd) || exit 1
command -v "${CROSS_COMPILE}gcc" >/dev/null || { echo "no ${CROSS_COMPILE}gcc on PATH" >&2; exit 1; }
command -v "$QEMU" >/dev/null || { echo "no $QEMU on PATH" >&2; exit 1; }

loader=$("${CROSS_COMPILE}gcc" -print-file-name=ld.so.1)
[ -f "$loader" ] || { echo "the toolchain has no ld.so.1" >&2; exit 1; }
toolchain_lib=$(cd "$(dirname "$loader")" && pwd -P)

root="$backend/build/qemu-root-$(basename "$CROSS_COMPILE" -)"
rm -rf "$root"
mkdir -p "$root/opt/lib"
cp -a "$toolchain_lib"/*.so* "$root/opt/lib/"
cp -a "$SYSROOT"/opt/lib/*.so* "$root/opt/lib/"

mk() {
    make -C "$backend" CROSS_COMPILE="$CROSS_COMPILE" SYSROOT="$SYSROOT" \
        CFLAGS_EXTRA="-I$SYSROOT/opt/include" \
        LDFLAGS_EXTRA="-L$SYSROOT/opt/lib -Wl,-rpath-link=$SYSROOT/opt/lib:$toolchain_lib" "$@"
}

bins=$(mk -s print-TEST_BINS)
[ -n "$bins" ] || { echo "the Makefile names no test binaries" >&2; exit 1; }
mk -j"$(nproc)" $bins || exit 1

mips_binfmt=no
if [ -r /proc/sys/fs/binfmt_misc/qemu-mips ] && grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-mips; then
    mips_binfmt=yes
fi

skip_reason() {
    case $1 in
    test_dnsproxy)
        echo "qemu-user hands IP_PKTINFO ancillary data over untranslated, so the reply's ifindex is byte-swapped and sendmsg fails with ENODEV; test_pktinfo pins those bytes"
        ;;
    test_spawn)
        [ "$mips_binfmt" = yes ] || echo "it re-executes itself, which needs a binfmt_misc handler for mips"
        ;;
    esac
}

export QEMU_LD_PREFIX="$root"
pass=0
fail=0
skip=0
failed=""
for b in $bins; do
    name=$(basename "$b")
    why=$(skip_reason "$name")
    if [ -n "$why" ]; then
        echo "== SKIP $name: $why"
        skip=$((skip + 1))
        continue
    fi
    echo "== $name"
    if (cd "$backend" && timeout 900 "$QEMU" -L "$root" "$b"); then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        failed="$failed $name"
    fi
done

echo
echo "mips qemu unit tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ] || { echo "FAILED:$failed"; exit 1; }
