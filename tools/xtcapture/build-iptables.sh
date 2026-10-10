#!/bin/sh
set -eu
[ $# -eq 2 ] || { echo "usage: build-iptables.sh iptables-1.4.21.tar.bz2 OUT_DIR" >&2; exit 2; }
TARBALL=$1
OUT=$2
WANT=52004c68021da9a599feed27f65defcfb22128f7da2c0531c0f75de0f479d3e0
GOT=$(sha256sum "$TARBALL" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || { echo "sha256 $GOT is not iptables 1.4.21's $WANT" >&2; exit 1; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
rm -rf "$OUT/src" "$OUT/inst"
mkdir "$OUT/src"
tar -xjf "$TARBALL" -C "$OUT/src"
cd "$OUT/src/iptables-1.4.21"
rm extensions/libxt_connlabel.c
./configure --prefix="$OUT/inst" --disable-shared --enable-static CFLAGS="-O2 -fcommon" > "$OUT/configure.log" 2>&1
make -j"$(nproc)" > "$OUT/make.log" 2>&1
make install >> "$OUT/make.log" 2>&1
"$OUT/inst/sbin/iptables" -V
