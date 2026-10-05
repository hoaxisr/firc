#!/bin/sh
# Emits the sample config with libyaml and diffs it against golden/go-yaml-v2.yaml.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$DIR/out}"
mkdir -p "$OUT"

cc -O2 -Wall -Wextra -o "$OUT/emit_config" "$DIR/emit_config.c" -lyaml

"$OUT/emit_config" > "$OUT/libyaml.yaml"

if diff -u "$DIR/golden/go-yaml-v2.yaml" "$OUT/libyaml.yaml" > "$OUT/divergence.diff"; then
    echo "IDENTICAL ($(wc -c < "$OUT/libyaml.yaml") bytes)"
else
    echo "DIVERGENCES:"
    cat "$OUT/divergence.diff"
    exit 1
fi
