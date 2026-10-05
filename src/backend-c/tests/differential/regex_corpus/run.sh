#!/bin/sh
# Replays PCRE2 over corpus.tsv and diffs it against golden/regexp2.tsv.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$DIR/out}"
mkdir -p "$OUT"

cc -O2 -Wall -Wextra -o "$OUT/pcre2_runner" "$DIR/pcre2_runner.c" $(pcre2-config --libs8 --cflags)

"$OUT/pcre2_runner" < "$DIR/corpus.tsv" > "$OUT/pcre2.tsv"

if diff -u "$DIR/golden/regexp2.tsv" "$OUT/pcre2.tsv" > "$OUT/divergence.diff"; then
    echo "IDENTICAL: $(grep -c . "$OUT/pcre2.tsv") cases, no divergence"
else
    echo "DIVERGENCES FOUND:"
    cat "$OUT/divergence.diff"
    exit 1
fi
