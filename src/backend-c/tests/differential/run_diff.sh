#!/bin/sh
# Runs the regex, yaml, config, match, subparse, dns, migrate and http suites, each diffed against golden/.
# A red suite is a regression until a named change explains it; regenerate a golden only with that change.
# Goldens that diverge by design: regexp2.tsv (see known_divergences.tsv), match, subparse, http_contract.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_C_DIR="$(cd "$DIR/../.." && pwd)"
OUT="$DIR/out"
GOLDEN="$DIR/golden"
mkdir -p "$OUT"

fail=0

echo "== differential: regex (PCRE2 vs golden regexp2.tsv)"
if ! sh "$DIR/regex_corpus/run.sh"; then
    KNOWN="$DIR/regex_corpus/known_divergences.tsv"
    ACTUAL_NORM="$DIR/regex_corpus/out/divergence.norm"
    grep -E '^[+-]' "$DIR/regex_corpus/out/divergence.diff" \
        | grep -vE '^(\+\+\+|---)' > "$ACTUAL_NORM" || true
    if [ -f "$KNOWN" ] && \
       diff -u "$KNOWN" "$ACTUAL_NORM" >/dev/null 2>&1; then
        echo "   divergences match the documented known set — OK"
    else
        echo "   UNEXPECTED regex divergence (known divergences are listed in regex_corpus/known_divergences.tsv)"
        fail=1
    fi
fi

echo "== differential: yaml emit (libyaml vs golden go-yaml-v2.yaml)"
if ! sh "$DIR/yaml_emit/run.sh"; then
    fail=1
fi

echo "== differential: building tools"
( cd "$BACKEND_C_DIR" && make >/dev/null )
CONFIGTOOL="$BACKEND_C_DIR/build/host/firc-configtool"
DNSTOOL="$BACKEND_C_DIR/build/host/firc-dnstool"

echo "== differential: config load/save fixtures (vs golden)"
for fixture in "$DIR"/fixtures/*.yaml; do
    name=$(basename "$fixture" .yaml)
    golden="$GOLDEN/config-fixtures/$name.golden.yaml"
    "$CONFIGTOOL" resave "$fixture" 0.99.0 > "$OUT/$name.c.yaml"
    if ! diff -u "$golden" "$OUT/$name.c.yaml" > "$OUT/$name.diff" 2>&1; then
        echo "   REGRESSION in $name (vs golden):"
        head -20 "$OUT/$name.diff"
        fail=1
    else
        echo "   $name: OK"
    fi
done

echo "== differential: missing-file behaviour (defaults, vs golden)"
"$CONFIGTOOL" resave /nonexistent/config.yaml 0.99.0 > "$OUT/missing.c.yaml"
if ! diff -u "$GOLDEN/config-fixtures/missing.golden.yaml" "$OUT/missing.c.yaml" \
     > "$OUT/missing.diff" 2>&1; then
    echo "   REGRESSION in defaults (vs golden):"
    head -20 "$OUT/missing.diff"
    fail=1
else
    echo "   defaults: OK"
fi

echo "== differential: rule matching corpus (vs golden)"
"$CONFIGTOOL" match < "$DIR/corpus/match_corpus.tsv" > "$OUT/match.c.tsv"
if ! diff -u "$GOLDEN/match.golden.tsv" "$OUT/match.c.tsv" \
     > "$OUT/match.diff" 2>&1; then
    echo "   REGRESSION (vs golden):"
    cat "$OUT/match.diff"
    fail=1
else
    echo "   $(grep -c . "$OUT/match.c.tsv") cases: OK"
fi

echo "== differential: list parse corpus (vs golden)"
"$CONFIGTOOL" subparse < "$DIR/corpus/subparse_corpus.txt" > "$OUT/subparse.c.txt"
if ! diff -u "$GOLDEN/subparse.golden.txt" "$OUT/subparse.c.txt" \
     > "$OUT/subparse.diff" 2>&1; then
    echo "   REGRESSION (vs golden):"
    cat "$OUT/subparse.diff"
    fail=1
else
    echo "   $(grep -c . "$OUT/subparse.c.txt") rules: OK"
fi

echo "== differential: DNS wire corpus (vs golden)"
DNS_CORPUS="$DIR/corpus/dns_corpus.hex"
for mode in dump stripaaaa ptrcheck; do
    "$DNSTOOL" "$mode" < "$DNS_CORPUS" > "$OUT/dns.$mode.c.txt"
    if ! diff -u "$GOLDEN/dns.$mode.golden.txt" "$OUT/dns.$mode.c.txt" \
         > "$OUT/dns.$mode.diff" 2>&1; then
        echo "   DNS $mode REGRESSION (vs golden):"
        head -30 "$OUT/dns.$mode.diff"
        fail=1
    else
        echo "   dns $mode: $(grep -c '^===' "$OUT/dns.$mode.c.txt") messages: OK"
    fi
done

echo "== differential: the groups.yaml migration in the package's postinst"
if ! sh "$DIR/run_migrate_groups_diff.sh"; then
    fail=1
fi

echo "== differential: the WebUI address the package's postinst reports"
if ! sh "$DIR/run_postinst_web_diff.sh"; then
    fail=1
fi

echo "== differential: HTTP API contract (vs golden)"
if ! sh "$DIR/run_http_diff.sh"; then
    fail=1
fi

exit $fail
