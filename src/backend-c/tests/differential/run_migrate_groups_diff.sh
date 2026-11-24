#!/bin/sh
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
POSTINST="$HERE/../../../../files/entware/_ipk/control/postinst"
GOLDEN="$HERE/golden"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
check() { # $1 = what, $2 = expected file, $3 = actual file
    if diff -u "$2" "$3" > "$WORK/diff" 2>&1; then
        echo "   $1: OK"
    else
        echo "   REGRESSION in $1:"
        head -30 "$WORK/diff"
        fail=1
    fi
}

echo "== migrate: a legacy groups.yaml loses its subscriptions' rules and nothing else"
cp "$GOLDEN/migrate-groups-legacy.yaml" "$WORK/groups.yaml"
FIRC_MIGRATE_FORCE=1 sh "$POSTINST" --migrate-only "$WORK/groups.yaml" 2> "$WORK/said"
check "the migrated file" "$GOLDEN/migrate-groups-expected.yaml" "$WORK/groups.yaml"

if grep -q '1 rule(s) you had switched off' "$WORK/said"; then
    echo "   the count of dropped switches: OK"
else
    echo "   REGRESSION: it did not say what it dropped, or said the wrong number:"
    cat "$WORK/said"
    fail=1
fi
if [ -f "$WORK/groups.yaml.off" ]; then
    echo "   REGRESSION: it left its scratch file behind"
    fail=1
fi
if [ -f "$WORK/groups.yaml.pre-0027.bak" ]; then
    check "the backup it kept" "$GOLDEN/migrate-groups-legacy.yaml" "$WORK/groups.yaml.pre-0027.bak"
else
    echo "   REGRESSION: no backup was kept"
    fail=1
fi

echo "== migrate: a file already in the new shape is left alone"
cp "$GOLDEN/migrate-groups-expected.yaml" "$WORK/new.yaml"
FIRC_MIGRATE_FORCE=1 sh "$POSTINST" --migrate-only "$WORK/new.yaml"
check "the untouched file" "$GOLDEN/migrate-groups-expected.yaml" "$WORK/new.yaml"
if [ -f "$WORK/new.yaml.pre-0027.bak" ]; then
    echo "   REGRESSION: it backed up a file it had no reason to touch"
    fail=1
fi

echo "== migrate: a small legacy file keeps its subscriptions' rules, its rule names become comments"
cp "$GOLDEN/migrate-groups-legacy.yaml" "$WORK/small.yaml"
sh "$POSTINST" --migrate-only "$WORK/small.yaml"   # no FORCE: under the size threshold
check "the small file" "$GOLDEN/migrate-groups-small-expected.yaml" "$WORK/small.yaml"

echo "== migrate: an older backup is kept, not overwritten"
cp "$GOLDEN/migrate-groups-legacy.yaml" "$WORK/again.yaml"
echo "the original from an earlier strip" > "$WORK/again.yaml.pre-0027.bak"
cp "$WORK/again.yaml.pre-0027.bak" "$WORK/older.bak"
FIRC_MIGRATE_FORCE=1 sh "$POSTINST" --migrate-only "$WORK/again.yaml" 2> /dev/null
check "the migrated file" "$GOLDEN/migrate-groups-expected.yaml" "$WORK/again.yaml"
check "the older backup" "$WORK/older.bak" "$WORK/again.yaml.pre-0027.bak"

( cd "$HERE/../.." && make build/host/firc-configtool > /dev/null )
CONFIGTOOL="$HERE/../../build/host/firc-configtool"

migrate_list() {
    cp "$GOLDEN/migrate-lists-$1.yaml" "$WORK/$1.yaml"
    sh "$POSTINST" --migrate-only "$WORK/$1.yaml"
    check "the migrated file" "$GOLDEN/migrate-lists-$1-expected.yaml" "$WORK/$1.yaml"
    check "the backup it kept" "$GOLDEN/migrate-lists-$1.yaml" "$WORK/$1.yaml.pre-0027.bak"
    "$CONFIGTOOL" resave "$WORK/$1.yaml" 0.99.0 2> "$WORK/$1.said" |
        sed -n '/^groups:/,$p' |
        awk -v given="$(sed -n 's/^ *-* *id: //p' "$GOLDEN/migrate-lists-$1.yaml" | tr '\n' ' ')" '
            BEGIN { n = split(given, g, " "); for (i = 1; i <= n; i++) { K[g[i]] = 1 } }
            prev ~ /^ *lists:$/ && /^ *- id: "?[0-9a-f]+"?$/ && !($NF in K) { sub(/"?[0-9a-f]+"?$/, "RANDOM") }
            { print; prev = $0 }' > "$WORK/$1.loaded"
    check "what the daemon loads from it" "$GOLDEN/migrate-lists-$1-loaded.yaml" "$WORK/$1.loaded"
    if grep -q 'no longer read' "$WORK/$1.said"; then
        echo "   REGRESSION: the daemon still finds a list key it ignores:"
        cat "$WORK/$1.said"
        fail=1
    fi
}

echo "== migrate: a group's list becomes its lists"
migrate_list one
echo "== migrate: a list keeps its id"
migrate_list id
echo "== migrate: a group with lists is left alone beside one that is rewritten"
migrate_list two
echo "== migrate: a list moves without touching the group's hand rules"
migrate_list rules
echo "== migrate: a CRLF file's list becomes its lists"
migrate_list crlf
echo "== migrate: a flow-style list becomes a flow-style lists"
migrate_list flow

untouched_list() {
    cp "$GOLDEN/migrate-lists-$1.yaml" "$WORK/$1.yaml"
    sh "$POSTINST" --migrate-only "$WORK/$1.yaml"
    check "the untouched file" "$GOLDEN/migrate-lists-$1.yaml" "$WORK/$1.yaml"
    if [ -f "$WORK/$1.yaml.pre-0027.bak" ]; then
        echo "   REGRESSION: it backed up a file it had no reason to touch"
        fail=1
    fi
}

echo "== migrate: a file with no list is not touched"
untouched_list none
echo "== migrate: a group that already has lists keeps its list key as it is"
untouched_list both
echo "== migrate: a CRLF file with no list is not touched"
untouched_list crlf-none

echo "== migrate: a missing file is not an error"
sh "$POSTINST" --migrate-only "$WORK/nonexistent.yaml"
echo "   absent file: OK"

if [ "$fail" -ne 0 ]; then
    echo "FAILED"
    exit 1
fi
echo "ok"
