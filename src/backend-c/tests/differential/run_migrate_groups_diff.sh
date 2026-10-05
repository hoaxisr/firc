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

echo "== migrate: a small legacy file is left for the daemon, which can load it"
cp "$GOLDEN/migrate-groups-legacy.yaml" "$WORK/small.yaml"
sh "$POSTINST" --migrate-only "$WORK/small.yaml"   # no FORCE: under the size threshold
check "the small file" "$GOLDEN/migrate-groups-legacy.yaml" "$WORK/small.yaml"

echo "== migrate: a missing file is not an error"
sh "$POSTINST" --migrate-only "$WORK/nonexistent.yaml"
echo "   absent file: OK"

if [ "$fail" -ne 0 ]; then
    echo "FAILED"
    exit 1
fi
echo "ok"
