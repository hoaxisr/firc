#!/bin/sh
set -eu
[ $# -eq 2 ] || { echo "usage: gen-dnat.sh v4|v6 COUNT" >&2; exit 2; }
FAM=$1
N=$2
echo '*nat'
echo ':FIRC_DNAT - [0:0]'
i=0
while [ "$i" -lt "$N" ]; do
    if [ "$FAM" = v4 ]; then
        echo "-A FIRC_DNAT -d 198.18.$((i / 256)).$((i % 256))/32 -j DNAT --to-destination 100.64.$((i / 256)).$((i % 256))"
    else
        printf -- '-A FIRC_DNAT -d fd37:9a00::%x/128 -j DNAT --to-destination 2001:db8::%x\n' $((i + 1)) $((i + 1))
    fi
    i=$((i + 1))
done
if [ "$FAM" = v4 ]; then
    echo '-A PREROUTING -d 198.18.0.0/15 -j FIRC_DNAT'
else
    echo '-A PREROUTING -d fd37:9a00::/48 -j FIRC_DNAT'
fi
echo 'COMMIT'
