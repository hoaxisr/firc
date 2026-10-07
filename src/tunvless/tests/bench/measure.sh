#!/bin/sh
# One iperf3 run on a router, with the CPU it cost: what the router measurements were taken with.
#
#   measure.sh <label> <process name | -> <iperf3 client arguments...>
#
# Prints the rate, the busy CPU of the whole box (out of 100% per hardware thread: 400% on a
# four-thread MT7621) and the CPU of the named process (100% = one thread), all over the run.
# BusyBox sh and awk are enough; USER_HZ is taken as 100.
#
#   measure.sh "tunvless down x4" tunvless -c 198.18.0.1 -t 15 -R -P 4
#   measure.sh "direct up x1" - -c <server> -t 15
LABEL=$1; PN=$2; shift 2

total() { awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8 " " $5+$6}' /proc/stat; }
proc_ticks() {
    s=0
    for p in $(pidof "$PN" 2>/dev/null); do
        v=$(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null)
        s=$((s + ${v:-0}))
    done
    echo $s
}

A0=$(total); P0=$(proc_ticks); T0=$(date +%s)
OUT=$(iperf3 -J "$@" 2>&1)
A1=$(total); P1=$(proc_ticks); T1=$(date +%s)

set -- $A0; t0=$1; i0=$2
set -- $A1; t1=$1; i1=$2
DT=$((T1 - T0)); [ $DT -lt 1 ] && DT=1
BUSY=$(awk -v a=$((t1 - t0)) -v b=$((i1 - i0)) 'BEGIN { if (a > 0) printf "%.0f", (a - b) * 400 / a; else print 0 }')
PROC=$(awk -v d=$((P1 - P0)) -v s=$DT 'BEGIN { printf "%.0f", d / s }')
MBIT=$(echo "$OUT" | awk -F: '/"sum_received"/ { f = 1 } f && /"bits_per_second"/ { gsub(/[ ,]/, "", $2); printf "%.1f", $2 / 1e6; exit }')
ERR=$(echo "$OUT" | awk -F'"' '/"error"/ { print $4; exit }')
printf '%-34s %8s Mbit/s  CPU total %4s%%/400  %s %4s%%  %s\n' \
    "$LABEL" "${MBIT:-?}" "$BUSY" "$PN" "$PROC" "$ERR"
