#!/bin/sh
# What N destination prefixes cost the kernel in the mangle table, by rule shape.
# Run as root ON THE ROUTER (iptables, iptables-restore, ipset, /proc). Not for a host.
#
# usage: run_subnet_sets.sh <prefixes> <base|A|B|B2|C>...
#
# Per variant it prints: rules loaded, loader peak RSS, load time, memory deltas,
# the time of one foreign `iptables -N`/`-X` (a rewrite by another program), and
# the ping RTT over loopback with the chain jumped from PREROUTING 1 (the cost per
# packet is about half the RTT gain over `base`, as each of the two packets walks
# the chain once).
#   base  no chain, the reference ping
#   A     MARK and CONNMARK rule per prefix
#   B     one MARK rule per prefix, one CONNMARK rule at the end
#   B2    `-d <cidr> -j <sub-chain>` per prefix, the tests once in the sub-chain
#   C     one hash:net set holding every prefix, and two rules matching it
#
# The prefixes lie in 240.0.0.0/4 and match no real traffic. Everything lives in
# the scratch chains ZBENCH, ZBENCHS, ZBENCHX, the set zbench and the work directory
# /tmp/zbench, which an exit trap removes;
# nothing is left behind. The run aborts when MemAvailable is under 40000 kB.
N=${1:-2000}; shift
W=/tmp/zbench; mkdir -p $W
MARK=0x40630000/0x40ff0000
MINFREE=40000

now() { cut -d' ' -f1 /proc/uptime; }
avail() { awk '/^MemAvailable/{print $2}' /proc/meminfo; }
slab() { awk '/^Slab/{print $2}' /proc/meminfo; }
vmxt() { awk '/xt_alloc_table_info|xt_replace|do_replace|translate_table/{s+=$2} END{print s+0}' /proc/vmallocinfo 2>/dev/null; }

cleanup() {
    iptables -w -t mangle -D PREROUTING -j ZBENCH 2>/dev/null
    iptables -w -t mangle -F ZBENCH 2>/dev/null
    iptables -w -t mangle -X ZBENCH 2>/dev/null
    iptables -w -t mangle -F ZBENCHS 2>/dev/null
    iptables -w -t mangle -X ZBENCHS 2>/dev/null
    ipset destroy zbench 2>/dev/null
    iptables -w -t mangle -F ZBENCHX 2>/dev/null
    iptables -w -t mangle -X ZBENCHX 2>/dev/null
}
pid=
finish() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        pid=
    fi
    cleanup
    rm -rf "$W"
}
trap 'finish; exit' EXIT HUP INT TERM

gen() {
    awk 'BEGIN{
        for(i=0;i<10000;i++) print "240." int(i/256) "." i%256 ".0/24";
        for(i=0;i<3000;i++)  print "241." int(i/256) "." i%256 ".1/32";
        for(i=0;i<4000;i++)  print "242." int(i/128) "." (i%128)*2 ".0/23";
        for(i=0;i<3000;i++)  print "243." int(i/64) "." (i%64)*4 ".0/22";
        for(i=0;i<2000;i++)  print "244." int(i/16) "." (i%16)*16 ".0/20";
        for(i=0;i<800;i++)   print "245." int(i/8) "." (i%8)*32 ".0/19";
        for(i=0;i<400;i++)   print "246." int(i/4) "." (i%4)*64 ".0/18";
        for(i=0;i<100;i++)   print "247." i ".0.0/16";
    }' | awk 'BEGIN{srand(7)}{print rand() "\t" $0}' | sort | cut -f2 | head -n "$N" > $W/cidrs
}

rules() {
    v=$1
    echo "*mangle"; echo ":ZBENCH - [0:0]"
    [ "$v" = B2 ] && echo ":ZBENCHS - [0:0]"
    case $v in
    A) awk -v m=$MARK '{
        print "-A ZBENCH -d " $1 " -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -j MARK --set-xmark " m;
        print "-A ZBENCH -d " $1 " -m conntrack --ctdir ORIGINAL -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000"}' $W/cidrs ;;
    B) awk -v m=$MARK '{
        print "-A ZBENCH -d " $1 " -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -j MARK --set-xmark " m}' $W/cidrs
       echo "-A ZBENCH -m mark --mark $MARK -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000" ;;
    B2) awk '{print "-A ZBENCH -d " $1 " -j ZBENCHS"}' $W/cidrs
        echo "-A ZBENCHS -m conntrack --ctdir REPLY -j RETURN"
        echo "-A ZBENCHS -m mark --mark 0x40000000/0x40000000 -j RETURN"
        echo "-A ZBENCHS -j MARK --set-xmark $MARK"
        echo "-A ZBENCHS -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000" ;;
    C) echo "-A ZBENCH -m set --match-set zbench dst -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -j MARK --set-xmark $MARK"
       echo "-A ZBENCH -m set --match-set zbench dst -m conntrack --ctdir ORIGINAL -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000" ;;
    esac
    echo COMMIT
}

peak() {
    hwm=0; vpk=0
    while :; do
        r=$(awk '/^VmHWM/{h=$2}/^VmPeak/{p=$2}END{print h+0, p+0}' /proc/"$1"/status 2>/dev/null)
        [ -z "$r" ] || [ "$r" = "0 0" ] && break
        h=${r% *}; p=${r#* }
        [ "$h" -gt "$hwm" ] && hwm=$h
        [ "$p" -gt "$vpk" ] && vpk=$p
    done
    echo "$hwm $vpk"
}

pingit() {
    ping -q -c 20 127.0.0.1 2>&1 | tail -1
}

gen
echo "prefixes=$(wc -l < $W/cidrs) lengths=$(cut -d/ -f2 $W/cidrs | sort -u | wc -l)"
for v in "$@"; do
    cleanup; sync; echo 3 > /proc/sys/vm/drop_caches; sleep 2
    a0=$(avail); s0=$(slab); x0=$(vmxt)
    [ "$a0" -lt $MINFREE ] && { echo "abort: MemAvailable $a0"; exit 1; }
    echo "== $v n=$N avail0=$a0"
    if [ "$v" = base ]; then echo "ping $(pingit)"; continue; fi
    if [ "$v" = C ]; then
        { echo "create zbench hash:net family inet maxelem 131072"; sed 's/^/add zbench /' $W/cidrs; } > $W/set
        t0=$(now); ipset restore < $W/set || { echo "ipset failed"; continue; }; t1=$(now)
        echo "ipset_load_s=$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}') $(ipset list -t zbench | grep -i -E 'memory|entries')"
    fi
    rules "$v" > $W/rules
    t0=$(now); iptables-restore --noflush < $W/rules & pid=$!
    pk=$(peak $pid); wait $pid; rc=$?; pid=; t1=$(now)
    echo 3 > /proc/sys/vm/drop_caches; sleep 1
    a1=$(avail); s1=$(slab); x1=$(vmxt)
    echo "restore rc=$rc s=$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}') hwm_kB,vmpeak_kB=$pk rules=$(iptables -t mangle -S ZBENCH | wc -l)"
    echo "mem avail_delta_kB=$((a0-a1)) slab_delta_kB=$((s1-s0)) vmalloc_xt_delta_B=$((x1-x0))"
    t0=$(now); iptables -t mangle -N ZBENCHX; t1=$(now); iptables -t mangle -X ZBENCHX; t2=$(now)
    echo "foreign_edit_s add=$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}') del=$(awk -v a="$t1" -v b="$t2" 'BEGIN{print b-a}')"
    iptables -t mangle -I PREROUTING 1 -j ZBENCH
    echo "ping $(pingit)"
    iptables -t mangle -D PREROUTING -j ZBENCH
    iptables -t mangle -S ZBENCH >/dev/null 2>&1 || echo "WARN: chain vanished (firmware rewrite?)"
done
