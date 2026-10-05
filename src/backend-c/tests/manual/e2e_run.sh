#!/bin/sh
# Runs the tap's NFLOG read path end to end against a dummy interface and real iptables.
# Run it only inside `unshare -Urn`: it changes links and iptables, which as plain root alters the host.
# Needs socat, openssl, iptables with NFLOG, and e2e_nflog built next to it (see README.md).
set -e
SP="$(dirname "$0")"
ip link set lo up
ip link add dummy0 type dummy
ip addr add 203.0.113.1/24 dev dummy0
ip link set dummy0 up

iptables -t mangle -A OUTPUT -d 203.0.113.1 -p tcp --dport 443 \
    --tcp-flags SYN,ACK ACK -m length --length 100: \
    -j NFLOG --nflog-group 42 --nflog-threshold 1

"$SP/e2e_nflog" 42 300 &
READER=$!
sleep 1

socat -u TCP-LISTEN:443,bind=203.0.113.1,reuseaddr,fork /dev/null &
LISTENER=$!
sleep 1
timeout 4 openssl s_client -connect 203.0.113.1:443 -servername bypass.example.com </dev/null >/dev/null 2>&1 || true
sleep 1
timeout 4 openssl s_client -connect 203.0.113.1:443 -servername UPPER.Example.COM. </dev/null >/dev/null 2>&1 || true

wait $READER
kill $LISTENER 2>/dev/null || true
echo "--- the rule, as the kernel kept it ---"
iptables -t mangle -S OUTPUT
