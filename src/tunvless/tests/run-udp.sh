#!/bin/sh
# UDP through the tunnel on a local test bed: no real node and no internet.
#
# run-tunnel.sh covers TCP (synthesis, retransmission, recovery after loss). UDP has none of
# that and fails in other ways. This checks what can break silently:
#
#   1. datagram boundaries. VLESS carries datagrams in a stream with a two-byte length, and the
#      TLS record knows nothing of them: one datagram may span two records, and one record may
#      bring one and a half datagrams. A reassembly bug looks like "works, but sometimes the data is
#      wrong", so the CONTENT of every answer is compared, not only their count. The server
#      echoes in pieces cut between the length bytes and inside datagrams (fake-vless.py,
#      echo_in_pieces), so these records come every time, not by chance;
#   2. sizes at the edges: 1 byte, exactly the MTU, and above the MTU (that one reaches the
#      client in fragments, and its stack must reassemble them);
#   3. one stream per address-port pair: two targets at once must not get mixed up. Every answer
#      must come from the address and port it was sent to, and the server must have been asked
#      for exactly one stream to each pair;
#   4. no ICMP refusal. If the tunnel answered UDP with "port unreachable", the client would
#      decide the port is closed, and QUIC would fail even with datagrams carried correctly.
#
# Setup: a network namespace, a fake VLESS server (tests/fake-vless.py) that echoes command 2,
# the tunnel brought up by tunvless, and Python as the UDP client.
#
# Usage: tests/run-udp.sh
set -eu
cd "$(dirname "$0")/.."

BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "no binary: $BIN (make)"; exit 2; }

NS=tunvless-udp
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
# Not in 127.0.0.0/8: such a node is rejected as one with no peer (sublink.c).
NODE=10.66.0.1
WORK="$(mktemp -d)"

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

LINK="vless://$UUID@$NODE:$PORT?security=none&type=tcp#local"

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add "$NODE/32" dev lo

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 1 --bind "$NODE" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

# Any address but localhost: the fake server ignores it, it only has to go into the tunnel.
ip netns exec "$NS" env STEER_TUN_STATS=1 "$BIN" "$LINK" -d vl -r 203.0.113.0/24 \
    > "$WORK/tun.log" 2>&1 &
TUN_PID=$!

for _ in $(seq 50); do
    ip netns exec "$NS" ip route show 203.0.113.0/24 2>/dev/null | grep -q 'dev vl' && break
    sleep 0.2
done
if ! ip netns exec "$NS" ip route show 203.0.113.0/24 2>/dev/null | grep -q 'dev vl'; then
    echo "device vl or the route into it did not come up:"; sed 's/^/  /' "$WORK/tun.log"; exit 1
fi

# The client is a plain UDP socket: no ready-made tool can tell whether the answer came back
# WHOLE and the same. ICMP is read on a raw socket: "port unreachable" would mean UDP is not
# supported, and that must be SEEN, not show up as a timeout.
rc=0
ip netns exec "$NS" python3 - "$WORK/srv.log" > "$WORK/out.txt" 2>&1 <<'PY' || rc=$?
import re, socket, sys, time

TARGET_A, TARGET_B = "203.0.113.7", "203.0.113.9"
SRV_LOG = sys.argv[1]
fails = []

def check(name, ok, detail=""):
    print("%-46s %s%s" % (name, "ok" if ok else "FAIL", ("  " + detail) if detail else ""))
    if not ok:
        fails.append(name)

icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp.setblocking(False)

def drain(sock):
    """Drain everything that has already arrived.

    Needed between checks: a late echo of the previous check would otherwise reach the next
    one, which would then compare the wrong data and fail on a working tunnel.
    """
    n = 0
    while True:
        try:
            sock.recvfrom(65535)
            n += 1
        except BlockingIOError:
            return n


def recv(sock, timeout):
    """One datagram and where it came from, (None, None) on timeout."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            return sock.recvfrom(65535)
        except BlockingIOError:
            time.sleep(0.02)
    return None, None


def echo(sock, host, port, payload, timeout=6.0):
    """Send a datagram and return the answer and its source.

    The source matters as much as the bytes: the echo server answers on whatever stream the
    datagram came by, so a datagram carried by another flow's stream comes back unchanged, but
    from that flow's address or port.
    """
    drain(sock)
    sock.sendto(payload, (host, port))
    return recv(sock, timeout)


def verdict(r, src, p, host, port):
    if r == p and src == (host, port):
        return True, ""
    return False, "got %s from %s" % (None if r is None else len(r), src)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(False)
s.bind(("", 0))

# 1. A plain datagram. Being the first, it also tests setup: the handshake with the node
#    happens after the datagram is already in the early-data buffer.
p = b"quic-ish-initial-" + bytes(range(200))
check("217-byte datagram echoed unchanged", *verdict(*echo(s, TARGET_A, 443, p), p, TARGET_A, 443))

# 2. Sizes at the edges. One byte is the minimum; 1472 is exactly the MTU (1500 - 20 - 8);
#    3000 is above the MTU IN BOTH DIRECTIONS: upstream it arrives in fragments the tunnel
#    reassembles, back it leaves in fragments the client's stack reassembles. If either is
#    broken the echo does not match.
for n in (1, 1472, 3000):
    p = bytes((i * 37 + n) % 251 for i in range(n))
    check("%d-byte datagram echoed unchanged" % n,
          *verdict(*echo(s, TARGET_A, 443, p), p, TARGET_A, 443))

# 3. A burst: boundaries must not merge. UDP promises no order, so the answers are compared
#    as a set.
drain(s)
sent = [bytes([i]) * (100 + i) for i in range(8)]
for p in sent:
    s.sendto(p, (TARGET_A, 443))
got = []
while len(got) < len(sent):
    r, src = recv(s, 8)
    if r is None:
        break
    got.append((r, src))
check("burst of 8: all echoed unchanged",
      sorted(got) == sorted((p, (TARGET_A, 443)) for p in sent),
      "got %d of %d" % (len(got), len(sent)))

# 4. Two targets at once, from one socket: each has its own stream to the node, and they must
#    not mix. Only the source of each answer can show it: a datagram sent into the other
#    target's stream comes back unchanged, but from that target.
drain(s)
pa, pb = b"aaaa-to-A" * 10, b"bbbb-to-B" * 10
s.sendto(pa, (TARGET_A, 443))
s.sendto(pb, (TARGET_B, 443))
got = {}
for _ in range(2):
    r, src = recv(s, 6)
    if r is None:
        break
    got[r] = src
check("two targets did not mix", got == {pa: (TARGET_A, 443), pb: (TARGET_B, 443)},
      "" if len(got) == 2 else "got %d of 2" % len(got))

# 5. Another port of the same address is a separate stream too.
p = b"wireguard-keepalive"
check("another port gets its own stream",
      *verdict(*echo(s, TARGET_A, 51820, p), p, TARGET_A, 51820))

# 6. No ICMP destination unreachable (type 3) may arrive.
unreach = 0
try:
    while True:
        data = icmp.recv(2048)
        if len(data) >= 21 and data[20] == 3:
            unreach += 1
except BlockingIOError:
    pass
check("no ICMP unreachable for UDP", unreach == 0, "got %d" % unreach)

# 7. What the node saw: one stream per address-port pair, each asking for that address and
#    port. The server logs a stream as it opens it, before the first echo.
seen = sorted(re.findall(r"UDP stream to (\S+):(\d+)$", open(SRV_LOG).read(), re.M))
want = sorted([(TARGET_A, "443"), (TARGET_B, "443"), (TARGET_A, "51820")])
check("the node got one stream per address and port", seen == want,
      "" if seen == want else "streams: %s" % seen)

print("\nfailures: %d" % len(fails))
sys.exit(1 if fails else 0)
PY
# `|| rc=$?` keeps set -e from stopping the script before out.txt is printed, which is the only
# record of which check failed. The verdict has two halves: the exit code catches a failure
# anywhere, the grep catches a report that was never printed (Python died before it).

sed 's/^/  /' "$WORK/out.txt"
if [ "$rc" -ne 0 ] || ! grep -q "^failures: 0" "$WORK/out.txt"; then
    echo "  --- tunnel log:"
    grep -iE "warn|datagram|udp" "$WORK/tun.log" | tail -10 | sed 's/^/    /' || true
    echo "  --- server log:"
    tail -5 "$WORK/srv.log" | sed 's/^/    /' || true
    exit 1
fi
exit 0
