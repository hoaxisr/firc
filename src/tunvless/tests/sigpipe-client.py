#!/usr/bin/env python3
"""A LAN client for tests/sigpipe.sh: many connections through the tunnel, cut at the worst
moment.

    sigpipe-client.py TARGET --ping       one "line — echo" connection: is the tunnel alive?
    sigpipe-client.py TARGET --storm SECS [--up N] [--abort-up N] [--abort-down N]

Three kinds of workers, each looping "connect, load, cut, again" until the deadline:

  up        upload to port 80 of the fake node (tests/sigpipe-node.py): the node closes the
            connection after a random number of bytes while the client is still sending, and the
            tunnel stack writes packets already queued in TUN into the node's closed socket. The
            worker sends until a write fails (the tunnel answered RST) or time runs out.
  abort-up  upload to port 82 (a sink that does not close): the client itself aborts mid-transfer
            with RST (SO_LINGER 1,0) while data is still in flight.
  abort-down download from port 81 (a source): the client aborts with RST while the node is still
            sending.

Prints one line of totals per kind — connections opened, how many were cut and how, bytes sent —
so the test sees the load was real.
"""
import argparse
import random
import socket
import struct
import sys
import threading
import time


def rst_close(s):
    """Close with an RST: unread and unsent data is dropped, not delivered."""
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def connect(target, port, timeout=5.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect((target, port))
    return s


def ping(target):
    """A line into the tunnel, an echo back: 0 — the tunnel is alive."""
    t0 = time.time()
    last = "no attempts"
    while time.time() - t0 < 20:
        try:
            s = connect(target, 7, 3.0)
            s.settimeout(3.0)
            s.sendall(b"ping\n")
            buf = b""
            while not buf.endswith(b"\n"):
                c = s.recv(4096)
                if not c:
                    break
                buf += c
            s.close()
            if buf == b"PONG ping\n":
                print("ping: answer after %.2f s" % (time.time() - t0))
                return 0
            last = "answer %r" % buf
        except OSError as e:
            last = "%s: %s" % (type(e).__name__, e)
        time.sleep(0.3)
    print("ping: no answer through the tunnel in 20 s (%s)" % last)
    return 1


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.d = {}

    def add(self, k, n=1):
        with self.lock:
            self.d[k] = self.d.get(k, 0) + n


def worker(kind, target, deadline, st):
    blob = b"\xa5" * (1 << 20)
    while time.time() < deadline:
        try:
            if kind == "up":
                s = connect(target, 80)
                s.settimeout(10.0)
                st.add("up:opened")
                sent = 0
                try:
                    while time.time() < deadline:
                        sent += s.send(blob)
                    st.add("up:deadline")
                except socket.timeout:
                    st.add("up:stalled")
                except OSError:
                    # the node closed, the tunnel answered RST (or cut the write): the expected end
                    st.add("up:cut-by-node")
                st.add("bytes-out", sent)
                rst_close(s)
            elif kind == "abort-up":
                s = connect(target, 82)
                s.settimeout(10.0)
                st.add("abort-up:opened")
                want = random.randint(100 * 1024, 3 * 1024 * 1024)
                sent = 0
                try:
                    while sent < want and time.time() < deadline:
                        sent += s.send(blob[:min(len(blob), want - sent)])
                except OSError:
                    st.add("abort-up:write-error")
                st.add("bytes-out", sent)
                rst_close(s)
                st.add("abort-up:RST")
            elif kind == "abort-down":
                s = connect(target, 81)
                s.settimeout(10.0)
                st.add("abort-down:opened")
                want = random.randint(50 * 1024, 2 * 1024 * 1024)
                got = 0
                try:
                    while got < want and time.time() < deadline:
                        c = s.recv(262144)
                        if not c:
                            break
                        got += len(c)
                except OSError:
                    st.add("abort-down:read-error")
                st.add("bytes-in", got)
                rst_close(s)
                st.add("abort-down:RST")
        except OSError as e:
            st.add("%s:connect-failed (%s)" % (kind, type(e).__name__))
            time.sleep(0.05)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--ping", action="store_true")
    ap.add_argument("--storm", type=float, default=0, metavar="SECS")
    ap.add_argument("--up", type=int, default=12)
    ap.add_argument("--abort-up", type=int, default=6)
    ap.add_argument("--abort-down", type=int, default=6)
    a = ap.parse_args()
    if a.ping:
        sys.exit(ping(a.target))
    if a.storm <= 0:
        ap.error("need --ping or --storm SECS")
    st = Stats()
    deadline = time.time() + a.storm
    ts = []
    for kind, n in (("up", a.up), ("abort-up", a.abort_up), ("abort-down", a.abort_down)):
        for _ in range(n):
            ts.append(threading.Thread(target=worker, args=(kind, a.target, deadline, st), daemon=True))
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=a.storm + 30)
    print("client: " + " ".join("%s=%d" % kv for kv in sorted(st.d.items())))


main()
