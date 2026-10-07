#!/usr/bin/env python3
"""A fake VLESS node for tests/sigpipe.sh: it closes connections the way a real server under load
does — before the client has finished writing.

The tunnel carries a LAN client's bytes to the node as they arrive from TUN. When the node closes
a connection, the client's TUN queue may still hold packets the stack then writes into the
closed socket. The node closes in two steps: FIN, then RST for every following segment (a closed
socket with unread input answers with a reset). A write to a socket that got both is EPIPE, and
unless SIGPIPE is ignored the process dies. A real node (Xray) does the same when the server
behind it, e.g. iperf3, closes its streams at the end of a test.

The destination port the client names in the VLESS header decides what happens (the address
itself is parsed and dropped, as in tests/fake-vless.py):

    7    line echo: the VLESS response, then reads a line up to \\n, answers "PONG <line>" and
         closes normally — checks that the tunnel is alive;
    80   a sink that closes early: the VLESS response, reads a random number of bytes in
         --early-min..--early-max and closes as described above (shutdown(WR), then close with
         unread input — FIN and an RST right after);
    81   a source: the VLESS response and a data stream until the client leaves;
    82   a sink that does not close: reads to the end of the stream.

security=none and security=tls (TLS 1.3 from the ssl module; the test certificate is
self-signed, the client uses insecure: true). Counters are printed to stderr every second, so
the test sees the load reached the node.
"""
import argparse
import os
import socket
import ssl
import sys
import threading
import time

ADDR_IPV4, ADDR_DOMAIN, ADDR_IPV6 = 1, 2, 3

counters = {}
clock = threading.Lock()


def bump(key, n=1):
    with clock:
        counters[key] = counters.get(key, 0) + n


def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_request(sock):
    """VLESS header: version, UUID, addon length, addons, command, port, address type and body.
    Returns (uuid, command, port) or None."""
    head = recv_exactly(sock, 18)
    if not head or head[0] != 0:
        return None
    uuid, addon_n = head[1:17], head[17]
    if addon_n and recv_exactly(sock, addon_n) is None:
        return None
    tail = recv_exactly(sock, 4)
    if not tail:
        return None
    cmd, port, atype = tail[0], (tail[1] << 8) | tail[2], tail[3]
    if atype == ADDR_IPV4:
        need = 4
    elif atype == ADDR_IPV6:
        need = 16
    elif atype == ADDR_DOMAIN:
        ln = recv_exactly(sock, 1)
        if not ln:
            return None
        need = ln[0]
    else:
        return None
    if recv_exactly(sock, need) is None:
        return None
    return uuid, cmd, port


def close_like_a_busy_server(sock):
    """FIN, then RST: shutdown(WR) sends FIN, close with unread input sends a reset. The client
    first sees end of stream (CLOSE_WAIT), its next segment gets an RST, and the write after
    that gets EPIPE."""
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class Node:
    def __init__(self, a):
        self.uuid = bytes.fromhex(a.uuid.replace("-", ""))
        self.early_min, self.early_max = a.early_min, a.early_max
        self.ctx = None
        if a.tls:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self.ctx.load_cert_chain(a.tls[0], a.tls[1])
        self.rand = os.urandom

    def serve(self, raw):
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock = raw
        try:
            if self.ctx:
                raw.settimeout(10)
                sock = self.ctx.wrap_socket(raw, server_side=True)
            sock.settimeout(30)
            req = read_request(sock)
            if req is None or req[0] != self.uuid:
                bump("refused")
                return
            _, _, port = req
            sock.sendall(b"\x00\x00")
            if port == 7:
                buf = b""
                while not buf.endswith(b"\n"):
                    c = sock.recv(4096)
                    if not c:
                        return
                    buf += c
                sock.sendall(b"PONG " + buf)
                bump("echo")
                time.sleep(0.2)
            elif port == 80:
                span = self.early_max - self.early_min
                want = self.early_min + int.from_bytes(self.rand(4), "big") % max(span, 1)
                got = 0
                while got < want:
                    c = sock.recv(min(262144, want - got))
                    if not c:
                        bump("client-closed-first")
                        return
                    got += len(c)
                bump("closed-early")
                bump("bytes-in", got)
                close_like_a_busy_server(sock)
                sock = None
            elif port == 81:
                chunk = b"\x5a" * 65536
                sent = 0
                try:
                    while True:
                        sock.sendall(chunk)
                        sent += len(chunk)
                except OSError:
                    bump("source-client-left")
                bump("bytes-out", sent)
            elif port == 82:
                got = 0
                while True:
                    c = sock.recv(262144)
                    if not c:
                        break
                    got += len(c)
                bump("sink-drained")
                bump("bytes-in", got)
        except (OSError, ssl.SSLError):
            bump("broken")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"))
    ap.add_argument("--early-min", type=int, default=64 * 1024)
    ap.add_argument("--early-max", type=int, default=1024 * 1024)
    a = ap.parse_args()
    node = Node(a)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((a.bind, a.port))
    ls.listen(512)
    print("ready", flush=True)

    def report():
        while True:
            time.sleep(1)
            with clock:
                line = " ".join("%s=%d" % kv for kv in sorted(counters.items()))
            print("node:", line, file=sys.stderr, flush=True)
    threading.Thread(target=report, daemon=True).start()
    while True:
        c, _ = ls.accept()
        threading.Thread(target=node.serve, args=(c,), daemon=True).start()


main()
