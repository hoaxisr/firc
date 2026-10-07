#!/usr/bin/env python3
"""A minimal VLESS server without TLS, to test the whole tunnel without a real node.

What the tunnel stack does (src/tunnel/stack.c: TCP synthesis, retransmission, spreading over
threads) can only be tested on live traffic. With a real node every check depends on someone
else's server, and "did not recover after loss" cannot be told from "the node went down". This
server speaks exactly the part of VLESS that is needed:

    request:  version(1) UUID(16) addon_len(1) addon command(1) port(2) addr_type(1) address
    response: version(1)=0 addon_len(1)=0, then data

security=none and type=tcp, so no Reality and no HTTP/2: this tests the tunnel loop, not the
cryptography.

Where the client asked to connect DOES NOT MATTER: the address is parsed and dropped, and the
answer is always an HTTP response of the given size, so the test does not depend on the
internet either.
"""
import argparse
import os
import select
import socket
import socketserver
import sys
import threading
import time

ADDR_IPV4, ADDR_DOMAIN, ADDR_IPV6 = 1, 2, 3
CMD_TCP, CMD_UDP = 1, 2

# The body of every answer: this filler over and over (with --kbps, its first chunk bytes over
# and over). Fixed, because generating 64 KB per chunk made Python, not the tunnel, the
# bottleneck; at module level, so a test can rebuild the body and compare what it got
# (tests/run-tunnel.sh).
FILLER = bytes(i * 131 % 251 for i in range(64 * 1024))


def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_request(sock):
    """Parse the request header. Returns (uuid, cmd, port, address) or None.

    The address is a string (IPv4, IPv6 or a name); only the UDP relay (--udp-relay) needs it,
    the other modes drop it."""
    head = recv_exactly(sock, 18)           # version + UUID + addon_len
    if not head or head[0] != 0:
        return None
    uuid, addon_n = head[1:17], head[17]
    if addon_n and recv_exactly(sock, addon_n) is None:
        return None
    tail = recv_exactly(sock, 4)            # command + port + addr_type
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
    raw = recv_exactly(sock, need)
    if raw is None:
        return None
    if atype == ADDR_IPV4:
        addr = socket.inet_ntop(socket.AF_INET, raw)
    elif atype == ADDR_IPV6:
        addr = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        addr = raw.decode("ascii", "replace")
    return uuid, cmd, port, addr


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        req = read_request(sock)
        if req is None:
            return
        uuid, cmd, port, addr = req
        if uuid != self.server.uuid:
            return                          # wrong key: stay silent, like a real server

        if cmd == CMD_UDP:
            if self.server.udp_relay:
                self.relay_udp(sock, addr, port)
            else:
                self.serve_udp(sock, addr, port)
            return

        # Port 9 (discard): a connection that stays OPEN and silent.
        #
        # This reproduces the main load of a weak router: a browser keeps dozens of connections
        # alive between requests (keep-alive), and the cost of a loop turn grows with their
        # number, not with traffic. Without them a benchmark measures an empty table, which is
        # not what a real router runs into.
        if port == 9:
            try:
                while sock.recv(65536):
                    pass
            except OSError:
                pass
            return

        # Port 7 (echo): the answer comes ONLY after the request is read up to a newline.
        #
        # For tests/run-tunnel-fin.sh: the client sends a line and FIN at once, often in one
        # segment, and the answer must reach the half the client has already closed. The
        # default mode below answers without looking at the request and would miss a lost tail.
        if port == 7:
            sock.sendall(b"\x00\x00")
            buf = b""
            try:
                while not buf.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                if buf.endswith(b"\n"):
                    sock.sendall(b"ECHO " + buf)
                sock.shutdown(socket.SHUT_WR)
                while sock.recv(65536):
                    pass
            except OSError:
                pass
            return

        # The rest of the request must be READ, not ignored: after the VLESS header the client
        # sends the HTTP request itself. Closing with unread data makes Linux send RST instead
        # of FIN, and RST discards whatever the receiver has not yet taken from its buffer: the
        # end of every download is lost, which looks exactly like the tunnel cutting it short.
        def drain():
            try:
                while sock.recv(65536):
                    pass
            except OSError:
                pass
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()

        # The VLESS response, then HTTP at once. A separate write, as Xray does.
        sock.sendall(b"\x00\x00")

        body_n = self.server.body_n
        head = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % body_n
        )
        sent = 0
        try:
            sock.sendall(head)
            chunk = 64 * 1024
            # --kbps: send no faster than this, so a download is long enough for a node to
            # "die" in the middle of a transfer, not after it.
            rate = self.server.kbps * 1024
            if rate:
                chunk = min(chunk, max(1024, rate // 10))
            t0 = time.monotonic()
            while sent < body_n:
                n = min(chunk, body_n - sent)
                sock.sendall(self.server.filler[:n])
                sent += n
                if rate:
                    ahead = sent / rate - (time.monotonic() - t0)
                    if ahead > 0:
                        time.sleep(ahead)
        except Exception as e:
            # ALWAYS print the reason: a silent break here looks like a break in the tunnel.
            print("fake-vless: cut at %d of %d bytes: %r" % (sent, body_n, e),
                  file=sys.stderr, flush=True)
            return
        # Close our half and wait for the client to close its own: then FIN goes out, not RST,
        # and everything sent arrives.
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        reader.join(timeout=10)
        print("fake-vless: sent %d bytes" % sent, file=sys.stderr, flush=True)


    def serve_udp(self, sock, addr, port):
        """A UDP stream (command 2): datagrams with a two-byte length, ECHOED back.

        An echo, because what is tested is the transfer itself: boundaries kept, bytes intact,
        no two datagrams merged into one.

        The answer reuses the length that ARRIVED: computing its own would hide exactly the
        error this checks for (a lost or shifted length).

        The destination from the request is logged as the stream opens: the echo does not depend
        on it, so the log is the only place a test can see which streams the tunnel opened.
        """
        print("fake-vless: UDP stream to %s:%d" % (addr, port), file=sys.stderr, flush=True)
        sock.sendall(b"\x00\x00")               # VLESS response: version, no addon
        buf = b""
        n_dg = 0
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
                # What comes within 20 ms goes back together, so a burst is echoed as one run.
                while select.select([sock], [], [], 0.02)[0]:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                frames = []
                while len(buf) >= 2 and len(buf) >= 2 + ((buf[0] << 8) | buf[1]):
                    want = (buf[0] << 8) | buf[1]
                    # Same framing back. A zero-length datagram is legal, and so is its echo.
                    frames.append(buf[:2 + want])
                    buf = buf[2 + want:]
                n_dg += len(frames)
                self.echo_in_pieces(sock, frames)
        except OSError:
            pass
        print("fake-vless: UDP stream closed, %d datagrams" % n_dg, file=sys.stderr, flush=True)

    @staticmethod
    def echo_in_pieces(sock, frames):
        """Send framed datagrams back in writes cut where a TLS node may cut its records, with a
        pause after each, so the tunnel reads every piece as a record of its own.

        Every other datagram is cut twice: between its two length bytes and in the middle. A
        datagram that is not cut rides whole in the record with the tail of the one before it and
        the first byte of the next. So records end between length bytes and inside a datagram,
        and one record brings parts of three datagrams; a local echo in one write per datagram
        would show none of it.
        """
        out = b"".join(frames)
        if not out:
            return
        cuts, at = [], 0
        for i, f in enumerate(frames):
            if i % 2 == 0:
                cuts += [at + 1, at + 2 + (len(f) - 2) // 2]
            at += len(f)
        prev = 0
        for c in sorted(set(c for c in cuts if 0 < c < len(out))) + [len(out)]:
            sock.sendall(out[prev:c])
            time.sleep(0.005)
            prev = c


    def relay_udp(self, sock, addr, port):
        """A UDP stream with REAL forwarding (--udp-relay): datagrams go where the client
        asked, answers come back in the same framing.

        For a protocol with a handshake inside UDP an echo is useless: it would return the
        client's own handshake, so such a test needs a real peer behind the server."""
        sock.sendall(b"\x00\x00")
        fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
        u = socket.socket(fam, socket.SOCK_DGRAM)
        u.connect((addr, port))
        stop = threading.Event()

        def back():
            try:
                while not stop.is_set():
                    u.settimeout(1.0)
                    try:
                        d = u.recv(65535)
                    except socket.timeout:
                        continue
                    sock.sendall(bytes([len(d) >> 8, len(d) & 255]) + d)
            except OSError:
                pass
        t = threading.Thread(target=back, daemon=True)
        t.start()
        buf = b""
        n_dg = 0
        try:
            while True:
                if len(buf) >= 2 and len(buf) >= 2 + ((buf[0] << 8) | buf[1]):
                    want = (buf[0] << 8) | buf[1]
                    u.send(buf[2:2 + want])
                    buf = buf[2 + want:]
                    n_dg += 1
                    continue
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        stop.set()
        u.close()
        print("fake-vless: UDP relay to %s:%d closed, %d datagrams" % (addr, port, n_dg),
              file=sys.stderr, flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10800)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--mb", type=int, default=20, help="megabytes to send in each answer")
    # The listening address is a parameter, not a fixed 127.0.0.1: tunvless rejects a node on
    # loopback as one with no peer (sublink.c, sl_host_leads_nowhere), so the test server
    # listens on an ordinary address the tunnel accepts as a node.
    ap.add_argument("--bind", default="127.0.0.1", help="listening address")
    ap.add_argument("--kbps", type=int, default=0, help="send rate limit, KB/s (0 — none)")
    ap.add_argument("--udp-relay", action="store_true",
                    help="forward UDP (command 2) to the address in the request instead of echoing")
    a = ap.parse_args()

    srv = Server((a.bind, a.port), Handler)
    srv.uuid = bytes.fromhex(a.uuid.replace("-", ""))
    srv.body_n = a.mb * 1024 * 1024
    srv.udp_relay = a.udp_relay
    srv.kbps = a.kbps
    srv.filler = FILLER
    print("fake-vless: %s:%d, serves %d MB" % (a.bind, a.port, a.mb), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
