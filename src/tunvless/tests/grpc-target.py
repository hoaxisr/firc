#!/usr/bin/env python3
"""Target for tests/run-xray.sh: HTTP on one address, no keep-alive.

  grpc-target.py ADDRESS PORT

  /pg/<KB>   a page of that size, then the connection closes (Connection: close);
  /big/<MB>  a large response, read for as long as needed (a long download);
  /up        takes an upload: the body is read and thrown away (a long upload).

The response and the close come back to back, as 1.1.1.1:80 answers the node probe ("GET /" with
"Connection: close"): the gRPC server then ends the stream with the data, the closing HEADERS and
RST_STREAM in one flush (see tests/grpcmatch.c)."""
import socket, sys, threading

def handle(c):
    try:
        c.settimeout(120)
        buf = b''
        while b'\r\n\r\n' not in buf:
            d = c.recv(65536)
            if not d:
                return
            buf += d
        head, _, rest = buf.partition(b'\r\n\r\n')
        parts = head.split(b'\r\n', 1)[0].decode('latin1').split()
        path = parts[1] if len(parts) > 1 else '/'
        if path.startswith('/up'):
            cl = 0
            for h in head.split(b'\r\n')[1:]:
                if h.lower().startswith(b'content-length:'):
                    cl = int(h.split(b':', 1)[1])
            got = len(rest)
            while got < cl:
                d = c.recv(1 << 20)
                if not d:
                    break
                got += len(d)
            body = b'ok %d' % got
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
            return
        n = 2
        if path.startswith('/pg/'):
            n = int(path[4:]) * 1024
        elif path.startswith('/big/'):
            n = int(path[5:]) * 1024 * 1024
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % n)
        blk = b'x' * 65536
        sent = 0
        while sent < n:
            k = min(len(blk), n - sent)
            c.sendall(blk[:k])
            sent += k
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass

def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[1], int(sys.argv[2])))
    s.listen(4096)
    while True:
        c, _ = s.accept()
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=handle, args=(c,), daemon=True).start()

main()
