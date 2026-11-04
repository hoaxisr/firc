#!/usr/bin/env python3
import argparse, os, socket, threading

ap = argparse.ArgumentParser()
ap.add_argument('--listen', required=True)
ap.add_argument('--to', required=True)
ap.add_argument('--dir', required=True)
ap.add_argument('--cap', type=int, default=1 << 62)
a = ap.parse_args()

def addr(s):
    h, p = s.rsplit(':', 1)
    return h, int(p)

def pump(src, dst, path, cap):
    with open(path, 'wb', buffering=0) as f:
        kept = 0
        try:
            while True:
                d = src.recv(65536)
                if not d:
                    break
                if kept < cap:
                    f.write(d[:cap - kept])
                    kept += min(len(d), cap - kept)
                dst.sendall(d)
        except OSError:
            pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass

def serve(c, n):
    try:
        u = socket.create_connection(addr(a.to), 10)
    except OSError:
        c.close()
        return
    u.settimeout(None)
    for s in (c, u):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    base = os.path.join(a.dir, str(n))
    t = threading.Thread(target=pump, args=(u, c, base + '.s2c', 65536), daemon=True)
    t.start()
    pump(c, u, base + '.c2s', a.cap)
    t.join()
    c.close()
    u.close()

os.makedirs(a.dir, exist_ok=True)
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(addr(a.listen))
ls.listen(512)
n = 0
while True:
    c, _ = ls.accept()
    n += 1
    threading.Thread(target=serve, args=(c, n), daemon=True).start()
