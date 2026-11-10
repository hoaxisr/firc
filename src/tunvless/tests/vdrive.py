import socket, sys, time
mode, host, port, ms, n = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
k = int(sys.argv[6]) if len(sys.argv) > 6 else 1
gap = int(sys.argv[7]) if len(sys.argv) > 7 else 0
s = socket.socket()
s.settimeout(10)
s.connect((host, port))
print("connect=%.6f" % time.time(), flush=True)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
g = b""
if mode == "greet":
    while not g.endswith(b"\r\n"):
        d = s.recv(100)
        if not d:
            break
        g += d
time.sleep(ms / 1000.0)
msg = b"%08d" % n + b"u" * (n - 8)
cut = [n * i // k for i in range(k + 1)]
for i in range(k):
    if i:
        time.sleep(gap / 1000.0)
    s.sendall(msg[cut[i]:cut[i + 1]])
r = b""
while not r.endswith(b"ok %d" % n):
    d = s.recv(65536)
    if not d:
        break
    r += d
print("%s %s:%d wait=%d n=%d k=%d -> %r%s" % (mode, host, port, ms, n, k, r[-20:], " greet=%r" % g if g else ""))
sys.exit(0 if r == b"ok %d" % n and (mode != "greet" or g == b"220 hi\r\n") else 1)
