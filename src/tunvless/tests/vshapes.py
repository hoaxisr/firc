import hashlib, os, select, socket, ssl, sys, time
mode, host, port, sni, cafile, size = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], int(sys.argv[6])
body = os.urandom(size)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations(cafile)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
if mode == "nocss":
    ctx.options &= ~ssl.OP_ENABLE_MIDDLEBOX_COMPAT
inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
o = ctx.wrap_bio(inc, out, server_hostname=sni)
s = socket.socket()
s.settimeout(10)
s.connect((host, port))
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
end = time.monotonic() + 30
def flush():
    d = out.read()
    if d:
        s.sendall(d)
    return len(d)
def pull():
    if time.monotonic() > end:
        raise TimeoutError("no answer in 30 s")
    d = s.recv(65536)
    if not d:
        raise ConnectionError("closed by the peer")
    inc.write(d)
def wr(d):
    o.write(d)
    return out.read()
while True:
    try:
        o.do_handshake()
        break
    except ssl.SSLWantReadError:
        flush()
        pull()
second = out.read()
head = b"PUT /up HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n" % (sni.encode(), size)
if mode == "joined":
    s.sendall(second + wr(head))
else:
    s.sendall(second)
    time.sleep(0.05)
    s.sendall(wr(head))
time.sleep(0.05)
s.sendall(wr(body[:1000]))
time.sleep(0.05)
for i in range(1000, size, 16384):
    s.sendall(wr(body[i:i + 16384]))
r = b""
while b"\r\n\r\n" not in r or len(r.split(b"\r\n\r\n", 1)[1]) < 64:
    try:
        d = o.read(65536)
        if not d:
            break
        r += d
    except ssl.SSLWantReadError:
        pull()
got = r.split(b"\r\n\r\n", 1)[-1][:64].decode("latin1")
want = hashlib.sha256(body).hexdigest()
print("%s: second flight %d B, answered %s, local %s" % (mode, len(second), got, want))
s.close()
sys.exit(0 if got == want else 1)
