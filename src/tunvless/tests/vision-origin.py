import hashlib, ssl, sys, time, random
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
host, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
BLOCK = bytes(random.getrandbits(8) for _ in range(65536))
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        n = int(q.get("bytes", ["3000000"])[0])
        d = float(q.get("delay", ["0"])[0])
        ch = int(q.get("chunk", ["65536"])[0])
        first = int(q.get("first", ["0"])[0])
        gap = float(q.get("gap", ["0"])[0])
        if d: time.sleep(d)
        head = b"HTTP/1.1 200 OK" + bytes([13,10]) + b"Content-Length: " + str(n).encode() + bytes([13,10,13,10])
        k = min(first, n)
        self.wfile.write(head + BLOCK[:k])
        self.wfile.flush()
        if gap: time.sleep(gap)
        left = n - k
        while left:
            k = min(left, ch)
            self.wfile.write(BLOCK[:k])
            left -= k
    def do_PUT(self):
        h = hashlib.sha256()
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                n = int(self.rfile.readline().split(b";")[0], 16)
                if not n:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                left = n
                while left:
                    d = self.rfile.read(min(left, 65536))
                    if not d:
                        return
                    h.update(d)
                    left -= len(d)
                self.rfile.readline()
        else:
            left = int(self.headers.get("Content-Length", "0"))
            while left:
                d = self.rfile.read(min(left, 65536))
                if not d:
                    return
                h.update(d)
                left -= len(d)
        out = h.hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    do_POST = do_PUT
class S(ThreadingHTTPServer):
    daemon_threads = True
    def get_request(self):
        s, a = self.socket.accept()
        return ctx.wrap_socket(s, server_side=True), a
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
if len(sys.argv) > 6 and sys.argv[6] == "1.2":
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(cert, key)
ctx.num_tickets = int(sys.argv[5]) if len(sys.argv) > 5 else 2
S((host, port), H).serve_forever()
