import socket, sys, threading
host = sys.argv[1]
def one(c, greet):
    try:
        c.settimeout(10)
        if greet:
            c.sendall(b"220 hi\r\n")
        b = b""
        while len(b) < 8 or len(b) < int(b[:8]):
            d = c.recv(65536)
            if not d:
                break
            b += d
        c.sendall(b"ok %d" % len(b))
    except (OSError, ValueError):
        pass
    finally:
        c.close()
def serve(port, greet):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port))
    ls.listen(64)
    while True:
        c, _ = ls.accept()
        threading.Thread(target=one, args=(c, greet), daemon=True).start()
threading.Thread(target=serve, args=(8080, False), daemon=True).start()
serve(2222, True)
