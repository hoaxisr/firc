import sys
b = open(sys.argv[1], "rb").read()
after = "--after-handshake" in sys.argv[2:]
r, off = [], 0
while off + 5 <= len(b):
    r.append((b[off], b[off + 3] << 8 | b[off + 4]))
    off += 5 + r[-1][1]
if after:
    i = 0
    while i < len(r) and r[i][0] in (20, 22):
        i += 1
    r = r[i + 1:]
print(" ".join(str(n) for _, n in r))
