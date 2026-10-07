#!/usr/bin/env python3
"""Compare the CONTENTS of two ClientHellos (ours and the uTLS reference): cipher suites, the set
of extensions with their lengths, groups, signature algorithms, key_share. Extension order is not
compared: Chrome and uTLS shuffle it on every connection. Exit code 1 — a mismatch.

    hellostruct.py reference.bin ours.bin [--show]

The reference comes from tests/utls/hello.go, our Hello from `out/tests/hellofreeze --raw-pq file`.
uTLS randomises the ECH and padding lengths within bounds, so extension sizes are compared, not
values. Checked 2026-09-30: uTLS Chrome 133 (HelloChrome_Auto) and our hybrid Hello have the same
17 extensions of the same lengths, 1757 bytes."""
import struct, sys

def grease(x): return (x & 0x0f0f) == 0x0a0a and (x >> 8) == (x & 0xff)
def norm(t): return 'GREASE' if grease(t) else '%04x' % t

def parse(b):
    assert b[0] == 0x16 and b[5] == 1
    p = 9 + 2 + 32
    p += 1 + b[p]
    cl = struct.unpack('>H', b[p:p+2])[0]; p += 2
    suites = [norm(struct.unpack('>H', b[p+i:p+i+2])[0]) for i in range(0, cl, 2)]; p += cl
    p += 1 + b[p]
    el = struct.unpack('>H', b[p:p+2])[0]; p += 2
    exts = {}
    order = []
    end = p + el
    while p < end:
        t, l = struct.unpack('>HH', b[p:p+4])
        exts.setdefault(norm(t), []).append(b[p+4:p+4+l]); order.append(norm(t)); p += 4 + l
    return suites, exts, order

def describe(exts):
    out = {}
    for t, lst in exts.items():
        for i, d in enumerate(lst):
            x = ''
            if t == '000a': x = ' '.join(norm(struct.unpack('>H', d[2+k:4+k])[0]) for k in range(0, len(d)-2, 2))
            elif t == '000d': x = d[2:].hex()
            elif t == '002b': x = ' '.join(norm(struct.unpack('>H', d[1+k:3+k])[0]) for k in range(0, len(d)-1, 2))
            elif t == '0033':
                q, ks = 2, []
                while q < len(d):
                    g, l = struct.unpack('>HH', d[q:q+4]); ks.append('%s:%d' % (norm(g), l)); q += 4 + l
                x = ' '.join(ks)
            elif t == '0010': x = d[2:].hex()
            elif t in ('001b', '44cd'): x = d.hex()
            out['%s#%d' % (t, i)] = (len(d), x)
    return out

a = parse(open(sys.argv[1], 'rb').read()); b = parse(open(sys.argv[2], 'rb').read())
bad = 0
if a[0] != b[0]: print('cipher suites DIFFER:\n ', a[0], '\n ', b[0]); bad = 1
da, db = describe(a[1]), describe(b[1])
for k in sorted(set(da) | set(db)):
    if da.get(k) != db.get(k):
        print('MISMATCH %s: reference=%s ours=%s' % (k, da.get(k), db.get(k))); bad = 1
if '--show' in sys.argv:
    for k in sorted(da): print(k, da[k])
print('Hello contents match the reference' if not bad else 'Hello contents DIFFER')
sys.exit(bad)
