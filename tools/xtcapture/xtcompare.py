#!/usr/bin/env python3
import os
import struct
import sys


def entries(blob, v6):
    at_t = 140 if v6 else 88
    off = 0
    while off < len(blob):
        toff, nxt = struct.unpack_from('<HH', blob, off + at_t)
        if nxt == 0:
            raise SystemExit('the entry at %d has next_offset 0' % off)
        yield off, toff, nxt
        off += nxt


def clean(path, v6, any_base):
    b = bytearray(open(path, 'rb').read())
    hdr, blob = b[:96], b[96:]
    hdr[88:96] = bytes(8)
    if any_base:
        hdr[84:88] = bytes(4)
    eh = 168 if v6 else 112
    at_from = 144 if v6 else 92
    at_cnt = 152 if v6 else 96
    for off, toff, _ in list(entries(blob, v6)):
        blob[off + at_from:off + at_from + 4] = bytes(4)
        blob[off + at_cnt:off + at_cnt + 16] = bytes(16)
        exts = []
        m = eh
        while m < toff:
            exts.append(m)
            m += struct.unpack_from('<H', blob, off + m)[0]
        exts.append(toff)
        for x in exts:
            name = blob[off + x + 2:off + x + 31]
            n = name.find(0)
            if n >= 0:
                blob[off + x + 2 + n:off + x + 31] = bytes(29 - n)
    return bytes(hdr), bytes(blob)


def counters_len(path):
    c = path[:-len('replace.bin')] + 'counters.bin'
    return os.path.getsize(c) if path.endswith('replace.bin') and os.path.exists(c) else None


def main():
    args = sys.argv[1:]
    any_base = bool(args) and args[0] == '--any-base'
    if any_base:
        args = args[1:]
    if len(args) != 3 or args[2] not in ('v4', 'v6'):
        print('usage: xtcompare.py [--any-base] A.replace.bin B.replace.bin v4|v6', file=sys.stderr)
        return 2
    v6 = args[2] == 'v6'
    ha, ba = clean(args[0], v6, any_base)
    hb, bb = clean(args[1], v6, any_base)
    if ha != hb:
        print('the headers differ')
        return 1
    if not any_base and counters_len(args[0]) != counters_len(args[1]):
        print('the counters files differ in length')
        return 1
    if ba == bb:
        return 0
    for (oa, _, na), (ob, _, nb) in zip(entries(ba, v6), entries(bb, v6)):
        if ba[oa:oa + na] != bb[ob:ob + nb]:
            print('first difference in the entry at %d' % oa)
            print(ba[oa:oa + na].hex())
            print(bb[ob:ob + nb].hex())
            return 1
    print('the blobs differ in length')
    return 1


sys.exit(main())
