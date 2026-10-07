#!/usr/bin/env python3
"""Load for tests/run-xray.sh: long flows both ways and short "pages" that open and close while
those run.

  grpc-load.py --target HOST:PORT --dur SEC [--down N] [--up N] [--rate R] [--kb K] [--report SEC]

The target is tests/grpc-target.py: /big/<MB> sends without end, /up takes an upload.

A failure (exit code 1, reasons on the last "RESULT" line):
  - a short page (GET /pg/<KB>, Connection: close) must arrive WHOLE and close; a truncated, hung
    or reset one is a failure, and there must be none;
  - long flows: each direction must move within every report window (otherwise it "stalled"), and
    no flow may break before the end of the run;
  - every window prints Mbit/s down and up, the number of pages and failures.
"""
import argparse, socket, sys, threading, time, collections

ap = argparse.ArgumentParser()
ap.add_argument('--target', required=True)
ap.add_argument('--dur', type=float, default=190)
ap.add_argument('--down', type=int, default=2, help='long flows down')
ap.add_argument('--up', type=int, default=2, help='long flows up')
ap.add_argument('--rate', type=float, default=10, help='short pages per second')
ap.add_argument('--kb', type=int, default=30)
ap.add_argument('--report', type=float, default=10)
ap.add_argument('--page-timeout', type=float, default=15)
ap.add_argument('--stall', type=float, default=15, help='seconds without movement that count as a stall')
a = ap.parse_args()

host, port = a.target.rsplit(':', 1)
port = int(port)
lock = threading.Lock()
t_start = time.time()
t_end = t_start + a.dur
cnt = {'down': 0, 'up': 0}                  # bytes in total
last_move = {'down': time.time(), 'up': time.time()}
pages = {'ok': 0, 'fail': 0, 'why': collections.Counter()}
long_dead = []                              # flows that broke before the end
stalls = []

def conn():
    s = socket.create_connection((host, port), timeout=20)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(30)
    return s

def down_flow(i):
    try:
        s = conn()
        s.sendall(('GET /big/100000 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n').encode())
        while time.time() < t_end:
            d = s.recv(1 << 20)
            if not d:
                raise OSError('EOF from the server')
            with lock:
                cnt['down'] += len(d)
                last_move['down'] = time.time()
        s.close()
    except Exception as e:
        if time.time() < t_end - 1:
            with lock:
                long_dead.append('down#%d: %s: %s' % (i, type(e).__name__, e))

def up_flow(i):
    try:
        s = conn()
        s.sendall(('POST /up HTTP/1.1\r\nHost: t\r\nContent-Length: 100000000000\r\nConnection: close\r\n\r\n').encode())
        blk = b'u' * (256 * 1024)
        while time.time() < t_end:
            s.sendall(blk)
            with lock:
                cnt['up'] += len(blk)
                last_move['up'] = time.time()
        s.close()
    except Exception as e:
        if time.time() < t_end - 1:
            with lock:
                long_dead.append('up#%d: %s: %s' % (i, type(e).__name__, e))

def page():
    why = None
    try:
        s = socket.create_connection((host, port), timeout=a.page_timeout)
        s.settimeout(a.page_timeout)
        s.sendall(('GET /pg/%d HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n' % a.kb).encode())
        got = 0
        while True:
            d = s.recv(65536)
            if not d:
                break
            got += len(d)
        s.close()
        if got < a.kb * 1024:
            why = 'truncated (%d of %d)' % (got, a.kb * 1024)
    except socket.timeout:
        why = 'hung (no end within %gs)' % a.page_timeout
    except Exception as e:
        why = '%s' % type(e).__name__
    with lock:
        if why:
            pages['fail'] += 1
            pages['why'][why.split(' (')[0]] += 1
        else:
            pages['ok'] += 1

threads = []
for i in range(a.down):
    t = threading.Thread(target=down_flow, args=(i,), daemon=True); t.start(); threads.append(t)
for i in range(a.up):
    t = threading.Thread(target=up_flow, args=(i,), daemon=True); t.start(); threads.append(t)

prev = dict(cnt); prev_t = time.time()
next_page = time.time() + 1.0         # pages start once the long flows are up to speed
next_rep = time.time() + a.report
page_threads = []
while time.time() < t_end:
    now = time.time()
    if a.rate > 0 and now >= next_page:
        t = threading.Thread(target=page, daemon=True); t.start(); page_threads.append(t)
        next_page += 1.0 / a.rate
    if now >= next_rep:
        with lock:
            dt = now - prev_t
            dn = (cnt['down'] - prev['down']) * 8 / dt / 1e6
            up = (cnt['up'] - prev['up']) * 8 / dt / 1e6
            prev = dict(cnt); prev_t = now
            print('t=%4.0fs down %7.1f Mbit/s  up %7.1f Mbit/s  pages %d (failures %d)' % (
                now - t_start, dn, up, pages['ok'] + pages['fail'], pages['fail']), flush=True)
            for k in ('down', 'up'):
                n = a.down if k == 'down' else a.up
                if n and now - last_move[k] > a.stall:
                    stalls.append('%s: no movement for %.0f s at second %.0f' % (k, now - last_move[k], now - t_start))
        next_rep += a.report
    time.sleep(0.005)

for t in page_threads:
    t.join(timeout=a.page_timeout + 2)

bad = []
if pages['fail']:
    bad.append('failed pages: %d (%s)' % (pages['fail'], dict(pages['why'])))
if long_dead:
    bad.append('long flows broke: ' + '; '.join(long_dead[:4]))
if stalls:
    bad.append('a flow stalled: ' + '; '.join(stalls[:3]))
if a.down and cnt['down'] == 0:
    bad.append('not a byte went down')
if a.up and cnt['up'] == 0:
    bad.append('not a byte went up')
print('RESULT: pages %d ok / %d failed; %.0f MB down, %.0f MB up; %s' % (
    pages['ok'], pages['fail'], cnt['down'] / 1e6, cnt['up'] / 1e6,
    'FAIL: ' + ' | '.join(bad) if bad else 'no failures'), flush=True)
sys.exit(1 if bad else 0)
