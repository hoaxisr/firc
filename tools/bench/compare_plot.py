#!/usr/bin/env python3
import argparse
import json
import math
import statistics
from pathlib import Path
from xml.sax.saxutils import escape

SERIES = (("original", "оригинал (Go)", "#d9822b"), ("mt-c", "mt-c", "#4f73c6"), ("firc", "firc", "#2e9e6b"))
W, H, L, R, T, B = 900, 420, 90, 800, 70, 350
CHARTS = (
    ("rps", "Успешные DNS-запросы в секунду, UDP, 10 клиентов", "запросов/с", "benchmark-throughput.svg", True),
    ("cpu_ms", "Процессорное время демона на успешный запрос", "мс CPU", "benchmark-cpu.svg", True),
    ("rss", "Пиковая память демона (VmHWM) за прогон", "МиБ", "benchmark-memory.svg", False),
)


def load(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        d = json.loads(line)
        if d.get("metric") != "load" or d.get("scenario") != "capacity" or d.get("proto") != "udp":
            continue
        values = {
            "rps": d["rps"],
            "cpu_ms": d["cpu_pct"] * 10 / d["rps"],
            "rss": d["after"]["VmHWM"] / 1024,
        }
        for k, v in values.items():
            out.setdefault((k, d["backend"], d["rules"]), []).append(v)
    return out


def fmt(v):
    return f"{v:.0f}" if v >= 100 else f"{v:.2g}" if v < 1 else f"{v:.1f}"


def chart(data, key, title, unit, log):
    rules = sorted({r for (k, _, r) in data if k == key})
    vals = [v for (k, _, _), vs in data.items() if k == key for v in vs]
    if log:
        lo, hi = math.floor(math.log10(min(vals))), math.ceil(math.log10(max(vals)))
        ticks = [10 ** p for p in range(lo, hi + 1)]
        f = math.log10
    else:
        lo, hi = 0, 5 * math.ceil(max(vals) / 5)
        ticks = list(range(0, hi + 1, 5))
        f = lambda v: v
    x = lambda r: L + (R - L) * (math.log10(r) - math.log10(rules[0])) / (math.log10(rules[-1]) - math.log10(rules[0]))
    y = lambda v: B - (B - T) * (f(v) - lo) / (hi - lo)
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" role="img">',
         f"<title>{escape(title)}</title>",
         "<style>text{font:14px sans-serif;fill:#57606a}.g{stroke:#8884;stroke-width:1}"
         "@media (prefers-color-scheme:dark){text{fill:#c9d1d9}}</style>",
         f'<text x="{L}" y="30" style="font-size:17px;font-weight:600">{escape(title)}</text>']
    for t in ticks:
        s.append(f'<line class="g" x1="{L}" x2="{R}" y1="{y(t):.1f}" y2="{y(t):.1f}"/>')
        s.append(f'<text x="{L - 8}" y="{y(t) + 5:.1f}" text-anchor="end">{t:g}</text>')
    for r in rules:
        s.append(f'<text x="{x(r):.1f}" y="{B + 24}" text-anchor="middle">{r:,}</text>'.replace(",", " "))
    s.append(f'<text x="{(L + R) / 2}" y="{B + 50}" text-anchor="middle">число правил</text>')
    s.append(f'<text x="20" y="{(T + B) / 2}" transform="rotate(-90 20 {(T + B) / 2})" text-anchor="middle">{unit}</text>')
    for i, (backend, label, color) in enumerate(SERIES):
        pts = [(r, data[(key, backend, r)]) for r in rules if (key, backend, r) in data]
        path = " ".join(f"{x(r):.1f},{y(statistics.median(v)):.1f}" for r, v in pts)
        s.append(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="3"/>')
        for r, v in pts:
            m = statistics.median(v)
            s.append(f'<line x1="{x(r):.1f}" x2="{x(r):.1f}" y1="{y(min(v)):.1f}" y2="{y(max(v)):.1f}" stroke="{color}" stroke-width="2"/>')
            s.append(f'<circle cx="{x(r):.1f}" cy="{y(m):.1f}" r="5" fill="{color}"/>')
            near = [statistics.median(data[(key, o, r)]) for o, _, _ in SERIES
                    if o != backend and (key, o, r) in data]
            near = [n for n in near if max(n, m) / min(n, m) < 2]
            dy = -10 if m >= max(near, default=m) else 20
            s.append(f'<text x="{x(r) + 8:.1f}" y="{y(m) + dy:.1f}">{fmt(m)}</text>')
        s.append(f'<rect x="{L + 160 * i}" y="45" width="14" height="14" fill="{color}"/>')
        s.append(f'<text x="{L + 160 * i + 20}" y="57">{escape(label)}</text>')
    s.append("</svg>")
    return "\n".join(s) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--output", default="img")
    a = ap.parse_args()
    data = load(a.results)
    for key, title, unit, name, log in CHARTS:
        (Path(a.output) / name).write_text(chart(data, key, title, unit, log))


if __name__ == "__main__":
    main()
