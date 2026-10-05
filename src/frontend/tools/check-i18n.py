#!/usr/bin/env python3
"""Every t() key the UI asks for must exist in every locale, and vice versa.

A key that is missing falls back to itself, so an untranslated string is
invisible in English and silently English everywhere else -- which is how
eighteen keys drifted out of ru.json without anyone noticing. A key that is
present and unused is the same drift in the other direction.

Concatenation inside t() is a third form of the same bug: `t("Imported: " +
n)` looks up "Imported: 42", which no locale can contain. That is an error
here rather than a missing key, because no amount of translating fixes it.
"""
import json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
LOCALES = ROOT / "src" / "locales"

OPEN = re.compile(r"\bt\(")
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
CONCAT = re.compile(r'\bt\(\s*"(?:[^"\\]|\\.)*"\s*\+')


def keys_in(text: str):
    """Every string literal inside a t(...) call, ternaries included.

    `t(cond ? "Disable Rule" : "Enable Rule")` is the common shape here, and
    a regex anchored on `t("` misses both arms -- which reads as two dead
    locale entries and sends someone to delete a translation that is in use.
    """
    for m in OPEN.finditer(text):
        i, depth = m.end(), 1
        while i < len(text) and depth:
            c = text[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == '"':
                lit = STRING.match(text, i)
                if lit is None:
                    break
                yield lit.group(1)
                i = lit.end()
                continue
            i += 1

def main() -> int:
    used, bad = set(), []
    for path in sorted(SRC.rglob("*")):
        if path.suffix not in (".ts", ".svelte") or "locales" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for m in CONCAT.finditer(text):
            line = text[: m.start()].count("\n") + 1
            bad.append(f"{path.relative_to(ROOT)}:{line}: t() called on a concatenation -- "
                       "the key can never be in a locale file")
        used.update(keys_in(text))

    rc = 0
    for line in bad:
        print(line, file=sys.stderr)
        rc = 1
    for locale in sorted(LOCALES.glob("*.json")):
        have = set(json.loads(locale.read_text(encoding="utf-8")))
        missing = sorted(used - have)
        unused = sorted(have - used)
        for k in missing:
            print(f"{locale.name}: missing {k!r}", file=sys.stderr)
        for k in unused:
            print(f"{locale.name}: unused {k!r}", file=sys.stderr)
        if missing or unused:
            rc = 1
    if rc == 0:
        print(f"{len(used)} keys, every locale complete and nothing dead")
    return rc

if __name__ == "__main__":
    sys.exit(main())
