#!/usr/bin/env python3
"""Checks that docs/swagger.yaml names every HTTP route the daemon registers, and no others."""

import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - the CI image has it
    sys.exit("PyYAML is needed: pip install pyyaml")

ROOT = pathlib.Path(__file__).resolve().parents[2]
SWAGGER = ROOT / "docs" / "swagger.yaml"
API_DIR = ROOT / "src" / "backend-c" / "src" / "api"
MAIN_C = ROOT / "src" / "backend-c" / "src" / "main" / "main.c"

# The handle is any identifier; an unknown helper name is an error, not a dropped route.
HELPER = re.compile(r'\b(must_route\w*)\s*\(\s*\w+\s*,\s*"([A-Z]+)"\s*,\s*"([^"]+)"')

# Must count the same as HELPER: an unreadable call would be a route nobody checks.
ANY_CALL = re.compile(r"\bmust_route\w*\s*\(\s*\w+\s*,")

PUBLIC_HELPER = "must_route"

HAND = re.compile(r'firc_httpd_route\s*\(\s*[\w.>-]+\s*,\s*"([A-Z]+)"\s*,\s*"([^"]+)"')

# Path-item keys like `parameters` are not operations.
METHODS = {"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"}


def registered() -> tuple:
    """(routes, complaints)."""
    public, problems = set(), []
    for path in sorted(API_DIR.glob("*.c")):
        text = path.read_text(encoding="utf-8")
        matches = HELPER.findall(text)
        seen = len(ANY_CALL.findall(text))
        if seen != len(matches):
            problems.append(
                f"{path.name}: {seen} must_route calls, {len(matches)} of them readable "
                "-- one is written in a form this checker cannot follow"
            )
        for helper, method, pattern in matches:
            if helper == PUBLIC_HELPER:
                public.add((method, pattern))
            else:
                problems.append(
                    f"{path.name}: {helper}() is not a must_route helper this checker "
                    "knows -- has one been renamed?"
                )
    return public, problems


def hand_registered() -> set:
    """Routes main.c registers itself, on either listener."""
    return set(HAND.findall(MAIN_C.read_text(encoding="utf-8")))


def documented() -> set:
    spec = yaml.safe_load(SWAGGER.read_text(encoding="utf-8"))
    found = set()
    for pattern, ops in (spec.get("paths") or {}).items():
        for key in ops or {}:
            if key.upper() in METHODS:
                found.add((key.upper(), pattern))
    return found


def main() -> int:
    public, problems = registered()
    public |= hand_registered()

    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 2
    if not public:
        print("no routes found -- has must_route been renamed?", file=sys.stderr)
        return 2
    doc = documented()

    missing = sorted(public - doc)
    extra = sorted(doc - public)
    for method, pattern in missing:
        print(f"served but not in swagger.yaml: {method} {pattern}", file=sys.stderr)
    for method, pattern in extra:
        print(f"in swagger.yaml but not served: {method} {pattern}", file=sys.stderr)
    if missing or extra:
        print(
            f"\n{len(public)} routes registered, {len(doc)} documented. "
            "docs/swagger.yaml is the API reference; the registrations are the "
            "source of truth.",
            file=sys.stderr,
        )
        return 1
    print(f"swagger.yaml names all {len(public)} registered routes and no others")
    return 0


if __name__ == "__main__":
    sys.exit(main())
