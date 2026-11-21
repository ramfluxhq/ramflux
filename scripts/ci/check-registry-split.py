#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Prove per-crate registries preserve every row of an immutable Git baseline.

Run with --base <commit-before-split>. Git is needed only for this one-time
migration proof, not by either registry loader.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import tomllib


def rows(text, timing):
    if timing:
        return Counter(json.dumps(row, sort_keys=True) for row in tomllib.loads(text).get("site", []))
    # Keep exact row text as well as its fields: even whitespace rewrites fail.
    return Counter(line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="immutable pre-split commit")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    base = subprocess.check_output(["git", "-C", str(root), "rev-parse", "--verify", args.base + "^{commit}"], text=True).strip()
    for old, name, timing in [
        ("ijson_decode_sites.registry", "ijson_decode_sites.registry", False),
        (".config/test-timing-allowlist.toml", "test-timing-allowlist.toml", True),
    ]:
        before = rows(subprocess.check_output(["git", "-C", str(root), "show", base + ":" + old], text=True), timing)
        after = Counter()
        files = sorted(path for top in ("apps", "crates", "tools", "tests") for path in (root / top).rglob(name))
        for path in files:
            after.update(rows(path.read_text(), timing))
        if rows((root / old).read_text(), timing):
            raise SystemExit("FAIL: retired registry contains rows: " + old)
        if before != after:
            raise SystemExit(f"FAIL: {old}: missing={sum((before - after).values())}, added/changed={sum((after - before).values())}")
        print(f"{old}: PASS {sum(before.values())} identical rows in {len(files)} files; added=0 dropped=0 reclassified=0")
    print("registry-split: PASS baseline=" + base)


if __name__ == "__main__":
    main()
