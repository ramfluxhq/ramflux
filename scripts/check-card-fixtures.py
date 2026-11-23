#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""The host-fixture index covers every catalog kind and variant enum.

LOCALE_FIXTURE_HOOK: published locale stays en until the resolver accepts the
launch locales. This script rejects any other locale.
"""
from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "crates/ramflux-protocol/catalogs/rf-card-v1.json"
INDEX = ROOT / "crates/ramflux-card/host-fixtures/index.json"
HOOK = ROOT / "crates/ramflux-card/src/bin/card_fixtures/cases.rs"
HOST = ROOT / "crates/ramflux-card/host-fixtures"


def fail(message):
    print(f"card fixtures: {message}", file=sys.stderr)
    return 1


def variant_enums(schema):
    found = []

    def walk(node):
        if isinstance(node, dict):
            variant = node.get("variant")
            if isinstance(variant, dict) and isinstance(variant.get("enum"), list):
                found.append(variant["enum"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)
    return found


def expected_rows(catalog):
    rows = []
    for kind, schema in catalog["components"].items():
        enums = variant_enums(schema)
        if not enums:
            rows.append((kind, None))
            continue
        if len(enums) != 1:
            raise SystemExit(fail(f"{kind} has {len(enums)} variant enums"))
        for variant in enums[0]:
            rows.append((kind, variant))
    return rows


def hook_locale():
    match = re.search(
        r'LOCALE_FIXTURE_HOOK: &str = "([^"]+)"', HOOK.read_text(encoding="utf-8")
    )
    if match is None:
        raise SystemExit(fail("LOCALE_FIXTURE_HOOK is missing"))
    return match.group(1)


def main():
    locale = hook_locale()
    if locale != "en":
        return fail("LOCALE_FIXTURE_HOOK must stay en until the resolver accepts launch locales")
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    if index.get("locale") != "en" or index.get("abi") != 5:
        return fail("index locale or abi does not match the English ABI 5 hook")
    if index.get("catalog") != catalog.get("catalogId"):
        return fail("index catalog does not match the card catalog")
    wanted = expected_rows(catalog)
    cases = index.get("cases")
    if not isinstance(cases, list):
        return fail("index cases is not a list")
    got = [(case.get("kind"), case.get("variant")) for case in cases]
    if got != wanted:
        return fail(f"index rows differ from the catalog ({len(got)} vs {len(wanted)})")
    for case in cases:
        outcome = case.get("outcome")
        expected = case.get("expected", "")
        fixture = HOST / case.get("fixture", "")
        target = HOST / expected
        if outcome == "tree" and not expected.endswith(".tree.json"):
            return fail(f"{case.get('kind')} tree path")
        if outcome == "refused" and not expected.endswith(".refusal.json"):
            return fail(f"{case.get('kind')} refusal path")
        if outcome not in ("tree", "refused") or not fixture.is_file() or not target.is_file():
            return fail(f"missing fixture for {case.get('kind')} {case.get('variant')}")
        if fixture.stat().st_size > 32768 or target.stat().st_size > 262144:
            return fail(f"fixture too large: {case.get('kind')}")
    print(f"card fixtures: ok ({len(cases)} rows, locale {locale})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
