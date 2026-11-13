#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the native method manifest from the SDK's explicit Rust policy rows."""
import argparse
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/ramflux-sdk/src/c_abi/v2/method_policy.rs"
OUTPUT = ROOT / "crates/ramflux-sdk/include/ramflux_sdk_methods.json"
ROW = re.compile(
    r'"([a-z][a-z0-9_.]*)"\s*=>\s*\(\s*"([a-z][a-z0-9_]*)"\s*,\s*'
    r'(true|false)\s*,\s*(true|false)\s*,\s*(true|false)\s*\)', re.MULTILINE
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rows = ROW.findall(SOURCE.read_text(encoding="utf-8"))
    if not rows or len({row[0] for row in rows}) != len(rows):
        raise SystemExit("missing or duplicate SDK method policy rows")
    methods = [dict(name=name, capability=capability, secret_input=inp == "true",
                    secret_output=out == "true", show_once=once == "true")
               for name, capability, inp, out, once in rows]
    data = dict(abi_major=2, policy_version=1, methods=methods)
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.check:
        if OUTPUT.read_text(encoding="utf-8") != encoded:
            raise SystemExit("stale method manifest; run scripts/generate-c-abi-methods.py")
    else:
        OUTPUT.write_text(encoded, encoding="utf-8")
    print(f"METHOD_POLICY_OK: {len(methods)} classified operations")


if __name__ == "__main__":
    main()
