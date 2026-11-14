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
    r'"([a-z][a-z0-9_.]*)"\s*=>\s*\(\s*"([a-z][a-z0-9_.]*)"\s*,\s*'
    r'(true|false)\s*,\s*(true|false)\s*,\s*(true|false)\s*,\s*(true|false)\s*\)', re.MULTILINE
)
CAS_CONST = re.compile(
    r'const\s+(CONTACT_VERIFY_CAS_[A-Z0-9_]+)\s*:\s*&str\s*=\s*"([^"]*)"\s*;'
)
CAS_REQUIRED = (
    "CONTACT_VERIFY_CAS_CAPABILITY",
    "CONTACT_VERIFY_CAS_CONTRACT",
    "CONTACT_VERIFY_CAS_REQUEST_TYPE",
    "CONTACT_VERIFY_CAS_RESPONSE_TYPE",
    "CONTACT_VERIFY_CAS_DESCRIPTOR",
    "CONTACT_VERIFY_CAS_PRODUCT_PIN",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = SOURCE.read_text(encoding="utf-8")
    denied_match = re.search(r'DENIED_METHODS:[^=]+?=\s*&\[(.*?)\];', source, re.DOTALL)
    if denied_match is None:
        raise SystemExit("missing native admission policy")
    denied = set(re.findall(r'"([^\"]+)"', denied_match[1]))
    rows = ROW.findall(source)
    if not rows or len({row[0] for row in rows}) != len(rows):
        raise SystemExit("missing or duplicate SDK method policy rows")
    consts = dict(CAS_CONST.findall(source))
    if any(not consts.get(name) for name in CAS_REQUIRED):
        raise SystemExit("contact.verify CAS metadata constants are incomplete")
    cas_fields = {
        "contract": consts["CONTACT_VERIFY_CAS_CONTRACT"],
        "request_type": consts["CONTACT_VERIFY_CAS_REQUEST_TYPE"],
        "response_type": consts["CONTACT_VERIFY_CAS_RESPONSE_TYPE"],
        "message_descriptor_blake3": consts["CONTACT_VERIFY_CAS_DESCRIPTOR"],
        "product_pin": consts["CONTACT_VERIFY_CAS_PRODUCT_PIN"],
    }
    methods = []
    for name, capability, inp, out, once, export in rows:
        if name == "contact.verify" and capability != consts["CONTACT_VERIFY_CAS_CAPABILITY"]:
            raise SystemExit("contact.verify capability does not match CONTACT_VERIFY_CAS_CAPABILITY")
        row = dict(name=name, capability=capability, bridge_allowed=name not in denied and "itest" not in name, secret_input=inp == "true",
                   secret_output=out == "true", show_once=once == "true", key_export=export == "true")
        if name == "contact.verify":
            row.update(cas_fields)
        methods.append(row)
    data = dict(abi_major=2, policy_version=2, methods=methods)
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.check:
        if OUTPUT.read_text(encoding="utf-8") != encoded:
            raise SystemExit("stale method manifest; run scripts/generate-c-abi-methods.py")
    else:
        OUTPUT.write_text(encoded, encoding="utf-8")
    print(f"METHOD_POLICY_OK: {len(methods)} classified operations")


if __name__ == "__main__":
    main()
