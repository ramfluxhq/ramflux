#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Index an offline signed SDK release and independently pin its host configuration."""
import argparse
import base64
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CARD = ROOT / "crates/ramflux-card"
OUT = ROOT / "crates/ramflux-sdk/include/card"


def encode(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    release = json.loads((OUT / "release.json").read_text(encoding="utf-8"))
    descriptor = (OUT / "library.descriptor.json").read_bytes()
    parsed = json.loads(descriptor)
    if any(parsed.get(key) != value for key, value in release.items()):
        raise SystemExit("signed release does not match the independently configured SDK release")
    bytecode = (OUT / "library.qjb").read_bytes()
    signature = (OUT / "library.sig").read_bytes()
    public = (OUT / "library.pub").read_bytes()
    digest = hashlib.sha256(descriptor).hexdigest()
    if len(signature) != 64 or len(public) != 32 or parsed["host_abi"] != 4:
        raise SystemExit("invalid card ABI or signature/key length")
    if parsed["bytecode_sha256"] != hashlib.sha256(bytecode).hexdigest():
        raise SystemExit("bytecode digest mismatch")
    if parsed["catalog_sha256"] != hashlib.sha256((CARD / "catalog.json").read_bytes()).hexdigest():
        raise SystemExit("catalog digest mismatch")
    policy = dict(app_id=release["app_id"], package_id=release["package_id"],
                  minimum_epoch=release["security_epoch"], minimum_version=release["version"],
                  exact_descriptor_sha256=digest)
    presentations = {}
    for locale in ("en", "zh-CN"):
        for theme in ("light", "dark"):
            presentations[f"{locale}_{theme}"] = dict(locale=locale, direction="ltr",
                strings=json.loads((CARD / "locales" / f"{locale}.json").read_text(encoding="utf-8")),
                tokens=json.loads((CARD / "themes" / f"{theme}.json").read_text(encoding="utf-8")))
    index = dict(format="ramflux.sdk.card.trust.v1", release=release,
                 card_abi_major=parsed["host_abi"], engine=parsed["engine"],
                 catalog_sha256=parsed["catalog_sha256"], descriptor_sha256=digest,
                 bytecode_base64url=base64.urlsafe_b64encode(bytecode).decode().rstrip("="),
                 descriptor=descriptor.decode(), signature_base64url=base64.urlsafe_b64encode(signature).decode().rstrip("="),
                 trusted_key_base64url=base64.urlsafe_b64encode(public).decode().rstrip("="),
                 policy=policy, presentations=presentations)
    for name, value in (("policy.json", policy), ("trust.json", index)):
        expected = encode(value)
        target = OUT / name
        if args.check:
            if target.read_text(encoding="utf-8") != expected:
                raise SystemExit(f"stale SDK card trust file: {name}")
        else:
            target.write_bytes(expected.encode("utf-8"))
    print(f"CARD_TRUST_OK: ABI 4, {release['package_id']}, descriptor {digest}")


if __name__ == "__main__":
    main()
