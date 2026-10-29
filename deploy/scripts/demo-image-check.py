#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Verify the identity and executable metadata of every prebuilt demo image."""
import json
import subprocess
import sys

SERVICES = ("gateway", "router", "notify", "federation", "relay", "signaling", "retention")


def verify_images(engine, version):
    missing = []
    invalid = set()
    identities = {}
    for service in SERVICES:
        binary = f"ramflux-{service}"
        image = f"ghcr.io/ramfluxhq/{binary}:{version}"
        result = subprocess.run([engine, "image", "inspect", image],
                                capture_output=True, text=True, check=False)
        if result.returncode:
            missing.append(image)
            continue
        try:
            items = json.loads(result.stdout)
            if not isinstance(items, list) or len(items) != 1:
                raise ValueError("expected one inspected image")
            item = items[0]
            identity = item.get("Id") or item.get("ID")
            if not isinstance(identity, str) or not identity.strip():
                raise ValueError("missing image ID")
            identity = identity.strip().removeprefix("sha256:").lower()
            if not identity:
                raise ValueError("empty image ID")
            identities.setdefault(identity, []).append(service)
            config = item["Config"]
            values = [entry.split("=", 1)[1] for entry in config.get("Env", []) or []
                      if entry.startswith("RAMFLUX_BIN=")]
            labels = config.get("Labels") or {}
            if "RAMFLUX_BIN" in labels:
                values.append(labels["RAMFLUX_BIN"])
            if not values or any(value != binary for value in values):
                invalid.add(service)
        except (ValueError, TypeError, KeyError, AttributeError):
            invalid.add(service)
    duplicates = {service for names in identities.values() if len(names) > 1 for service in names}
    if missing:
        print(f"missing demo images for version {version}:\n" + "\n".join(missing), file=sys.stderr)
        print("load every listed image into the selected container engine before retrying", file=sys.stderr)
    if invalid:
        print("invalid demo image identity or RAMFLUX_BIN: " + ", ".join(sorted(invalid)), file=sys.stderr)
    if duplicates:
        print("demo images share an image ID: " + ", ".join(sorted(duplicates)), file=sys.stderr)
    return not (missing or invalid or duplicates)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: demo-image-check.py ENGINE VERSION")
    sys.exit(0 if verify_images(*sys.argv[1:]) else 1)
