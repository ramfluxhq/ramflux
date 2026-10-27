#!/usr/bin/env python3
"""Append Compose input aliases to a generated, private demo environment file."""
import json
from pathlib import Path
import sys


def append_inputs(path):
    mapping = json.loads((Path(__file__).resolve().parents[1] / "compose-inputs.json").read_text())
    values = dict(line.split("=", 1) for line in path.read_text().splitlines()
                  if "=" in line and not line.startswith("#"))
    additions = []
    for service_key, compose_key in mapping.items():
        if service_key not in values:
            continue
        if compose_key in values:
            if values[compose_key] != values[service_key]:
                raise ValueError(f"conflicting generated Compose input: {compose_key}")
            continue
        additions.append(f"{compose_key}={values[service_key]}\n")
    with path.open("a") as output:
        output.writelines(additions)


if __name__ == "__main__":
    append_inputs(Path(sys.argv[1]))
