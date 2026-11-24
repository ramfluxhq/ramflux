#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check a provisioned demo through two already unlocked rf daemons.

Recovery phrase files stay private. Output contains public command results only.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rf", default="rf")
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--name", required=True)
    for side in ("a", "b"):
        parser.add_argument("--socket-"+side, required=True)
        parser.add_argument("--account-"+side, required=True)
        parser.add_argument("--phrase-"+side, required=True)
    args = parser.parse_args()
    pin = json.loads(args.pin.read_text())
    if set(pin) != {"url", "id", "public_key", "generation"} or pin["generation"] != 1:
        sys.exit("unexpected demo username pin")
    env = dict(os.environ)
    env.update({"RAMFLUX_USERNAME_CENTER_"+suffix: str(pin[key]) for suffix, key in
                (("URL", "url"), ("ID", "id"), ("PUBLIC_KEY", "public_key"))})
    env["RAMFLUX_USERNAME_TRUST_GENERATION"] = str(pin["generation"])

    def call(side, action, mutation=False):
        command = [args.rf, "--socket", getattr(args, "socket_"+side), "username", action,
                   args.name, "--account", getattr(args, "account_"+side)]
        if mutation:
            command += ["--recovery-phrase-file", getattr(args, "phrase_"+side)]
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=90)
        if len(result.stdout) + len(result.stderr) > 262144:
            sys.exit("rf response exceeds check bound")
        return result

    claim = call("a", "set", True)
    if claim.returncode:
        sys.exit("A set failed: " + claim.stderr[-2000:])
    status = json.loads(claim.stdout)
    if status.get("state") != "committed":
        sys.exit("A set did not commit")
    resolved = call("b", "resolve")
    if resolved.returncode:
        sys.exit("B resolve failed: " + resolved.stderr[-2000:])
    value = json.loads(resolved.stdout)
    if value.get("root_commitment") != status.get("binding", {}).get("body", {}).get("principal_commitment") or not value.get("root_commitment") or value.get("name") != args.name.removeprefix("@"):
        sys.exit("B resolved a different account")
    duplicate = call("b", "set", True)
    if duplicate.returncode == 0 or "username_taken" not in duplicate.stderr:
        sys.exit("B duplicate set was not refused as username_taken")
    print(json.dumps(dict(claim=status, resolve=value, duplicate="username_taken"), indent=2))
    print("PASS: A committed; B resolved A; B duplicate refused username_taken")


if __name__ == "__main__":
    main()
