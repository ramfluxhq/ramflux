#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Check the locked descriptor and generated protobuf/ProtoJSON artifacts offline."""
from pathlib import Path
import subprocess

subprocess.run([
    "perl", "-e", "alarm 1800; exec @ARGV", "cargo", "run", "--locked", "--offline",
    "-p", "ramflux-message-schema", "--", "--check",
], cwd=Path(__file__).resolve().parent.parent, check=True)
print("message schema freshness: OK")
