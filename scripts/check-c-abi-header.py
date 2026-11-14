#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Compare the locked SDK build's C header with the reviewed bytes."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
target = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
if not target.is_absolute():
    target = ROOT / target
generated = target / "include/ramflux_sdk.h"
committed = ROOT / "crates/ramflux-sdk/include/ramflux_sdk.h"
if not generated.is_file():
    raise SystemExit("missing generated SDK header; cargo check --locked -p ramflux-sdk --features c-abi")
if generated.read_bytes() != committed.read_bytes():
    raise SystemExit("SDK header drift: copy the locked build's include/ramflux_sdk.h to crates/ramflux-sdk/include/ramflux_sdk.h")
print("C_ABI_HEADER_OK: generated header matches committed bytes")
