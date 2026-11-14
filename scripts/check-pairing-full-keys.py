#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent scalar and keyless-row framing vectors; no product code or Rust crypto.

Uses the repository's vendored pure Python BLAKE3 reference port. --write regenerates
public synthetic vectors; the default compares the checked-in exact artifact.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'scripts/reference/dm_fs_v3/pure_blake3.py'
FIXTURE = ROOT / 'crates/ramflux-protocol/fixtures/full_transfer/keys.json'

def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')

def generate():
    spec = importlib.util.spec_from_file_location('pairing_key_blake3_reference', REFERENCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    cells = [(0, b''), (1, struct.pack('>q', -2)), (2, bytes.fromhex('8000000000000000')),
             (3, 'é'.encode('utf-8')), (4, b'\x00\xff')]
    frame = b''.join(bytes([kind]) + struct.pack('>I', len(value)) + value for kind, value in cells)
    domain = b'ramflux.pairing.full.rowkey.v1'
    preimage = struct.pack('>I', len(domain)) + domain + frame
    hasher = module.Hasher()
    hasher.update(preimage)
    digest = hasher.finalize()
    return dict(reference_sha256=hashlib.sha256(REFERENCE.read_bytes()).hexdigest(),
                cells=[dict(type=kind, hex=value.hex()) for kind,value in cells],
                stable_key=b64(frame), keyless_preimage_hex=preimage.hex(),
                occurrences=[dict(occurrence=n,key=b64(digest+struct.pack('>I',n))) for n in [0,1,4294967295]])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    expected = json.dumps(generate(), sort_keys=True, indent=2, ensure_ascii=False)+'\n'
    if args.write:
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(expected)
    elif FIXTURE.read_text() != expected:
        raise SystemExit('full-transfer key vectors differ; inspect codec changes before --write')
    print('PAIRING_FULL_KEYS_OK')

if __name__ == '__main__':
    main()
