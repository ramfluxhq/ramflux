#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent Surface v3 state/action fixtures, using the pinned pure Python BLAKE3 oracle."""
import base64
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/reference/username_directory'))
from pure_blake3 import Hasher


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(domain, data):
    h = Hasher()
    h.update(domain.encode())
    h.update(data)
    return base64.urlsafe_b64encode(h.finalize()).rstrip(b'=').decode()


def fixtures():
    components = [
        {'id': 'root', 'component': 'Card', 'child': 'form'},
        {'id': 'form', 'component': 'Column', 'children': ['label', 'input', 'button']},
        {'id': 'label', 'component': 'Text', 'text': {'@path': '/text'}},
        {'id': 'input', 'component': 'TextField', 'label': 'Comment', 'value': {'@path': '/note'}},
        {'id': 'button', 'component': 'Button', 'child': 'submit_label',
         'action': {'event': {'name': 'submit', 'context': {'note': {'@path': '/note'}, 'mode': 'save'}, 'userMessage': 'Saved'}},
         '@checks': [{'condition': {'@call': 'required', 'args': {'value': {'@path': '/note'}}}}]},
        {'id': 'submit_label', 'component': 'Text', 'text': 'Save'},
    ]
    snapshot = {'surfaceId': 'surface', 'catalogId': 'urn:ramflux:catalog:rf-card:1.0',
                'fallbackText': 'Save note', 'metadata': {'extensions': {'example': {'label': 'fixture'}}},
                'components': sorted(components, key=lambda c: c['id']),
                'dataModel': {'note': 'base', 'text': 'Hello'}, 'final': [], 'closed': False}
    state_hash = digest('ramflux.a2ui.surface_hash.v2', canonical(snapshot))
    create = {'schema': 'ramflux.surface.event.v3', 'conversationId': 'conversation', 'surfaceVersion': 1,
              'fallbackText': snapshot['fallbackText'], 'newSurfaceHash': state_hash,
              'a2ui': {'version': '1.0', 'createSurface': {k: snapshot[k] for k in ['surfaceId', 'catalogId', 'components', 'dataModel', 'metadata']}}}
    args = {'sourceInstance': [], 'name': 'submit', 'context': {'note': 'edited', 'mode': 'save'}, 'userMessage': 'Saved'}
    action = {'schema': 'ramflux.surface.action.v3', 'conversationId': 'conversation', 'surfaceVersion': 1,
              'surfaceHash': state_hash, 'sourceInstance': [], 'argsHash': digest('ramflux.a2ui.action_args.v2', canonical(args)),
              'a2ui': {'version': '1.0', 'action': {'name': 'submit', 'surfaceId': 'surface', 'sourceComponentId': 'button',
                        'timestamp': '2026-11-14T00:00:00Z', 'context': args['context'], 'userMessage': 'Saved'}}}
    return {'snapshot.json': canonical(snapshot), 'create.event.json': canonical(create), 'submit.action.json': canonical(action),
            'surface.hash': state_hash.encode() + b'\n'}


def main():
    target = ROOT / 'crates/ramflux-protocol/fixtures/protocol/v1/a2ui_surface'
    target.mkdir(parents=True, exist_ok=True)
    result = fixtures()
    for name, data in result.items():
        path = target / name
        if '--check' in sys.argv:
            if path.read_bytes() != data:
                raise SystemExit(f'Surface v3 fixture drift: {name}')
        else:
            path.write_bytes(data)
    print(f'SURFACE_V3_ORACLE_OK: {len(result)} independent fixtures')


if __name__ == '__main__':
    main()
