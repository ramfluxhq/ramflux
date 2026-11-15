#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent synthetic recursive rule/census vectors, not production schema coverage."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'scripts/reference/dm_fs_v3/pure_blake3.py'
FIXTURE = ROOT / 'crates/ramflux-protocol/fixtures/full_transfer/catalog.json'

def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def lp(value):
    return struct.pack('>I', len(value)) + value

def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')

def generate():
    spec = importlib.util.spec_from_file_location('pairing_catalog_blake3_reference', REFERENCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    def digest(value):
        hasher = module.Hasher()
        hasher.update(value)
        return hasher.finalize()
    def field(name, disposition, merge, codec):
        return dict(name=name, nullable=False, disposition=disposition, merge=merge, codec=codec)
    def rule(projection, restrictive):
        fields = [field('note', 'exclude' if restrictive else 'transfer', 'prefer_local',dict(kind='scalar',cell_type='utf8')),
                  field('private_seed','exclude','immutable',dict(kind='encoded_bytes',decoded_bytes='32')),
                  field('veto','transfer' if restrictive else 'exclude','restrict_union',dict(kind='decimal_u64'))]
        codec = [field('row_id','transfer','immutable',dict(kind='scalar',cell_type='i64')),
                 field('body','transfer','restrict_union' if restrictive else 'inert_history',dict(kind='object',fields=fields))]
        return dict(cells=[dict(name='row_id',nullable=False,type='i64'),dict(name='body',nullable=False,type='utf8')],
                    codec_version='1',disposition='transfer',excluded=[],id='sql/catalog_vector/'+projection,
                    key=['row_id'],merge='restrict_union' if restrictive else 'inert_history',restrictive=restrictive,
                    selector=dict(table='catalog_vector'),codec=codec,key_grammar_version='1',
                    restrictive_projection=['/body/veto'] if restrictive else [])
    rules = [rule('history',False),rule('veto',True)]
    hashes = [digest(lp(b'ramflux.pairing.full.rule.v1')+jcs(rule)) for rule in rules]
    census = lp(b'ramflux.pairing.full.census.v1')+struct.pack('>I',len(rules))
    census += b''.join(lp(rule['id'].encode())+value for rule,value in zip(rules,hashes))
    changed = copy.deepcopy(rules[0])
    changed['codec'][1]['codec']['fields'][1]['disposition']='transfer'
    changed_merge = copy.deepcopy(rules[1])
    changed_merge['codec'][1]['codec']['fields'][2]['merge']='prefer_local'
    return dict(reference_sha256=hashlib.sha256(REFERENCE.read_bytes()).hexdigest(),rules=rules,
                rule_hashes=[b64(value) for value in hashes],census_hash=b64(digest(census)),
                changed_nested_disposition_hash=b64(digest(lp(b'ramflux.pairing.full.rule.v1')+jcs(changed))),
                changed_nested_merge_hash=b64(digest(lp(b'ramflux.pairing.full.rule.v1')+jcs(changed_merge))))

def baseline_vectors():
    spec=importlib.util.spec_from_file_location('pairing_baseline_blake3_reference',REFERENCE)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    def digest(value):
        hasher=module.Hasher()
        hasher.update(value)
        return hasher.finalize()
    rules=json.loads((FIXTURE.parent/'catalog-baseline-rules.json').read_text())
    assert rules and all(a['id']<b['id'] for a,b in zip(rules,rules[1:]))
    hashes=[digest(lp(b'ramflux.pairing.full.rule.v1')+jcs(rule)) for rule in rules]
    preimage=lp(b'ramflux.pairing.full.census.v1')+struct.pack('>I',len(rules))
    preimage+=b''.join(lp(rule['id'].encode())+value for rule,value in zip(rules,hashes))
    return dict(reference_sha256=hashlib.sha256(REFERENCE.read_bytes()).hexdigest(),
        rule_hashes=[dict(id=rule['id'],hash=b64(value)) for rule,value in zip(rules,hashes)],
        census_hash=b64(digest(preimage)))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    expected=json.dumps(generate(),sort_keys=True,indent=2)+'\n'
    if args.write:
        FIXTURE.parent.mkdir(parents=True,exist_ok=True)
        FIXTURE.write_text(expected)
    elif FIXTURE.read_text()!=expected:
        raise SystemExit('recursive catalog vectors differ; review semantic change before --write')
    baseline=FIXTURE.parent/'catalog-baseline-vectors.json'
    expected_baseline=json.dumps(baseline_vectors(),sort_keys=True,indent=2)+'\n'
    if args.write:
        baseline.write_text(expected_baseline)
    elif baseline.read_text()!=expected_baseline:
        raise SystemExit('baseline catalog vectors differ; review every rule before --write')
    print('PAIRING_FULL_CATALOG_VECTORS_OK')

if __name__=='__main__':
    main()
