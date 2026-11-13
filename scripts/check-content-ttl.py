#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Inventory every SDK envelope TTL constructor; reject unclassified new send sites."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
# Short controls have a documented lifetime, independent of retained content.
EPHEMERAL = {
    'bus/dispatch/message.rs': 'crate::offline_retention::DIRECT_RECEIPT_TTL_SECS',
    'bus/delivery_receipts.rs': 'crate::offline_retention::RECEIPT_TTL_SECS',
    'bus/delivery_receipts/background.rs': 'crate::offline_retention::RECEIPT_TTL_SECS',
    'bus/dispatch/call_driver/background.rs': 'crate::offline_retention::CALL_SIGNAL_TTL_SECS',
    'client/typing/send.rs': 'if active { 5 } else { 1 }',
    'client/routed/reset_prepare.rs': 'crate::offline_retention::RESET_TTL_SECS',
}
FORWARD = {
    'dm.rs': 'message.ttl',
    'bus/protocol.rs': 'self.ttl',
    'bus/task_delivery.rs': 'envelope.ttl',
    'client/routed/mod.rs': 'persist.message.ttl',
    'client/routed/report.rs': 'message.ttl',
}


def production(text):
    # Preserve offsets/newlines, hiding strings/comments for cfg(test) brace matching.
    literals = r'//[^\n]*|/\*[\s\S]*?\*/|r(#+)?"[\s\S]*?"\1|"(?:\\.|[^"\\])*"'
    masked = re.sub(literals, lambda m: re.sub(r'[^\n]', ' ', m[0]), text)
    if re.search(r'#!\[cfg\(test\)\]', masked):
        return re.sub(r'[^\n]', ' ', text)
    spans = []
    for match in re.finditer(r'#\[cfg\(test\)\]', masked):
        opening = masked.find('{', match.end())
        semi = masked.find(';', match.end())
        if semi >= 0 and (opening < 0 or semi < opening):
            spans.append((match.start(), semi + 1))
            continue
        if opening < 0:
            continue
        depth, end = 1, opening + 1
        while depth and end < len(masked):
            depth += (masked[end] == '{') - (masked[end] == '}')
            end += 1
        spans.append((match.start(), end))
    chars = list(text)
    for start, end in spans:
        for i in range(start, end):
            if chars[i] != '\n':
                chars[i] = ' '
    return ''.join(chars)


def classification(relative, expr):
    if '.content_ttl()?' in expr:
        return 'Content'
    if relative in EPHEMERAL and expr.rstrip(',') == EPHEMERAL[relative]:
        return 'Ephemeral'
    if relative in FORWARD and expr.startswith(FORWARD[relative]):
        return 'Content/ephemeral passthrough'
    return None


def check():
    rows, errors = [], []
    for path in sorted((ROOT / 'crates/ramflux-sdk/src').rglob('*.rs')):
        relative = path.relative_to(ROOT / 'crates/ramflux-sdk/src').as_posix()
        if any(part == 'tests' or part.endswith('_tests') for part in path.parts) or path.stem.endswith('_tests') or path.name == 'tests.rs':
            continue
        text = production(path.read_text())
        for match in re.finditer(r'(?m)(?:^\s*ttl:|"ttl"\s*:)\s*([^\n]+)', text):
            expr = match[1].strip()
            line = text.count('\n', 0, match.start(1)) + 1
            kind = classification(relative, expr)
            if kind is None:
                errors.append(f'{relative}:{line}: unclassified TTL: {expr}')
                continue
            rows.append((relative, line, kind, expr))
    if errors:
        raise ValueError('\n'.join(errors))
    if '--inventory' in sys.argv:
        for file, line, kind, expr in rows:
            print(f'| {file}:{line} | {kind} | {expr} |')
    print(f'content TTL inventory: OK ({len(rows)} classified constructors)')


if __name__ == '__main__':
    try:
        check()
    except ValueError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
