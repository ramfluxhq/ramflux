#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Reject transaction bypasses in the storage crate's live account boundary.

This is a conservative source guard, not a Rust or SQL type checker. Managed
connections are crate-private; scan every production Rust file in that crate.
Exceptions name an exact function, never a whole staging/snapshot source file.
Transaction keywords supplied through format! substitutions and calls through
aliased rusqlite types remain review responsibilities because this lightweight
source scanner cannot resolve Rust values or types.
"""
import argparse
import re
from pathlib import Path

BASE = 'crates/ramflux-storage/src/'
ALLOW = {
    ('database.rs', 'deferred_transaction'): 'managed deferred entrypoint',
    ('database.rs', 'immediate_transaction'): 'managed immediate entrypoint',
    ('database.rs', 'transaction'): 'sole managed transaction acquisition boundary',
    ('database.rs', 'commit'): 'managed transaction completion boundary',
    ('database.rs', 'drop'): 'managed transaction rollback boundary',
    ('account_db/backup_database.rs', 'enqueue_restore_events'): 'private restore staging database',
    ('account_db/backup_merge.rs', 'merge_backup_with_group_actor'): 'private restore staging database',
}
METHOD = re.compile(r'\.\s*(?:savepoint(?:_with_name)?|transaction(?:_with_behavior)?|unchecked_transaction)\s*(?:::\s*<[^;{}]*>)?\s*\(')
ASSOCIATED = re.compile(r'\b(?:Transaction|Savepoint)\s*::\s*(?:new(?:_unchecked)?|with_name)\b|(?:\bConnection\s*|<[^;{}>]*\bConnection[^;{}>]*>\s*)::\s*(?:savepoint(?:_with_name)?|transaction(?:_with_behavior)?|unchecked_transaction)\b')
SQL = re.compile(r'(?:^|;)\s*(?:BEGIN|SAVEPOINT|COMMIT|END|ROLLBACK|RELEASE)\b', re.I)
FUNCTION = re.compile(r'\bfn\s+(\w+)\s*(?:<[^{}]*>)?\s*\(')
SQL_METHOD = re.compile(r'\.\s*(?:execute|execute_batch|prepare|prepare_cached|query_row)\s*\(')


def lex(source):
    """Mask comments and literals while preserving offsets and line numbers."""
    masked, strings, i = list(source), [], 0
    while i < len(source):
        start, end = i, None
        if source.startswith('//', i):
            end = source.find('\n', i)
            if end < 0:
                end = len(source)
        elif source.startswith('/*', i):
            depth, end = 1, i + 2
            while end < len(source) and depth:
                if source.startswith('/*', end):
                    depth, end = depth + 1, end + 2
                elif source.startswith('*/', end):
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
        else:
            raw = re.match(r'(?:b|c)?r(#{0,255})"', source[i:])
            normal = re.match(r'(?:b|c)?"', source[i:])
            char = re.match(r"(?:b)?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'", source[i:])
            if raw:
                opening = i + raw.end()
                close = source.find('"' + raw[1], opening)
                end = len(source) if close < 0 else close + 1 + len(raw[1])
                strings.append((start, source[opening:close if close >= 0 else len(source)]))
            elif normal:
                opening, end = i + normal.end(), i + normal.end()
                while end < len(source):
                    if source[end] == '\\':
                        end += 2
                    elif source[end] == '"':
                        break
                    else:
                        end += 1
                value = source[opening:end]
                # Rust continuation escapes and escaped whitespace cannot hide BEGIN.
                value = re.sub(r'\\\n\s*', '', value)
                value = re.sub(r'\\([nrt])', lambda match: {'n': '\n', 'r': '\r', 't': '\t'}[match[1]], value)
                value = re.sub(r'\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F_]+)\}', lambda match: chr(int((match[1] or match[2]).replace('_', ''), 16)), value)
                strings.append((start, value))
                end = min(end + 1, len(source))
            elif char:
                end = i + char.end()
        if end is None:
            i += 1
            continue
        for offset in range(start, end):
            if masked[offset] != '\n':
                masked[offset] = ' '
        i = end
    return ''.join(masked), strings


def closing(masked, opening):
    depth = 1
    for i in range(opening + 1, len(masked)):
        depth += (masked[i] == '{') - (masked[i] == '}')
        if depth == 0:
            return i + 1
    return len(masked)


def closing_pair(masked, opening, left='(', right=')'):
    depth = 1
    for i in range(opening + 1, len(masked)):
        depth += (masked[i] == left) - (masked[i] == right)
        if depth == 0:
            return i + 1
    return len(masked)


def first_argument_end(masked, opening):
    """Return the first top-level comma or the call's closing parenthesis."""
    parens = brackets = braces = 0
    for i in range(opening + 1, len(masked)):
        char = masked[i]
        if char == '(':
            parens += 1
        elif char == ')':
            if parens == 0 and brackets == 0 and braces == 0:
                return i
            parens -= 1
        elif char == '[':
            brackets += 1
        elif char == ']':
            brackets -= 1
        elif char == '{':
            braces += 1
        elif char == '}':
            braces -= 1
        elif char == ',' and parens == 0 and brackets == 0 and braces == 0:
            return i
    return len(masked)


def without_trigger_programs(value):
    # Trigger programs use BEGIN/END as grammar, not transaction boundaries.
    trigger = re.compile(r'\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TRIGGER\b', re.I)
    token = re.compile(r'\b(BEGIN|CASE|END)\b', re.I)
    result, cursor = [], 0
    while match := trigger.search(value, cursor):
        result.append(value[cursor:match.start()])
        begin = re.search(r'\bBEGIN\b', value[match.end():], re.I)
        if begin is None:
            result.append(value[match.start():])
            return ''.join(result)
        body = match.end() + begin.end()
        depth, end = 1, None
        for marker in token.finditer(value, body):
            word = marker[1].upper()
            if word == 'CASE':
                depth += 1
            elif word == 'END':
                depth -= 1
                if depth == 0:
                    end = marker.end()
                    break
        if end is None:
            result.append(value[match.start():])
            return ''.join(result)
        cursor = end
        if cursor < len(value) and value[cursor] == ';':
            cursor += 1
    result.append(value[cursor:])
    return ''.join(result)


def contains_transaction_sql(value):
    without_triggers = without_trigger_programs(value)
    without_comments = re.sub(r'/\*.*?\*/|--[^\n]*', ' ', without_triggers, flags=re.S)
    return bool(SQL.search(without_comments))


def test_ranges(masked):
    if re.search(r'#!\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]', masked):
        return [(0, len(masked))]
    ranges = []
    for match in re.finditer(r'#\s*\[\s*(?:cfg\s*\(\s*test\s*\)|test)\s*\]', masked):
        opening = masked.find('{', match.end())
        semicolon = masked.find(';', match.end())
        if opening >= 0 and not (0 <= semicolon < opening):
            ranges.append((match.start(), closing(masked, opening)))
    return ranges


def violations(source, path):
    masked, strings = lex(source)
    tests = test_ranges(masked)
    functions = []
    for match in FUNCTION.finditer(masked):
        opening = masked.find('{', match.end())
        semicolon = masked.find(';', match.end())
        if opening >= 0 and not (0 <= semicolon < opening):
            functions.append((match.start(), closing(masked, opening), match[1]))
    hits = [(match.start(), 'raw transaction/savepoint API') for match in METHOD.finditer(masked)]
    hits.extend(
        (match.start(), 'raw transaction/savepoint API') for match in ASSOCIATED.finditer(masked)
    )
    sql_calls = []
    for match in SQL_METHOD.finditer(masked):
        opening = masked.find('(', match.start())
        sql_calls.append((opening, first_argument_end(masked, opening)))
    for opening, end in sql_calls:
        for offset, value in strings:
            if opening < offset < end and contains_transaction_sql(value):
                hits.append((offset, 'raw SQL transaction/savepoint'))
        for match in re.finditer(r'\bconcat\s*!\s*\(', masked[opening:end]):
            concat_opening = masked.find('(', opening + match.start())
            concat_end = closing_pair(masked, concat_opening)
            joined = ''.join(
                value for offset, value in strings if concat_opening < offset < concat_end
            )
            if contains_transaction_sql(joined):
                hits.append((opening + match.start(), 'raw SQL transaction/savepoint'))
    found = []
    for offset, reason in hits:
        if any(start <= offset < end for start, end in tests):
            continue
        owner = next((name for start, end, name in reversed(functions) if start <= offset < end), None)
        if (path, owner) not in ALLOW:
            found.append((source.count('\n', 0, offset) + 1, reason))
    return sorted(found)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    source_root = args.root / BASE
    paths = sorted(source_root.rglob('*.rs'))
    if not paths:
        parser.error(f'no storage Rust sources under {source_root}')
    errors = 0
    for path in paths:
        relative = path.relative_to(source_root).as_posix()
        for line, reason in violations(path.read_text(), relative):
            print(f'{BASE}{relative}:{line}: {reason}; use the managed writer')
            errors += 1
    print(f'Account transaction guard: {len(paths)} files, {errors} violations')
    return int(errors != 0)


if __name__ == '__main__':
    raise SystemExit(main())
