#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Primary-transfer export classification guard.

Fails when the storage schema and the checked-in export classification disagree:
- every account table created by `crates/ramflux-storage/src` is either on the export list
  (`transfer_export/tables.rs`) or excluded with a reason (`transfer_export/classification.rs`);
- every live column of an exported table is declared on the export list or excluded with a reason;
- every actor-kind literal in storage and SDK code is covered by an exported exact namespace or an
  excluded prefix; inside a first segment that has an exported namespace, every second segment
  must be classified explicitly;
- no classification entry is stale (names a table, column or prefix the code no longer has).
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
STORAGE = ROOT / 'crates/ramflux-storage/src'
SDK = ROOT / 'crates/ramflux-sdk/src'
EXPORT = STORAGE / 'account_db/transfer_export'
TABLES_RS = EXPORT / 'tables.rs'
CLASSIFICATION_RS = EXPORT / 'classification.rs'

CREATE = re.compile(
    r'CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?'
    r'(?:"?[a-z]+"?\.)?"?([A-Za-z_{][A-Za-z0-9_{}]*)"?\s*(\(|AS\b)?')
ADD_COLUMN = re.compile(r'ALTER\s+TABLE\s+"?([a-z_][a-z0-9_]*)"?\s+ADD\s+COLUMN\s+"?([a-z_][a-z0-9_]*)')
ENSURE_COLUMN = re.compile(r'ensure_column\(\s*[a-z_]+\s*,\s*"([a-z_][a-z0-9_]*)"\s*,\s*"([a-z_][a-z0-9_]*)"')
KIND_LITERAL = re.compile(r'"([a-z][a-z0-9-]*/[a-z0-9_{}./:-]*)"')
# `client_record` / `persist_client_record` store `directory/{segment}/{id}` (read_model.rs).
# The segment is a separate literal, so the kind scan above does not see it.
CLIENT_DIRECTORY = re.compile(
    r'(?:persist_client_record|client_record)\(\s*"([a-z][a-z0-9_-]*)"')
CONSTRAINTS = ('PRIMARY', 'UNIQUE', 'FOREIGN', 'CHECK', 'CONSTRAINT')


def production_text(path):
    """File text without `#[cfg(test)]` modules (brace-matched, string-aware)."""
    text = path.read_text()
    out = []
    index = 0
    marker = re.compile(r'#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{')
    while True:
        found = marker.search(text, index)
        if not found:
            out.append(text[index:])
            return ''.join(out)
        out.append(text[index:found.start()])
        depth, cursor, quoted = 1, found.end(), False
        while cursor < len(text) and depth:
            char = text[cursor]
            if quoted:
                if char == '\\':
                    cursor += 1
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
            cursor += 1
        index = cursor


def production_files(root):
    for path in sorted(root.rglob('*.rs')):
        if 'test' in path.name or 'tests' in path.relative_to(root).parts:
            continue
        yield path


def table_bodies(text, name):
    """Column definition lists of every literal `CREATE TABLE name(` in text."""
    for found in CREATE.finditer(text):
        if found.group(1) != name or found.group(2) != '(':
            continue
        depth, cursor = 1, found.end()
        while cursor < len(text) and depth:
            depth += {'(': 1, ')': -1}.get(text[cursor], 0)
            cursor += 1
        yield text[found.end():cursor - 1]


def column_names(body):
    items, depth, current = [], 0, ''
    for char in body:
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        if char == ',' and depth == 0:
            items.append(current)
            current = ''
        else:
            current += char
    items.append(current)
    names = set()
    for item in items:
        words = item.replace('\\n', ' ').split()
        if not words or words[0].upper() in CONSTRAINTS:
            continue
        names.add(words[0].strip('"'))
    return names


def census():
    tables, columns, kinds = set(), {}, set()
    texts = {path: production_text(path) for path in production_files(STORAGE)}
    for text in texts.values():
        for found in CREATE.finditer(text):
            if '{' not in found.group(1):
                tables.add(found.group(1))
        for table, column in ADD_COLUMN.findall(text) + ENSURE_COLUMN.findall(text):
            columns.setdefault(table, set()).add(column)
    sdk_texts = [production_text(path) for path in production_files(SDK)]
    for text in list(texts.values()) + sdk_texts:
        kinds.update(KIND_LITERAL.findall(text))
        for segment in CLIENT_DIRECTORY.findall(text):
            kinds.add('directory/%s/' % segment)
    return tables, columns, kinds, texts


def const_block(text, name):
    found = re.search(r'const\s+' + name + r'\s*:[^=]*=\s*&\[(.*?)\];', text, re.S)
    if not found:
        raise SystemExit('check-transfer-export: missing const %s' % name)
    return found.group(1)


def declared():
    tables_text = TABLES_RS.read_text()
    exported = {}
    for block in re.split(r'\nconst [A-Z_]+: Table = ', tables_text)[1:]:
        name = re.search(r'"([a-z_][a-z0-9_]*)"', block).group(1)
        exported[name] = set(re.findall(r'\b(?:plain|optional|content|body)\("([a-z_][a-z0-9_]*)"', block))
    text = CLASSIFICATION_RS.read_text()
    excluded_tables = re.findall(r'\(\s*"([A-Za-z_][A-Za-z0-9_]*)",\s*"[^"]+",?\s*\)', const_block(text, 'EXCLUDED_TABLES'))
    excluded_columns = re.findall(r'\(\s*"([a-z_][a-z0-9_]*)",\s*"([a-z_][a-z0-9_]*)",\s*"[^"]+",?\s*\)',
                                  const_block(text, 'EXCLUDED_COLUMNS'))
    actor_exported = re.findall(r'prefix:\s*"([^"]+)"', const_block(text, 'ACTOR_EXPORTED'))
    actor_excluded = re.findall(r'\(\s*"([^"]+)",\s*"[^"]+",?\s*\)', const_block(text, 'ACTOR_EXCLUDED'))
    return exported, excluded_tables, excluded_columns, actor_exported, actor_excluded


def main():
    tables, added, kinds, texts = census()
    exported, excluded_tables, excluded_columns, actor_exported, actor_excluded = declared()
    problems = []
    for name in sorted(set(excluded_tables)):
        if excluded_tables.count(name) > 1:
            problems.append('table excluded twice: %s' % name)
    both = set(exported) & set(excluded_tables)
    problems += ['table both exported and excluded: %s' % name for name in sorted(both)]
    for name in sorted(tables - set(exported) - set(excluded_tables)):
        problems.append('unclassified table: %s' % name)
    for name in sorted((set(exported) | set(excluded_tables)) - tables):
        problems.append('stale table classification: %s' % name)
    column_excluded = {}
    for table, column in excluded_columns:
        column_excluded.setdefault(table, set()).add(column)
    for table in sorted(exported):
        live = set(added.get(table, set()))
        for text in texts.values():
            for body in table_bodies(text, table):
                live |= column_names(body)
        declared_columns = exported[table] | column_excluded.get(table, set())
        for column in sorted(live - declared_columns):
            problems.append('unclassified column: %s.%s' % (table, column))
        for column in sorted(declared_columns - live):
            problems.append('stale column classification: %s.%s' % (table, column))
        for column in sorted(exported[table] & column_excluded.get(table, set())):
            problems.append('column both exported and excluded: %s.%s' % (table, column))
    for table in sorted(set(column_excluded) - set(exported)):
        problems.append('column exclusion for a table that is not exported: %s' % table)
    mixed = {prefix.split('/')[0] for prefix in actor_exported}
    for prefix in actor_exported:
        if not re.fullmatch(r'[a-z][a-z0-9-]*/[a-z0-9_-]+/', prefix):
            problems.append('exported namespace is not an exact two-segment prefix: %s' % prefix)
    for prefix in actor_excluded:
        head = prefix.split('/')[0]
        if head in mixed and prefix.count('/') < 2:
            problems.append('broad exclusion inside a segment with exported namespaces: %s' % prefix)
    used = set()
    for literal in sorted(kinds):
        parts = literal.split('/')
        head = parts[0]
        if head in mixed and parts[1] == '':
            # A scan over the whole segment, not a kind: every kind in it is classified below.
            continue
        if head in mixed:
            probe = head + '/' + parts[1] + '/'
        else:
            probe = head + '/'
        hits = [p for p in actor_exported + actor_excluded if probe.startswith(p)]
        if not hits and 'unclassified actor-kind literal: %s' % probe not in problems:
            problems.append('unclassified actor-kind literal: %s' % probe)
        used.update(hits)
    for prefix in sorted(set(actor_exported + actor_excluded) - used):
        problems.append('stale actor namespace classification: %s' % prefix)
    if problems:
        for problem in problems:
            print('check-transfer-export: ' + problem)
        print('check-transfer-export: %d problem(s)' % len(problems))
        return 1
    print('check-transfer-export: ok (%d tables, %d exported, %d actor-kind literals)'
          % (len(tables), len(exported), len(kinds)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
