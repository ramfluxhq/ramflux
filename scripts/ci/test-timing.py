#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Ratchet test timing syntax using expiring, occurrence-counted exceptions.

This is a conservative source guard, not a Rust compiler or a proof of determinism.
It follows test module declarations and normalizes imported/function-value aliases.
"""
import argparse
from collections import Counter, defaultdict, deque
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORD = re.compile(r'(?:r#)?[A-Za-z_][A-Za-z_0-9]*|[0-9][A-Za-z_0-9]*')
RAW = re.compile(r'(?:br|cr|r)(#*)"')
LITERAL = re.compile(r'''(?:b|c)?"(?:\\.|[^"\\])*"|b?'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])' ''', re.S | re.X)
TIMING = re.compile(r'^(?:sleep(?:_until)?|timeout(?:_at)?|.*_timeout(?:_while)?)$')


def tokens(source):
    """Comments and literals cannot introduce timing expressions."""
    out, i = [], 0
    while i < len(source):
        if source[i].isspace():
            i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
            continue
        if source.startswith("/*", i):
            depth, i = 1, i + 2
            while i < len(source) and depth:
                if source.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif source.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        raw, literal, word = RAW.match(source, i), LITERAL.match(source, i), WORD.match(source, i)
        if raw:
            end = source.find('"' + raw[1], raw.end())
            end = len(source) if end < 0 else end + 1 + len(raw[1])
        else:
            match = literal or word
            end = match.end() if match else i + 1
        value = source[i:end]
        if not raw and not literal and word and value.startswith("r#"):
            value = value[2:]
        out.append((value, i, end))
        i = end
    return out


def pairs_for(ts):
    pairs, stack = {}, []
    for i, (value, _, _) in enumerate(ts):
        if value in ("(", "[", "{"):
            stack.append((i, value))
        elif value in (")", "]", "}"):
            if not stack or stack[-1][1] != {")": "(", "]": "[", "}": "{"}[value]:
                raise ValueError("unbalanced Rust token delimiters")
            start, _ = stack.pop()
            pairs[start] = i
    if stack:
        raise ValueError("unclosed Rust token delimiter")
    return pairs


def test_attribute(attr):
    # Include test-reachable conditional scopes conservatively, even any(test, X).
    return (attr == ["test"] or attr[:4] in (["tokio", ":", ":", "test"],
                                           ["async_std", ":", ":", "test"])
            or attr[:1] in (["cfg"], ["cfg_attr"]) and "test" in attr)


def structure(ts, pairs, path):
    spans, edges = [], []
    file = PurePosixPath(path)
    directory = file.parent if file.stem in ("lib", "main", "mod") else file.with_suffix("")

    def walk(lo, hi, test, paused, item, directory):
        i, begin, attrs, header = lo, lo, [], []
        while i < hi:
            value = ts[i][0]
            if value == "#":
                opening = i + 1
                inner = opening < hi and ts[opening][0] == "!"
                opening += int(inner)
                if opening in pairs and ts[opening][0] == "[":
                    end = pairs[opening]
                    attr = [t[0] for t in ts[opening + 1:end]]
                    if inner:
                        test = test or test_attribute(attr)
                        spans.append((lo, hi, test, paused, item))
                    else:
                        attrs.append(attr)
                    i = end + 1
                    continue
            if value in ("(", "[") and i in pairs:
                end = pairs[i]
                header.extend(t[0] for t in ts[i:end + 1])
                i = end + 1
                continue
            if value in ("{", ";"):
                end = pairs.get(i, i)
                local_test = test or any(test_attribute(a) for a in attrs)
                local_paused, name, mod = paused, item, None
                if "impl" in header:
                    name = item + "::impl<" + " ".join(header[header.index("impl") + 1:]) + ">"
                for kind in ("fn", "mod", "macro_rules", "trait"):
                    if kind not in header:
                        continue
                    pos = header.index(kind) + 1
                    if pos < len(header) and header[pos] == "!":
                        pos += 1
                    if pos < len(header) and WORD.fullmatch(header[pos]):
                        name = item + "::" + header[pos]
                        if kind == "mod":
                            mod = header[pos]
                        if kind == "fn":
                            local_paused = any(
                                a[:4] == ["tokio", ":", ":", "test"]
                                and "start_paused=true" in "".join(a) for a in attrs)
                        break
                spans.append((begin, end + 1, local_test, local_paused, name))
                if value == "{":
                    walk(i + 1, end, local_test, local_paused, name,
                         directory / mod if mod else directory)
                elif mod:
                    override = next((a[2] for a in attrs if len(a) == 3 and a[:2] == ["path", "="]), None)
                    if override:
                        parent = file.parent if directory == (file.parent if file.stem in ("lib", "main", "mod") else file.with_suffix("")) else directory
                        candidates = [str(parent / json.loads(override))]
                    else:
                        candidates = [str(directory / (mod + ".rs")), str(directory / mod / "mod.rs")]
                    edges.append(([posixpath.normpath(p) for p in candidates], local_test))
                i, begin, attrs, header = end + 1, end + 1, [], []
                continue
            header.append(value)
            i += 1
    walk(0, len(ts), False, False, "<file>", directory)
    return spans, edges


def imports(values):
    """Expand use trees, including grouped/module aliases; overapproximate shadowing."""
    aliases = defaultdict(set)

    def tree(parts, prefix=()):
        depth, start = 0, 0
        for i, value in enumerate(parts + [","]):
            if value == "," and depth == 0:
                branch = parts[start:i]
                start = i + 1
                if not branch:
                    continue
                if "{" in branch:
                    opening = branch.index("{")
                    pre = tuple(v for v in branch[:opening] if v != ":")
                    tree(branch[opening + 1:-1], prefix + pre)
                else:
                    original, alias = branch, None
                    if "as" in branch:
                        at = branch.index("as")
                        original, alias = branch[:at], branch[at + 1]
                    path = prefix + tuple(v for v in original if v != ":")
                    if path and path[-1] not in ("*", "self"):
                        aliases[alias or path[-1]].add(path)
                    elif path and path[-1] == "self":
                        aliases[alias or path[-2]].add(path[:-1])
            depth += (value == "{") - (value == "}")
    for i, value in enumerate(values):
        if value == "use":
            end = next((j for j in range(i + 1, len(values)) if values[j] == ";"), i)
            tree(values[i + 1:end])
    # Simple function-value aliases are timing references too.
    for i in range(len(values) - 3):
        if values[i] == "let" and WORD.fullmatch(values[i + 1]) and values[i + 2] == "=":
            end = next((j for j in range(i + 3, len(values)) if values[j] == ";"), i)
            rhs = values[i + 3:end]
            if rhs and all(v == ":" or WORD.fullmatch(v) for v in rhs):
                aliases[values[i + 1]].add(tuple(v for v in rhs if v != ":"))
    return aliases


def resolve(path, aliases, seen=frozenset()):
    if not path or path[0] not in aliases or path[0] in seen:
        return {path}
    return {p for alias in aliases[path[0]]
            for p in resolve(alias + path[1:], aliases, seen | {path[0]})}


def constants(values):
    """Track local constant initializers so changing a named cap changes its hash."""
    definitions = defaultdict(set)
    for i in range(len(values) - 3):
        if values[i] not in ("const", "static") or not WORD.fullmatch(values[i + 1]) or values[i + 2] != ":":
            continue
        end = next((j for j in range(i + 3, len(values)) if values[j] == ";"), i)
        body = values[i + 3:end]
        if "=" in body:
            definitions[values[i + 1]].add(tuple(body[body.index("=") + 1:]))
    return definitions


def referenced_constants(values, definitions):
    pending, seen, result = list(values), set(), []
    while pending:
        name = pending.pop()
        if name in seen or name not in definitions:
            continue
        seen.add(name)
        for expression in sorted(definitions[name]):
            result.append(name + " = " + " ".join(expression))
            pending.extend(expression)
    return " | ".join(sorted(result))


def inventory(sources):
    parsed, edges, incoming = {}, defaultdict(list), set()
    for path, source in sources.items():
        ts = tokens(source)
        pairs = pairs_for(ts)
        spans, links = structure(ts, pairs, path)
        parsed[path] = (ts, pairs, spans)
        for candidates, test in links:
            for child in candidates:
                if child in sources:
                    edges[path].append((child, test))
                    incoming.add(child)
    test_files, seen = set(), set()
    queue = deque((p, "tests" in PurePosixPath(p).parts or PurePosixPath(p).stem.endswith("_tests"))
                  for p in sources if p not in incoming)
    while queue:
        path, test = queue.popleft()
        if (path, test) in seen:
            continue
        seen.add((path, test))
        if test:
            test_files.add(path)
        queue.extend((child, test or local) for child, local in edges[path])
    sites, paused_sites = [], []
    for path, (ts, pairs, spans) in parsed.items():
        values = [t[0] for t in ts]
        aliases = imports(values)
        definitions = constants(values)
        # Avoid one scan over all spans for every token: only candidate calls need classification.
        for i in range(len(ts) - 1):
            leaf = values[i]
            if not WORD.fullmatch(leaf) or values[i + 1] != "(" or i + 1 not in pairs:
                continue
            if i and values[i - 1] in ("fn", "macro_rules"):
                continue
            start = i
            while start >= 3 and values[start - 2:start] == [":", ":"] and WORD.fullmatch(values[start - 3]):
                start -= 3
            paths = resolve(tuple(v for v in values[start:i + 1] if v != ":"), aliases)
            candidates = {p for p in paths if p and TIMING.fullmatch(p[-1])}
            if not candidates:
                continue
            enclosing = [s for s in spans if s[0] <= i < s[1]]
            is_test = path in test_files or "tests" in PurePosixPath(path).parts or any(s[2] for s in enclosing)
            if not is_test:
                continue
            nearest = min(enclosing, key=lambda s: s[1] - s[0]) if enclosing else (0, 0, True, False, "<file>")
            end = pairs[i + 1]
            # Hash the whole expression: edits to guards or their protected work require review.
            expression = " ".join(sorted("::".join(p) for p in candidates)) + " " + " ".join(values[i + 1:end + 1])
            expression += " | " + referenced_constants(values[i + 1:end + 1], definitions)
            row = {"path": path, "item": nearest[4],
                   "expression": hashlib.sha256(expression.encode()).hexdigest(),
                   "line": sources[path].count("\n", 0, ts[i][1]) + 1,
                   "call": "/".join(sorted("::".join(p) for p in candidates))}
            virtual = nearest[3] and all(p[:2] == ("tokio", "time") for p in paths)
            (paused_sites if virtual else sites).append(row)
    return sites, paused_sites


def key(row):
    return row["path"], row["item"], row["expression"]


def validate(sites, data, today):
    allowed, errors = {}, []
    for row in data.get("site", []):
        k = key(row)
        if k in allowed:
            errors.append("duplicate allow-list key: " + repr(k))
        for field in ("owner", "reason", "expires"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                raise ValueError("allow-list entry requires " + field)
        if type(row.get("count")) is not int or row["count"] < 1:
            raise ValueError("allow-list count must be positive")
        if date.fromisoformat(row["expires"]) < today:
            errors.append("EXPIRED: " + row["path"] + " " + row["item"])
        allowed[k] = row["count"]
    counts = Counter(key(s) for s in sites)
    for k, count in counts.items():
        if count > allowed.get(k, 0):
            row = next(s for s in sites if key(s) == k)
            errors.append("NEW/CHANGED/UNCLASSIFIED: {}:{} {} {} (count {}, allowed {})".format(
                row["path"], row["line"], row["item"], row["call"], count, allowed.get(k, 0)))
    # Deleted sites may be removed independently; they do not authorize a different expression.
    return errors


def load_sources(root):
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
                                   "--exclude-standard", "--", "crates", "apps"])
    paths = sorted(set(p for p in raw.decode().split("\0") if p.endswith(".rs")))
    return {p: (root / p).read_text() for p in paths if (root / p).is_file()}


def seed(sites, owner, reason, expiry):
    counts = Counter(key(s) for s in sites)
    lines = ["# SPDX-License-Identifier: BSD-3-Clause", "# Existing test timing sites; review renewals individually.", "site = ["]
    for (path, item, expression), count in sorted(counts.items()):
        row = {"path": path, "item": item, "expression": expression, "count": count,
               "owner": owner or PurePosixPath(path).parts[1], "reason": reason, "expires": expiry}
        lines.append("  { " + ", ".join(k + " = " + json.dumps(v) for k, v in row.items()) + " },")
    return "\n".join(lines + ["]", ""])


class Tests(unittest.TestCase):
    def scan(self, source):
        return inventory({"crates/example/src/lib.rs": source})

    def test_new_sleep_is_rejected(self):
        sites, _ = self.scan('#[test] fn sample() { std::thread::sleep(D); }')
        self.assertEqual(len(sites), 1)
        self.assertIn("NEW/CHANGED/UNCLASSIFIED", validate(sites, {}, date.today())[0])

    def test_multiline_and_grouped_alias_timeout(self):
        sites, _ = self.scan('use tokio::{time::{timeout as cap}}; #[tokio::test] async fn sample() { cap(\n LIMIT,\n work()\n).await; }')
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["call"], "tokio::time::timeout")
        self.assertTrue(validate(sites, {}, date.today()))

    def test_module_and_function_value_alias(self):
        sites, _ = self.scan('use tokio::time as clock; #[test] fn sample() { let cap = clock::timeout; cap(D, work()); }')
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["call"], "tokio::time::timeout")

    def test_raw_identifier_and_changed_constant(self):
        source = '#[cfg(test)] mod tests { const LIMIT: Duration = Duration::from_secs(1); #[test] fn sample() { tokio::time::r#timeout(LIMIT, work()); } }'
        before, _ = self.scan(source)
        after, _ = self.scan(source.replace("from_secs(1)", "from_secs(2)"))
        self.assertEqual(len(before), 1)
        self.assertNotEqual(before[0]["expression"], after[0]["expression"])

    def test_paused_tokio_allowed_but_thread_sleep_not_allowed(self):
        sites, paused = self.scan('use tokio::time::sleep as nap; #[tokio::test(start_paused = true)] async fn sample() { nap(D).await; std::thread::sleep(D); }')
        self.assertEqual(len(paused), 1)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["call"], "std::thread::sleep")

    def test_external_cfg_inheritance_and_path(self):
        sources = {"crates/example/src/lib.rs": '#[cfg(test)] #[path="cases.rs"] mod cases;',
                   "crates/example/src/cases.rs": 'fn helper() { tokio::time::timeout(D, f()); }'}
        self.assertEqual(len(inventory(sources)[0]), 1)

    def test_impl_identity_and_nested_module(self):
        sites, _ = self.scan('#[cfg(test)] mod tests { impl One { fn wait() { std::thread::sleep(D); } } impl Two { fn wait() { std::thread::sleep(D); } } }')
        self.assertEqual(len(sites), 2)
        self.assertNotEqual(sites[0]["item"], sites[1]["item"])

    def test_comment_literal_and_production_excluded(self):
        source = 'fn production() { std::thread::sleep(D); } #[test] fn sample() { let s = "tokio::time::sleep(D)"; /* sleep(D); */ }'
        self.assertEqual(self.scan(source), ([], []))

    def test_count_change_rename_expiry_and_whitespace(self):
        source = '#[test] fn sample() { std::thread::sleep(D); }'
        sites, _ = self.scan(source)
        data = tomllib.loads(seed(sites, "sdk", "existing", "2026-12-12"))
        today = date(2026, 11, 12)
        self.assertEqual(validate(sites, data, today), [])
        self.assertTrue(validate(sites * 2, data, today))
        self.assertTrue(validate(sites, data, date(2026, 12, 13)))
        changed, _ = self.scan(source.replace("(D)", "(OTHER)"))
        self.assertTrue(validate(changed, data, today))
        renamed, _ = self.scan(source.replace("sample", "renamed"))
        self.assertTrue(validate(renamed, data, today))
        spaced, _ = self.scan(source.replace("(D)", "(\n D \n)"))
        self.assertEqual(validate(spaced, data, today), [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--seed", action="store_true", help="print candidate TOML for explicit review")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--owner", help="default: owning crate directory")
    parser.add_argument("--reason", default="Existing test watchdog or real-component wait; migrate or justify before expiry")
    parser.add_argument("--expires", default="2026-12-12")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        sites, paused = inventory(load_sources(args.root))
        if args.seed:
            print(seed(sites, args.owner, args.reason, args.expires), end="")
            return 0
        allowlist = args.allowlist or args.root / ".config/test-timing-allowlist.toml"
        errors = validate(sites, tomllib.loads(allowlist.read_text()), datetime.now(timezone.utc).date())
        for error in errors:
            print(error, file=sys.stderr)
        print("test-timing: {} ({} wall-clock/unclassified sites, {} paused-time sites, {} errors)".format(
            "FAIL" if errors else "PASS", len(sites), len(paused), len(errors)))
        return 1 if errors else 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print("test-timing: ERROR: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
