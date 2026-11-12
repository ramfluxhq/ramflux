#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Ratchet test timing syntax using expiring, occurrence-counted exceptions.

This is a conservative source guard, not a Rust compiler or a proof of determinism.
It follows test module declarations and normalizes scoped imports and durations.
"""
import argparse
from collections import Counter, defaultdict, deque
from datetime import date, datetime, timezone
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
# Exact APIs only. Interval/elapsed polling and function values need review.
TIMING = {
    ("tokio", "time", name): 0 for name in ("sleep", "sleep_until", "timeout", "timeout_at")
}
TIMING.update({("std", "thread", name): 0 for name in ("sleep", "park_timeout")})
TIMING.update({("std", "net", "TcpStream", "connect_timeout"): 1,
               ("std", "sync", "mpsc", "Receiver", "recv_timeout"): 1,
               ("std", "sync", "Condvar", "wait_timeout"): 2,
               ("std", "sync", "Condvar", "wait_timeout_while"): 2})
# These exact method spellings are explicitly covered without type inference.
METHODS = {"recv_timeout": 0, "wait_timeout": 1, "wait_timeout_while": 1}
EXPIRIES = ("2026-12-12", "2026-12-19", "2026-12-26", "2027-01-02")


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
    """Only unconditional test markers or positive all(test, ...) are test-only."""
    if attr == ["test"] or attr[:4] in (["tokio", ":", ":", "test"],
                                        ["async_std", ":", ":", "test"]):
        return True
    if attr[:2] != ["cfg", "("] or attr[-1:] != [")"]:
        return False
    predicate = attr[2:-1]
    if predicate == ["test"]:
        return True
    return (predicate[:2] == ["all", "("] and predicate[-1:] == [")"]
            and "test" in predicate and not any(x in predicate for x in ("any", "not")))


def structure(ts, pairs, path):
    spans, edges, regions = [], [], {}
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
                local_paused, name, mod, function = paused, item, None, False
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
                            function = True
                            local_paused = any(
                                a[:4] == ["tokio", ":", ":", "test"]
                                and "start_paused=true" in "".join(a) for a in attrs)
                        break
                spans.append((begin, end + 1, local_test, local_paused, name))
                if value == "{":
                    regions[i] = (mod, function, local_paused)
                    walk(i + 1, end, local_test, local_paused, name,
                         directory / mod if mod else directory)
                elif mod:
                    override = next((a[2] for a in attrs if len(a) == 3 and a[:2] == ["path", "="]), None)
                    if override:
                        parent = file.parent if directory == (file.parent if file.stem in ("lib", "main", "mod") else file.with_suffix("")) else directory
                        candidates = [str(parent / json.loads(override))]
                    else:
                        candidates = [str(directory / (mod + ".rs")), str(directory / mod / "mod.rs")]
                    edges.append(([posixpath.normpath(p) for p in candidates], local_test, begin, mod))
                i, begin, attrs, header = end + 1, end + 1, [], []
                continue
            header.append(value)
            i += 1
    walk(0, len(ts), False, False, "<file>", directory)
    return spans, edges, regions


def use_tree(parts, prefix=()):
    """Yield (visible name or *, imported path) for a grouped Rust use tree."""
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
                yield from use_tree(branch[opening + 1:-1], prefix + pre)
            else:
                original, alias = branch, None
                if "as" in branch:
                    at = branch.index("as")
                    original, alias = branch[:at], branch[at + 1]
                path = prefix + tuple(v for v in original if v != ":")
                if path and path[-1] == "self":
                    path = path[:-1]
                if path:
                    yield alias or path[-1], path
        depth += (value == "{") - (value == "}")


def generic_end(values, opening):
    depth = 0
    for i in range(opening, len(values)):
        depth += (values[i] == "<") - (values[i] == ">")
        if depth == 0:
            return i + 1
    return len(values)


def call_opening(values, i):
    after = i + 1
    if values[after:after + 3] == [":", ":", "<"]:
        after = generic_end(values, after + 2)
    return after if values[after:after + 1] == ["("] else None


def argument(values, pairs, opening, index):
    start, cursor, number = opening + 1, opening + 1, 0
    end = pairs[opening]
    while cursor < end:
        if cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if values[cursor:cursor + 3] == [":", ":", "<"]:
            cursor = generic_end(values, cursor + 2)
            continue
        if values[cursor] == ",":
            if number == index:
                return values[start:cursor]
            number, start = number + 1, cursor + 1
        cursor += 1
    return values[start:end] if number == index else []


class Names:
    """Bounded lexical resolution: scoped imports, globs and declared modules.

    No function-value or receiver-type inference. Local declarations shadow imports.
    """
    def __init__(self, parsed):
        self.nodes, self.at = {}, {}
        for path, (ts, pairs, _, _, regions) in parsed.items():
            values = [t[0] for t in ts]
            root = (path, 0)
            self.nodes[root] = self.node(None, root, None)
            stack, locations = [root], []
            for i, value in enumerate(values):
                locations.append(stack[-1])
                if value == "{":
                    current = (path, i + 1)
                    mod, function, paused = regions.get(i, (None, False, False))
                    parent_module = self.nodes[stack[-1]]["module"]
                    module = current if mod else parent_module
                    self.nodes[current] = self.node(stack[-1], module, parent_module if mod else None)
                    self.nodes[current].update(function=function, paused=paused)
                    if mod:
                        self.nodes[stack[-1]]["bindings"][mod] = ("module", current)
                    stack.append(current)
                elif value == "}" and len(stack) > 1:
                    stack.pop()
            self.at[path] = locations
            for i, value in enumerate(values):
                node = self.nodes[locations[i]]
                if value == "use":
                    end = next((j for j in range(i + 1, len(values)) if values[j] == ";"), i)
                    for name, target in use_tree(values[i + 1:end]):
                        if name == "*":
                            node["globs"].append(target[:-1])
                        else:
                            node["bindings"][name] = ("import", target)
                elif value in ("fn", "struct", "enum", "type", "trait") and i + 1 < len(values):
                    node["locals"].add(values[i + 1])
                elif value == "let" and i + 1 < len(values):
                    pos = i + 2 if values[i + 1] == "mut" else i + 1
                    if pos < len(values) and WORD.fullmatch(values[pos]):
                        node["variables"].setdefault(values[pos], i)
                elif value in ("const", "static") and i + 2 < len(values) and values[i + 2] == ":":
                    end = next((j for j in range(i + 3, len(values)) if values[j] == ";"), i)
                    body = values[i + 3:end]
                    if "=" in body:
                        node["bindings"][values[i + 1]] = ("constant", tuple(body[body.index("=") + 1:]))
        # Connect external modules so super::* works across source files too.
        for path, (_, _, _, links, _) in parsed.items():
            for candidates, _, start, mod in links:
                for child in candidates:
                    if child in parsed:
                        parent = self.at[path][start]
                        root = (child, 0)
                        self.nodes[parent]["bindings"][mod] = ("module", root)
                        self.nodes[root]["module_parent"] = self.nodes[parent]["module"]

    @staticmethod
    def node(parent, module, module_parent):
        return dict(parent=parent, module=module, module_parent=module_parent,
                    bindings={}, globs=[], locals=set(), variables={}, function=False, paused=False)

    def lookup(self, scope, name, position, seen):
        marker = (scope, name)
        if marker in seen:
            return set()
        seen = seen | {marker}
        node = self.nodes[scope]
        if name in node["locals"] or node["variables"].get(name, position + 1) < position:
            return set()
        if name in node["bindings"]:
            kind, value = node["bindings"][name]
            if kind == "import":
                return self.resolve(scope, value, position, seen)
            if kind == "module":
                return {("@module", value)}
            return {("@constant", scope, name)}
        found = set()
        for glob in node["globs"]:
            for target in self.resolve(scope, glob, position, seen):
                if target[0] == "@module":
                    found.update(self.lookup(target[1], name, position, seen))
                elif target[:1] in (("tokio",), ("std",)):
                    found.add(target + (name,))
        if found:
            return found
        if scope != node["module"] and node["parent"] is not None:
            return self.lookup(node["parent"], name, position, seen)
        return {(name,)} if name in ("std", "tokio") else set()

    def resolve(self, scope, path, position, seen=frozenset()):
        if not path:
            return set()
        module = self.nodes[scope]["module"]
        if path[0] in ("self", "super", "crate"):
            if path[0] == "super":
                module = self.nodes[module]["module_parent"]
            elif path[0] == "crate":
                while self.nodes[module]["module_parent"] is not None:
                    module = self.nodes[module]["module_parent"]
            found = {("@module", module)} if module else set()
        else:
            found = self.lookup(scope, path[0], position, seen)
        for part in path[1:]:
            more = set()
            for target in found:
                if target[0] == "@module":
                    if part == "super":
                        parent = self.nodes[target[1]]["module_parent"]
                        if parent:
                            more.add(("@module", parent))
                    else:
                        more.update(self.lookup(target[1], part, position, seen))
                elif target[0] != "@constant":
                    more.add(target + (part,))
            found = more
        return found

    def duration(self, values, scope, position, seen=frozenset()):
        result, i = [], 0
        while i < len(values):
            if not WORD.fullmatch(values[i]):
                result.append(values[i])
                i += 1
                continue
            end = i + 1
            while end + 2 < len(values) and values[end:end + 2] == [":", ":"] and WORD.fullmatch(values[end + 2]):
                end += 3
            path = tuple(v for v in values[i:end] if v != ":")
            resolved = self.resolve(scope, path, position)
            if len(resolved) == 1:
                target = next(iter(resolved))
                if target[0] == "@constant" and target not in seen:
                    _, defining_scope, name = target
                    body = self.nodes[defining_scope]["bindings"][name][1]
                    result.append("(" + self.duration(list(body), defining_scope, position, seen | {target}) + ")")
                elif target[0].startswith("@"):
                    result.extend(values[i:end])
                else:
                    # Tokio reexports std Duration; spelling/import changes are not cap changes.
                    if target[:3] == ("tokio", "time", "Duration"):
                        target = ("std", "time", "Duration") + target[3:]
                    result.append("::".join(target))
            else:
                result.extend(values[i:end])
            i = end
        return " ".join(result)

    def paused(self, scope, position, events):
        chain = []
        while scope is not None:
            chain.append(scope)
            node = self.nodes[scope]
            if node["function"]:
                break
            scope = node["parent"]
        state = self.nodes[chain[-1]]["paused"]
        prior = sorted((i, pause) for ancestor in chain for i, pause in events.get(ancestor, []) if i < position)
        for _, state in prior:
            pass
        return state


def inventory(sources):
    parsed, edges, incoming = {}, defaultdict(list), set()
    for path, source in sources.items():
        ts = tokens(source)
        pairs = pairs_for(ts)
        spans, links, regions = structure(ts, pairs, path)
        parsed[path] = (ts, pairs, spans, links, regions)
        for candidates, test, _, _ in links:
            for child in candidates:
                if child in sources:
                    edges[path].append((child, test))
                    incoming.add(child)
    test_files, seen = set(), set()
    queue = deque((p, "tests" in PurePosixPath(p).parts) for p in sources if p not in incoming)
    while queue:
        path, test = queue.popleft()
        if (path, test) in seen:
            continue
        seen.add((path, test))
        if test:
            test_files.add(path)
        queue.extend((child, test or local) for child, local in edges[path])
    names = Names(parsed)
    sites, paused_sites = [], []
    for path, (ts, pairs, spans, _, _) in parsed.items():
        values = [t[0] for t in ts]
        calls, events = [], defaultdict(list)
        for i, leaf in enumerate(values):
            if not WORD.fullmatch(leaf) or i and values[i - 1] in ("fn", "macro_rules"):
                continue
            opening = call_opening(values, i)
            if opening not in pairs:
                continue
            start = i
            while start >= 3 and values[start - 2:start] == [":", ":"] and WORD.fullmatch(values[start - 3]):
                start -= 3
            scope = names.at[path][i]
            paths = names.resolve(scope, tuple(v for v in values[start:i + 1] if v != ":"), i)
            if start == i and i and values[i - 1] == ".":
                paths = {("method", leaf)} if leaf in METHODS else set()
            if paths == {("tokio", "time", "pause")}:
                events[scope].append((i, True))
            elif paths == {("tokio", "time", "resume")}:
                events[scope].append((i, False))
            candidates = {p: TIMING[p] for p in paths if p in TIMING}
            candidates.update({p: METHODS[p[1]] for p in paths if p[0] == "method"})
            if candidates:
                calls.append((i, opening, scope, candidates))
        for i, opening, scope, candidates in calls:
            enclosing = [s for s in spans if s[0] <= i < s[1]]
            if not (path in test_files or "tests" in PurePosixPath(path).parts or any(s[2] for s in enclosing)):
                continue
            nearest = min(enclosing, key=lambda s: s[1] - s[0]) if enclosing else (0, 0, True, False, "<file>")
            for call, index in sorted(candidates.items()):
                duration = names.duration(argument(values, pairs, opening, index), scope, i)
                row = {"path": path, "item": nearest[4], "duration": duration,
                       "line": sources[path].count("\n", 0, ts[i][1]) + 1, "call": "::".join(call)}
                virtual = call[:2] == ("tokio", "time") and names.paused(scope, i, events)
                (paused_sites if virtual else sites).append(row)
    return sites, paused_sites


def key(row):
    return row["path"], row["call"], row["duration"]


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
            errors.append("EXPIRED: " + row["path"] + " " + row["call"])
        allowed[k] = row["count"]
    counts = Counter(key(s) for s in sites)
    for k, count in counts.items():
        if count > allowed.get(k, 0):
            row = next(s for s in sites if key(s) == k)
            errors.append("NEW/CHANGED/UNCLASSIFIED: {}:{} {} {} (count {}, allowed {})".format(
                row["path"], row["line"], row["item"], row["call"], count, allowed.get(k, 0)))
    for k, count in allowed.items():
        if counts.get(k, 0) < count:
            errors.append("STALE: stale row, delete it (or reduce count): " + repr(k))
    return errors


def load_sources(root):
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
                                   "--exclude-standard", "--", "crates", "apps", "tests", "tools"])
    paths = sorted(set(p for p in raw.decode().split("\0") if p.endswith(".rs")))
    return {p: (root / p).read_text() for p in paths if (root / p).is_file()}


def seed(sites, owner, reason, expiry):
    counts = Counter(key(s) for s in sites)
    lines = ["# SPDX-License-Identifier: BSD-3-Clause", "# Existing test timing sites; review renewals individually.", "site = ["]
    def group(path):
        parts = PurePosixPath(path).parts
        return "/".join(parts[:2]) if parts[0] in ("crates", "apps", "tools") else parts[0]
    groups = sorted({group(path) for path, _, _ in counts})
    dates = {name: EXPIRIES[i % len(EXPIRIES)] for i, name in enumerate(groups)}
    for (path, call, duration), count in sorted(counts.items()):
        row = {"path": path, "call": call, "duration": duration, "count": count,
               "owner": owner or group(path), "reason": reason, "expires": expiry or dates[group(path)]}
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

    def test_module_alias(self):
        sites, _ = self.scan('use tokio::time as clock; #[test] fn sample() { clock::timeout(D, work()); }')
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["call"], "tokio::time::timeout")

    def test_raw_identifier_and_changed_constant(self):
        source = '#[cfg(test)] mod tests { const LIMIT: Duration = Duration::from_secs(1); #[test] fn sample() { tokio::time::r#timeout(LIMIT, work()); } }'
        before, _ = self.scan(source)
        after, _ = self.scan(source.replace("from_secs(1)", "from_secs(2)"))
        self.assertEqual(len(before), 1)
        self.assertNotEqual(before[0]["duration"], after[0]["duration"])

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
        self.assertEqual(validate(renamed, data, today), [])
        spaced, _ = self.scan(source.replace("(D)", "(\n D \n)"))
        self.assertEqual(validate(spaced, data, today), [])

    def test_cfg_forms(self):
        for cfg, count in (("test", 1), ('all(test, target_os="linux")', 1),
                           ('any(target_os="linux", test)', 0), ("not(test)", 0),
                           ('all(any(test, target_os="linux"))', 0)):
            with self.subTest(cfg=cfg):
                sites, _ = self.scan(f'#[cfg({cfg})] fn sample() {{ std::thread::sleep(D); }}')
                self.assertEqual(len(sites), count)
                sources = {"crates/example/src/lib.rs": f'#[cfg({cfg})] mod child;',
                           "crates/example/src/child.rs": 'fn work() { std::thread::sleep(D); }'}
                self.assertEqual(len(inventory(sources)[0]), count)
        self.assertEqual(self.scan('#[cfg_attr(test, allow(dead_code))] fn sample() { std::thread::sleep(D); }'), ([], []))

    def test_helpers_constructors_and_socket_settings_are_not_sites(self):
        sites, _ = self.scan('#[test] fn sample() { assert!(is_deadline_timeout(err)); expect_deadline_timeout(err); rf_output_timeout(x); socket.set_read_timeout(D); socket.set_write_timeout(D); timeout(); } fn timeout() {}')
        self.assertEqual(sites, [])

    def test_local_declarations_shadow_glob_imports(self):
        source = 'use tokio::time::*; fn timeout() {} #[test] fn sample() { timeout(); }'
        self.assertEqual(self.scan(source), ([], []))
        source = '#[cfg(test)] mod a { use tokio::time::timeout; fn run() { timeout(D,f()); } } #[cfg(test)] mod b { fn timeout() {} fn run() { timeout(); } }'
        self.assertEqual(len(self.scan(source)[0]), 1)

    def test_globs_parent_imports_and_manual_pause(self):
        sources = {"crates/example/src/lib.rs": 'use tokio::time::*; #[cfg(test)] mod child;',
                   "crates/example/src/child.rs": 'use super::*; #[tokio::test(start_paused=true)] async fn a() { sleep(D).await; } #[tokio::test] async fn b() { pause(); timeout(D,f()).await; resume(); sleep(D).await; }'}
        sites, paused = inventory(sources)
        self.assertEqual(len(sites), 1)
        self.assertEqual(len(paused), 2)
        self.assertTrue(all(s['call'].startswith('tokio::time::') for s in sites + paused))

    def test_pause_is_scoped_and_not_retroactive(self):
        source = '#[tokio::test] async fn a() { tokio::time::sleep(D).await; { tokio::time::pause(); tokio::time::sleep(D).await; } tokio::time::sleep(D).await; }'
        sites, paused = self.scan(source)
        self.assertEqual((len(sites), len(paused)), (2, 1))
        source = '#[tokio::test(start_paused=true)] async fn a() { tokio::time::sleep(D).await; fn helper() { tokio::time::sleep(D); } }'
        sites, paused = self.scan(source)
        self.assertEqual((len(sites), len(paused)), (1, 1))

    def test_turbofish_and_duration_only_identity(self):
        first = '#[tokio::test] async fn a() { tokio::time::timeout::<_>(std::time::Duration::from_secs(1), async { old().await }).await; }'
        second = 'use std::time::Duration; #[tokio::test] async fn renamed() { tokio::time::timeout(Duration::from_secs(1), async { new().await }).await; }'
        old, _ = self.scan(first)
        new, _ = self.scan(second)
        self.assertEqual(len(old), 1)
        self.assertEqual(key(old[0]), key(new[0]))

    def test_method_duration_position(self):
        source = '#[test] fn a() { rx.recv_timeout(D); cv.wait_timeout_while(guard, LIMIT, |x| check(x)); }'
        sites, _ = self.scan(source)
        self.assertEqual([s['duration'] for s in sites], ['D', 'LIMIT'])

    def test_root_tests_tools_and_stale_count(self):
        sources = {'tests/sample.rs': 'fn helper() { std::thread::sleep(D); }',
                   'tools/message-schema/src/lib.rs': '#[test] fn sample() { std::thread::sleep(D); }'}
        sites, _ = inventory(sources)
        self.assertEqual(len(sites), 2)
        data = tomllib.loads(seed(sites, None, 'existing', None))
        self.assertTrue(any('stale row, delete it' in e for e in validate(sites[:1], data, date(2026, 11, 12))))
        same = sites[:1] * 2
        data = tomllib.loads(seed(same, None, 'existing', None))
        self.assertTrue(any('stale row, delete it' in e for e in validate(sites[:1], data, date(2026, 11, 12))))

    def test_expiry_groups_and_documented_limits(self):
        sites = [{'path': f'crates/crate{i}/src/lib.rs', 'call': 'std::thread::sleep', 'duration': 'D'} for i in range(4)]
        data = tomllib.loads(seed(sites, None, 'existing', None))
        self.assertEqual({r['expires'] for r in data['site']}, set(EXPIRIES))
        source = '#[test] fn a() { iter.for_each(std::thread::sleep); let cap=tokio::time::timeout; cap(D,f()); tokio::time::interval(D); tokio::time::interval_at(now,D); while now.elapsed()<D {} }'
        self.assertEqual(self.scan(source), ([], []))


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
    parser.add_argument("--expires", help="override the four weekly crate/app groups")
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
