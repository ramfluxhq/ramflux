// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Static guard: new ephemeral modules must not name durable-sink symbols.
//!
//! Production modules are discovered by walking `crates/*/src` and
//! `apps/*/src` for `.rs` files whose path contains `ephemeral` or
//! `transient`. Test-only files are excluded. Before matching, each file is
//! normalised: comments and string literals are stripped, whitespace around
//! `::` is collapsed, and `use` / `pub use` groups are expanded into full
//! paths. Alias bindings are rewritten to their full paths. `#[cfg(test)]`
//! items are ignored, so absence proofs may open a store.

use std::io;
use std::path::{Path, PathBuf};

const FORBIDDEN_SYMBOLS: &[&str] = &[
    "begin_write",
    "RouterRedbStore",
    "router_wal",
    "notify_wal",
    "spool_outbound_forward",
    "notify_offline_wake",
    "submit_envelope",
    "accept_envelope_replay",
    "replay_guard_shards",
    "check_envelope_replay_once",
    "refresh_registered_envelope_authority",
    "authenticate_submission",
    "authenticated_envelope_source_from",
    "observe_foreign_device_set",
    "record_session_entry",
    "capture_itest_gateway_json",
    "std::fs",
    "OpenOptions",
    "AccountDb",
    "write_transaction",
    "append_journal",
];

/// Top-level directories whose `src/` trees are walked for module discovery.
const DISCOVERY_ROOTS: &[&str] = &["crates", "apps"];

/// Path fragments that select a production module.
const DISCOVERY_NEEDLES: &[&str] = &["ephemeral", "transient"];

/// This guard. It also lives under `tests/`, so the directory rule already
/// excludes it; the explicit entry keeps the exclusion visible.
const GUARD_REL: &str = "crates/ramflux-node-core/src/tests/ephemeral_durable_sinks.rs";

/// Files that match the discovery needles but are test-only. Each entry names
/// the declaring file and line, and `declared_cfg_test` re-checks the
/// declaration so that a stale entry fails the test.
const TEST_ONLY_MODULES: &[(&str, &str)] = &[
    // Declared `#[cfg(test)] mod ephemeral_reassertion;` at
    // apps/ramflux-router/src/handlers/session_push.rs:266-267.
    (
        "apps/ramflux-router/src/handlers/session_push/ephemeral_reassertion.rs",
        "apps/ramflux-router/src/handlers/session_push.rs",
    ),
];

/// Modules the discovery must always find.
const REQUIRED_MODULES: &[&str] = &[
    "crates/ramflux-node-core/src/ephemeral/mod.rs",
    "crates/ramflux-node-core/src/ephemeral/capability.rs",
    "crates/ramflux-protocol/src/ephemeral.rs",
];

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn workspace_root() -> io::Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_test_filename(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
}

fn is_scanned_rs(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "rs") && !is_test_filename(path)
}

fn collect_rs_dir(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_rs_dir(&path, files)?;
        } else if file_type.is_file() && is_scanned_rs(&path) {
            files.push(path);
        }
    }
    Ok(())
}

/// Walks `<root>/{crates,apps}/*/src` and returns the production modules whose
/// workspace-relative path contains a discovery needle. Sorted, deduplicated.
fn discover_ephemeral_modules(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut all = Vec::new();
    for top in DISCOVERY_ROOTS {
        let top_dir = root.join(top);
        if !top_dir.is_dir() {
            continue;
        }
        let mut members = std::fs::read_dir(&top_dir)?.collect::<io::Result<Vec<_>>>()?;
        members.sort_by_key(std::fs::DirEntry::path);
        for member in members {
            let src = member.path().join("src");
            if src.is_dir() {
                collect_rs_dir(&src, &mut all)?;
            }
        }
    }
    let mut selected = Vec::new();
    for path in all {
        let rel = rel_path(root, &path);
        if !DISCOVERY_NEEDLES.iter().any(|needle| rel.contains(needle)) {
            continue;
        }
        if is_excluded(&rel) {
            continue;
        }
        selected.push(path);
    }
    selected.sort();
    selected.dedup();
    Ok(selected)
}

fn is_excluded(rel: &str) -> bool {
    rel == GUARD_REL
        || TEST_ONLY_MODULES.iter().any(|(excluded, _)| *excluded == rel)
        || Path::new(rel).components().any(|c| c.as_os_str() == "tests")
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}

/// True when `decl_src` declares `mod <stem>;` directly after `#[cfg(test)]`.
fn declared_cfg_test(decl_src: &str, stem: &str) -> bool {
    let decl = format!("mod {stem};");
    decl_src.match_indices(&decl).any(|(at, _)| decl_src[..at].trim_end().ends_with("#[cfg(test)]"))
}

fn has_symbol(src: &str, symbol: &str) -> bool {
    let mut from = 0;
    while from < src.len() {
        let Some(rel) = src[from..].find(symbol) else {
            return false;
        };
        let at = from + rel;
        let before_ok = src[..at].chars().next_back().is_none_or(|c| !is_ident_char(c));
        let after = at + symbol.len();
        let after_ok =
            src.get(after..).and_then(|tail| tail.chars().next()).is_none_or(|c| !is_ident_char(c));
        if before_ok && after_ok {
            return true;
        }
        from = next_char_boundary(src, at);
    }
    false
}

fn next_char_boundary(src: &str, at: usize) -> usize {
    let mut from = at.saturating_add(1);
    while from < src.len() && !src.is_char_boundary(from) {
        from += 1;
    }
    from
}

fn forbidden_hits(src: &str) -> Vec<&'static str> {
    FORBIDDEN_SYMBOLS.iter().copied().filter(|symbol| has_symbol(src, symbol)).collect()
}

/// Normalised text used for matching: comments and string literals stripped,
/// `#[cfg(test)]` items removed, whitespace collapsed, and use-group aliases
/// expanded. Both the raw text and the expanded paths are included.
fn production_source(src: &str) -> String {
    let stripped = strip_cfg_test_items(&strip_comments(src));
    let collapsed = collapse_path_ws(&stripped);
    expand_detection_text(&collapsed)
}

fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if let Some(end) = skip_raw_string(src, i) {
            out.push_str("\"\"");
            i = end;
            continue;
        }
        let rest = &src[i..];
        if rest.starts_with("//") {
            i = skip_until_newline(src, i);
            out.push('\n');
            continue;
        }
        if rest.starts_with("/*") {
            i = skip_block_comment(src, i);
            out.push(' ');
            continue;
        }
        if rest.starts_with('"') {
            i = skip_string(src, i);
            out.push_str("\"\"");
            continue;
        }
        if rest.starts_with('\'') {
            let end = skip_char_or_lifetime(src, i);
            out.push_str(&src[i..end]);
            i = end;
            continue;
        }
        let Some(c) = rest.chars().next() else {
            break;
        };
        out.push(c);
        i += c.len_utf8();
    }
    out
}

fn skip_until_newline(src: &str, i: usize) -> usize {
    match src[i..].find('\n') {
        Some(rel) => i + rel,
        None => src.len(),
    }
}

fn skip_block_comment(src: &str, i: usize) -> usize {
    let from = i.saturating_add(2);
    match src.get(from..).and_then(|rest| rest.find("*/")) {
        Some(rel) => from + rel + 2,
        None => src.len(),
    }
}

fn skip_string(src: &str, mut i: usize) -> usize {
    i += 1;
    while i < src.len() {
        let Some(c) = src[i..].chars().next() else {
            break;
        };
        i += c.len_utf8();
        if c == '\\' {
            if let Some(next) = src[i..].chars().next() {
                i += next.len_utf8();
            }
            continue;
        }
        if c == '"' {
            return i;
        }
    }
    src.len()
}

fn skip_char_or_lifetime(src: &str, i: usize) -> usize {
    let after = i + 1;
    let next = src.get(after..).and_then(|rest| rest.chars().next());
    if next.is_some_and(is_ident_char) {
        return after;
    }
    skip_char_lit(src, i)
}

fn skip_char_lit(src: &str, mut i: usize) -> usize {
    i += 1;
    while i < src.len() {
        let Some(c) = src[i..].chars().next() else {
            break;
        };
        i += c.len_utf8();
        if c == '\\' {
            if let Some(next) = src[i..].chars().next() {
                i += next.len_utf8();
            }
            continue;
        }
        if c == '\'' {
            return i;
        }
    }
    src.len()
}

fn skip_raw_string(src: &str, i: usize) -> Option<usize> {
    let rest = &src[i..];
    let after_prefix = if rest.starts_with("br") {
        2
    } else if rest.starts_with('r') {
        1
    } else {
        return None;
    };
    let mut hashes = 0;
    let mut j = i + after_prefix;
    while src.get(j..).is_some_and(|tail| tail.starts_with('#')) {
        hashes += 1;
        j += 1;
    }
    if !src.get(j..).is_some_and(|tail| tail.starts_with('"')) {
        return None;
    }
    j += 1;
    let closer = format!("\"{}", "#".repeat(hashes));
    src.get(j..).and_then(|tail| tail.find(&closer)).map(|rel| j + rel + closer.len())
}

fn skip_ws(src: &str, mut i: usize) -> usize {
    while i < src.len() {
        let Some(c) = src[i..].chars().next() else {
            break;
        };
        if !c.is_whitespace() {
            break;
        }
        i += c.len_utf8();
    }
    i
}

fn skip_attribute(src: &str, i: usize) -> usize {
    if !src[i..].starts_with("#[") {
        return i;
    }
    skip_delimited(src, i + 1, '[', ']')
}

fn skip_delimited(src: &str, mut i: usize, open: char, close: char) -> usize {
    let mut depth = 0;
    while i < src.len() {
        if src[i..].starts_with('"') {
            i = skip_string(src, i);
            continue;
        }
        if src[i..].starts_with('\'') {
            i = skip_char_or_lifetime(src, i);
            continue;
        }
        let Some(c) = src[i..].chars().next() else {
            break;
        };
        i += c.len_utf8();
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return i;
            }
        }
    }
    i
}

fn skip_item(src: &str, mut i: usize) -> usize {
    i = skip_ws(src, i);
    if src[i..].starts_with("pub") {
        i += 3;
        i = skip_ws(src, i);
        if src[i..].starts_with('(') {
            i = skip_delimited(src, i, '(', ')');
        }
        i = skip_ws(src, i);
    }
    for prefix in ["async ", "const ", "unsafe "] {
        if src[i..].starts_with(prefix) {
            i += prefix.len();
            i = skip_ws(src, i);
        }
    }
    let mut brace = 0;
    let mut opened = false;
    while i < src.len() {
        if src[i..].starts_with('"') {
            i = skip_string(src, i);
            continue;
        }
        if src[i..].starts_with('\'') {
            i = skip_char_or_lifetime(src, i);
            continue;
        }
        let Some(c) = src[i..].chars().next() else {
            break;
        };
        i += c.len_utf8();
        if c == '{' {
            brace += 1;
            opened = true;
        } else if c == '}' {
            if brace > 0 {
                brace -= 1;
            }
            if brace == 0 && opened {
                return i;
            }
        } else if c == ';' && brace == 0 {
            return i;
        }
    }
    i
}

fn is_cfg_test_attr(src: &str, i: usize) -> bool {
    src[i..].starts_with("#[cfg(test)]")
}

fn strip_cfg_test_items(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i..].starts_with('"') {
            let end = skip_string(src, i);
            out.push_str(&src[i..end]);
            i = end;
            continue;
        }
        if src[i..].starts_with('\'') {
            let end = skip_char_or_lifetime(src, i);
            out.push_str(&src[i..end]);
            i = end;
            continue;
        }
        if is_cfg_test_attr(src, i) {
            i = skip_attribute(src, i);
            i = skip_ws(src, i);
            while src[i..].starts_with("#[") {
                i = skip_attribute(src, i);
                i = skip_ws(src, i);
            }
            i = skip_item(src, i);
            out.push('\n');
            continue;
        }
        let Some(c) = src[i..].chars().next() else {
            break;
        };
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// Collapses runs of whitespace to one space and removes spaces around `::`,
/// so `std :: fs :: write` becomes `std::fs::write`.
fn collapse_path_ws(src: &str) -> String {
    src.split_whitespace().collect::<Vec<_>>().join(" ").replace(" ::", "::").replace(":: ", "::")
}

/// Appends the expanded paths of every `use` item and the alias-rewritten text.
fn expand_detection_text(collapsed: &str) -> String {
    let mut bindings: Vec<(String, String)> = Vec::new();
    for body in use_bodies(collapsed) {
        expand_use_tree("", body, &mut bindings);
    }
    let mut rewritten = collapsed.to_string();
    for (full, alias) in &bindings {
        if alias != "*" && alias != "_" {
            rewritten = rewrite_alias(&rewritten, alias, full);
        }
    }
    let mut out = String::with_capacity(collapsed.len() * 2);
    out.push_str(collapsed);
    out.push('\n');
    for (full, _) in &bindings {
        out.push_str(full);
        out.push('\n');
    }
    out.push_str(&rewritten);
    out
}

/// Bodies of `use` / `pub use` items, without the leading keyword or the `;`.
fn use_bodies(text: &str) -> Vec<&str> {
    let mut bodies = Vec::new();
    let mut from = 0;
    while let Some(rel) = text[from..].find("use ") {
        let at = from + rel;
        let body_start = at + 4;
        let boundary = text[..at].chars().next_back().is_none_or(|c| !is_ident_char(c) && c != ':');
        let found = if boundary { text[body_start..].find(';') } else { None };
        match found {
            Some(end_rel) => {
                let end = body_start + end_rel;
                bodies.push(&text[body_start..end]);
                from = end + 1;
            }
            None => from = body_start,
        }
    }
    bodies
}

fn join_path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() { path.to_string() } else { format!("{prefix}::{path}") }
}

/// Splits on commas that sit outside braces.
fn split_top_level(tree: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in tree.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&tree[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&tree[start..]);
    parts
}

/// Expands a use tree into `(full path, bound alias)` pairs. Nested groups,
/// `self`, `as` renames and globs are handled. Unsupported shapes are skipped.
fn expand_use_tree(prefix: &str, tree: &str, out: &mut Vec<(String, String)>) {
    for part in split_top_level(tree) {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        if let Some(open) = item.find('{') {
            let close = item.rfind('}').unwrap_or(item.len());
            let head = item[..open].trim().trim_end_matches("::");
            let next = join_path(prefix, head);
            expand_use_tree(&next, &item[open + 1..close], out);
            continue;
        }
        let words: Vec<&str> = item.split_whitespace().collect();
        let (path, alias) = match words.as_slice() {
            [path] => (*path, None),
            [path, "as", alias] => (*path, Some(*alias)),
            _ => continue,
        };
        let full = if path == "self" { prefix.to_string() } else { join_path(prefix, path) };
        let alias = alias.map_or_else(
            || full.rsplit("::").next().unwrap_or_default().to_string(),
            str::to_string,
        );
        out.push((full, alias));
    }
}

/// Rewrites `alias::x` to `full::x` wherever `alias` is a whole path segment.
fn rewrite_alias(text: &str, alias: &str, full: &str) -> String {
    let needle = format!("{alias}::");
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (at, _) in text.match_indices(&needle) {
        let boundary = text[..at].chars().next_back().is_none_or(|c| !is_ident_char(c) && c != ':');
        if boundary {
            out.push_str(&text[last..at]);
            out.push_str(full);
            out.push_str("::");
            last = at + needle.len();
        }
    }
    out.push_str(&text[last..]);
    out
}

fn planted_spellings(symbol: &str) -> [(&'static str, String); 3] {
    [
        ("bare", format!("fn sink() {{ {symbol}(); }}\n")),
        ("path_qualified", format!("fn sink() {{ crate::persist::{symbol}(); }}\n")),
        (
            "use_alias",
            format!(
                "use crate::persist::{symbol} as persist_sink;\nfn sink() {{ persist_sink(); }}\n"
            ),
        ),
    ]
}

fn detect(src: &str) -> Vec<&'static str> {
    forbidden_hits(&production_source(src))
}

#[test]
fn ephemeral_modules_have_no_durable_sinks() -> TestResult {
    let root = workspace_root()?;
    let files = discover_ephemeral_modules(&root)?;
    if files.is_empty() {
        return Err(io::Error::other("ephemeral module scan produced zero files").into());
    }
    let mut violations = String::new();
    for path in &files {
        let source = std::fs::read_to_string(path)?;
        for symbol in detect(&source) {
            violations.push_str(&rel_path(&root, path));
            violations.push_str(": ");
            violations.push_str(symbol);
            violations.push('\n');
        }
    }
    if !violations.is_empty() {
        return Err(io::Error::other(format!(
            "ephemeral modules name durable-sink symbols:\n{violations}"
        ))
        .into());
    }
    Ok(())
}

#[test]
fn ephemeral_inventory_discovery() -> TestResult {
    let root = workspace_root()?;
    let files = discover_ephemeral_modules(&root)?;
    let rels: Vec<String> = files.iter().map(|path| rel_path(&root, path)).collect();
    assert!(!rels.is_empty(), "discovery must find at least one module");
    for required in REQUIRED_MODULES {
        assert!(
            rels.iter().any(|rel| rel.as_str() == *required),
            "discovery must include {required}, got {rels:?}"
        );
    }
    for (excluded, declaring) in TEST_ONLY_MODULES {
        let stem = Path::new(excluded).file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        let decl_src = std::fs::read_to_string(root.join(declaring))?;
        assert!(
            declared_cfg_test(&decl_src, stem),
            "exclusion {excluded} must still be declared #[cfg(test)] in {declaring}"
        );
        assert!(!rels.iter().any(|rel| rel.as_str() == *excluded), "{excluded} must stay excluded");
    }
    assert!(
        !rels.iter().any(|rel| rel.as_str() == GUARD_REL || rel.contains("/tests/")),
        "guard and tests/ files must be excluded, got {rels:?}"
    );
    Ok(())
}

#[test]
fn normaliser_grouped_alias_is_detected() {
    let src = "use std::{fs as disk}; fn f() { disk::write(\"x\", b\"x\"); }\n";
    assert_eq!(detect(src), vec!["std::fs"]);
}

#[test]
fn normaliser_pub_use_reexport_is_detected() {
    let src = "pub use std::{fs as disk};\n";
    assert_eq!(detect(src), vec!["std::fs"]);
}

#[test]
fn normaliser_nested_group_is_detected() {
    let src = "use std::{io::{self, Write}, fs as disk};\nfn f() { let _ = disk::read(\"x\"); }\n";
    assert_eq!(detect(src), vec!["std::fs"]);
}

#[test]
fn normaliser_whitespace_separated_path_is_detected() {
    let src = "fn f() { std :: fs :: write(\"x\", b\"x\"); }\n";
    assert_eq!(detect(src), vec!["std::fs"]);
}

#[test]
fn normaliser_direct_call_is_detected() {
    let src = "fn f() { std::fs::write(\"x\", b\"x\"); }\n";
    assert_eq!(detect(src), vec!["std::fs"]);
}

#[test]
fn normaliser_comment_and_string_are_not_detected() {
    let src = "// std::fs begin_write\nfn f() { let _ = \"std::fs OpenOptions\"; }\n";
    assert_eq!(detect(src), Vec::<&'static str>::new());
}

#[test]
fn planted_forbidden_symbols_are_caught() {
    for symbol in FORBIDDEN_SYMBOLS {
        for (kind, source) in planted_spellings(symbol) {
            let hits = detect(&source);
            assert!(
                hits.iter().any(|hit| hit == symbol),
                "symbol {symbol} spelling {kind} must be caught in {source:?}, hits={hits:?}"
            );
        }
    }
}

#[test]
fn planted_near_miss_identifiers_are_not_caught() {
    let src = "fn sink() { begin_write_txn(); std::fmt::write(); open_options(); }\n";
    let hits = detect(src);
    assert!(hits.is_empty(), "near-miss identifiers must not match, hits={hits:?}");
}

#[test]
fn ephemeral_sink_guard_ignores_cfg_test_items() {
    let src = r#"
        fn production() {}
        #[cfg(test)]
        #[allow(clippy::expect_used, reason = "hang guards must panic")]
        mod tests {
            use crate::RouterRedbStore;
            fn t() {
                let _ = std::fs::remove_file("x");
                RouterRedbStore::open("p");
            }
        }
    "#;
    let hits = detect(src);
    assert!(hits.is_empty(), "cfg(test) fixtures must not count, hits={hits:?}");

    let src = "fn production() { begin_write(); }\n#[cfg(test)]\nmod tests {}\n";
    let hits = detect(src);
    assert!(hits.contains(&"begin_write"), "production hits must remain visible, hits={hits:?}");
}

#[test]
fn comments_naming_forbidden_symbols_are_not_hits() {
    let src = "// begin_write RouterRedbStore std::fs\nfn f() {}\n";
    let hits = detect(src);
    assert!(hits.is_empty(), "comments must not count, hits={hits:?}");
}
