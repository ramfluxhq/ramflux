// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Static guard: new ephemeral modules must not name durable-sink symbols.
//!
//! Production items are scanned. `#[cfg(test)]` items and `tests.rs` /
//! `*_tests.rs` files are ignored so absence proofs may open a store.

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

/// Module dirs (and in-flight sibling files) under node-core, gateway, router, sdk.
/// `read_dir` discovers `.rs` files; a missing path is skipped, not an error.
const CANDIDATE_MODULE_ROOTS: &[&str] = &[
    "crates/ramflux-node-core/src/ephemeral",
    "apps/ramflux-router/src/ephemeral",
    "apps/ramflux-router/src/ephemeral_route.rs",
    "apps/ramflux-gateway/src/ephemeral",
    "apps/ramflux-gateway/src/ephemeral.rs",
    "apps/ramflux-gateway/src/ephemeral_queue",
    "crates/ramflux-sdk/src/ephemeral",
    "crates/ramflux-sdk/src/ephemeral.rs",
    "crates/ramflux-sdk/src/transient",
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

fn collect_rs_files(path: &Path) -> io::Result<Vec<PathBuf>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    if path.is_file() {
        if is_scanned_rs(path) {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }
    if !path.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    collect_rs_dir(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_rs_dir(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs_read_dir(dir)? {
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

fn fs_read_dir(dir: &Path) -> io::Result<std::fs::ReadDir> {
    std::fs::read_dir(dir)
}

fn collect_ephemeral_sources(workspace: &Path) -> io::Result<(Vec<PathBuf>, Vec<&'static str>)> {
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    for rel in CANDIDATE_MODULE_ROOTS {
        let path = workspace.join(rel);
        if path.exists() {
            files.extend(collect_rs_files(&path)?);
        } else {
            skipped.push(*rel);
        }
    }
    files.sort();
    files.dedup();
    Ok((files, skipped))
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

fn production_source(src: &str) -> String {
    strip_cfg_test_items(&strip_comments(src))
}

fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if let Some(end) = skip_raw_string(src, i) {
            out.push_str(&src[i..end]);
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
            let end = skip_string(src, i);
            out.push_str(&src[i..end]);
            i = end;
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

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map_or_else(|_| path.display().to_string(), |rel| rel.display().to_string())
}

#[test]
fn ephemeral_modules_have_no_durable_sinks() -> TestResult {
    let root = workspace_root()?;
    let node_core = root.join("crates/ramflux-node-core/src/ephemeral");
    if !node_core.is_dir() {
        return Err(io::Error::other("node-core ephemeral module dir is missing").into());
    }
    let (files, _skipped) = collect_ephemeral_sources(&root)?;
    if files.is_empty() {
        return Err(io::Error::other("ephemeral module scan produced zero files").into());
    }
    let mut violations = String::new();
    for path in &files {
        let source = std::fs::read_to_string(path)?;
        let hits = forbidden_hits(&production_source(&source));
        for symbol in hits {
            violations.push_str(&display_path(&root, path));
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
fn planted_forbidden_symbols_are_caught() {
    for symbol in FORBIDDEN_SYMBOLS {
        for (kind, source) in planted_spellings(symbol) {
            let hits = forbidden_hits(&production_source(&source));
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
    let hits = forbidden_hits(&production_source(src));
    assert!(hits.is_empty(), "near-miss identifiers must not match, hits={hits:?}");
}

#[test]
fn ephemeral_sink_guard_skips_missing_module_roots() -> TestResult {
    let root = workspace_root()?;
    let missing = root.join("this_path_is_not_an_ephemeral_module");
    let files = collect_rs_files(&missing)?;
    assert!(files.is_empty(), "missing path must yield zero files, not an error");
    let (_files, skipped) = collect_ephemeral_sources(&root)?;
    assert!(!skipped.is_empty(), "in-flight module roots absent on this tree must be skipped");
    Ok(())
}

#[test]
fn ephemeral_sink_guard_inclusive_scan_bounds() -> TestResult {
    let root = workspace_root()?;
    let zero_path = root.join("apps/ramflux-router/src/ephemeral");
    let zero = collect_rs_files(&zero_path)?;
    if !zero_path.exists() {
        assert!(zero.is_empty(), "absent dir must yield zero scanned files");
    }
    let n_path = root.join("crates/ramflux-node-core/src/ephemeral");
    let n = collect_rs_files(&n_path)?;
    assert!(!n.is_empty(), "existing ephemeral module dir must yield scanned files");
    Ok(())
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
    let hits = forbidden_hits(&production_source(src));
    assert!(hits.is_empty(), "cfg(test) fixtures must not count, hits={hits:?}");

    let src = "fn production() { begin_write(); }\n#[cfg(test)]\nmod tests {}\n";
    let hits = forbidden_hits(&production_source(src));
    assert!(hits.contains(&"begin_write"), "production hits must remain visible, hits={hits:?}");
}

#[test]
fn comments_naming_forbidden_symbols_are_not_hits() {
    let src = "// begin_write RouterRedbStore std::fs\nfn f() {}\n";
    let hits = forbidden_hits(&production_source(src));
    assert!(hits.is_empty(), "comments must not count, hits={hits:?}");
}
