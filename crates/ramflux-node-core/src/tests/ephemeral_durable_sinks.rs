// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Static guard: ephemeral modules may import only what the allow-list names.
//!
//! Production modules are discovered by walking `crates/*/src` and
//! `apps/*/src` for `.rs` files whose path contains `ephemeral` or
//! `transient`. Test-only files are excluded. Each module passes two layers:
//!
//! 1. Import allow-list. Every `use` path and every module-style path
//!    expression (`a::b::c(..)`) must start with an entry of
//!    `ALLOWED_IMPORT_PREFIXES`. Glob imports are refused.
//! 2. Forbidden-symbol scan over the normalised text, with `use` aliases
//!    expanded. This is a second layer, not the proof.
//!
//! Comments and string literals are stripped and `#[cfg(test)]` items are
//! ignored first, so absence proofs may open a store.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// Import allow-list. An ephemeral module may name a path only when the path
/// starts with one of these prefixes, on whole segments. Each entry records why
/// the prefix is safe. Filesystem, network, process, environment and storage
/// paths (`std::fs`, `std::io`, `std::net`, `std::process`, `std::env`,
/// `std::path`, `tokio`, `redb`, `rusqlite`, ...) must never appear here; the
/// `allow_list_excludes_persistence_prefixes` test enforces it.
const ALLOWED_IMPORT_PREFIXES: &[(&str, &str)] = &[
    ("crate::ephemeral::capability", "this module family's capability state (same crate)"),
    ("crate::ephemeral::route", "this module family's route gate and responses (same crate)"),
    ("crate::EphemeralRouteGate", "route gate enum, crate root re-export (no I/O)"),
    ("crate::Envelope", "protocol wire envelope, crate root re-export (no I/O)"),
    ("crate::Priority", "protocol priority enum, crate root re-export (no I/O)"),
    ("crate::HomeNodeMigrationRecord", "migration record type, crate root re-export (type only)"),
    ("crate::NodeCoreError", "error type, crate root re-export (type only)"),
    ("crate::EnvelopeAuthorityReason", "authority refusal enum, crate root re-export (type only)"),
    (
        "crate::RouterCore",
        "router handle type named in signatures; sinks on it are caught by layer 2",
    ),
    (
        "crate::EphemeralRegistrationItem",
        "ephemeral registration record, crate root re-export (type only)",
    ),
    ("crate::SessionLifecycle", "session lifecycle enum, crate root re-export (type only)"),
    ("crate::lock_unpoisoned", "mutex lock helper (no I/O)"),
    ("ramflux_protocol", "protocol wire types and canonical encoding (no storage dependency)"),
    ("ramflux_crypto::verify_canonical_signature", "signature verification only (no storage)"),
    ("blake3::Hasher::new_derive_key", "pure hasher constructor (no I/O)"),
    ("serde::Deserialize", "derive trait (no I/O)"),
    ("serde::Serialize", "derive trait (no I/O)"),
    ("serde_json::Value", "JSON value type (no I/O)"),
    ("serde_json::to_vec", "JSON serialisation to memory (no I/O)"),
    ("thiserror::Error", "error derive (no I/O)"),
    ("std::collections", "in-memory maps and sets (no I/O)"),
    ("std::sync", "in-memory locks, atomics and Arc (no I/O)"),
    ("std::time", "wall-clock reads (no I/O)"),
    ("tracing", "structured logging macros only (no durable state)"),
    (
        "crate::router_store::incarnation::new_id",
        "boot id from OS randomness only (no storage; not the whole incarnation module)",
    ),
    ("crate::GatewayQuicContext", "gateway QUIC context type, crate root re-export (type only)"),
    ("crate::GatewaySendHandle", "gateway send handle type, crate root re-export (type only)"),
    (
        "crate::GatewaySessionRuntime",
        "gateway session runtime type, crate root re-export (type only)",
    ),
    ("crate::GatewaySessionHub", "gateway session hub type, crate root re-export (type only)"),
    (
        "crate::push_queue::TransientAdmission",
        "P08 bounded volatile FIFO admission result enum (one type, not the module)",
    ),
    (
        "crate::router_post_json_async",
        "gateway-to-router network hand-off for ephemeral routing; no local durable write",
    ),
    (
        "crate::session::verify_gateway_session_signed_request",
        "signature check of a gateway session request (no I/O)",
    ),
    (
        "crate::session::write_gateway_handle",
        "network write of one frame to a client handle; no local durable write",
    ),
    (
        "crate::submit_source::bind_source",
        "binds a submit to the authenticated session source (no I/O)",
    ),
    (
        "ramflux_node_core::GatewayServerFrame",
        "gateway wire frame enum from node-core (type; variants covered)",
    ),
    (
        "ramflux_node_core::GatewaySubmitFrame",
        "gateway submit frame type from node-core (type only)",
    ),
    ("serde_json::json", "JSON literal macro (no I/O)"),
    ("std::future::Future", "async trait (no I/O)"),
    ("tokio::sync::Mutex", "async mutex (no I/O)"),
    ("anyhow::Result", "error result alias (no I/O)"),
    (
        "ramflux_node_core::SessionPushForwardOutcome",
        "forward outcome enum from node-core (type; no I/O)",
    ),
    (
        "ramflux_node_core::SessionPushForwardResponse",
        "forward response type from node-core (type only)",
    ),
    ("std::fmt::Display", "formatting trait (no I/O)"),
    ("std::fmt::Formatter", "formatter type for Display (no I/O)"),
    ("std::fmt::Result", "formatting result alias (no I/O)"),
    ("std::future::ready", "immediately-ready future constructor (no I/O)"),
    ("anyhow::ensure", "error-check macro (no I/O)"),
    ("anyhow::anyhow", "error-construction macro (no I/O)"),
    ("crate::ephemeral::lifetime", "same-crate lifetime types and helpers (no I/O)"),
    ("crate::ephemeral::receiver", "same-crate receiver types and bounds (no I/O)"),
    ("blake3::Hasher", "in-memory digest hasher (no I/O)"),
    ("blake3::hash", "in-memory digest of one payload (no I/O)"),
    ("serde_json::from_slice", "JSON decode from memory (no I/O)"),
];

/// Primitive type names. Their associated functions (`i64::try_from`) cannot
/// reach storage, so they are exempt from the allow-list.
const PRIMITIVE_TYPES: &[&str] = &[
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64",
    "i128", "isize", "f32", "f64",
];

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
    // Declared `#[cfg(test)] mod ephemeral_route;` at
    // apps/ramflux-router/src/handlers/session_push.rs:285-286 on origin/main.
    (
        "apps/ramflux-router/src/handlers/session_push/ephemeral_route.rs",
        "apps/ramflux-router/src/handlers/session_push.rs",
    ),
    // Declared `#[cfg(test)] mod ephemeral_negotiation;` at
    // apps/ramflux-gateway/src/session_push/tests.rs:6-7 (the tests module is
    // itself `#[cfg(test)]` at apps/ramflux-gateway/src/session_push.rs:750-751).
    (
        "apps/ramflux-gateway/src/session_push/ephemeral_negotiation.rs",
        "apps/ramflux-gateway/src/session_push/tests.rs",
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

/// Comments and strings stripped, `#[cfg(test)]` items removed, whitespace collapsed.
fn normalised_items(src: &str) -> String {
    collapse_path_ws(&strip_cfg_test_items(&strip_comments(src)))
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

/// Bodies of `use` / `pub use` items with their byte offsets, without the
/// leading keyword or the `;`.
fn use_bodies(text: &str) -> Vec<(usize, &str)> {
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
                bodies.push((body_start, &text[body_start..end]));
                from = end + 1;
            }
            None => from = body_start,
        }
    }
    bodies
}

/// Byte ranges `(name, start, end)` of inline `mod name { .. }` items, in
/// source order. Nested items follow their enclosing item.
fn inline_mod_spans(text: &str) -> Vec<(String, usize, usize)> {
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(rel) = text[from..].find("mod ") {
        let at = from + rel;
        from = at + 4;
        let boundary = text[..at].chars().next_back().is_none_or(|c| !is_ident_char(c) && c != ':');
        if !boundary {
            continue;
        }
        let name_start = skip_ws(text, at + 4);
        let name_len =
            text[name_start..].find(|c: char| !is_ident_char(c)).unwrap_or(text.len() - name_start);
        let name_end = name_start + name_len;
        let brace = skip_ws(text, name_end);
        if name_len == 0 || !text[brace..].starts_with('{') {
            continue;
        }
        let end = skip_delimited(text, brace, '{', '}');
        spans.push((text[name_start..name_end].to_string(), at, end));
    }
    spans
}

/// Module path in effect at byte `at`: the file's module plus every inline
/// `mod` span that strictly encloses `at`.
fn module_at(file_module: &str, spans: &[(String, usize, usize)], at: usize) -> String {
    let mut module = file_module.to_string();
    for (name, start, end) in spans {
        if *start < at && at < *end {
            module = join_module(&module, name);
        }
    }
    module
}

fn join_module(module: &str, segment: &str) -> String {
    format!("{module}::{segment}")
}

fn parent_module(module: &str) -> Option<String> {
    module.rsplit_once("::").map(|(parent, _)| parent.to_string())
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

/// Rewrites every whole-segment occurrence of `needle` to `replacement`. A
/// match preceded by an identifier, `:` or `.` is a different name and is kept.
fn rewrite_word(text: &str, needle: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (at, _) in text.match_indices(needle) {
        let boundary = text[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !is_ident_char(c) && c != ':' && c != '.');
        if boundary {
            out.push_str(&text[last..at]);
            out.push_str(replacement);
            last = at + needle.len();
        }
    }
    out.push_str(&text[last..]);
    out
}

/// Rewrites `alias::x` to `full::x` wherever `alias` is a whole path segment.
fn rewrite_alias(text: &str, alias: &str, full: &str) -> String {
    rewrite_word(text, &format!("{alias}::"), &format!("{full}::"))
}

/// Anchors a path written inside `module` to an absolute path. `crate::` paths
/// are already absolute, `self::` and `super::` are relative to `module`, and
/// a first segment naming a child module of `module` is resolved into it.
/// Anything else (`std::fs`, an extern crate) is returned unchanged.
fn normalise_target(
    module: &str,
    full: &str,
    modules: &BTreeSet<String>,
) -> Result<String, String> {
    let mut parts: Vec<&str> = full.split("::").collect();
    let mut base = match parts[0] {
        "crate" => return Ok(full.to_string()),
        "self" => {
            parts.remove(0);
            module.to_string()
        }
        "super" => {
            let mut base = module.to_string();
            while parts.first() == Some(&"super") {
                parts.remove(0);
                base = parent_module(&base)
                    .ok_or_else(|| format!("`{full}` escapes the crate root in {module}"))?;
            }
            base
        }
        first if modules.contains(&join_module(module, first)) => module.to_string(),
        _ => return Ok(full.to_string()),
    };
    for part in parts {
        base = join_module(&base, part);
    }
    Ok(base)
}

/// Module path (`crate::a::b`) of a file under a crate's `src/`.
fn module_path_of(src_dir: &Path, path: &Path) -> io::Result<String> {
    let rel = rel_path(src_dir, path);
    let stem = rel
        .strip_suffix(".rs")
        .ok_or_else(|| io::Error::other(format!("{rel} is not a .rs file")))?;
    let mut segments: Vec<&str> = stem.split('/').collect();
    match segments.last().copied() {
        Some("mod") => {
            segments.pop();
        }
        Some("lib" | "main") if segments.len() == 1 => {
            segments.pop();
        }
        _ => {}
    }
    Ok(std::iter::once("crate").chain(segments).collect::<Vec<_>>().join("::"))
}

/// `<root>/{crates,apps}/<name>/src` for a discovered module.
fn crate_src_of(root: &Path, path: &Path) -> io::Result<PathBuf> {
    let rel = rel_path(root, path);
    match rel.split('/').collect::<Vec<_>>().as_slice() {
        [top, name, "src", ..] => Ok(root.join(top).join(name).join("src")),
        _ => Err(io::Error::other(format!("{rel} is outside a crate src tree"))),
    }
}

fn planted_spellings(symbol: &str) -> [(&'static str, String); 3] {
    // A path-shaped symbol (`std::fs`) is spelt as itself. A bare identifier
    // is an item of the fixture module `crate::persist`.
    let path = if symbol.contains("::") {
        symbol.to_string()
    } else {
        format!("crate::persist::{symbol}")
    };
    [
        ("bare", format!("fn sink() {{ {symbol}(); }}\n")),
        ("path_qualified", format!("fn sink() {{ {path}(); }}\n")),
        ("use_alias", format!("use {path} as persist_sink;\nfn sink() {{ persist_sink(); }}\n")),
    ]
}

/// True when `path` starts with an allow-listed prefix on whole segments.
fn is_allowed_path(path: &str) -> bool {
    let first = path.split("::").next().unwrap_or_default();
    PRIMITIVE_TYPES.contains(&first)
        || ALLOWED_IMPORT_PREFIXES.iter().any(|(prefix, _)| {
            path == *prefix || path.strip_prefix(*prefix).is_some_and(|rest| rest.starts_with("::"))
        })
}

/// Multi-segment paths in `text`, as written, with byte offsets. A path that
/// starts with an uppercase letter names a type or variant already in scope, so
/// it is not a module path and is skipped.
fn path_expressions(text: &str) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    let mut last = 0;
    for (at, c) in text.char_indices() {
        if at < last || !(c.is_ascii_alphabetic() || c == '_') {
            continue;
        }
        if text[..at].chars().next_back().is_some_and(is_ident_char) {
            continue;
        }
        let tail = &text[at..];
        let len = tail.find(|ch: char| !(is_ident_char(ch) || ch == ':')).unwrap_or(tail.len());
        last = at + len;
        let token = tail[..len].trim_end_matches("::");
        let first = token.split("::").next().unwrap_or_default();
        if token.contains("::") && !first.starts_with(char::is_uppercase) {
            found.push((token.to_string(), at));
        }
    }
    found
}

/// Layer 1. Every `use` path and every module-style path expression of an
/// ephemeral module must be allow-listed, and glob imports are refused.
fn check_allow_list(
    text: &str,
    label: &str,
    file_module: &str,
    modules: &BTreeSet<String>,
) -> Result<(), String> {
    let spans = inline_mod_spans(text);
    for (at, body) in use_bodies(text) {
        let module = module_at(file_module, &spans, at);
        let mut raw = Vec::new();
        expand_use_tree("", body, &mut raw);
        for (full, alias) in raw {
            let is_glob = alias == "*";
            let base =
                if is_glob { full.strip_suffix("::*").unwrap_or(&full) } else { full.as_str() };
            let path = normalise_target(&module, base, modules).map_err(|reason| {
                format!("import {base} not on the ephemeral allow-list in {label}: {reason}")
            })?;
            let shown = if is_glob { format!("{path}::*") } else { path.clone() };
            if !is_allowed_path(&shown) {
                return Err(format!("import {shown} not on the ephemeral allow-list in {label}"));
            }
            if is_glob {
                return Err(format!("glob import {path} not allowed in ephemeral module {label}"));
            }
        }
    }
    for (token, at) in path_expressions(text) {
        let module = module_at(file_module, &spans, at);
        let path = normalise_target(&module, &token, modules).map_err(|reason| {
            format!("import {token} not on the ephemeral allow-list in {label}: {reason}")
        })?;
        if !is_allowed_path(&path) {
            return Err(format!("import {path} not on the ephemeral allow-list in {label}"));
        }
    }
    Ok(())
}

/// Both layers over one module. Layer 1 runs first, so a refusal names the
/// path. Layer 2 returns the forbidden symbols it finds.
fn scan_file(
    src: &str,
    label: &str,
    file_module: &str,
    modules: &BTreeSet<String>,
) -> Result<Vec<&'static str>, String> {
    let collapsed = normalised_items(src);
    check_allow_list(&collapsed, label, file_module, modules)?;
    Ok(forbidden_hits(&expand_detection_text(&collapsed)))
}

/// Layer 2 alone, for the normaliser and planted-spelling rows.
fn detect(src: &str) -> Vec<&'static str> {
    forbidden_hits(&expand_detection_text(&normalised_items(src)))
}

/// Appends the expanded paths of every `use` item, then the alias-rewritten
/// text, so a name bound by `use` is seen at its full path.
fn expand_detection_text(collapsed: &str) -> String {
    let mut bindings: Vec<(String, String)> = Vec::new();
    for (_, body) in use_bodies(collapsed) {
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

/// Module paths of one crate's production `src/`, file and inline, used to
/// anchor relative `use` and expression paths.
fn load_crate_modules(src_dir: &Path) -> io::Result<BTreeSet<String>> {
    let mut files = Vec::new();
    collect_rs_dir(src_dir, &mut files)?;
    files.sort();
    let mut modules = BTreeSet::new();
    for path in &files {
        if rel_path(src_dir, path).split('/').any(|part| part == "tests") {
            continue;
        }
        let module = module_path_of(src_dir, path)?;
        let text = normalised_items(&std::fs::read_to_string(path)?);
        let spans = inline_mod_spans(&text);
        for (name, start, _) in &spans {
            modules.insert(join_module(&module_at(&module, &spans, *start), name));
        }
        modules.insert(module);
    }
    Ok(modules)
}

const FIXTURE_LABEL: &str = "src/ephemeral.rs";
const FIXTURE_MODULE: &str = "crate::ephemeral";

fn fixture_modules() -> BTreeSet<String> {
    BTreeSet::from(["crate".to_string(), FIXTURE_MODULE.to_string()])
}

fn scan_fixture(src: &str) -> Result<Vec<&'static str>, String> {
    scan_file(src, FIXTURE_LABEL, FIXTURE_MODULE, &fixture_modules())
}

/// Asserts that the fixture is refused with exactly `expected`.
fn expect_refusal(src: &str, expected: &str) -> TestResult {
    match scan_fixture(src) {
        Err(err) => {
            assert_eq!(err, expected);
            Ok(())
        }
        Ok(hits) => Err(format!("expected refusal `{expected}`, got hits {hits:?}").into()),
    }
}

#[test]
fn ephemeral_modules_have_no_durable_sinks() -> TestResult {
    let root = workspace_root()?;
    let files = discover_ephemeral_modules(&root)?;
    if files.is_empty() {
        return Err(io::Error::other("ephemeral module scan produced zero files").into());
    }
    let mut crates: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let mut violations = String::new();
    for path in &files {
        let src_dir = crate_src_of(&root, path)?;
        if !crates.contains_key(&src_dir) {
            crates.insert(src_dir.clone(), load_crate_modules(&src_dir)?);
        }
        let Some(modules) = crates.get(&src_dir) else {
            return Err(io::Error::other("crate module set missing after insert").into());
        };
        let label = rel_path(&root, path);
        let file_module = module_path_of(&src_dir, path)?;
        let source = std::fs::read_to_string(path)?;
        for symbol in scan_file(&source, &label, &file_module, modules).map_err(io::Error::other)? {
            violations.push_str(&label);
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
fn allow_list_excludes_persistence_prefixes() {
    const BANNED: &[&str] = &[
        "std::fs",
        "std::io",
        "std::net",
        "std::process",
        "std::env",
        "std::path",
        "tokio::fs",
        "tokio::io",
        "tokio::net",
        "tokio::process",
        "redb",
        "rusqlite",
        "sqlx",
        "sled",
        "rocksdb",
        "diesel",
    ];
    let overlaps = |a: &str, b: &str| {
        a == b || a.starts_with(&format!("{b}::")) || b.starts_with(&format!("{a}::"))
    };
    for (prefix, why) in ALLOWED_IMPORT_PREFIXES {
        assert!(!why.is_empty(), "allow-list entry {prefix} needs a justification");
        for banned in BANNED {
            assert!(!overlaps(prefix, banned), "allow-list entry {prefix} must not cover {banned}");
        }
    }
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

/// Allowed imports pass, including primitive associated functions.
#[test]
fn allow_listed_imports_pass() -> TestResult {
    let src = "use std::collections::BTreeMap;\nfn f(x: i64) -> Option<u8> {\n    let _m = BTreeMap::<u8, u8>::new();\n    u8::try_from(x).ok()\n}\n";
    assert_eq!(scan_fixture(src)?, Vec::<&'static str>::new());
    Ok(())
}

/// Reviewer r1 and r2: a re-export in another file hides `std::fs` behind
/// `crate::disk`. The path is not allow-listed, so the module is refused.
#[test]
fn reexport_cross_file_is_refused() -> TestResult {
    expect_refusal(
        "fn sink() { crate::disk::write(\"x\", b\"x\"); }\n",
        "import crate::disk::write not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// Reviewer r2: a two-hop re-export through `foo/mod.rs` is refused.
#[test]
fn reexport_two_hop_is_refused() -> TestResult {
    expect_refusal(
        "fn sink() { let _ = crate::disk::read(\"x\"); }\n",
        "import crate::disk::read not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// Reviewer r2: `self::` and `super::` chains are refused by their written path.
#[test]
fn reexport_relative_chain_is_refused() -> TestResult {
    expect_refusal(
        "fn sink() { let _ = crate::wal::inner::d::write(\"x\", b\"x\"); }\n",
        "import crate::wal::inner::d::write not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// Reviewer r3: the cycle `a -> b -> a` is refused without resolution.
#[test]
fn reexport_cycle_is_refused() -> TestResult {
    expect_refusal(
        "fn sink() { crate::a::x::write(); }\n",
        "import crate::a::x::write not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// Reviewer r3: a long re-export chain is refused, with no hop cap to reach.
#[test]
fn reexport_chain_is_refused() -> TestResult {
    expect_refusal(
        "fn sink() { crate::m0::write(); }\n",
        "import crate::m0::write not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// An unresolvable crate path is refused.
#[test]
fn unresolvable_crate_path_is_refused() -> TestResult {
    expect_refusal(
        "fn sink() { crate::nowhere::x(); }\n",
        "import crate::nowhere::x not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// Reviewer r3 and r4: a glob import from a crate module is refused.
#[test]
fn glob_from_crate_module_is_refused() -> TestResult {
    expect_refusal(
        "use crate::io::*;\npub fn sink() { let _ = write(\"x\", b\"x\"); }\n",
        "import crate::io::* not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// Reviewer r4: a glob through an external re-export is refused at the import.
#[test]
fn ephemeral_glob_through_external_reexport_is_refused() -> TestResult {
    expect_refusal(
        "use crate::io::*;\npub fn sink() { let _ = write(\"x\", b\"x\"); }\n",
        "import crate::io::* not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// Reviewer r4 and r6: an explicit path through an external glob
/// (`pub use std::fs::*;` or `pub use self::disk::*;` over `std::fs`) is refused.
#[test]
fn explicit_path_through_external_glob_is_refused() -> TestResult {
    expect_refusal(
        "use crate::io::write;\npub fn sink() { let _ = write(\"x\", b\"x\"); }\n",
        "import crate::io::write not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// A glob of an external module is refused by its path.
#[test]
fn external_glob_import_is_refused() -> TestResult {
    expect_refusal(
        "use std::fs::*;\nfn sink() { write(\"x\", b\"x\"); }\n",
        "import std::fs::* not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// A direct `std::fs` import is refused.
#[test]
fn std_fs_import_is_refused() -> TestResult {
    expect_refusal(
        "use std::fs::write;\nfn sink() { write(\"x\", b\"x\"); }\n",
        "import std::fs::write not on the ephemeral allow-list in src/ephemeral.rs",
    )
}

/// Adding `use std::fs::write;` to a real ephemeral module is refused.
#[test]
fn real_ephemeral_module_with_fs_import_is_refused() -> TestResult {
    let root = workspace_root()?;
    let rel = "crates/ramflux-protocol/src/ephemeral.rs";
    let src_dir = root.join("crates/ramflux-protocol/src");
    let modules = load_crate_modules(&src_dir)?;
    let mut src = std::fs::read_to_string(root.join(rel))?;
    src.push_str("\nuse std::fs::write;\n");
    let Err(err) = scan_file(&src, rel, "crate::ephemeral", &modules) else {
        return Err("a real ephemeral module importing std::fs must be refused".into());
    };
    assert_eq!(
        err,
        "import std::fs::write not on the ephemeral allow-list in crates/ramflux-protocol/src/ephemeral.rs"
    );
    Ok(())
}
