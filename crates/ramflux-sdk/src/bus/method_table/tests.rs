// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dispatch source audit fails when a new literal method has no deliberate classification.

use super::*;
use std::{collections::BTreeSet, path::Path};

#[test]
fn method_table_covers_every_dispatch_arm_and_routes_local_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let bus = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bus");
    let mut methods = BTreeSet::new();
    let dispatch = bus.join("dispatch");
    for entry in std::fs::read_dir(dispatch)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "rs")
            && !path.file_stem().is_some_and(|name| name.to_string_lossy().contains("test"))
        {
            collect(&std::fs::read_to_string(path)?, &mut methods);
        }
    }
    for path in ["daemon.rs", "read_model/mod.rs", "shared_group_sync/mod.rs"] {
        collect(&std::fs::read_to_string(bus.join(path))?, &mut methods);
    }
    for method in methods {
        assert!(classify(&method).is_some(), "unclassified dispatch method: {method}");
    }
    let mut names = BTreeSet::new();
    for entry in METHODS {
        assert!(names.insert(entry.name), "duplicate registry method {}", entry.name);
        assert_eq!(classify(entry.name), Some(*entry));
        assert_eq!(
            super::super::readers::is_reader_request(entry.name),
            entry.class == MethodClass::LocalRead && entry.route == MethodRoute::Reader,
            "reader routing mismatch: {}",
            entry.name,
        );
    }
    assert!(!super::super::readers::is_reader_request("message.new_unclassified_method"));
    Ok(())
}

#[test]
fn method_scan_stops_at_a_unix_gated_test_module() {
    let mut methods = BTreeSet::new();
    collect(
        "\"kept.method\" => {}\n#[cfg(all(test, unix))]\n#[allow(clippy::expect_used)]\nmod tests {\n    \"hidden.method\" => {}\n}\n",
        &mut methods,
    );
    assert_eq!(methods.into_iter().collect::<Vec<_>>(), vec!["kept.method".to_owned()]);
}

#[test]
fn method_scan_keeps_arms_that_are_not_inside_a_test_module() {
    let mut methods = BTreeSet::new();
    collect(
        "#[cfg(feature = \"itest-local-mint\")]\n\"kept.method\" => {}\n#[cfg(not(test))]\n\"also.kept\" => {}\n#[cfg(all(test, unix))]\nfn helper() {}\n\"still.kept\" => {}\n",
        &mut methods,
    );
    assert_eq!(
        methods.into_iter().collect::<Vec<_>>(),
        vec!["also.kept".to_owned(), "kept.method".to_owned(), "still.kept".to_owned()]
    );
}

/// `#[cfg(test)]` and `#[cfg(all(test, unix))]` both open a test module.
/// `not(test)` and feature names such as `itest-local-mint` do not.
fn cfg_line_starts_test_module(line: &str) -> bool {
    let Some(body) = line.strip_prefix("#[cfg(").and_then(|rest| rest.strip_suffix(")]")) else {
        return false;
    };
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() && bytes[index] != b'"' {
                index += 1;
            }
            index = index.saturating_add(1);
            continue;
        }
        if body[index..].starts_with("test") {
            let before_ok = index == 0
                || (!bytes[index - 1].is_ascii_alphanumeric() && bytes[index - 1] != b'_');
            let after = index + 4;
            let after_ok = after >= bytes.len()
                || (!bytes[after].is_ascii_alphanumeric() && bytes[after] != b'_');
            let prefix = body[..index].trim_end();
            if before_ok && after_ok && !prefix.ends_with("not(") {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn collect(source: &str, methods: &mut BTreeSet<String>) {
    let mut testing = false;
    let mut test_attribute = false;
    for line in source.lines() {
        let line = line.trim();
        if cfg_line_starts_test_module(line) {
            test_attribute = true;
            continue;
        }
        if test_attribute && line.starts_with("mod ") && line.ends_with('{') {
            testing = true;
        }
        if testing {
            break;
        }
        if line.ends_with(';')
            || line.starts_with("fn ")
            || line.starts_with("async fn ")
            || line.starts_with("pub ")
        {
            test_attribute = false;
        }
        let arm = line.starts_with('"') && line.contains("=>")
            || line.starts_with("| \"")
            || line.starts_with('"') && line.ends_with('"')
            || line.contains("request.method ==")
            || line.contains("method ==")
            || line.contains("method !=");
        if !arm {
            continue;
        }
        for literal in line.split('"').skip(1).step_by(2) {
            if literal.contains('.')
                && !literal.starts_with("ramflux.")
                && literal
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte == b'.')
                && !literal.ends_with('.')
            {
                methods.insert(literal.to_owned());
            }
        }
    }
}
