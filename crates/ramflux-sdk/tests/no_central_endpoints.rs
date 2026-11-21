// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The default client build names no central service, vendor push host or store host.
//!
//! Scans the client crates' non-test sources for URL literals and known vendor hosts, and
//! the client manifests for vendor dependencies and default features.

use std::fs;
use std::path::{Path, PathBuf};

/// Crates that are linked into a client host. Node services under `apps/` are not clients.
const CLIENT_SOURCE_ROOTS: &[&str] = &[
    "crates/ramflux-core/src",
    "crates/ramflux-protocol/src",
    "crates/ramflux-crypto/src",
    "crates/ramflux-storage/src",
    "crates/ramflux-sync/src",
    "crates/ramflux-transport/src",
    "crates/ramflux-sdk/src",
    "apps/rf/src",
];

const CLIENT_MANIFESTS: &[&str] =
    &["crates/ramflux-transport/Cargo.toml", "crates/ramflux-sdk/Cargo.toml", "apps/rf/Cargo.toml"];

/// Host fragments of vendor push, store, telemetry and update services.
const FORBIDDEN_HOST_FRAGMENTS: &[&str] = &[
    "googleapis.com",
    "firebaseio.com",
    "firebaseinstallations",
    "push.apple.com",
    "itunes.apple.com",
    "apps.apple.com",
    "play.google.com",
    "microsoft.com",
    "windowsupdate",
    "notify.windows.com",
    "push.services.mozilla.com",
    "hicloud.com",
    "xiaomi.com",
    "sentry.io",
    "crashlytics",
    "appcenter.ms",
    "google-analytics",
    "segment.io",
    "amplitude.com",
    "mixpanel.com",
];

/// Dependency names that would add a vendor push, telemetry or self-update client.
const FORBIDDEN_DEPENDENCY_FRAGMENTS: &[&str] = &[
    "firebase",
    "fcm",
    "apns",
    "web-push",
    "sentry",
    "analytics",
    "telemetry",
    "opentelemetry",
    "self_update",
    "self-update",
    "crashpad",
    "bugsnag",
];

fn forbidden_dependency(name: &str) -> Option<&'static str> {
    if name == "a2" {
        return Some("a2");
    }
    FORBIDDEN_DEPENDENCY_FRAGMENTS.iter().copied().find(|fragment| name.contains(fragment))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn is_test_source(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.contains("/tests/")
        || text.contains("_tests/")
        || text.ends_with("_tests.rs")
        || text.ends_with("/tests.rs")
        || text.contains("fixture")
        || text.contains("itest")
}

/// Production lines of one file: comment lines and everything from the first `#[cfg(test)]`
/// on are dropped (test modules sit at the end of a file in this workspace).
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        lines.push((index + 1, line));
    }
    lines
}

/// Hosts of every `scheme://host` literal in `line`.
fn url_hosts(line: &str) -> Vec<&str> {
    let mut hosts = Vec::new();
    let mut rest = line;
    while let Some(position) = rest.find("://") {
        let after = &rest[position + 3..];
        let end = after
            .find(|character: char| {
                !(character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '-' | '[' | ']' | ':'))
            })
            .unwrap_or(after.len());
        let authority = &after[..end];
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            bracketed.split(']').next().unwrap_or_default()
        } else {
            authority.split(':').next().unwrap_or_default()
        };
        hosts.push(host);
        rest = &after[end..];
    }
    hosts
}

/// A host that cannot be a real service: empty (a format placeholder follows the scheme),
/// an address literal, a single label, or a name under a reserved documentation domain.
fn host_is_not_a_service(host: &str) -> bool {
    if host.is_empty() || !host.contains('.') || host.contains(':') {
        return true;
    }
    if host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.') {
        return true;
    }
    let lower = host.to_ascii_lowercase();
    [
        ".example",
        ".invalid",
        ".test",
        ".local",
        ".localhost",
        ".example.com",
        ".example.org",
        ".example.net",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
        || matches!(lower.as_str(), "example.com" | "example.org" | "example.net")
}

/// Exact identifiers of vendored schemas; HTTP/filesystem resolution is disabled there.
/// These are resource names, not dial targets. Do not exempt the host or other files.
fn embedded_schema_identifier(file: &Path, line: &str) -> bool {
    if !file.ends_with("crates/ramflux-protocol/src/a2ui/schema.rs") {
        return false;
    }
    matches!(
        line.trim(),
        "const BASE: &str = \"https://a2ui.org/specification/v1_0/catalog.json\";"
            | ".with_base_uri(\"https://a2ui.org/specification/v1_0/validation.json\")"
            | "\"https://a2ui.org/specification/v1_0/common_types.json\","
            | "\"https://a2ui.org/specification/v1_0/catalogs/basic/common_types.json\","
    )
}

#[test]
fn client_sources_name_no_central_or_vendor_endpoint() {
    let root = workspace_root();
    let mut files = Vec::new();
    for source_root in CLIENT_SOURCE_ROOTS {
        let dir = root.join(source_root);
        assert!(dir.is_dir(), "client source root is missing: {source_root}");
        rust_files(&dir, &mut files);
    }
    assert!(files.len() > 50, "the scan found too few client sources: {}", files.len());
    let mut violations = Vec::new();
    for file in files.iter().filter(|file| !is_test_source(file)) {
        let Ok(source) = fs::read_to_string(file) else { continue };
        for (number, line) in production_lines(&source) {
            let lower = line.to_ascii_lowercase();
            for fragment in FORBIDDEN_HOST_FRAGMENTS {
                if lower.contains(fragment) {
                    violations
                        .push(format!("{}:{number}: vendor host `{fragment}`", file.display()));
                }
            }
            for host in url_hosts(line) {
                if !host_is_not_a_service(host) && !embedded_schema_identifier(file, line) {
                    violations.push(format!("{}:{number}: endpoint `{host}`", file.display()));
                }
            }
        }
    }
    assert!(violations.is_empty(), "compiled-in endpoints:\n{}", violations.join("\n"));
}

#[test]
fn client_manifests_have_no_vendor_dependency_and_no_default_feature() {
    let root = workspace_root();
    for manifest in CLIENT_MANIFESTS {
        let path = root.join(manifest);
        let text = fs::read_to_string(&path).expect("test: client manifest must be readable");
        let mut in_dependencies = false;
        let mut default_seen = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_dependencies = trimmed.contains("dependencies");
                continue;
            }
            if trimmed.starts_with("default =") {
                default_seen = true;
                assert_eq!(
                    trimmed.replace(' ', ""),
                    "default=[]",
                    "{manifest}: the default client build enables no feature"
                );
            }
            if !in_dependencies || trimmed.starts_with('#') {
                continue;
            }
            let Some(name) = trimmed.split('=').next() else { continue };
            let name = name.trim().to_ascii_lowercase();
            assert!(
                forbidden_dependency(&name).is_none(),
                "{manifest}: dependency `{name}` is forbidden vendor software"
            );
        }
        assert!(
            default_seen || !text.contains("[features]"),
            "{manifest}: no default feature line"
        );
    }
}

#[test]
fn scanner_flags_a_real_host_and_passes_reserved_ones() {
    assert_eq!(
        url_hosts("let url = \"https://updates.vendor.com/v1\";"),
        vec!["updates.vendor.com"]
    );
    assert!(!host_is_not_a_service("updates.vendor.com"));
    for reserved in
        ["node.example", "relay.invalid", "127.0.0.1", "localhost", "", "node-a", "2001:db8::1"]
    {
        assert!(host_is_not_a_service(reserved), "{reserved}");
    }
    assert_eq!(url_hosts("format!(\"https://{host}/x\")"), vec![""]);
    assert_eq!(url_hosts("\"http://[::1]:8080/\""), vec!["::1"]);
}

#[test]
fn dependency_guard_distinguishes_exact_short_names_from_crypto_packages() {
    for name in ["a2", "apns", "firebase", "fcm", "sentry"] {
        assert!(forbidden_dependency(name).is_some(), "vendor dependency {name} escaped the guard");
    }
    for name in ["sha2", "base64", "ramflux-sdk"] {
        assert!(
            forbidden_dependency(name).is_none(),
            "ordinary dependency {name} was mistaken for vendor software"
        );
    }
}

#[test]
fn embedded_schema_exception_is_exact_and_file_scoped() {
    let schema = Path::new("crates/ramflux-protocol/src/a2ui/schema.rs");
    let other = Path::new("crates/ramflux-sdk/src/gateway.rs");
    for line in [
        "const BASE: &str = \"https://a2ui.org/specification/v1_0/catalog.json\";",
        ".with_base_uri(\"https://a2ui.org/specification/v1_0/validation.json\")",
        "\"https://a2ui.org/specification/v1_0/common_types.json\",",
        "\"https://a2ui.org/specification/v1_0/catalogs/basic/common_types.json\",",
    ] {
        assert!(embedded_schema_identifier(schema, line));
        assert!(!embedded_schema_identifier(other, line));
    }
    for line in [
        "fetch(\"https://a2ui.org/specification/v1_0/catalog.json\");",
        "\"https://a2ui.org/telemetry\",",
        "\"https://vendor.example.com/\",",
    ] {
        assert!(!embedded_schema_identifier(schema, line));
    }
}
