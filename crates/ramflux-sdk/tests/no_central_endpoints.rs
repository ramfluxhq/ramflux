// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The default client build names no central service, vendor push host or store host.
//!
//! Scans the client crates' non-test sources for URL literals and known vendor hosts, and
//! the client manifests for vendor dependencies and default features.
//! Syntax is parsed without compiling: cfg(test)-only items and module files are excluded,
//! uncertain feature/platform configurations are scanned, and input errors fail closed.
//! Macro literals are inspected recursively; expansions, includes, name resolution and
//! addresses assembled at runtime are outside this guard's proof. Resource identifiers
//! are allowed only in exact schema-builder positions backed by verified embedded JSON.

use std::path::{Path, PathBuf};

mod endpoint_guard;

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

#[test]
fn client_sources_name_no_central_or_vendor_endpoint() {
    let root = workspace_root();
    endpoint_guard::embedded_resources(&root).expect("test: embedded resource contract");
    let sources =
        endpoint_guard::sources(&root).expect("test: all sources must be readable and parseable");
    assert!(sources.len() > 50, "the scan found too few client sources: {}", sources.len());
    let mut violations = Vec::new();
    for (file, source) in sources {
        let errors = endpoint_guard::scan(&file, &source).expect("test: source must be decidable");
        violations.extend(errors.into_iter().map(|error| format!("{}:{error}", file.display())));
    }
    assert!(violations.is_empty(), "compiled-in endpoints:\n{}", violations.join("\n"));
}

#[test]
fn client_manifests_have_no_vendor_dependency_and_no_default_feature() {
    let root = workspace_root();
    for manifest in CLIENT_MANIFESTS {
        let path = root.join(manifest);
        let text = endpoint_guard::read(&path).expect("test: client manifest must be readable");
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
fn scanner_catches_production_after_test_items_and_in_macro_arguments() {
    for source in [
        r#"#[cfg(test)] fn helper() {} const URL: &str = "https://updates.vendor.com/v1";"#,
        r#"mod outer { #[cfg(test)] fn helper() {} const URL: &str = "https://updates.vendor.com/v1"; }"#,
        r#"#[cfg(test)] mod tests {} endpoint!({ [ ("https://updates.vendor.com/v1") ] });"#,
        r####"const URL: &str = r###"https://updates.vendor.com/v1"###;"####,
        r#"const URL: &str = "https://updates.\x76endor.com/v1";"#,
        r#"const URL: &[u8] = b"https://updates.vendor.com/v1";"#,
        r#"/* #[cfg(test)] */ const URL: &str = "https://updates.vendor.com/v1";"#,
        r#"#[cfg_attr(not(test), endpoint("https://updates.vendor.com/v1"))] fn run() {}"#,
        r#"#[cfg(test)] fn helper() {} #[cfg(not(test))] fn run() { endpoint!("https://updates.vendor.com/v1"); }"#,
    ] {
        let errors = endpoint_guard::scan(Path::new("src/fixture_itest_tests.rs"), source)
            .expect("test: valid regression source");
        assert!(!errors.is_empty(), "production endpoint escaped: {source}");
    }
}

#[test]
fn scanner_cfg_excludes_only_proven_test_only_syntax() {
    for cfg in ["test", "all(test, feature = \"x\")", "not(not(test))", "any()"] {
        let source = format!("#[cfg({cfg})] const URL: &str = \"https://updates.vendor.com/v1\";");
        assert!(
            endpoint_guard::scan(Path::new("src/main.rs"), &source)
                .expect("test: valid cfg")
                .is_empty(),
            "test-only syntax scanned: {cfg}"
        );
    }
    for cfg in ["not(test)", "any(test, feature = \"x\")", "all()", "target_os = \"linux\""] {
        let source = format!("#[cfg({cfg})] const URL: &str = \"https://updates.vendor.com/v1\";");
        assert!(
            !endpoint_guard::scan(Path::new("src/main.rs"), &source)
                .expect("test: valid cfg")
                .is_empty(),
            "possible production syntax excluded: {cfg}"
        );
    }
    for source in [
        r#"#[cfg_attr(not(test), cfg(test))] const URL: &str = "https://updates.vendor.com/v1";"#,
        r#"fn run() { #[cfg(test)] let url = "https://updates.vendor.com/v1"; }"#,
        r#"#![cfg(test)] const URL: &str = "https://updates.vendor.com/v1";"#,
    ] {
        assert!(
            endpoint_guard::scan(Path::new("src/main.rs"), source)
                .expect("test: valid test-only syntax")
                .is_empty(),
            "test-only syntax scanned: {source}"
        );
    }
    for source in [
        r#"#[cfg_attr(test, cfg(test))] const URL: &str = "https://updates.vendor.com/v1";"#,
        r#"#[cfg_attr(feature = "x", cfg(test))] const URL: &str = "https://updates.vendor.com/v1";"#,
    ] {
        assert!(
            !endpoint_guard::scan(Path::new("src/main.rs"), source)
                .expect("test: valid uncertain syntax")
                .is_empty(),
            "uncertain syntax excluded: {source}"
        );
    }
    for source in ["fn broken(", "#[cfg(unknown(test))] fn f() {}", "#[cfg_attr(test)] fn f() {}"] {
        let result = endpoint_guard::scan(Path::new("src/main.rs"), source);
        assert!(
            result.is_err() || result.is_ok_and(|errors| !errors.is_empty()),
            "undecidable source passed: {source}"
        );
    }
}

#[test]
fn schema_identifiers_are_exact_and_usage_scoped() {
    let schema = Path::new("crates/ramflux-protocol/src/a2ui/schema.rs");
    for source in [
        r#"const BASE: &str = "https://a2ui.org/specification/v1_0/catalog.json";"#,
        r#"fn f() { jsonschema::options().with_base_uri("https://a2ui.org/specification/v1_0/validation.json"); }"#,
        r#"fn f() { jsonschema::options().with_resource("https://a2ui.org/specification/v1_0/common_types.json", jsonschema::Resource::from_contents(common.clone())); }"#,
        r#"fn f() { jsonschema::options().with_resource("https://a2ui.org/specification/v1_0/catalogs/basic/common_types.json", jsonschema::Resource::from_contents(common.clone())); }"#,
    ] {
        assert!(
            endpoint_guard::scan(schema, source).expect("test: identifier syntax").is_empty(),
            "embedded identifier rejected: {source}"
        );
        assert!(
            !endpoint_guard::scan(Path::new("src/other.rs"), source)
                .expect("test: identifier syntax")
                .is_empty(),
            "identifier allowed outside schema owner"
        );
    }
    for source in [
        r#"fn f() { fetch("https://a2ui.org/specification/v1_0/catalog.json"); }"#,
        r#"fn f() { jsonschema::options().with_base_uri("https://a2ui.org/telemetry"); }"#,
        r#"fn f() { jsonschema::options().with_resource("https://a2ui.org/specification/v1_0/common_types.json", jsonschema::Resource::from_contents(other.clone())); }"#,
        r#"const BASE: &str = "https://a2ui.org/specification/v1_0/catalog.json"; const URL: &str = "https://a2ui.org/telemetry";"#,
    ] {
        assert!(
            !endpoint_guard::scan(schema, source)
                .expect("test: negative identifier syntax")
                .is_empty(),
            "unregistered identifier or endpoint escaped: {source}"
        );
    }
}

#[test]
fn source_reads_and_traversal_fail_closed() {
    let dir = tempfile::TempDir::new().expect("test: isolated source directory");
    assert!(
        endpoint_guard::read(&dir.path().join("missing.rs")).is_err(),
        "missing source skipped"
    );
    assert!(
        endpoint_guard::rust_files(&dir.path().join("missing"), &mut Vec::new(), 0).is_err(),
        "missing source directory skipped"
    );
}

#[test]
fn module_graph_excludes_tests_without_trusting_filenames() {
    let dir = tempfile::TempDir::new().expect("test: isolated module tree");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("test: source root");
    std::fs::write(src.join("lib.rs"),
        "#[cfg(test)] mod fixtures; mod production_tests; #[cfg(test)] mod shared; mod live { #[path = \"../shared.rs\"] mod shared; }")
        .expect("test: module declarations");
    std::fs::create_dir(src.join("live")).expect("test: inline module directory");
    for file in ["fixtures.rs", "production_tests.rs", "shared.rs", "orphan_fixture.rs"] {
        std::fs::write(src.join(file), "const URL: &str = \"https://updates.vendor.com/v1\";")
            .expect("test: module source");
    }
    let sources =
        endpoint_guard::sources_under(dir.path(), &["src"]).expect("test: valid source graph");
    let names: Vec<_> = sources
        .iter()
        .filter_map(|(file, _)| file.file_name())
        .map(|file| file.to_string_lossy().into_owned())
        .collect();
    assert!(!names.iter().any(|name| name == "fixtures.rs"), "proven test-only file scanned");
    for name in ["production_tests.rs", "shared.rs", "orphan_fixture.rs"] {
        assert!(
            names.iter().any(|file| file == name),
            "production or orphan source hidden: {name}"
        );
    }
    std::fs::write(src.join("lib.rs"), "mod missing;").expect("test: unresolved module fixture");
    assert!(
        endpoint_guard::sources_under(dir.path(), &["src"]).is_err(),
        "unresolved module source silently skipped"
    );
}

#[test]
fn embedded_resource_contract_rejects_data_registration_and_resolver_drift() {
    let root = workspace_root();
    let paths = [
        "crates/ramflux-protocol/Cargo.toml",
        "crates/ramflux-protocol/src/a2ui/schema.rs",
        "crates/ramflux-protocol/vendor/a2ui/specification/v1_0/json/common_types.json",
        "crates/ramflux-protocol/catalogs/rf-card-v1.json",
    ];
    for (index, from, to) in [
        (0, "default-features = false", "default-features = true"),
        (1, ".with_resource(BASE,", ".with_resource(OTHER,"),
        (1, "fn build(", "#[cfg(test)] fn build("),
        (1, "../../catalogs/rf-card-v1.json", "../../catalogs/other.json"),
        (
            2,
            "https://a2ui.org/specification/v1_0/common_types.json",
            "https://a2ui.org/unknown.json",
        ),
        (3, "urn:ramflux:catalog:rf-card:1.0", "urn:unknown:catalog"),
    ] {
        let dir = tempfile::TempDir::new().expect("test: isolated resource contract");
        for (file_index, relative) in paths.iter().enumerate() {
            let mut text =
                endpoint_guard::read(&root.join(relative)).expect("test: embedded source");
            if file_index == index {
                assert!(text.contains(from), "contract regression mutation does not match: {from}");
                text = text.replace(from, to);
            }
            let destination = dir.path().join(relative);
            std::fs::create_dir_all(destination.parent().expect("test: fixture parent"))
                .expect("test: fixture directories");
            std::fs::write(destination, text).expect("test: fixture data");
        }
        assert!(
            endpoint_guard::embedded_resources(dir.path()).is_err(),
            "embedded contract drift accepted: {from} -> {to}"
        );
    }
}
