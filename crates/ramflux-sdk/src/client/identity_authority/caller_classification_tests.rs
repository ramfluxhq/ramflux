// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compile-time source inventory of explicitly classified authority consumers.
use super::HeadUse;

const SOURCES: &[(&str, &str, [usize; 4])] = &[
    (
        "bus/delivery_receipts.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bus/delivery_receipts.rs")),
        [1, 0, 0, 0],
    ),
    (
        "bus/dispatch/call_driver/background.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bus/dispatch/call_driver/background.rs"
        )),
        [1, 0, 0, 0],
    ),
    (
        "bus/dispatch/call_lease.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bus/dispatch/call_lease.rs")),
        [1, 0, 0, 0],
    ),
    (
        "bus/dispatch/group/history.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bus/dispatch/group/history.rs")),
        [1, 0, 0, 0],
    ),
    (
        "bus/dispatch/shared_group_transfer_tests.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bus/dispatch/shared_group_transfer_tests.rs"
        )),
        [1, 0, 0, 0],
    ),
    (
        "bus/dispatch/surface_own_tests.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bus/dispatch/surface_own_tests.rs")),
        [0, 1, 0, 0],
    ),
    (
        "bus/group_delivery.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bus/group_delivery.rs")),
        [3, 0, 0, 0],
    ),
    (
        "bus/native_account.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bus/native_account.rs")),
        [0, 0, 0, 2],
    ),
    (
        "client/backup_activation.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/backup_activation.rs")),
        [0, 1, 0, 0],
    ),
    (
        "client/call/mod.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/call/mod.rs")),
        [3, 0, 0, 0],
    ),
    (
        "client/contact_requests/delivery.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/contact_requests/delivery.rs"
        )),
        [1, 0, 0, 0],
    ),
    (
        "client/contact_requests/wire.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/contact_requests/wire.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/delivery_receipts.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/delivery_receipts.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/group.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/group.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/group_control_roots.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/group_control_roots.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/group_identity.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/group_identity.rs")),
        [2, 0, 0, 0],
    ),
    (
        "client/group_session.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/group_session.rs")),
        [0, 1, 0, 0],
    ),
    (
        "client/identity_authority/custody_directory.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/custody_directory.rs"
        )),
        [0, 0, 0, 1],
    ),
    (
        "client/identity_authority/custody_freshness.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/custody_freshness.rs"
        )),
        [0, 0, 0, 2],
    ),
    (
        "client/identity_authority/custody_scopes.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/custody_scopes.rs"
        )),
        [0, 1, 0, 0],
    ),
    (
        "client/identity_authority/gateway_tests.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/gateway_tests.rs"
        )),
        [0, 1, 0, 0],
    ),
    (
        "client/identity_authority/group_review_r3_tests.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/group_review_r3_tests.rs"
        )),
        [0, 1, 0, 0],
    ),
    (
        "client/identity_authority/mod.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/identity_authority/mod.rs")),
        [0, 1, 1, 0],
    ),
    (
        "client/identity_authority/proof_lifetime_tests.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/proof_lifetime_tests.rs"
        )),
        [5, 0, 0, 0],
    ),
    (
        "client/identity_authority/review_r2_tests.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/review_r2_tests.rs"
        )),
        [0, 4, 0, 0],
    ),
    (
        "client/identity_authority/tests.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/tests.rs"
        )),
        [0, 2, 0, 0],
    ),
    (
        "client/identity_authority/verify.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/identity_authority/verify.rs"
        )),
        [0, 2, 0, 0],
    ),
    (
        "client/own_device_sync/receive_job.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/own_device_sync/receive_job.rs"
        )),
        [2, 1, 0, 0],
    ),
    (
        "client/own_device_sync/tests/stale_group_snapshot_tests.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/own_device_sync/tests/stale_group_snapshot_tests.rs"
        )),
        [0, 1, 0, 0],
    ),
    (
        "client/own_device_sync.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/own_device_sync.rs")),
        [0, 4, 0, 0],
    ),
    (
        "client/own_group_lazy_authority.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/own_group_lazy_authority.rs"
        )),
        [1, 0, 0, 0],
    ),
    (
        "client/own_sent_delivery.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/own_sent_delivery.rs")),
        [0, 1, 0, 0],
    ),
    (
        "client/routed/auth.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/routed/auth.rs")),
        [2, 2, 0, 0],
    ),
    (
        "client/routed/bootstrap_sequence.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/routed/bootstrap_sequence.rs"
        )),
        [1, 0, 0, 0],
    ),
    (
        "client/routed/control.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/routed/control.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/raw_inner_reparse.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/raw_inner_reparse.rs")),
        [0, 1, 0, 0],
    ),
    (
        "client/routed/device_revocation_tests.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/routed/device_revocation_tests.rs"
        )),
        [1, 0, 0, 0],
    ),
    (
        "client/routed/discovery_tests.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/routed/discovery_tests.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/routed/object_slot.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/routed/object_slot.rs")),
        [0, 2, 0, 0],
    ),
    (
        "client/routed/prepared.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/routed/prepared.rs")),
        [0, 1, 0, 0],
    ),
    (
        "client/routed/reset_work.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/routed/reset_work.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/routed/send_candidate.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/routed/send_candidate.rs")),
        [0, 1, 0, 0],
    ),
    (
        "client/routed/session.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/routed/session.rs")),
        [0, 1, 0, 0],
    ),
    (
        "client/shared_group/bootstrap.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/shared_group/bootstrap.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/shared_group/controls.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/shared_group/controls.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/shared_group/invitations.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/shared_group/invitations.rs"
        )),
        [1, 0, 0, 0],
    ),
    (
        "client/shared_group/own_consent.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/client/shared_group/own_consent.rs"
        )),
        [1, 1, 0, 0],
    ),
    (
        "client/shared_group/requests.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/shared_group/requests.rs")),
        [1, 1, 0, 0],
    ),
    (
        "client/shared_group/routes.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/shared_group/routes.rs")),
        [1, 0, 0, 0],
    ),
    (
        "client/shared_group/transfer.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/shared_group/transfer.rs")),
        [2, 1, 0, 0],
    ),
    (
        "client/surface/resync_request.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/surface/resync_request.rs")),
        [2, 0, 0, 0],
    ),
    (
        "client/task/carrier.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client/task/carrier.rs")),
        [0, 1, 0, 0],
    ),
];

#[test]
fn caller_classification_is_exhaustive() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(HeadUse::default(), HeadUse::NewAuthorization);
    scan_historical_consumers(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
    )?;
    let names = [
        "trusted_device",
        "require_cached_root_authority",
        "require_custody_device",
        "require_fresh_custody_head",
    ];
    for (path, source, counts) in SOURCES {
        for (name, expected) in names.iter().zip(counts) {
            let needle = format!(".{name}(");
            assert_eq!(source.matches(&needle).count(), *expected, "classify new caller in {path}");
            for (offset, _) in source.match_indices(&needle) {
                let arguments = source[offset + needle.len()..].trim_start();
                if arguments.starts_with("HeadUse::HistoricalRead") {
                    assert!(
                        historical_consumer_allowed(std::path::Path::new(path), source, offset)?,
                        "unreviewed historical consumer in {path}"
                    );
                }
                assert!(
                    arguments.starts_with("HeadUse::NewAuthorization")
                        || arguments.starts_with("HeadUse::HistoricalRead")
                        || arguments.starts_with("purpose,"),
                    "unclassified {path}: {name}"
                );
            }
        }
    }
    Ok(())
}

// Inspect all source files, including files absent from the static call inventory.
fn scan_historical_consumers(
    directory: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let needle = ["HeadUse::", "HistoricalRead"].concat();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            scan_historical_consumers(&path)?;
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "rs")
            || path.ends_with("client/identity_authority/caller_classification_tests.rs")
        {
            continue;
        }
        let source = std::fs::read_to_string(&path)?;
        for (offset, _) in source.match_indices(&needle) {
            let allowed = historical_consumer_allowed(&path, &source, offset)?;
            assert!(allowed, "unreviewed historical authority consumer: {}", path.display());
        }
    }
    Ok(())
}

// Historical scope bypasses only the fetch-age clock. The retained-input worker
// rechecks receipt/header/source/scope, discards ephemeral and native controls,
// and permits no legacy-origin operation except already-admitted Message projection.
fn historical_consumer_allowed(
    path: &std::path::Path,
    source: &str,
    offset: usize,
) -> Result<bool, Box<dyn std::error::Error>> {
    if path.ends_with("bus/dispatch/group/history.rs") {
        return Ok(true);
    }
    if path.ends_with("bus/dispatch/group.rs") {
        return within_function(source, "group_receive_compat", offset);
    }
    if path.ends_with("client/raw_inner_reparse.rs") {
        return Ok(within_function(source, "install_raw_reparse", offset)?
            || within_function(source, "legacy_raw_reparse_source", offset)?);
    }
    // This terminal comparison defines the clock-only bypass, not a consumer.
    Ok(path.ends_with("client/identity_authority/custody_freshness.rs")
        && source[..offset].ends_with("if purpose == "))
}

fn within_function(
    source: &str,
    function: &str,
    offset: usize,
) -> Result<bool, Box<dyn std::error::Error>> {
    let marker = format!("fn {function}(");
    if source.matches(&marker).count() != 1 {
        return Err(format!("ambiguous reviewed consumer {function}").into());
    }
    let start = source.find(&marker).ok_or("reviewed consumer absent")?;
    let line = source[..start].rsplit('\n').next().ok_or("consumer line")?;
    let indent = &line[..line.len() - line.trim_start().len()];
    let close = format!("\n{indent}}}\n");
    let end = start + source[start..].find(&close).ok_or("reviewed consumer end")?;
    Ok((start..end).contains(&offset))
}

#[test]
fn historical_reparse_scope_does_not_admit_another_authority_consumer()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::Path::new("client/raw_inner_reparse.rs");
    let source = include_str!("../raw_inner_reparse.rs");
    let needle = ["HeadUse::", "HistoricalRead"].concat();
    for (offset, _) in source.match_indices(&needle) {
        assert!(historical_consumer_allowed(path, source, offset)?);
    }
    let planted =
        format!("{source}\nfn new_authority() {{ client.trusted_device({needle}, source); }}\n");
    let offset = planted.rfind(&needle).ok_or("planted consumer")?;
    assert!(
        !historical_consumer_allowed(path, &planted, offset)?,
        "a new authority consumer requires its own review"
    );
    Ok(())
}
