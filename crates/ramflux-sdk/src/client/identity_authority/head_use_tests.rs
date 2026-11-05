// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Inventory guard for current-authority consumers. Signature checking enforces the purpose
//! argument at every call; this inventory requires review when production callers change.
use super::HeadUse;

#[test]
fn caller_classification_is_exhaustive() {
    assert_eq!(HeadUse::default(), HeadUse::NewAuthorization);
    let classified: &[(&str, &str, usize)] = &[
        ("bus/delivery_receipts.rs", include_str!("../../bus/delivery_receipts.rs"), 1),
        (
            "bus/dispatch/call_driver/background.rs",
            include_str!("../../bus/dispatch/call_driver/background.rs"),
            1,
        ),
        ("bus/dispatch/call_lease.rs", include_str!("../../bus/dispatch/call_lease.rs"), 1),
        ("bus/native_account.rs", include_str!("../../bus/native_account.rs"), 2),
        ("client/backup_activation.rs", include_str!("../backup_activation.rs"), 1),
        ("client/call/mod.rs", include_str!("../call/mod.rs"), 3),
        ("client/contact_requests/delivery.rs", include_str!("../contact_requests/delivery.rs"), 1),
        ("client/contact_requests/wire.rs", include_str!("../contact_requests/wire.rs"), 1),
        ("client/delivery_receipts.rs", include_str!("../delivery_receipts.rs"), 1),
        ("client/group.rs", include_str!("../group.rs"), 1),
        ("client/group_control_roots.rs", include_str!("../group_control_roots.rs"), 1),
        ("client/group_identity.rs", include_str!("../group_identity.rs"), 2),
        ("client/group_session.rs", include_str!("../group_session.rs"), 1),
        ("client/identity_authority/custody_directory.rs", include_str!("custody_directory.rs"), 2),
        ("client/identity_authority/custody_freshness.rs", include_str!("custody_freshness.rs"), 3),
        ("client/identity_authority/custody_scopes.rs", include_str!("custody_scopes.rs"), 1),
        ("client/identity_authority/mod.rs", include_str!("mod.rs"), 3),
        ("client/identity_authority/verify.rs", include_str!("verify.rs"), 2),
        ("client/own_device_sync.rs", include_str!("../own_device_sync.rs"), 4),
        (
            "client/own_device_sync/receive_job.rs",
            include_str!("../own_device_sync/receive_job.rs"),
            3,
        ),
        ("client/own_group_lazy_authority.rs", include_str!("../own_group_lazy_authority.rs"), 1),
        ("client/own_sent_delivery.rs", include_str!("../own_sent_delivery.rs"), 1),
        ("client/routed/auth.rs", include_str!("../routed/auth.rs"), 5),
        ("client/routed/bootstrap_sequence.rs", include_str!("../routed/bootstrap_sequence.rs"), 1),
        ("client/routed/control.rs", include_str!("../routed/control.rs"), 1),
        ("client/routed/object_slot.rs", include_str!("../routed/object_slot.rs"), 2),
        ("client/routed/prepared.rs", include_str!("../routed/prepared.rs"), 1),
        ("client/routed/reset_work.rs", include_str!("../routed/reset_work.rs"), 1),
        ("client/routed/send_candidate.rs", include_str!("../routed/send_candidate.rs"), 1),
        ("client/routed/session.rs", include_str!("../routed/session.rs"), 1),
        ("client/shared_group/bootstrap.rs", include_str!("../shared_group/bootstrap.rs"), 1),
        ("client/shared_group/controls.rs", include_str!("../shared_group/controls.rs"), 1),
        ("client/shared_group/invitations.rs", include_str!("../shared_group/invitations.rs"), 1),
        ("client/shared_group/own_consent.rs", include_str!("../shared_group/own_consent.rs"), 2),
        ("client/shared_group/requests.rs", include_str!("../shared_group/requests.rs"), 2),
        ("client/shared_group/routes.rs", include_str!("../shared_group/routes.rs"), 1),
        ("client/shared_group/transfer.rs", include_str!("../shared_group/transfer.rs"), 3),
        ("client/surface/resync_request.rs", include_str!("../surface/resync_request.rs"), 2),
        ("client/task/carrier.rs", include_str!("../task/carrier.rs"), 1),
    ];
    let guards = [
        "trusted_device",
        "require_cached_root_authority",
        "require_custody_device",
        "require_fresh_custody_head",
    ];
    let mut total = 0;
    for &(path, source, expected) in classified {
        // Inline fixture calls are inventoried too; all require explicit purpose arguments.
        let production = source;
        let actual: usize = guards
            .iter()
            .map(|guard| {
                production
                    .match_indices(guard)
                    .filter(|&(offset, _)| {
                        production[offset + guard.len()..].trim_start().starts_with('(')
                    })
                    .count()
            })
            .sum();
        assert_eq!(actual, expected, "authority caller census changed: {path}");
        assert!(!production.contains("HeadUse::default()"), "implicit purpose: {path}");
        total += actual;
    }
    assert!(total >= 62);
    assert_eq!(classified.len(), 39);
}
