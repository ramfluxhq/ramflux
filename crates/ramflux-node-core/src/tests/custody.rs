// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persistence and legacy compatibility for the local v3 registry foundation.
use super::*;
use ramflux_crypto::custody::{CustodyConflictKind, SelfSigningKey, verify_record};
use ramflux_protocol::custody::{DeviceSet, Envelope};
use zeroize::Zeroizing;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn native() -> TestResult<crate::CustodyPublication> {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let record: Envelope<DeviceSet> = serde_json::from_value(vector["record"].clone())?;
    Ok(crate::CustodyPublication { record, compacted_ids: None })
}
#[test]
fn custody_registry_reads_legacy_snapshot_without_changing_legacy_bytes() -> TestResult {
    let legacy = serde_json::json!({"root_public_keys":{},"devices":{},"revoked_devices":[],"seen_proofs":[],"prekey_bundles":{}});
    let mut registry: IdentityRegistry = serde_json::from_value(legacy)?;
    assert!(registry.custody.is_empty());
    let router = RouterCore::new();
    let request =
        registration_request(&router, "legacy-custody-regression", "phone", 9841, None, "source")?;
    registry.register_identity(&request)?;
    let before = serde_json::to_vec(&registry)?;
    assert!(
        !serde_json::from_slice::<serde_json::Value>(&before)?
            .as_object()
            .ok_or("registry")?
            .contains_key("custody")
    );
    let loaded: IdentityRegistry = serde_json::from_slice(&before)?;
    assert_eq!(loaded, registry);
    assert_eq!(serde_json::to_vec(&loaded)?, before);
    assert!(loaded.custody.permits_legacy(&request.principal_commitment));
    Ok(())
}
#[test]
fn custody_registry_durable_head_latch_and_conflict_fence_survive_restart() -> TestResult {
    let path = temp_store_path("custody-head")?;
    let publication = native()?;
    let now = publication.record.body.issued_at;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
    let verified = verify_record(&publication.record, now, None, None)?;
    let mut revoked = publication.clone();
    revoked.record = primary.revoke_device(&verified, "primary", now + 1)?;
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = RouterCore::new();
        store.save_router(&router)?;
        router.publish_custody_record(&publication, now, &store)?;
        router.publish_custody_record(&revoked, now + 1, &store)?;
    }
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = store.load_router()?.ok_or("router")?;
        let anchor = &publication.record.body.account_anchor;
        assert_eq!(router.custody_record(anchor, now + 1)?.ok_or("head")?, revoked);
        assert!(router.publish_custody_record(&publication, now + 1, &store).is_err());
        let mut conflict = revoked.clone();
        let mut body = conflict.record.body;
        body.profile.display_name = "Conflict".into();
        conflict.record = primary.sign_record(body)?;
        let Err(error) = router.publish_custody_record(&conflict, now + 1, &store) else {
            return Err("conflicting head was accepted".into());
        };
        let NodeCoreError::CustodyConflict { alert } = error else {
            return Err("conflict did not surface a typed alert".into());
        };
        assert_eq!(alert.kind, CustodyConflictKind::RecordHead);
        let evidence = router
            .custody_conflict_evidence(anchor, alert.range_index)
            .ok_or("conflict evidence")?;
        assert_eq!(evidence.alert, *alert);
        assert_eq!(evidence.accepted, revoked.record);
        assert_eq!(evidence.conflicting, conflict.record);
        assert!(router.custody_record(anchor, now + 1).is_err());
    }
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = store.load_router()?.ok_or("router")?;
        let anchor = &publication.record.body.account_anchor;
        assert!(router.custody_record(anchor, now + 1).is_err());
        let range =
            ramflux_protocol::custody::decode_epoch(revoked.record.body.device_set_epoch)?.0;
        let evidence =
            router.custody_conflict_evidence(anchor, range).ok_or("restarted conflict evidence")?;
        assert_eq!(evidence.alert.kind, CustodyConflictKind::RecordHead);
        assert_eq!(evidence.accepted, revoked.record);
        let control = router.control.lock().map_err(|_| "registry lock")?;
        assert!(
            !control
                .mvp1_identities
                .custody
                .permits_legacy(&publication.record.body.account_anchor)
        );
    }
    std::fs::remove_file(path)?;
    Ok(())
}
#[test]
fn custody_registry_rejects_legacy_publication_after_native_genesis() -> TestResult {
    let mut registry = IdentityRegistry::default();
    let publication = native()?;
    registry.observe_custody(&publication, publication.record.body.issued_at)?;
    let mut legacy = crate::DeviceSetPublishRequest {
        root_public_key: publication.record.body.master_certificate.body.master_public_key.clone(),
        record: ramflux_protocol::SignedDeviceSetRecord {
            schema: "unused".into(),
            version: 1,
            domain: "unused".into(),
            principal_id: publication.record.body.principal_id.clone(),
            principal_commitment: publication.record.body.account_anchor.clone(),
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            devices: vec![],
            profile: None,
            signature: String::new(),
        },
    };
    // The mode gate rejects before trying to reinterpret either legacy wire version.
    for version in [1, 2] {
        legacy.record.version = version;
        let result = registry.publish_signed_device_set(&legacy);
        assert!(result.is_err_and(|error| {
            error.to_string().contains("custody anchor cannot use legacy publication")
        }));
    }
    Ok(())
}
