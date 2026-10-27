// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Principal routing labels have one authenticated owner across registration profiles.

use super::*;
use ramflux_crypto::custody::{
    GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, create_genesis,
};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn native(principal: &str, seed: u8) -> TestResult<crate::CustodyPublication> {
    native_at(principal, seed, 1_760_000_000)
}
fn native_at(principal: &str, seed: u8, now: u64) -> TestResult<crate::CustodyPublication> {
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[seed; 32])?)?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([seed + 1; 32]));
    let branch = ramflux_crypto::create_device_branch(principal, "primary", 1, [seed + 2; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([seed + 3; 32]);
    let record = create_genesis(
        &master,
        &primary,
        &branch,
        &agreement,
        GenesisInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            display_name: "Human".into(),
            issued_at: now,
            master_cert_id: ramflux_protocol::encode_base64url([seed + 4; 32]),
            branch_cert_id: ramflux_protocol::encode_base64url([seed + 5; 32]),
            external_human_primary: None,
        },
    )?;
    Ok(crate::CustodyPublication { record, compacted_ids: None })
}

#[test]
fn custody_principal_owner_is_first_authenticated_root_and_survives_restart() -> TestResult {
    let path = temp_store_path("custody-principal-ownership")?;
    let first = native("alice", 10)?;
    let second = native("alice", 20)?;
    let now = first.record.body.issued_at;
    assert_ne!(first.record.body.account_anchor, second.record.body.account_anchor);
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = RouterCore::new();
        store.save_router(&router)?;
        router.publish_custody_record(&first, now, &store)?;
        assert!(matches!(
            router.publish_custody_record(&second, now, &store),
            Err(NodeCoreError::PrincipalIdTaken)
        ));
    }
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = store.load_router()?.ok_or("router")?;
        assert!(matches!(
            router.publish_custody_record(&second, now, &store),
            Err(NodeCoreError::PrincipalIdTaken)
        ));
        assert_eq!(router.publish_custody_record(&first, now, &store)?, first.record);
        assert!(router.custody_record(&second.record.body.account_anchor, now)?.is_none());
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn unauthenticated_custody_publication_cannot_reserve_a_principal() -> TestResult {
    let mut registry = IdentityRegistry::default();
    let mut forged = native("alice", 10)?;
    forged.record.signature = ramflux_protocol::encode_base64url([0; 64]);
    assert!(registry.observe_custody(&forged, forged.record.body.issued_at).is_err());
    let valid = native("alice", 20)?;
    registry.observe_custody(&valid, valid.record.body.issued_at)?;
    Ok(())
}

#[test]
fn custody_and_current_registration_profiles_cannot_take_each_others_principal() -> TestResult {
    let router = RouterCore::new();
    let legacy = registration_request(&router, "alice", "phone", 91, None, "source")?;
    let born = native("alice", 10)?;
    let mut legacy_first = IdentityRegistry::default();
    legacy_first.register_identity(&legacy)?;
    assert!(matches!(
        legacy_first.observe_custody(&born, born.record.body.issued_at),
        Err(NodeCoreError::PrincipalIdTaken)
    ));
    let mut native_first = IdentityRegistry::default();
    native_first.observe_custody(&born, born.record.body.issued_at)?;
    assert!(matches!(
        native_first.register_identity(&legacy),
        Err(NodeCoreError::PrincipalIdTaken)
    ));
    Ok(())
}

#[test]
fn custody_publication_prefix_budget_and_incremental_head_survive_restart() -> TestResult {
    let path = temp_store_path("custody-publication-budget")?;
    let now = 1_760_000_000;
    let source = "192.0.2.1".parse()?;
    let first = native("budget-0", 10)?;
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = RouterCore::new();
        store.save_router(&router)?;
        router.publish_custody_record_from(&first, now, &store, source)?;
        let incremental_writes = store.custody_publication_write_count();
        let writes = store.identity_registry_write_count();
        router.publish_custody_record_from(&first, now, &store, source)?;
        assert_eq!(store.identity_registry_write_count(), writes);
        assert_eq!(store.custody_publication_write_count(), incremental_writes);
        for n in 1..8 {
            router.publish_custody_record_from(
                &native(&format!("budget-{n}"), 10 + n)?,
                now,
                &store,
                source,
            )?;
        }
        assert!(matches!(
            router.publish_custody_record_from(
                &native("over-prefix", 30)?,
                now,
                &store,
                "192.0.2.99".parse()?
            ),
            Err(NodeCoreError::Capacity { .. })
        ));
        router.publish_custody_record_from(
            &native("another-prefix", 40)?,
            now,
            &store,
            "198.51.100.1".parse()?,
        )?;
    }
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = store.load_router()?.ok_or("missing router")?;
        assert_eq!(
            router.custody_record(&first.record.body.account_anchor, now)?,
            Some(first.clone())
        );
        assert!(matches!(
            router.publish_custody_record_from(&native("after-restart", 50)?, now, &store, source),
            Err(NodeCoreError::Capacity { .. })
        ));
        router.publish_custody_record_from(&first, now, &store, source)?;
        router.publish_custody_record_from(
            &native("next-day", 60)?,
            now + 86_400,
            &store,
            source,
        )?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn custody_global_principal_rate_is_shared_across_prefixes_and_durable() -> TestResult {
    let path = temp_store_path("custody-global-principal-rate")?;
    let now = 1_760_000_000;
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = RouterCore::new();
        store.save_router(&router)?;
        for n in 0_u8..16 {
            let source = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, n, 0, 1));
            router.publish_custody_record_from(
                &native(&format!("global-{n}"), 100 + n)?,
                now,
                &store,
                source,
            )?;
        }
    }
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = store.load_router()?.ok_or("router")?;
        let record = native("global-over", 130)?;
        assert!(matches!(
            router.publish_custody_record_from(&record, now, &store, "203.0.113.1".parse()?),
            Err(NodeCoreError::Capacity { .. })
        ));
        assert!(router.custody_record(&record.record.body.account_anchor, now)?.is_none());
        router.publish_custody_record_from(&record, now + 60, &store, "203.0.113.1".parse()?)?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn custody_ordinary_directory_uses_native_authority_and_current_signed_prekeys() -> TestResult {
    let path = temp_store_path("custody-ordinary-directory")?;
    let now = crate::now_unix_seconds();
    let publication = native_at("ordinary-alice", 10, now)?;
    let branch = ramflux_crypto::create_device_branch("ordinary-alice", "primary", 1, [12; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([13; 32]);
    let signed = ramflux_crypto::X25519KeyPair::from_seed([99; 32]);
    let bundle =
        ramflux_crypto::create_prekey_bundle(&branch, &agreement, "signed-1", &signed, None, None)?;
    let address =
        ramflux_protocol::qualified_device_id(&publication.record.body.account_anchor, "primary")?;
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = RouterCore::new();
        store.save_router(&router)?;
        router.publish_custody_record(&publication, now, &store)?;
        let response = router.mvp1_device_auth_key_checked(&address)?.ok_or("native auth key")?;
        assert!(response.custody_authority.is_some());
        assert!(response.signed_device_set.is_none());
        assert!(response.root_public_key.is_none());
        let identity = response.authenticated_device_identity_for("message", now)?;
        assert_eq!(identity.storage_key(), address);
        let mut mixed = response;
        mixed.root_public_key =
            Some(publication.record.body.master_certificate.body.master_public_key.clone());
        assert!(mixed.authenticated_device_identity_for("message", now).is_err());
        let request =
            crate::PrekeyPublishRequest { device_id: "primary".into(), bundle: bundle.clone() };
        assert!(router.publish_custody_prekey(&request, now, &store)?.is_some());
        let fetched = router.custody_prekey_response(&address, now, &store)?.ok_or("prekey")?;
        assert_eq!(fetched.bundle, Some(bundle.clone()));
        let manifest = router
            .custody_manifest(&publication.record.body.account_anchor, now, &store)?
            .ok_or("manifest")?;
        assert_eq!(manifest.publication.record, publication.record);
        assert_eq!(manifest.devices.len(), 1);
        assert_eq!(manifest.devices[0].target_delivery_id, address);
        router.upsert_session(crate::SessionDescriptor {
            target_delivery_id: address.clone(),
            device_id: "primary".into(),
            gateway_id: "gateway".into(),
            session_id: "session".into(),
            device_epoch: 1,
            session_seq: now,
            last_cursor: None,
            push_alias_hash: None,
            lifecycle: crate::SessionLifecycle::Live,
        })?;
        let lookup = crate::PrincipalLookupRequest {
            principal_id: "ordinary-alice".into(),
            session_id: "session".into(),
            requester_device_id: "primary".into(),
            target_delivery_id: address.clone(),
            gateway_id: "gateway".into(),
            source: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        let found = router.authenticated_principal_lookup(&lookup, now, &store)?;
        assert!(found.reason_code.is_none());
        let found = found.manifest.ok_or("authenticated native manifest")?;
        assert!(found.signed_device_set.is_none());
        assert_eq!(found.devices, Vec::<crate::mvp1_registry::DeviceManifestEntry>::new());
        assert_eq!(*found.custody.ok_or("native evidence")?, manifest);
        let mut forged = request;
        forged.bundle.device_identity_ed25519_public =
            ramflux_crypto::fixture_public_key_base64url();
        assert!(router.publish_custody_prekey(&forged, now, &store).is_err());
        assert_eq!(
            router.custody_prekey_response(&address, now, &store)?.ok_or("retained prekey")?.bundle,
            Some(bundle)
        );
    }
    std::fs::remove_file(path)?;
    Ok(())
}
