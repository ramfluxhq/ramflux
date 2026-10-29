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
            issued_at: 1_760_000_000,
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
                now + u64::from(n) * 60,
                &store,
                source,
            )?;
        }
        assert!(matches!(
            router.publish_custody_record_from(
                &native("over-prefix", 30)?,
                now + 8 * 60,
                &store,
                "192.0.2.99".parse()?
            ),
            Err(NodeCoreError::Capacity { .. })
        ));
        router.publish_custody_record_from(
            &native("another-prefix", 40)?,
            now + 8 * 60,
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
        for n in 0_u8..8 {
            let source = std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001,
                0xdb8,
                u16::from(n),
                0,
                0,
                0,
                0,
                1,
            ));
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
        let honest = native("global-honest", 130)?;
        router.publish_custody_record_from(&honest, now, &store, "203.0.113.1".parse()?)?;
        for n in 0_u8..7 {
            router.publish_custody_record_from(
                &native(&format!("global-fill-{n}"), 140 + n)?,
                now,
                &store,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16 + n, 0, 1)),
            )?;
        }
        let over = native("global-over", 160)?;
        assert!(matches!(
            router.publish_custody_record_from(&over, now, &store, "198.51.100.1".parse()?),
            Err(NodeCoreError::Capacity { .. })
        ));
        router.publish_custody_record_from(&over, now + 60, &store, "198.51.100.1".parse()?)?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn custody_rows_do_not_grow_or_deep_clone_the_legacy_registry_snapshot() -> TestResult {
    let path = temp_store_path("custody-snapshot-isolation")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let before = serde_json::to_vec(&router.mvp1_identities_snapshot())?;
    for n in 0_u8..8 {
        router.publish_custody_record_from(
            &native(&format!("snapshot-{n}"), 10 + n)?,
            1_760_000_000,
            &store,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, n, 0, 1)),
        )?;
    }
    let snapshot = router.mvp1_identities_snapshot();
    assert_eq!(serde_json::to_vec(&snapshot)?, before);
    let candidate = snapshot.clone();
    assert!(std::sync::Arc::ptr_eq(&snapshot.custody, &candidate.custody));

    let request =
        registration_request(&router, "legacy-after-custody", "phone", 4101, None, "source")?;
    let writes = store.identity_registry_write_count();
    router.register_identity_durable(&request, &store)?;
    assert_eq!(store.identity_registry_write_count(), writes + 1);
    let serialized = serde_json::to_vec(&router.mvp1_identities_snapshot())?;
    assert!(serialized.windows(b"snapshot-".len()).all(|window| window != b"snapshot-"));

    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let restored = store.load_router()?.ok_or("router")?;
    assert!(
        restored
            .custody_record(&native("snapshot-0", 10)?.record.body.account_anchor, 1_760_000_000)?
            .is_some()
    );
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn custody_ownership_survives_scoped_legacy_admission_and_journal_replay() -> TestResult {
    let path = temp_store_path("custody-scoped-registration-owner")?;
    let publication = native("alice", 10)?;
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = RouterCore::new();
        store.save_router(&router)?;
        router.publish_custody_record(&publication, publication.record.body.issued_at, &store)?;
        let conflicting = registration_request(&router, "alice", "phone", 91, None, "source-a")?;
        let before = store.identity_registry_write_count();
        assert!(matches!(
            router.register_identity_durable(&conflicting, &store),
            Err(NodeCoreError::PrincipalIdTaken)
        ));
        assert_eq!(store.identity_registry_write_count(), before);
        let independent = registration_request(&router, "bob", "phone", 92, None, "source-b")?;
        router.register_identity_durable(&independent, &store)?;
    }
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = store.load_router()?.ok_or("router")?;
        let conflicting = registration_request(&router, "alice", "phone", 93, None, "source-c")?;
        assert!(matches!(
            router.register_identity_durable(&conflicting, &store),
            Err(NodeCoreError::PrincipalIdTaken)
        ));
        assert!(
            router
                .custody_record(
                    &publication.record.body.account_anchor,
                    publication.record.body.issued_at
                )?
                .is_some()
        );
    }
    std::fs::remove_file(path)?;
    Ok(())
}
