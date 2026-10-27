// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Principal routing labels have one authenticated owner across registration profiles.

use super::*;
use ramflux_crypto::custody::{
    GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, create_genesis,
};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn native(principal: &str, seed: u8) -> TestResult<crate::CustodyPublication> {
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
