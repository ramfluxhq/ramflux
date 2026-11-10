// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A populated data/key fixture does not silently grant management approval.
use super::*;
use crate::custody::{
    CreationCeremony, HomeAuthorizationRequest,
    home_authorization::{HomeAuthorizationInput, proposal_digest},
    tests::{Root, TestVault, input, words},
};
use ramflux_protocol::{
    custody::object_hash,
    encode_base64url,
    home_migration::{Authorization, Refusal},
};

#[test]
fn home_migration_memory_fixture_requires_a_new_explicit_approval_for_each_exact_signature()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let vault = MemoryPrimaryVault::default();
    let now = 1_700_000_000;
    let mut ceremony = CreationCeremony::begin(&root.0, input("human"), now)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    let account = ceremony.confirm(&words(&phrase, positions)?, &vault, now)?;
    let stored: serde_json::Value = serde_json::from_slice(&std::fs::read(
        root.0.join("custody_accounts/human/authority.json"),
    )?)?;
    let reference = stored["primary_vault_ref"].as_str().ok_or("primary reference")?;
    let (actor, credentials) = account.credentials(&vault, "primary", now)?;
    let hash = |value| encode_base64url([value; 32]);
    let body = Authorization {
        version: 1,
        migration_id: hash(1),
        account_anchor: account.record().body.account_anchor.clone(),
        actor,
        authority_record_hash: object_hash(account.record())?,
        management_certificate_hash: object_hash(&account.record().body.master_certificate)?,
        previous_home_hash: hash(2),
        next_home_epoch: 1,
        old_node: "source".into(),
        destination_node: "destination".into(),
        destination_key: SelfSigningKey::from_vault_seed(&Zeroizing::new([6; 32])).public_key(),
        gateway_tcp_addr: "127.0.0.1:1".into(),
        offer_hash: hash(3),
        delivery_map_hash: hash(4),
        nonce: hash(5),
        issued_at: now,
        seal_until: now + 600,
        max_commit_delay: 600,
        forward_seconds: 86400,
    };
    let digest = proposal_digest(&body)?;
    let request = || {
        HomeAuthorizationRequest::new(HomeAuthorizationInput {
            local_account_id: "human",
            reference,
            body: &body,
            branch: &credentials.signing,
            authority: account.verified(),
            digest: &digest,
            now,
        })
    };
    assert!(matches!(
        vault.sign_home_authorization(request()?),
        Err(SdkError::HomeMigrationRefused(Refusal::CustodyUserPresenceUnavailable))
    ));
    // An older provider with an available primary but no presence-specific operation also refuses.
    assert_older_provider_refuses(reference, &vault.load_primary(reference)?, request()?)?;
    vault.approve_migration_once_for_test("human", &hash(1))?;
    assert!(matches!(
        vault.approve_migration_once_for_test("human", &hash(1)),
        Err(SdkError::LocalBusRefused { code, .. }) if code == "MigrationApprovalAlreadyArmed"
    ));
    assert!(matches!(
        vault.approve_migration_once_for_test("human", &hash(7)),
        Err(SdkError::LocalBusRefused { code, .. }) if code == "MigrationApprovalAlreadyArmed"
    ));
    let mut other_body = body.clone();
    other_body.migration_id = hash(7);
    let other_digest = proposal_digest(&other_body)?;
    assert!(matches!(
        vault.sign_home_authorization(HomeAuthorizationRequest::new(HomeAuthorizationInput {
            local_account_id: "human",
            reference,
            body: &other_body,
            branch: &credentials.signing,
            authority: account.verified(),
            digest: &other_digest,
            now,
        })?),
        Err(SdkError::HomeMigrationRefused(Refusal::CustodyUserPresenceUnavailable))
    ));
    let signed = vault.sign_home_authorization(request()?)?;
    assert_eq!(signed.body, body);
    ramflux_crypto::home_migration::verify_authorization(&signed, account.verified(), now)?;
    assert!(matches!(
        vault.sign_home_authorization(request()?),
        Err(SdkError::HomeMigrationRefused(Refusal::CustodyUserPresenceUnavailable))
    ));
    assert_consumed_cannot_rearm(&vault, &hash(1), &hash(7))?;
    assert!(
        HomeAuthorizationRequest::new(HomeAuthorizationInput {
            local_account_id: "human",
            reference,
            body: &body,
            branch: &credentials.signing,
            authority: account.verified(),
            digest: &hash(8),
            now,
        })
        .is_err()
    );
    Ok(())
}

#[test]
fn persist_at_reloads_primary_seed_after_drop() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let path = root.0.join("itest-memory-vault.json");
    let key = SelfSigningKey::from_vault_seed(&Zeroizing::new([7; 32]));
    {
        let vault = MemoryPrimaryVault::persist_at(&path)?;
        vault.store_new("primary-ref", &key)?;
    }
    let reloaded = MemoryPrimaryVault::persist_at(&path)?;
    assert_eq!(*reloaded.load_primary("primary-ref")?.vault_seed(), *key.vault_seed());
    Ok(())
}

#[test]
fn persist_at_missing_file_starts_empty() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let vault = MemoryPrimaryVault::persist_at(root.0.join("itest-memory-vault.json"))?;
    assert!(matches!(vault.load_primary("missing"), Err(SdkError::CustodyVaultUnavailable)));
    Ok(())
}

#[test]
fn persist_at_rejects_corrupt_json() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let path = root.0.join("itest-memory-vault.json");
    std::fs::write(&path, b"{not-json")?;
    assert!(matches!(
        MemoryPrimaryVault::persist_at(&path),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    Ok(())
}

#[test]
fn persist_at_rejects_invalid_base64url() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let path = root.0.join("itest-memory-vault.json");
    std::fs::write(&path, br#"{"primary-ref":"@@@"}"#)?;
    assert!(matches!(
        MemoryPrimaryVault::persist_at(&path),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    Ok(())
}

#[test]
fn persist_at_delete_removes_entry_from_file() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let path = root.0.join("itest-memory-vault.json");
    let key = SelfSigningKey::from_vault_seed(&Zeroizing::new([9; 32]));
    let vault = MemoryPrimaryVault::persist_at(&path)?;
    vault.store_new("primary-ref", &key)?;
    vault.delete("primary-ref")?;
    drop(vault);
    let reloaded = MemoryPrimaryVault::persist_at(&path)?;
    assert!(matches!(reloaded.load_primary("primary-ref"), Err(SdkError::CustodyVaultUnavailable)));
    Ok(())
}

#[test]
fn default_vault_does_not_write_a_file() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let path = root.0.join("itest-memory-vault.json");
    let vault = MemoryPrimaryVault::default();
    let key = SelfSigningKey::from_vault_seed(&Zeroizing::new([3; 32]));
    vault.store_new("primary-ref", &key)?;
    assert!(!path.exists());
    Ok(())
}

fn assert_older_provider_refuses(
    reference: &str,
    primary: &SelfSigningKey,
    request: HomeAuthorizationRequest<'_>,
) -> Result<(), SdkError> {
    let old_provider = TestVault::default();
    old_provider.store_new(reference, primary)?;
    assert!(matches!(
        old_provider.sign_home_authorization(request),
        Err(SdkError::HomeMigrationRefused(Refusal::CustodyUserPresenceUnavailable))
    ));
    Ok(())
}

fn assert_consumed_cannot_rearm(
    vault: &MemoryPrimaryVault,
    consumed: &str,
    next: &str,
) -> Result<(), SdkError> {
    assert!(matches!(vault.approve_migration_once_for_test("human", consumed),
        Err(SdkError::LocalBusRefused { code, .. }) if code == "MigrationApprovalConsumed"));
    vault.approve_migration_once_for_test("human", next)?;
    assert!(matches!(vault.approve_migration_once_for_test("human", consumed),
        Err(SdkError::LocalBusRefused { code, .. }) if code == "MigrationApprovalConsumed"));
    Ok(())
}
