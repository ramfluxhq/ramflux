// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A populated data/key fixture does not silently grant management approval.
use super::*;
use crate::custody::{
    CreationCeremony, HomeAuthorizationRequest,
    home_authorization::proposal_digest,
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
    let mut ceremony = CreationCeremony::begin(true, &root.0, input("human"), now)?;
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
        HomeAuthorizationRequest::new(
            reference,
            &body,
            &credentials.signing,
            account.verified(),
            &digest,
            now,
        )
    };
    assert!(matches!(
        vault.sign_home_authorization(request()?),
        Err(SdkError::HomeMigrationRefused(Refusal::CustodyUserPresenceUnavailable))
    ));
    // An older provider with an available primary but no presence-specific operation also refuses.
    let old_provider = TestVault::default();
    old_provider.store_new(reference, &vault.load_primary(reference)?)?;
    assert!(matches!(
        old_provider.sign_home_authorization(request()?),
        Err(SdkError::HomeMigrationRefused(Refusal::CustodyUserPresenceUnavailable))
    ));
    vault.approve_next_migration_for_test();
    let signed = vault.sign_home_authorization(request()?)?;
    assert_eq!(signed.body, body);
    ramflux_crypto::home_migration::verify_authorization(&signed, account.verified(), now)?;
    assert!(matches!(
        vault.sign_home_authorization(request()?),
        Err(SdkError::HomeMigrationRefused(Refusal::CustodyUserPresenceUnavailable))
    ));
    assert!(
        HomeAuthorizationRequest::new(
            reference,
            &body,
            &credentials.signing,
            account.verified(),
            &hash(8),
            now
        )
        .is_err()
    );
    Ok(())
}
