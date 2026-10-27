// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A live peer accepts fresh post-restore chains while retaining delayed pre-restore decryption.
use super::*;
use super::{
    r5::{outgoing, settle},
    review::{pool, trust},
    session_record::Wire,
};
use ramflux_storage::{BackupDatabase, FileVaultSecretSource, VaultSecretSource};
fn archived(fixture: &Fixture) -> Result<(), SdkError> {
    let client = &fixture.client;
    let vault = FileVaultSecretSource::new(&fixture.root).vault_secret(&fixture.id)?;
    let kek = crate::client::account::account_db_key_encryption_key(&vault, b"routed-test");
    let key = ramflux_storage::unwrap_with_vault_secret(
        &kek,
        &client
            .account_index()?
            .load_wrapped_db_key(&fixture.id)?
            .ok_or(SdkError::AccountDbNotUnlocked)?,
    )?;
    BackupDatabase::open(&client.account_db()?.path, &key)?.archive_outbound()?;
    client.account_db()?.persist_actor_state("backup/reestablishing", &true)?;
    client.account_db()?.persist_actor_state("backup/fresh-outbound", &true)?;
    client.account_db()?.persist_actor_state("backup/previous-device-epoch", &1_u64)?;
    Ok(())
}
fn activated(alice: &mut Fixture, bob: &Fixture) -> Result<(), SdkError> {
    alice.client.create_device_branch("alice", "alice", 2, [42; 32]);
    alice.client.initialize_and_publish_prekey_bundle("alice", "alice", "alice", [42; 32], None)?;
    let mut manifest = crate::client::identity_authority::test_support::manifest(&alice.client)?;
    crate::client::identity_authority::test_support::sign_manifest(
        alice.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut manifest,
        2,
    )?;
    let commitment = manifest.principal_commitment.clone();
    alice.client.observe_device_manifest_json(serde_json::to_value(&manifest)?, &commitment)?;
    bob.client.observe_device_manifest_json(serde_json::to_value(&manifest)?, &commitment)?;
    alice.client.complete_backup_activation()?;
    Ok(())
}
#[tokio::test]
async fn the_first_post_restore_dm_uses_a_fresh_session_accepted_by_the_live_peer()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let old = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &bob.client.local_device_identity("bob")?,
        )?
        .ok_or_else(|| invalid("old session"))?
        .0
        .session_id;
    let saved = alice
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&format!("dm-pair/session/{old}"))?
        .ok_or_else(|| invalid("saved session"))?;
    let later = seal(&alice, &bob, outgoing(&alice, &bob, "after-backup"), b"later")?;
    let mut receiver =
        GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut receiver, &pool()?, &later, false).await?;
    alice.client.account_db()?.persist_actor_state(&format!("dm-pair/session/{old}"), &saved)?;
    archived(&alice)?;
    assert!(alice.client.require_backup_outbound_ready().is_err());
    activated(&mut alice, &bob)?;
    trust(&alice, &bob)?;
    let (mut sender, _) = Wire::engine(&alice, &bob)?;
    let msg = outgoing(&alice, &bob, "restored-first");
    let entry = alice
        .client
        .send_plaintext_direct_message_via_gateway(&mut sender, msg, b"restored")
        .await?;
    let parsed: SdkDmEncryptedEnvelope = serde_json::from_slice(
        &ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|_| invalid("encoded delivery"))?,
    )?;
    assert_ne!(parsed.ciphertext.session_id, old);
    assert_eq!(parsed.ciphertext.counter, 0);
    bob.client.apply_routed_entry(&mut receiver, &pool()?, &entry, false).await?;
    assert_eq!(
        bob.client.account_db()?.message_content("restored-first")?,
        Some(b"restored".to_vec())
    );
    assert!(alice.client.account_db()?.actor_state_exists(&format!("dm-pair/session/{old}"))?);
    Ok(())
}
#[test]
fn a_restored_group_sender_rotates_its_chain_and_the_live_peer_keeps_late_old_messages()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let bob = Fixture::new("bob", 61)?;
    trust(&alice, &bob)?;
    trust(&bob, &alice)?;
    for client in [&alice.client, &bob.client] {
        fixture_group(client, "group", &alice)?;
        fixture_member(client, "group", &bob)?;
    }
    let old_distribution = alice.client.export_group_sender_key_distribution("group", "alice")?;
    bob.client.import_group_sender_key_distribution(&old_distribution)?;
    let old0: SdkGroupEncryptedEnvelope = serde_json::from_slice(
        &alice.client.encrypt_group_message("group", "alice", b"old zero")?,
    )?;
    assert_eq!(bob.client.decrypt_group_envelope(&old0, "old-zero")?, b"old zero");
    let delayed: SdkGroupEncryptedEnvelope = serde_json::from_slice(
        &alice.client.encrypt_group_message("group", "alice", b"delayed old")?,
    )?;
    let old2: SdkGroupEncryptedEnvelope =
        serde_json::from_slice(&alice.client.encrypt_group_message("group", "alice", b"old two")?)?;
    bob.client.decrypt_group_envelope(&old2, "old-two")?;
    archived(&alice)?;
    activated(&mut alice, &bob)?;
    let new_distribution = alice.client.export_group_sender_key_distribution("group", "alice")?;
    let decoded: SdkGroupSenderKeyDistribution = serde_json::from_slice(&new_distribution)?;
    assert_eq!(decoded.version, 3);
    bob.client.import_group_sender_key_distribution(&new_distribution)?;
    let first: SdkGroupEncryptedEnvelope = serde_json::from_slice(
        &alice.client.encrypt_group_message("group", "alice", b"fresh zero")?,
    )?;
    assert_ne!(first.ciphertext.session_id, old0.ciphertext.session_id);
    assert_eq!(first.ciphertext.counter, 0);
    assert_eq!(bob.client.decrypt_group_envelope(&first, "new-zero")?, b"fresh zero");
    bob.client.import_group_sender_key_distribution(&old_distribution)?;
    assert_eq!(bob.client.decrypt_group_envelope(&delayed, "old-late")?, b"delayed old");
    let next: SdkGroupEncryptedEnvelope = serde_json::from_slice(
        &alice.client.encrypt_group_message("group", "alice", b"fresh one")?,
    )?;
    assert_eq!(bob.client.decrypt_group_envelope(&next, "new-one")?, b"fresh one");
    assert!(bob.client.decrypt_group_envelope(&first, "duplicate").is_err());
    Ok(())
}

#[tokio::test]
async fn r2_key_only_recovery_then_full_merge_creates_a_unique_group_chain_accepted_by_live_peer()
-> Result<(), SdkError> {
    let original = Fixture::new("alice", 41)?;
    let bob = Fixture::new("bob", 61)?;
    trust(&original, &bob)?;
    trust(&bob, &original)?;
    for client in [&original.client, &bob.client] {
        fixture_group(client, "group", &original)?;
        fixture_member(client, "group", &bob)?;
    }
    let old = original.client.export_group_sender_key_distribution("group", "alice")?;
    bob.client.import_group_sender_key_distribution(&old)?;
    let old_message: SdkGroupEncryptedEnvelope = serde_json::from_slice(
        &original.client.encrypt_group_message("group", "alice", b"before")?,
    )?;
    assert_eq!(bob.client.decrypt_group_envelope(&old_message, "before")?, b"before");
    let saved_path = original.root.join("full.db");
    let saved = original.client.account_db()?.write_backup_snapshot(&saved_path)?;
    // Same recovered root/device seeds, no group or sending checkpoint (legacy key import).
    let recovered_root = original.root.join("key-recovered");
    let client =
        crate::bus::dispatch::account::key_backup_restore::recover_alice(&recovered_root).await?;
    let recovered = Fixture {
        root: recovered_root,
        client,
        id: "alice".into(),
        leased_one_time_prekeys: std::sync::atomic::AtomicUsize::new(0),
    };
    let vault = FileVaultSecretSource::new(&recovered.root).vault_secret(&recovered.id)?;
    let kek = crate::client::account::account_db_key_encryption_key(&vault, b"routed-test");
    let key = ramflux_storage::unwrap_with_vault_secret(
        &kek,
        &recovered
            .client
            .account_index()?
            .load_wrapped_db_key(&recovered.id)?
            .ok_or(SdkError::AccountDbNotUnlocked)?,
    )?;
    BackupDatabase::open(&recovered.client.account_db()?.path, &key)?.merge_backup(
        &saved_path,
        &saved.key,
        || Ok(()),
    )?;
    let new = recovered.client.export_group_sender_key_distribution("group", "alice")?;
    bob.client.import_group_sender_key_distribution(&new)?;
    let message: SdkGroupEncryptedEnvelope = serde_json::from_slice(
        &recovered.client.encrypt_group_message("group", "alice", b"after merge")?,
    )?;
    assert_ne!(message.ciphertext.session_id, old_message.ciphertext.session_id);
    assert_eq!(bob.client.decrypt_group_envelope(&message, "after")?, b"after merge");
    Ok(())
}

#[tokio::test]
async fn r2_inactive_restored_sessions_retire_and_destroy_their_private_state()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let local = alice.client.local_device_identity("alice")?;
    let remote = bob.client.local_device_identity("bob")?;
    let id =
        alice.client.active_pair(&local, &remote)?.ok_or_else(|| invalid("pair"))?.0.session_id;
    archived(&alice)?;
    alice.client.retire_pair(&local, &remote, &id)?;
    assert!(!alice.client.account_db()?.actor_state_exists(&format!("dm-pair/session/{id}"))?);
    assert!(!alice.client.account_db()?.actor_state_exists(&format!("backup/inactive-pair/{id}"))?);
    assert!(alice.client.account_db()?.actor_state_exists(&format!("dm-pair/retired/{id}"))?);
    Ok(())
}

#[test]
fn r2_a_known_legacy_group_chain_id_with_different_secret_is_rejected_loudly()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let bob = Fixture::new("bob", 61)?;
    trust(&alice, &bob)?;
    trust(&bob, &alice)?;
    for client in [&alice.client, &bob.client] {
        fixture_group(client, "group", &alice)?;
        fixture_member(client, "group", &bob)?;
    }
    let mut distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(
        &alice.client.export_group_sender_key_distribution("group", "alice")?,
    )?;
    distribution.schema = "ramflux.sdk.group_sender_key.distribution.v2".into();
    distribution.version = 2;
    let original = serde_json::to_vec(&distribution)?;
    bob.client.import_group_sender_key_distribution(&original)?;
    distribution.sender_key_seed[0] ^= 1;
    assert!(
        bob.client
            .import_group_sender_key_distribution(&serde_json::to_vec(&distribution)?)
            .is_err()
    );
    bob.client.import_group_sender_key_distribution(&original)?;
    Ok(())
}
