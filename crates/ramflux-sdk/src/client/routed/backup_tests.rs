// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native restore starts fresh outbound chains and retains authenticated delayed receive state.
use super::*;
use ramflux_storage::BackupDatabase;

fn archive_native(fixture: &Fixture) -> Result<(), SdkError> {
    let vault = fixture.client.vault_secret_source()?.vault_secret(&fixture.id)?;
    let kek = crate::client::account::account_db_key_encryption_key(
        &vault,
        b"native fixture data passphrase",
    )?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &kek,
        &fixture
            .client
            .account_index()?
            .load_wrapped_db_key(&fixture.id)?
            .ok_or(SdkError::AccountDbNotUnlocked)?,
    )?;
    BackupDatabase::open(&fixture.client.account_db()?.path, &key)?.archive_outbound()?;
    Ok(())
}

#[tokio::test]
async fn first_native_post_restore_dm_is_fresh_and_the_live_peer_keeps_delayed_old_traffic()
-> Result<(), SdkError> {
    let mut alice = Fixture::native_named("alice", 41).await?;
    let mut bob = Fixture::native_named("bob", 61).await?;
    super::r5::settle(&mut alice, &mut bob).await?;
    let delayed = generated_delivery(&alice, &bob, "delayed-before-restore", "late old message")?;
    let old = decode(&delayed.entry.envelope)?.ciphertext.session_id;
    archive_native(&alice)?;
    assert!(
        alice
            .client
            .sendable_pair(
                &alice.client.owned_device_identity()?,
                &bob.client.owned_device_identity()?
            )?
            .is_none()
    );
    alice.reopen_native().await?;
    let fresh = generated_delivery(&alice, &bob, "first-after-restore", "fresh native message")?;
    let packet = decode(&fresh.entry.envelope)?;
    assert_ne!(packet.ciphertext.session_id, old, "restore reused an archived sending chain");
    assert_eq!(packet.ciphertext.counter, 0);
    assert!(packet.x3dh.is_some(), "first restored send must bootstrap");
    receive_generated(&mut bob, &fresh.entry).await?;
    receive_generated(&mut bob, &delayed.entry).await?;
    assert_eq!(
        bob.client
            .generated_message_detail(&fresh.conversation, &fresh.message)?
            .message
            .text
            .as_deref(),
        Some("fresh native message")
    );
    assert_eq!(
        bob.client
            .generated_message_detail(&delayed.conversation, &delayed.message)?
            .message
            .text
            .as_deref(),
        Some("late old message")
    );
    let local = alice.client.owned_device_identity()?;
    let remote = bob.client.owned_device_identity()?;
    alice.client.retire_pair(&local, &remote, &old)?;
    assert!(!alice.client.account_db()?.actor_state_exists(&format!("dm-pair/session/{old}"))?);
    assert!(
        !alice.client.account_db()?.actor_state_exists(&format!("backup/inactive-pair/{old}"))?
    );
    assert!(alice.client.account_db()?.actor_state_exists(&format!("dm-pair/retired/{old}"))?);
    Ok(())
}




#[tokio::test]
async fn native_data_merge_rebootstraps_without_reusing_the_archived_outbound_ratchet()
-> crate::client::native_test_support::TestResult {
    use crate::client::native_test_support::Fixture as NativeFixture;
    let alice = NativeFixture::new("native-restore-alice").await?;
    let bob = NativeFixture::new("native-restore-bob").await?;
    alice.client.persist_observed_identity_directory_now(&bob.manifest)?;
    bob.client.persist_observed_identity_directory_now(&alice.manifest)?;
    let local = alice.client.owned_device_identity()?;
    let remote = bob.client.owned_device_identity()?;
    let bundle = bob.client.load_x3dh_private_state(&remote)?.bundle;
    let message = GatewayDirectMessage {
        conversation_id: "native-restore-thread".into(),
        message_id: "before".into(),
        envelope_id: "before".into(),
        source_principal_id: alice.manifest.principal_id.clone(),
        sender_id: "primary".into(),
        recipient_device_id: Some("primary".into()),
        recipient_principal_commitment: Some(bob.manifest.principal_commitment.clone()),
        target_delivery_id: remote.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let (mut saved, header, hash) = alice.client.new_send_pair(&local, &message, bundle.clone())?;
    saved.encrypt(b"before backup", b"test archive chain")?;
    alice.client.persist_pair(&local, &remote, &hash, &saved)?;
    let sequence_key = crate::client::routed::bootstrap_sequence::bootstrap_sequence_key(&local);
    let sequence_floor = header
        .ok_or("bootstrap")?
        .bootstrap_sequence
        .ok_or("sequence")?
        .checked_add(100)
        .ok_or("floor")?;
    let receive_floor = alice.client.bootstrap_high_water_key(&local, &remote)?;
    alice.client.account_db()?.persist_actor_state(&receive_floor, &10_u64)?;
    let snapshot_path = alice.root.0.join("saved.db");
    let snapshot = alice.client.account_db()?.write_backup_snapshot(&snapshot_path)?;
    let pair = RamfluxClient::pair_key(&local, &remote)?;
    let db = alice.client.account_db()?;
    db.persist_actor_state(&sequence_key, &sequence_floor)?;
    db.persist_actor_state(&receive_floor, &20_u64)?;
    db.remove_actor_state(&pair)?;
    db.remove_actor_state(&format!("dm-pair/session/{}", saved.session_id))?;
    db.remove_actor_state(&format!("dm-pair/bootstrap/{}", saved.session_id))?;
    let vault = alice.client.vault_secret_source()?.vault_secret("native-restore-alice")?;
    let kek = crate::client::account::account_db_key_encryption_key(
        &vault,
        b"native fixture data passphrase",
    )?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &kek,
        &alice
            .client
            .account_index()?
            .load_wrapped_db_key("native-restore-alice")?
            .ok_or("wrapped key")?,
    )?;
    // No actor or live transport runs in this test; the SDK reads the same committed DB again.
    let mut merged = BackupDatabase::open(&db.path, &key)?;
    merged.merge_native_backup(&snapshot_path, &snapshot.key, || Ok(()))?;
    drop(merged);
    assert!(db.actor_state_exists(&format!("backup/inactive-pair/{}", saved.session_id))?);
    assert!(alice.client.sendable_pair(&local, &remote)?.is_none());
    assert_eq!(db.load_actor_state::<u64>(&sequence_key)?, Some(sequence_floor));
    assert_eq!(db.load_actor_state::<u64>(&receive_floor)?, Some(20));
    let mut after = message;
    after.message_id = "after".into();
    after.envelope_id = "after".into();
    let (mut fresh, header, _) = alice.client.new_send_pair(&local, &after, bundle)?;
    assert_ne!(fresh.session_id, saved.session_id);
    assert!(header.is_some());
    let header = header.ok_or("fresh bootstrap")?;
    assert!(header.bootstrap_sequence.ok_or("fresh sequence")? > sequence_floor);
    let aad = associated_data(&after.envelope_id, "primary", "primary", &hash)?;
    let mut recipient = bob.client.create_recv_dm_session_with_aad(&header, &aad)?;
    let encrypted = fresh.encrypt(b"fresh native session", b"message AAD")?;
    assert_eq!(encrypted.counter, 0);
    assert_eq!(recipient.decrypt(&encrypted, b"message AAD")?, b"fresh native session");
    assert!(recipient.decrypt(&encrypted, b"message AAD").is_err());
    Ok(())
}
