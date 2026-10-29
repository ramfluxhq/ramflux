// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Routed replay admission through the receiving daemon after message deletion.
use super::*;
use crate::bus::sync_driver;

#[tokio::test(flavor = "current_thread")]
async fn deleted_routed_replay_is_acked_without_decrypt_retry_or_identity_dead_letter() -> TestResult
{
    let root = runtime_tests::root("deleted-routed-replay");
    let a = Spec::new(&root, "privacy-source-principal", 41);
    let b = Spec::new(&root, "privacy-recipient-principal", 51);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let mut source = a.account(None, mail.clone())?;
    let mut sender = source.take_live_engine().await?;
    let entry = source
        .client
        .send_plaintext_direct_message_without_franking(
            &mut sender,
            a.message(&b, "privacy-envelope-id"),
            b"private body",
            crate::client::routed::Route::direct(),
        )
        .await?;
    let mut recipient = b.account(None, mail.clone())?;
    let mut receiver = recipient.take_live_engine().await?;
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    sync_driver::process(&mut recipient, &mut receiver, &pool, &entry).await?;
    let committed = recipient.client.authenticated_committed_key(&entry)?;
    let marker = recipient.client.account_db()?.routed_seen_key(&committed)?;
    assert_eq!(
        recipient.client.account_db()?.load_actor_state::<String>(&marker)?,
        Some(entry.envelope.payload_hash.clone())
    );
    recipient.client.delete_direct_message(
        "thread",
        "privacy-envelope-id",
        "local",
        "delete-marker",
    )?;
    assert!(!recipient.client.account_db()?.actor_state_exists(&committed)?);
    for restart in [false, true] {
        if restart {
            drop(recipient);
            recipient = b.account(None, mail.clone())?;
            receiver = recipient.take_live_engine().await?;
        }
        sync_driver::process(&mut recipient, &mut receiver, &pool, &entry).await?;
        recipient.client.ack_gateway_entry(&mut receiver, &entry, now_unix_timestamp()).await?;
        assert!(!recipient.client.account_db()?.has_inbox_retry(&committed)?);
        assert!(
            recipient.client.account_db()?.latest_journal_event("message.undeliverable")?.is_none()
        );
        assert_eq!(recipient.client.account_db()?.message_content("privacy-envelope-id")?, None);
    }
    assert!(
        mail.lock()
            .map_err(|_| "mailbox")?
            .acked
            .contains(&(b.device.clone(), entry.envelope.envelope_id.clone()))
    );
    // A changed authenticated payload is a replay mismatch before any pair decryption.
    let changed = source
        .client
        .send_plaintext_direct_message_without_franking(
            &mut sender,
            a.message(&b, "privacy-other-envelope"),
            b"different body",
            crate::client::routed::Route::direct(),
        )
        .await?;
    let mut conflict = changed;
    conflict.envelope.envelope_id = entry.envelope.envelope_id.clone();
    let branch = source.client.device_branch.as_ref().ok_or("source branch")?;
    conflict.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::envelope_sender_signed_bytes(&conflict.envelope)?,
        branch,
    );
    assert_conflict_quarantine(&mut recipient, &mut receiver, &pool, conflict, &committed, &marker)
        .await?;
    drop(recipient);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn assert_conflict_quarantine(
    recipient: &mut LocalBusAccountState,
    receiver: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    mut conflict: GatewayInboxEntry,
    committed: &str,
    marker: &str,
) -> TestResult {
    let error = sync_driver::process(recipient, receiver, pool, &conflict)
        .await
        .err()
        .ok_or("replay accepted")?;
    assert!(matches!(error, SdkError::ReplayMismatch));
    assert!(sync_driver::quarantine_failure(
        &recipient.client,
        &receiver.config.device_id,
        &conflict,
        committed,
        &error,
        now_unix_timestamp()
    )?);
    assert!(
        recipient.client.account_db()?.latest_journal_event("message.undeliverable")?.is_some()
    );
    assert!(!recipient.client.account_db()?.has_inbox_retry(committed)?);
    // No source or envelope is written to the failure journal even for an invalid signature.
    conflict.envelope.signed.signature = "invalid".into();
    let unverified = recipient.client.inbox_admission_key(&conflict)?;
    assert!(unverified.starts_with("inbox/unverified/"));
    sync_driver::quarantine_failure(
        &recipient.client,
        &receiver.config.device_id,
        &conflict,
        &unverified,
        &SdkError::InboundRejected("invalid signature".into()),
        now_unix_timestamp(),
    )?;
    let db = recipient.client.account_db()?;
    let mut owner = db
        .client_record("identity", &conflict.envelope.source_principal_id)?
        .ok_or("source identity")?;
    owner["contact_identity_commitment"] = json!(ramflux_protocol::encode_base64url([0x71; 32]));
    db.persist_client_record("identity", &conflict.envelope.source_principal_id, &owner)?;
    assert!(recipient.client.inbound_device_reference(&conflict).is_err());
    let replaced = recipient.client.inbox_admission_key(&conflict)?;
    assert!(replaced.starts_with("inbox/unverified/"));
    sync_driver::quarantine_failure(
        &recipient.client,
        &receiver.config.device_id,
        &conflict,
        &replaced,
        &SdkError::InboundRejected("current root replaced".into()),
        now_unix_timestamp(),
    )?;
    assert_failure_journal(
        &recipient.client,
        &[
            &conflict.envelope.source_principal_id,
            &conflict.envelope.source_device_id,
            &conflict.envelope.envelope_id,
            committed,
        ],
        marker,
    )?;
    Ok(())
}

fn assert_failure_journal(client: &RamfluxClient, forbidden: &[&str], marker: &str) -> TestResult {
    let journal = client.account_db()?.journal_after(0, 128)?;
    let failures: Vec<_> = journal.iter().filter(|e| e.topic == "message.undeliverable").collect();
    assert_eq!(failures.len(), 1);
    for event in failures {
        let json = serde_json::to_string(event)?;
        for value in forbidden {
            assert!(!json.contains(value), "identity retained in failure journal: {value}");
        }
        assert_eq!(event.body["marker"], marker);
    }
    Ok(())
}
