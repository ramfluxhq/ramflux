// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real routed own/peer DM and group erasure, replay, quarantine and reopen coverage.
use super::*;
use crate::bus::sync_driver;

#[tokio::test(flavor = "current_thread")]
async fn generic_message_copy_scan_covers_own_peer_dm_group_replay_and_restart() -> TestResult {
    for own in [false, true] {
        for group in [false, true] {
            Box::pin(case(own, group)).await?;
        }
    }
    Ok(())
}
fn seed_own_pair(
    source: &RamfluxClient,
    recipient: &RamfluxClient,
    a: &Spec,
    b: &Spec,
) -> TestResult {
    let mut manifest = crate::client::identity_authority::test_support::manifest(source)?;
    manifest
        .devices
        .extend(crate::client::identity_authority::test_support::manifest(recipient)?.devices);
    crate::client::identity_authority::test_support::sign_manifest(
        source.identity_root.as_ref().ok_or("root")?,
        &mut manifest,
        2,
    )?;
    for client in [source, recipient] {
        client.persist_root_verified_directory(&manifest)?;
    }
    let send = ramflux_crypto::DmSession::initiator(
        [17; 32],
        dm_device_id_hash(&a.device),
        dm_device_id_hash(&b.device),
        [3; 32],
    )?;
    let recv = ramflux_crypto::DmSession::recipient(
        [17; 32],
        dm_device_id_hash(&b.device),
        dm_device_id_hash(&a.device),
        [3; 32],
    )?;
    source.persist_pair(&a.identity()?, &b.identity()?, &[4; 32], &send)?;
    recipient.persist_pair(&b.identity()?, &a.identity()?, &[4; 32], &recv)?;
    Ok(())
}
fn prepare_group(
    source: &RamfluxClient,
    recipient: &RamfluxClient,
    a: &Spec,
    b: &Spec,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    for client in [source, recipient] {
        client.create_group("group", a.identity()?.storage_key())?;
        client.add_group_member("group", b.identity()?.storage_key(), "member")?;
        let key =
            source.device_branch.as_ref().ok_or("branch")?.signing_key.verifying_key().to_bytes();
        client.account_db()?.persist_group_member_device_key(
            "group",
            &a.identity()?,
            &ramflux_protocol::encode_base64url(key),
        )?;
        client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"group","group_id":"group"}),
        )?;
    }
    let distribution = source.export_group_sender_key_distribution("group", &a.device)?;
    recipient.import_group_sender_key_distribution(&distribution)?;
    let body = source.encrypt_group_message("group", &a.device, b"private-group-content")?;
    Ok(body)
}
async fn case(own: bool, group: bool) -> TestResult {
    eprintln!("erasure matrix start: own={own} group={group}");
    let root = runtime_tests::root(&format!("generic-erasure-{own}-{group}"));
    let a = Spec::new(&root, "private-source-principal", 41);
    let mut b = Spec::new(
        &root,
        if own { "private-source-principal" } else { "recipient-principal" },
        if own { 41 } else { 51 },
    );
    b.root = root.join("recipient");
    b.device = "recipient-device".into();
    let mail: Shared = Arc::new(Mutex::default());
    if !own {
        fixture::seed_pair(&a, &b)?;
    }
    let mut source = a.account(None, mail.clone())?;
    let mut recipient = b.account(None, mail.clone())?;
    if own {
        seed_own_pair(&source.client, &recipient.client, &a, &b)?;
    }
    let logical = "private-logical-group-message";
    let mut sender = source.take_live_engine().await?;
    let message = a.message(&b, if group { logical } else { "kept-projection-id" });
    let entry = if group {
        let body = prepare_group(&source.client, &recipient.client, &a, &b)?;
        source
            .client
            .send_plaintext_direct_message_without_franking(
                &mut sender,
                message,
                &body,
                crate::client::routed::Route::group_message("group"),
            )
            .await?
    } else {
        source
            .client
            .send_plaintext_direct_message_without_franking(
                &mut sender,
                message,
                b"private-dm-content",
                crate::client::routed::Route::direct(),
            )
            .await?
    };
    let mut receiver = recipient.take_live_engine().await?;
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    sync_driver::process(&mut recipient, &mut receiver, &pool, &entry).await?;
    let routing = recipient.client.committed_routing(&entry)?.ok_or("routing")?;
    let message = routing.message_id;
    let raw = super::erasure_audit::open(&b, &recipient.client)?;
    let identities = super::erasure_audit::identities(&raw)?;
    let mut forbidden = super::erasure_audit::forbidden(&raw, &entry, &a.identity()?)?;
    if group {
        forbidden.push(logical.into());
    }
    drop(raw);
    recipient.client.delete_direct_message("thread", &message, "local", "delete-marker")?;
    assert_eq!(
        recipient.client.account_db()?.direct_message_by_id(&message)?.map(|row| row.is_own),
        Some(own),
        "own={own} group={group}"
    );
    for reopen in [false, true] {
        if reopen {
            drop(recipient.client.active_account_db.take());
            recipient.client.unlock_account(&b.principal, b"receipt-test")?;
        }
        let raw = super::erasure_audit::open(&b, &recipient.client)?;
        assert_eq!(identities, super::erasure_audit::identities(&raw)?);
        super::erasure_audit::assert_erased(&raw, &forbidden, &message)?;
        drop(raw);
        let before = recipient.client.account_db()?.journal_after(0, 1024)?.len();
        sync_driver::process(&mut recipient, &mut receiver, &pool, &entry).await?;
        sync_driver::quarantine_failure(
            &recipient.client,
            &b.device,
            &entry,
            "unused",
            &SdkError::InboundRejected("duplicate".into()),
            now_unix_timestamp(),
        )?;
        assert_eq!(before, recipient.client.account_db()?.journal_after(0, 1024)?.len());
        quarantine_changed(&mut recipient, &mut receiver, &pool, &entry, &b.device).await?;
        let raw = super::erasure_audit::open(&b, &recipient.client)?;
        super::erasure_audit::assert_erased(&raw, &forbidden, &message)?;
        drop(raw);
        // Clear only opaque failures so the next exact replay assertion checks new writes.
        assert_eq!(recipient.client.account_db()?.message_content(&message)?, None);
    }
    drop(recipient);
    drop(source);
    std::fs::remove_dir_all(root)?;
    eprintln!("erasure matrix passed: own={own} group={group}");
    Ok(())
}

async fn quarantine_changed(
    recipient: &mut LocalBusAccountState,
    receiver: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    entry: &GatewayInboxEntry,
    device: &str,
) -> TestResult {
    let mut changed = entry.clone();
    changed.envelope.signed.signature = "invalid-signature".into();
    let error = sync_driver::process(recipient, receiver, pool, &changed)
        .await
        .err()
        .ok_or("invalid entry accepted")?;
    let key = recipient.client.inbox_admission_key(&changed)?;
    assert!(sync_driver::quarantine_failure(
        &recipient.client,
        device,
        &changed,
        &key,
        &error,
        now_unix_timestamp(),
    )?);
    Ok(())
}
