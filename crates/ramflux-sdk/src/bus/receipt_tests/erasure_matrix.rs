// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real routed own/peer DM and group erasure, replay, quarantine and reopen coverage.
use super::*;
use crate::bus::sync_driver;
use crate::client::routed::SendMaterial;

#[tokio::test(flavor = "current_thread")]
async fn generic_message_copy_scan_covers_own_peer_dm_group_replay_and_restart() -> TestResult {
    for own in [false, true] {
        for group in [false, true] {
            Box::pin(case(own, group)).await?;
        }
    }
    Ok(())
}
/// The sibling's copy of the author's message: the real authored-history Sent copy, sealed by the
/// source for the enrolled device and delivered as a routed entry.
fn own_copy(
    source: &LocalBusAccountState,
    sibling: &LocalBusAccountState,
    merged: &crate::SdkDeviceManifestResponse,
) -> Result<GatewayInboxEntry, Box<dyn std::error::Error>> {
    let config = source.gateway_config.clone();
    let plan = source.client.prepare_authored_history(&config)?.ok_or("authored history plan")?;
    let reference = sibling.client.owned_device_identity()?;
    let material = SendMaterial {
        manifest: Some((reference.root_commitment().into(), merged.clone())),
        bundle: Some(sibling.client.load_x3dh_private_state(&reference)?.bundle),
    };
    let (_, envelope) = source
        .client
        .seal_authored_history(&source.sealing_config()?, plan, material)?
        .ok_or("sealed own copy")?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    })
}
/// What the generated own-sent path needs the enrolled sibling to know about the thread.
fn seed_sibling(
    source: &LocalBusAccountState,
    sibling: &LocalBusAccountState,
    (a, b, peer): (&Spec, &Spec, &Spec),
    group: bool,
) -> TestResult {
    if group {
        let state =
            source.client.account_db()?.shared_group_state("group")?.ok_or("group state")?;
        sibling.client.accept_shared_group_state(&state, b.identity()?.storage_key())?;
    } else {
        // The same direct-thread binding `seed_pair` gives the author and the remote party.
        sibling.client.account_db()?.persist_client_record(
            "conversation",
            &a.conversation(peer)?,
            &json!({"kind":"direct","group_id":null,"participants":[a.principal,peer.principal],"participant_roots":[a.identity()?.root_commitment(),peer.identity()?.root_commitment()]}),
        )?;
    }
    Ok(())
}
async fn case(own: bool, group: bool) -> TestResult {
    eprintln!("erasure matrix start: own={own} group={group}");
    let root = runtime_tests::root(&format!("generic-erasure-{own}-{group}"));
    let a = Spec::new(&root, "private-source-principal", 41);
    // The recipient. In the own cases it is a second native device of the author's account.
    let mut b = Spec::new(
        &root,
        if own { "private-source-principal" } else { "recipient-principal" },
        if own { 41 } else { 51 },
    );
    b.root = root.join("recipient");
    b.device = "recipient-device".into();
    // The remote party the author writes to; in the peer cases it is the recipient itself.
    let peer = if own { Spec::new(&root, "recipient-principal", 51) } else { b.clone() };
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &peer)?;
    if group {
        let author = a.client(None)?;
        let member = peer.client(None)?;
        a.prepare_group(&author, "group", "thread", &[(&peer, &member)])?;
    }
    let mut source = a.account(None, mail.clone())?;
    let peer_account = peer.account(None, mail.clone())?;
    let merged = if own { Some(b.enroll_sibling_of(&a, &source.client)?) } else { None };
    let (mut recipient, _peer_account) = if own {
        (b.account(None, mail.clone())?, Some(peer_account))
    } else {
        (peer_account, None)
    };
    if own {
        seed_sibling(&source, &recipient, (&a, &b, &peer), group)?;
    }
    let body = if group { "private-group-content" } else { "private-dm-content" };
    let conversation = if group { "thread".to_owned() } else { a.conversation(&peer)? };
    let message = if group {
        Box::pin(a.send_group_text(&mut source, "group", "kept-projection-id", body)).await?
    } else {
        let mut sender = source.session_client().await?;
        let operation = "kept-projection-id";
        a.send_text(&source.client, &mut sender, a.message(&peer, operation), body.as_bytes())
            .await?;
        a.event(operation)?
    };
    let entry = if let Some(merged) = &merged {
        own_copy(&source, &recipient, merged)?
    } else {
        if group {
            recipient.client.import_group_sender_key_distribution(
                &source.client.export_group_sender_key_distribution("group", &a.device)?,
            )?;
        }
        mail.lock()
            .map_err(|_| "mailbox")?
            .messages
            .iter()
            .rev()
            .find(|entry| entry.target_delivery_id == recipient.target_delivery_id)
            .cloned()
            .ok_or("routed delivery")?
    };
    let mut receiver = recipient.session_client().await?;
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    sync_driver::process(&mut recipient, &mut receiver, &pool, &entry).await?;
    let raw = super::erasure_audit::open(&b, &recipient.client)?;
    let identities = super::erasure_audit::identities(&raw)?;
    let mut forbidden = super::erasure_audit::forbidden(&raw, &entry, &a.identity()?)?;
    if own {
        // The sibling is the author's own account: its principal id and root commitment are its
        // permanent identity, not residue of the erased copy. Every envelope-, device- and
        // copy-derived value stays forbidden.
        let author = a.identity()?;
        forbidden.retain(|value| {
            value != &entry.envelope.source_principal_id && value != author.root_commitment()
        });
    }
    forbidden.push(body.into());
    drop(raw);
    recipient.client.delete_direct_message(
        &conversation,
        &message,
        "local",
        &ramflux_protocol::encode_base64url([66; 32]),
    )?;
    assert_eq!(
        recipient.client.account_db()?.direct_message_by_id(&message)?.map(|row| row.is_own),
        Some(own),
        "own={own} group={group}"
    );
    let erased = Erased {
        spec: &b,
        entry: &entry,
        forbidden: &forbidden,
        identities: &identities,
        message: &message,
        label: format!("own={own} group={group}"),
    };
    Box::pin(replay_erased(&mut recipient, &mut receiver, &pool, &erased)).await?;
    drop(recipient);
    drop(source);
    std::fs::remove_dir_all(root)?;
    eprintln!("erasure matrix passed: own={own} group={group}");
    Ok(())
}

/// Source of the replay and quarantine checks after the local erase.
struct Erased<'a> {
    spec: &'a Spec,
    entry: &'a GatewayInboxEntry,
    forbidden: &'a [String],
    identities: &'a super::erasure_audit::IdentitySnapshot,
    message: &'a str,
    label: String,
}
async fn replay_erased(
    recipient: &mut LocalBusAccountState,
    receiver: &mut impl crate::GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    erased: &Erased<'_>,
) -> TestResult {
    for reopen in [false, true] {
        if reopen {
            drop(recipient.client.active_account_db.take());
            recipient.client.unlock_account(&erased.spec.principal, b"receipt-test")?;
        }
        let raw = super::erasure_audit::open(erased.spec, &recipient.client)?;
        assert_eq!(*erased.identities, super::erasure_audit::identities(&raw)?);
        super::erasure_audit::assert_erased(&raw, erased.forbidden, erased.message)?;
        drop(raw);
        let before = recipient.client.account_db()?.journal_after(0, 1024)?.len();
        sync_driver::process(recipient, receiver, pool, erased.entry).await?;
        sync_driver::quarantine_failure(
            &recipient.client,
            &erased.spec.device,
            erased.entry,
            "unused",
            &SdkError::InboundRejected("duplicate".into()),
            now_unix_timestamp(),
        )?;
        assert_eq!(before, recipient.client.account_db()?.journal_after(0, 1024)?.len());
        quarantine_changed(recipient, receiver, pool, erased.entry, &erased.spec.device).await?;
        let raw = super::erasure_audit::open(erased.spec, &recipient.client)?;
        super::erasure_audit::assert_erased(&raw, erased.forbidden, erased.message)?;
        drop(raw);
        // No-resurrection: the redelivered envelope neither revives the row nor its plaintext.
        assert!(
            recipient.client.account_db()?.message_is_deleted(erased.message)?,
            "redelivery resurrected the erased message: {}",
            erased.label
        );
        assert!(
            recipient
                .client
                .account_db()?
                .direct_message_by_id(erased.message)?
                .is_some_and(|row| row.deleted),
            "the erased projection row came back: {}",
            erased.label
        );
        // Clear only opaque failures so the next exact replay assertion checks new writes.
        assert_eq!(recipient.client.account_db()?.message_content(erased.message)?, None);
    }
    Ok(())
}

async fn quarantine_changed(
    recipient: &mut LocalBusAccountState,
    receiver: &mut impl crate::GatewaySessionAccess,
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
