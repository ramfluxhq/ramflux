// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `legacy_effect_marker_atomic` and `legacy_stage_redrive` (P13's `receive_stage_redrive`
//! first leg has not landed; the controller merges these rows after P13).
#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::unused_async
)]
use super::*;
use crate::bus::sync_driver::source::w0::SourceW0;
use crate::client::legacy_w1::{self, Fault, LegacyW1};
use ramflux_storage::{ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError};
use std::time::Duration;

const INTEGRITY: &str = "source effect requires staged receive work";
const BEFORE: &str = "legacy w1 before-commit";
const INCARNATION: &str = "e";

#[derive(Debug, PartialEq, Eq)]
struct Snap {
    marker: bool,
    ratchet: bool,
    messages: usize,
    rejected: usize,
    a2i: usize,
    cursor: u64,
    work: i64,
    disposition: Option<String>,
    held: u64,
}

struct HangGuard(Option<std::sync::mpsc::Sender<()>>);
impl Drop for HangGuard {
    fn drop(&mut self) {
        drop(self.0.take());
    }
}

async fn hang<T>(future: impl Future<Output = Result<T, SdkError>>) -> Result<T, SdkError> {
    let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if matches!(
            cancelled.recv_timeout(Duration::from_secs(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            panic!("30-second hang guard expired");
        }
    });
    let _guard = HangGuard(Some(cancel));
    future.await
}

fn reopen(client: &mut RamfluxClient, id: &str) -> Result<(), SdkError> {
    let root = client.identity_root.clone();
    let branch = client.device_branch.clone();
    client.active_account_db = None;
    client.unlock_account(id, b"routed-test")?;
    if client.identity_root.is_none() {
        client.identity_root = root;
    }
    if client.device_branch.is_none() {
        client.device_branch = branch.clone();
        if let (Some(branch), Some(db)) = (branch, client.active_account_db.as_mut()) {
            db.set_device_signer(branch);
        }
    }
    Ok(())
}

fn stage_w0(
    client: &RamfluxClient,
    target: &str,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(target, INCARNATION)?;
    let json = serde_json::to_vec(entry)?;
    let gate = SourceW0 {
        expected: ReceiveExpectation {
            target,
            incarnation: INCARNATION,
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    };
    assert_eq!(
        gate.stage(
            db,
            ReceiveStage {
                target,
                incarnation: INCARNATION,
                sequence: entry.inbox_seq,
                entry_json: &json,
                admission_key: "authenticated-legacy",
                retain_until: now_unix_timestamp() + 300,
                first_seen: 1,
            },
        )?,
        ReceiveStageResult::Staged
    );
    Ok(())
}

fn snap(
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<Snap, SdkError> {
    let db = client.account_db()?;
    let (disposition, work) = db.receive_state_for_test(entry.inbox_seq)?;
    let key = client.legacy_committed_key(entry)?;
    Ok(Snap {
        marker: db.actor_state_exists(&key)?,
        ratchet: client.recv_session_checkpoint_at(conversation, &entry.envelope.envelope_id)?,
        messages: client.direct_messages(conversation).map_or(0, |rows| rows.len()),
        rejected: client.rejected_inbox(conversation).map_or(0, |rows| rows.len()),
        a2i: db.actor_state_keys("legacy/a2i/")?.len() + db.actor_state_keys("a2i/scoped/")?.len(),
        cursor: client.gateway_receive_cursor(&entry.target_delivery_id)?,
        work,
        disposition,
        held: db.unrouted_count()?,
    })
}

fn bound(
    sender: &Fixture,
    receiver: &mut Fixture,
    conversation: &str,
    id: &str,
    body: &[u8],
    seq: u64,
) -> Result<GatewayInboxEntry, SdkError> {
    review::trust(receiver, sender)?;
    review::trust(sender, receiver)?;
    receiver.client.establish_friend_link("link", &receiver.id, &sender.id)?;
    let mut msg = message(id, conversation);
    msg.source_principal_id = sender.id.clone();
    msg.sender_id = sender.id.clone();
    msg.recipient_device_id = Some(receiver.id.clone());
    msg.target_delivery_id = receiver.id.clone();
    let bundle = receiver
        .client
        .load_x3dh_private_state(&receiver.client.local_device_identity(&receiver.id)?)?
        .bundle;
    let (mut session, header) =
        sender.client.create_send_dm_session_from_bundle(&msg, &receiver.id, bundle, &sender.id)?;
    let ciphertext = session.encrypt(body, dm_associated_data(conversation))?;
    msg.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        source_principal_commitment: None,
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".to_owned(),
        version: 1,
        x3dh: header.clone(),
        ciphertext,
    })?;
    let receiving =
        receiver.client.load_or_create_recv_dm_session(conversation, header.as_ref())?;
    receiver.client.send_direct_message(
        conversation,
        &format!("prior-{id}"),
        &sender.id,
        b"prior",
    )?;
    receiver.client.persist_dm_session(conversation, &format!("prior-{id}"), "recv", &receiving)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: seq,
        target_delivery_id: receiver.id.clone(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &msg, None)?,
    })
}

fn a2i_entry(
    sender: &Fixture,
    receiver: &mut Fixture,
    seq: u64,
) -> Result<GatewayInboxEntry, SdkError> {
    review::trust(receiver, sender)?;
    review::trust(sender, receiver)?;
    let conversation = a2i_control_conversation_id(&sender.id, &receiver.id);
    let event = ramflux_sync::A2iControlEvent {
        source_principal_id: Some(sender.id.clone()),
        source_principal_commitment: None,
        event_id: format!("a2i-{seq}"),
        event_type: "a2i.control".into(),
        source_device_id: sender.id.clone(),
        target_device_id: receiver.id.clone(),
        control_domain: "message".into(),
        action: "test".into(),
        subject_base64: String::new(),
        created_at: now_unix_timestamp(),
        acknowledged: false,
    };
    let mut msg = message(&format!("a2i:{seq}"), &conversation);
    msg.source_principal_id = sender.id.clone();
    msg.sender_id = sender.id.clone();
    msg.recipient_device_id = Some(receiver.id.clone());
    msg.target_delivery_id = receiver.id.clone();
    let bundle = receiver
        .client
        .load_x3dh_private_state(&receiver.client.local_device_identity(&receiver.id)?)?
        .bundle;
    let (mut session, header) =
        sender.client.create_send_dm_session_from_bundle(&msg, &receiver.id, bundle, &sender.id)?;
    let ciphertext =
        session.encrypt(&serde_json::to_vec(&event)?, dm_associated_data(&conversation))?;
    msg.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        source_principal_commitment: None,
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".to_owned(),
        version: 1,
        x3dh: header.clone(),
        ciphertext,
    })?;
    let receiving =
        receiver.client.load_or_create_recv_dm_session(&conversation, header.as_ref())?;
    receiver.client.persist_dm_session(&conversation, "a2i-prior", "recv", &receiving)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: seq,
        target_delivery_id: receiver.id.clone(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &msg, None)?,
    })
}

fn apply_success(
    receiver: &RamfluxClient,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<(), SdkError> {
    receiver.apply_legacy_success_w1(entry, conversation)
}

fn apply_reject(
    receiver: &RamfluxClient,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<(), SdkError> {
    receiver.apply_legacy_reject_w1(entry, conversation)
}

fn apply_a2i(receiver: &RamfluxClient, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    receiver.apply_legacy_a2i_w1(entry)
}

fn apply_hold(receiver: &RamfluxClient, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    receiver.apply_legacy_group_hold_w1(entry)
}

fn assert_fault(result: Result<(), SdkError>) {
    match result {
        Err(SdkError::Storage(StorageError::Integrity(text))) if text == BEFORE => {}
        Err(error) => panic!("expected Integrity({BEFORE:?}), got {error}"),
        Ok(()) => panic!("expected Integrity({BEFORE:?}), got Ok"),
    }
}

fn cut_success(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<(), SdkError> {
    stage_w0(&receiver.client, &receiver.id, entry)?;
    let pre = snap(&receiver.client, entry, conversation)?;
    assert!(!pre.marker);
    assert_eq!(pre.cursor, 0);
    assert_eq!(pre.work, 1);
    assert_fault(legacy_w1::run(Fault::BeforeCommit, || {
        apply_success(&receiver.client, entry, conversation)
    }));
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, pre);
    apply_success(&receiver.client, entry, conversation)?;
    let post = snap(&receiver.client, entry, conversation)?;
    assert!(post.marker, "success missing terminal marker");
    assert!(post.ratchet, "success missing ratchet");
    assert!(post.messages > pre.messages, "success wrote no content");
    assert_eq!(post.cursor, 0, "W1 must not embed the receive cursor");
    assert_eq!(post.work, 1);
    assert_eq!(post.disposition.as_deref(), Some("staged"));
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, post);
    Ok(())
}

fn cut_reject(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<(), SdkError> {
    receiver.client.block_friend_link("link")?;
    stage_w0(&receiver.client, &receiver.id, entry)?;
    let pre = snap(&receiver.client, entry, conversation)?;
    assert_eq!(pre.cursor, 0);
    assert_fault(legacy_w1::run(Fault::BeforeCommit, || {
        apply_reject(&receiver.client, entry, conversation)
    }));
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, pre);
    apply_reject(&receiver.client, entry, conversation)?;
    let post = snap(&receiver.client, entry, conversation)?;
    assert!(post.marker);
    assert!(post.ratchet);
    assert!(post.rejected > pre.rejected);
    assert_eq!(post.cursor, 0, "rejection W1 must not embed the receive cursor");
    assert_eq!(post.work, 1);
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, post);
    Ok(())
}

fn cut_a2i(receiver: &mut Fixture, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    let conversation = a2i_control_conversation_id("alice", "bob");
    stage_w0(&receiver.client, &receiver.id, entry)?;
    let pre = snap(&receiver.client, entry, &conversation)?;
    assert_eq!(pre.a2i, 0);
    assert_eq!(pre.cursor, 0);
    assert_fault(legacy_w1::run(Fault::BeforeCommit, || apply_a2i(&receiver.client, entry)));
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, &conversation)?, pre);
    apply_a2i(&receiver.client, entry)?;
    let post = snap(&receiver.client, entry, &conversation)?;
    assert!(post.a2i > 0, "A2I missing receipt/event");
    assert!(post.ratchet);
    assert_eq!(post.cursor, 0, "A2I W1 must not embed ACK/cursor");
    assert_eq!(post.work, 1);
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, &conversation)?, post);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_effect_marker_atomic() -> Result<(), SdkError> {
    Box::pin(hang(atomic())).await
}

async fn atomic() -> Result<(), SdkError> {
    let receiver = Fixture::new("bob", 21)?;
    let db = receiver.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(&receiver.id, INCARNATION)?;
    let target = receiver.id.clone();
    let gate = LegacyW1 {
        expected: ReceiveExpectation {
            target: &target,
            incarnation: INCARNATION,
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    };
    let refused = gate.effect(db, 1, None, || Ok(()));
    assert!(
        matches!(&refused, Err(SdkError::Storage(StorageError::Integrity(text))) if *text == INTEGRITY),
        "{refused:?}"
    );

    let sender = Fixture::new("alice", 31)?;
    let mut receiver = Fixture::new("bob", 41)?;
    let entry = bound(&sender, &mut receiver, "thread", "success-one", b"hello", 1)?;
    cut_success(&mut receiver, &entry, "thread")?;

    let sender = Fixture::new("alice", 51)?;
    let mut receiver = Fixture::new("bob", 61)?;
    let entry = bound(&sender, &mut receiver, "blocked", "reject-one", b"nope", 1)?;
    cut_reject(&mut receiver, &entry, "blocked")?;

    let sender = Fixture::new("alice", 71)?;
    let mut receiver = Fixture::new("bob", 81)?;
    let entry = a2i_entry(&sender, &mut receiver, 1)?;
    cut_a2i(&mut receiver, &entry)?;

    let sender = Fixture::new("alice", 91)?;
    let mut receiver = Fixture::new("bob", 101)?;
    let entry = bound(&sender, &mut receiver, "held-group", "hold-one", b"group", 1)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    let pre = snap(&receiver.client, &entry, "held-group")?;
    apply_hold(&receiver.client, &entry)?;
    let post = snap(&receiver.client, &entry, "held-group")?;
    assert!(post.held > 0, "group hold must remain held");
    assert!(!post.marker, "held group must not gain a terminal marker");
    assert_eq!(post.cursor, pre.cursor);
    reopen(&mut receiver.client, &receiver.id)?;
    let again = snap(&receiver.client, &entry, "held-group")?;
    assert!(again.held > 0);
    assert!(!again.marker);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_stage_redrive() -> Result<(), SdkError> {
    Box::pin(hang(redrive())).await
}

async fn redrive() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 111)?;
    let mut receiver = Fixture::new("bob", 121)?;
    let entry = bound(&sender, &mut receiver, "redrive", "redrive-success", b"once", 1)?;
    redrive_success(&mut receiver, &entry, "redrive")?;

    let sender = Fixture::new("alice", 131)?;
    let mut receiver = Fixture::new("bob", 141)?;
    let entry = bound(&sender, &mut receiver, "redrive-reject", "redrive-no", b"once", 1)?;
    receiver.client.block_friend_link("link")?;
    redrive_reject(&mut receiver, &entry, "redrive-reject")?;

    let sender = Fixture::new("alice", 151)?;
    let mut receiver = Fixture::new("bob", 161)?;
    let entry = a2i_entry(&sender, &mut receiver, 1)?;
    redrive_a2i(&mut receiver, &entry)?;
    Ok(())
}

fn redrive_success(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<(), SdkError> {
    stage_w0(&receiver.client, &receiver.id, entry)?;
    assert_fault(legacy_w1::run(Fault::BeforeCommit, || {
        apply_success(&receiver.client, entry, conversation)
    }));
    apply_success(&receiver.client, entry, conversation)?;
    let once = snap(&receiver.client, entry, conversation)?;
    assert!(once.marker);
    assert_eq!(once.work, 1);
    reopen(&mut receiver.client, &receiver.id)?;
    apply_success(&receiver.client, entry, conversation)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, once);
    Ok(())
}

fn redrive_reject(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<(), SdkError> {
    stage_w0(&receiver.client, &receiver.id, entry)?;
    assert_fault(legacy_w1::run(Fault::BeforeCommit, || {
        apply_reject(&receiver.client, entry, conversation)
    }));
    apply_reject(&receiver.client, entry, conversation)?;
    let once = snap(&receiver.client, entry, conversation)?;
    assert!(once.marker);
    reopen(&mut receiver.client, &receiver.id)?;
    apply_reject(&receiver.client, entry, conversation)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, once);
    Ok(())
}

fn redrive_a2i(receiver: &mut Fixture, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    let conversation = a2i_control_conversation_id("alice", "bob");
    stage_w0(&receiver.client, &receiver.id, entry)?;
    assert_fault(legacy_w1::run(Fault::BeforeCommit, || apply_a2i(&receiver.client, entry)));
    apply_a2i(&receiver.client, entry)?;
    let once = snap(&receiver.client, entry, &conversation)?;
    assert!(once.a2i > 0);
    reopen(&mut receiver.client, &receiver.id)?;
    apply_a2i(&receiver.client, entry)?;
    assert_eq!(snap(&receiver.client, entry, &conversation)?, once);
    Ok(())
}
