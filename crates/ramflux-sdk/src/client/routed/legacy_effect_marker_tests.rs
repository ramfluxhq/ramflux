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
use super::selector_reopen::Case;
use super::*;
use crate::bus::push_receiver::apply::cover_held_in;
use crate::bus::sync_driver::source::w0::SourceW0;
use crate::client::a2i::queue_unbound_answers;
use crate::client::dm::LegacyReceive;
use crate::client::legacy_w1::{self, Fault, LegacyW1};
use crate::dm::SdkDmAttachmentEnvelope;
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

/// Watcher aborts the process after 120s so a hang fails this test. Completing work
/// cancels the watcher; a watcher panic is joined and resumed on the test thread.
fn hang<T>(f: impl FnOnce() -> T) -> T {
    let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
    let watcher = std::thread::spawn(move || {
        if matches!(
            cancelled.recv_timeout(Duration::from_secs(120)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            eprintln!("120-second hang guard expired");
            std::process::abort();
        }
    });
    let guard = HangGuard(Some(cancel));
    let value = f();
    drop(guard);
    match watcher.join() {
        Ok(()) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
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

#[allow(clippy::too_many_arguments)]
fn bound_to(
    sender: &Fixture,
    receiver: &mut Fixture,
    conversation: &str,
    id: &str,
    body: &[u8],
    seq: u64,
    delivery: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    review::trust(receiver, sender)?;
    review::trust(sender, receiver)?;
    receiver.client.establish_friend_link("link", &receiver.id, &sender.id)?;
    let mut msg = message(id, conversation);
    msg.source_principal_id = sender.id.clone();
    msg.sender_id = sender.id.clone();
    msg.recipient_device_id = Some(receiver.id.clone());
    msg.target_delivery_id = delivery.to_owned();
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
        target_delivery_id: delivery.to_owned(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &msg, None)?,
    })
}

fn a2i_entry(
    sender: &Fixture,
    receiver: &mut Fixture,
    seq: u64,
) -> Result<GatewayInboxEntry, SdkError> {
    let target = receiver.id.clone();
    a2i_sealed(sender, receiver, seq, &target, true, None)
}

fn a2i_sealed(
    sender: &Fixture,
    receiver: &mut Fixture,
    seq: u64,
    event_target: &str,
    persist_session: bool,
    envelope_id: Option<&str>,
) -> Result<GatewayInboxEntry, SdkError> {
    let delivery = receiver.id.clone();
    a2i_sealed_to(sender, receiver, seq, event_target, persist_session, envelope_id, &delivery)
}

#[allow(clippy::too_many_arguments)]
/// `delivery` is the entry's delivery id (ledger target). It is signed into the envelope and may
/// differ from the receiver's local device id `receiver.id`.
fn a2i_sealed_to(
    sender: &Fixture,
    receiver: &mut Fixture,
    seq: u64,
    event_target: &str,
    persist_session: bool,
    envelope_id: Option<&str>,
    delivery: &str,
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
        target_device_id: event_target.to_owned(),
        control_domain: "message".into(),
        action: "test".into(),
        subject_base64: String::new(),
        created_at: now_unix_timestamp(),
        acknowledged: false,
    };
    let mut msg = message(&format!("a2i:{seq}"), &conversation);
    if let Some(envelope_id) = envelope_id {
        msg.envelope_id = envelope_id.to_owned();
        msg.message_id = envelope_id.to_owned();
    }
    msg.source_principal_id = sender.id.clone();
    msg.sender_id = sender.id.clone();
    msg.recipient_device_id = Some(receiver.id.clone());
    msg.target_delivery_id = delivery.to_owned();
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
    if persist_session {
        let receiving =
            receiver.client.load_or_create_recv_dm_session(&conversation, header.as_ref())?;
        let prior = format!("a2i-prior-{seq}");
        receiver.client.send_direct_message(&conversation, &prior, &sender.id, b"prior")?;
        receiver.client.persist_dm_session(&conversation, &prior, "recv", &receiving)?;
    }
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: seq,
        target_delivery_id: delivery.to_owned(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &msg, None)?,
    })
}

fn apply_success(
    receiver: &RamfluxClient,
    local: &str,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<(), SdkError> {
    let db = receiver.account_db()?;
    let gate = RamfluxClient::w1_gate(db, &entry.target_delivery_id)?;
    receiver.apply_legacy_success_w1(entry, local, conversation, gate.expected, gate.generation)
}

fn apply_reject(
    receiver: &RamfluxClient,
    local: &str,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<(), SdkError> {
    let db = receiver.account_db()?;
    let gate = RamfluxClient::w1_gate(db, &entry.target_delivery_id)?;
    receiver.apply_legacy_reject_w1(entry, local, conversation, gate.expected, gate.generation)
}

fn apply_a2i(
    receiver: &RamfluxClient,
    local: &str,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    let db = receiver.account_db()?;
    let gate = RamfluxClient::w1_gate(db, &entry.target_delivery_id)?;
    receiver.apply_legacy_a2i_w1(entry, local, gate.expected, gate.generation)
}

fn apply_hold(receiver: &RamfluxClient, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    let db = receiver.account_db()?;
    let gate = RamfluxClient::w1_gate(db, &entry.target_delivery_id)?;
    receiver.apply_legacy_group_hold_w1(entry, gate.expected, gate.generation)
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
        apply_success(&receiver.client, &receiver.id, entry, conversation)
    }));
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, pre);
    apply_success(&receiver.client, &receiver.id, entry, conversation)?;
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
        apply_reject(&receiver.client, &receiver.id, entry, conversation)
    }));
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, pre);
    apply_reject(&receiver.client, &receiver.id, entry, conversation)?;
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
    assert_fault(legacy_w1::run(Fault::BeforeCommit, || {
        apply_a2i(&receiver.client, &receiver.id, entry)
    }));
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, entry, &conversation)?, pre);
    apply_a2i(&receiver.client, &receiver.id, entry)?;
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
    hang(atomic)
}

fn atomic() -> Result<(), SdkError> {
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

#[test]
fn legacy_w1_a2i_endpoint_mismatch() -> Result<(), SdkError> {
    hang(cut_a2i_endpoint_mismatch)
}

#[test]
fn legacy_w1_a2i_payload_reuse() -> Result<(), SdkError> {
    hang(cut_a2i_payload_reuse)
}

#[test]
fn legacy_w1_a2i_routing_hold() -> Result<(), SdkError> {
    hang(cut_a2i_routing_hold)
}

#[test]
fn legacy_w1_a2i_delivery_id_is_not_local_device() -> Result<(), SdkError> {
    hang(cut_a2i_delivery_is_not_device)
}

#[test]
fn legacy_w1_dm_delivery_id_is_not_local_device() -> Result<(), SdkError> {
    hang(cut_dm_delivery_is_not_device)
}

#[test]
fn legacy_w1_binding_appeared_redrives() -> Result<(), SdkError> {
    hang(cut_binding_appeared)
}

#[test]
fn legacy_w1_binding_flip_one_disposition() -> Result<(), SdkError> {
    hang(cut_binding_flip)
}

#[test]
fn legacy_w1_dm_erased_attachment_completes() -> Result<(), SdkError> {
    hang(cut_erased_dm_row)
}

#[test]
fn legacy_w1_effect_error_rollback() -> Result<(), SdkError> {
    hang(cut_effect_error_rollback)
}

#[test]
fn legacy_w1_generation_erasure_cursor_fences() -> Result<(), SdkError> {
    hang(cut_w1_fences)
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_stage_redrive() -> Result<(), SdkError> {
    hang(redrive)
}

fn redrive() -> Result<(), SdkError> {
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
        apply_success(&receiver.client, &receiver.id, entry, conversation)
    }));
    apply_success(&receiver.client, &receiver.id, entry, conversation)?;
    let once = snap(&receiver.client, entry, conversation)?;
    assert!(once.marker);
    assert_eq!(once.work, 1);
    reopen(&mut receiver.client, &receiver.id)?;
    apply_success(&receiver.client, &receiver.id, entry, conversation)?;
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
        apply_reject(&receiver.client, &receiver.id, entry, conversation)
    }));
    apply_reject(&receiver.client, &receiver.id, entry, conversation)?;
    let once = snap(&receiver.client, entry, conversation)?;
    assert!(once.marker);
    reopen(&mut receiver.client, &receiver.id)?;
    apply_reject(&receiver.client, &receiver.id, entry, conversation)?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, once);
    Ok(())
}

fn redrive_a2i(receiver: &mut Fixture, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    let conversation = a2i_control_conversation_id("alice", "bob");
    stage_w0(&receiver.client, &receiver.id, entry)?;
    assert_fault(legacy_w1::run(Fault::BeforeCommit, || {
        apply_a2i(&receiver.client, &receiver.id, entry)
    }));
    apply_a2i(&receiver.client, &receiver.id, entry)?;
    let once = snap(&receiver.client, entry, &conversation)?;
    assert!(once.a2i > 0);
    reopen(&mut receiver.client, &receiver.id)?;
    apply_a2i(&receiver.client, &receiver.id, entry)?;
    assert_eq!(snap(&receiver.client, entry, &conversation)?, once);
    Ok(())
}

fn assert_inbound(result: Result<(), SdkError>, text: &str) {
    match result {
        Err(SdkError::InboundRejected(got)) if got == text => {}
        other => panic!("expected InboundRejected({text:?}), got {other:?}"),
    }
}

fn stored_body(
    client: &RamfluxClient,
    conversation: &str,
    message: &str,
) -> Result<Vec<u8>, SdkError> {
    client
        .direct_messages(conversation)?
        .into_iter()
        .find(|row| row.message_id == message)
        .map(|row| row.encrypted_body)
        .ok_or_else(|| SdkError::LocalBus(format!("missing {message}")))
}

fn cut_a2i_endpoint_mismatch() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 201)?;
    let mut receiver = Fixture::new("bob", 211)?;
    let entry = a2i_sealed(&sender, &mut receiver, 1, "carol", true, None)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    assert_inbound(
        apply_a2i(&receiver.client, &receiver.id, &entry),
        "legacy A2I endpoint mismatch",
    );
    Ok(())
}

fn cut_a2i_payload_reuse() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 221)?;
    let mut receiver = Fixture::new("bob", 231)?;
    let entry = a2i_entry(&sender, &mut receiver, 1)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    apply_a2i(&receiver.client, &receiver.id, &entry)?;
    let local = receiver.id.clone();
    // Same envelope id, different payload. Bind its session to the same conversation (the recv
    // session is one row per conversation) so the routing check passes and the receipt check
    // rejects the reuse, matching the live order.
    let envelope_id = entry.envelope.envelope_id.clone();
    let reused =
        a2i_sealed_to(&sender, &mut receiver, 2, &local, false, Some(&envelope_id), &local)?;
    let wire: SdkDmEncryptedEnvelope = serde_json::from_slice(
        &ramflux_protocol::decode_base64url(&reused.envelope.encrypted_payload)
            .map_err(|error| SdkError::LocalBus(error.to_string()))?,
    )?;
    let header = wire.x3dh.ok_or_else(|| SdkError::LocalBus("reused A2I has no header".into()))?;
    let conversation = a2i_control_conversation_id("alice", "bob");
    let recv = receiver
        .client
        .create_recv_dm_session_with_aad(&header, dm_associated_data(&conversation))?;
    receiver.client.send_direct_message(&conversation, "a2i-reuse-prior", &sender.id, b"prior")?;
    receiver.client.persist_dm_session(&conversation, "a2i-reuse-prior", "recv", &recv)?;
    assert_inbound(
        apply_a2i(&receiver.client, &receiver.id, &reused),
        "legacy A2I envelope id reused",
    );
    Ok(())
}

fn cut_a2i_routing_hold() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 241)?;
    let mut receiver = Fixture::new("bob", 251)?;
    let target = receiver.id.clone();
    let entry = a2i_sealed(&sender, &mut receiver, 1, &target, false, None)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    let pre = snap(&receiver.client, &entry, "held-a2i")?;
    apply_a2i(&receiver.client, &receiver.id, &entry)?;
    let post = snap(&receiver.client, &entry, "held-a2i")?;
    assert!(post.held > pre.held, "unbound A2I must remain held");
    assert_eq!(post.a2i, 0, "held A2I must not persist a receipt");
    assert_eq!(post.cursor, 0);
    Ok(())
}

/// The ledger target is the delivery id; the receiver's local device id is `receiver.id`. The
/// legitimate A2I must bind to the local device, so it is applied exactly once (not held).
fn cut_a2i_delivery_is_not_device() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 245)?;
    let mut receiver = Fixture::new("bob", 247)?;
    let delivery = "delivery-bob";
    assert_ne!(delivery, receiver.id);
    let local = receiver.id.clone();
    let entry = a2i_sealed_to(&sender, &mut receiver, 1, &local, true, None, delivery)?;
    stage_w0(&receiver.client, delivery, &entry)?;
    let conversation = a2i_control_conversation_id("alice", "bob");
    let pre = snap(&receiver.client, &entry, &conversation)?;
    apply_a2i(&receiver.client, &receiver.id, &entry)?;
    let post = snap(&receiver.client, &entry, &conversation)?;
    assert!(post.a2i > pre.a2i, "bound A2I was not applied against the local device");
    assert_eq!(post.held, pre.held, "bound A2I must not be held");
    assert!(post.ratchet);
    assert_eq!(post.work, 1);
    apply_a2i(&receiver.client, &receiver.id, &entry)?;
    assert_eq!(snap(&receiver.client, &entry, &conversation)?, post, "A2I applied twice");
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, &entry, &conversation)?, post);
    Ok(())
}

fn cut_dm_delivery_is_not_device() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 248)?;
    let mut receiver = Fixture::new("bob", 249)?;
    let delivery = "delivery-bob";
    assert_ne!(delivery, receiver.id);
    let conversation = "dm-delivery";
    let entry = bound_to(&sender, &mut receiver, conversation, "dm-one", b"once", 1, delivery)?;
    stage_w0(&receiver.client, delivery, &entry)?;
    let pre = snap(&receiver.client, &entry, conversation)?;
    apply_success(&receiver.client, &receiver.id, &entry, conversation)?;
    let post = snap(&receiver.client, &entry, conversation)?;
    assert!(post.marker, "bound DM was not applied against the local device");
    assert_eq!(post.messages, pre.messages + 1, "exactly one DM effect");
    assert_eq!(post.held, pre.held, "bound DM must not be held");
    apply_success(&receiver.client, &receiver.id, &entry, conversation)?;
    assert_eq!(snap(&receiver.client, &entry, conversation)?, post, "DM applied twice");
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, &entry, conversation)?, post);
    Ok(())
}

fn cut_binding_appeared() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 250)?;
    let mut receiver = Fixture::new("bob", 252)?;
    let target = receiver.id.clone();
    let entry = a2i_sealed(&sender, &mut receiver, 1, &target, false, None)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    let pre = snap(&receiver.client, &entry, "held-a2i")?;
    let raced = legacy_w1::run(Fault::BindingAppeared, || {
        apply_a2i(&receiver.client, &receiver.id, &entry)
    });
    assert!(matches!(raced, Err(SdkError::LegacyBindingChanged)), "{raced:?}");
    let mid = snap(&receiver.client, &entry, "held-a2i")?;
    assert_eq!(mid, pre, "binding-appeared race must write nothing");
    apply_a2i(&receiver.client, &receiver.id, &entry)?;
    let post = snap(&receiver.client, &entry, "held-a2i")?;
    assert!(post.held > pre.held, "redrive without the hook must hold unbound A2I");
    assert_eq!(post.a2i, 0, "held A2I must not persist a receipt");
    Ok(())
}

fn cut_binding_flip() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 70)?;
    let mut receiver = Fixture::new("bob", 72)?;
    let target = receiver.id.clone();
    let entry = a2i_sealed(&sender, &mut receiver, 1, &target, false, None)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    let db = receiver.client.account_db()?;
    let gate = RamfluxClient::w1_gate(db, &entry.target_delivery_id)?;
    let mut held = None;
    let mut apply_error = None;
    db.receive_transaction(gate.expected, 1, |tx| {
        match receiver.client.apply_legacy_a2i_w1_in(tx, &entry, &receiver.id, gate.expected, 1) {
            Ok(is_held) => {
                if is_held {
                    cover_held_in(tx, entry.inbox_seq)?;
                }
                held = Some(is_held);
                Ok(())
            }
            Err(error) => {
                apply_error = Some(error);
                Err(StorageError::Integrity("binding flip apply failed"))
            }
        }
    })?;
    assert!(apply_error.is_none(), "unbound A2I must hold: {apply_error:?}");
    assert_eq!(held, Some(true), "in-tx unbound check holds");
    let held_snap = snap(&receiver.client, &entry, "held-a2i")?;
    assert!(held_snap.held > 0, "held cover matches the in-tx hold");
    assert_eq!(held_snap.a2i, 0, "held path must not also apply a receipt");

    let sender = Fixture::new("alice", 74)?;
    let mut receiver = Fixture::new("bob", 76)?;
    let target = receiver.id.clone();
    let entry = a2i_sealed(&sender, &mut receiver, 1, &target, false, None)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    let pre = snap(&receiver.client, &entry, "held-a2i")?;
    queue_unbound_answers([false]);
    let db = receiver.client.account_db()?;
    let gate = RamfluxClient::w1_gate(db, &entry.target_delivery_id)?;
    let mut apply_error = None;
    let mut flipped = None;
    let fenced = db.receive_transaction(gate.expected, 1, |tx| {
        match receiver.client.apply_legacy_a2i_w1_in(tx, &entry, &receiver.id, gate.expected, 1) {
            Ok(is_held) => {
                if is_held {
                    cover_held_in(tx, entry.inbox_seq)?;
                }
                flipped = Some(is_held);
                Ok(())
            }
            Err(error) => {
                apply_error = Some(error);
                Err(StorageError::Integrity("binding flip apply failed"))
            }
        }
    });
    let post = snap(&receiver.client, &entry, "held-a2i")?;
    match (fenced, flipped, apply_error) {
        (Ok(()), Some(true), None) => {
            assert!(post.held > pre.held, "held disposition covers");
            assert_eq!(post.a2i, pre.a2i, "held must not also apply a receipt");
        }
        (Ok(()), Some(false), None) => {
            assert_eq!(post.held, pre.held, "applied disposition must not issue held cover");
            assert!(post.a2i > pre.a2i, "applied A2I writes a receipt");
        }
        (Err(_), None, Some(_)) => {
            assert_eq!(post, pre, "failed inner apply rolls back");
        }
        other => panic!("mixed or unexpected flip outcome: {other:?} snap={post:?}"),
    }
    Ok(())
}

/// A DM whose attachment object is erased completes with one effect (`ObjectErased` is consumed
/// like the live path), instead of rolling back and redriving forever.
fn cut_erased_dm_row() -> Result<(), SdkError> {
    let mut case = Case::new()?;
    case.fence()?;
    review::trust(&case.b, &case.a)?;
    let conversation = "erased-thread";
    let mut send = ramflux_crypto::DmSession::initiator(
        [9; 32],
        dm_device_id_hash("alice"),
        dm_device_id_hash("bob"),
        [6; 32],
    )?;
    let recv = ramflux_crypto::DmSession::recipient(
        [9; 32],
        dm_device_id_hash("bob"),
        dm_device_id_hash("alice"),
        [6; 32],
    )?;
    case.b.client.send_direct_message(conversation, "erased-history", "alice", b"prior")?;
    case.b.client.persist_dm_session(conversation, "erased-history", "recv", &recv)?;
    let body = serde_json::to_vec(&SdkDmAttachmentEnvelope {
        schema: "ramflux.sdk.dm_attachment_envelope.v1".into(),
        version: 1,
        body_base64: ramflux_protocol::encode_base64url(b"erased-ref-text"),
        attachments: vec![case.refs[1].clone()],
    })?;
    let mut msg = message("erased-dm-one", conversation);
    msg.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        source_principal_commitment: None,
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".into(),
        version: 1,
        x3dh: None,
        ciphertext: send.encrypt(&body, dm_associated_data(conversation))?,
    })?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: case.b.id.clone(),
        envelope: gateway_direct_message_envelope(&case.a.config()?, &msg, None)?,
    };
    stage_w0(&case.b.client, &case.b.id, &entry)?;
    let pre = snap(&case.b.client, &entry, conversation)?;
    apply_success(&case.b.client, &case.b.id, &entry, conversation)?;
    let post = snap(&case.b.client, &entry, conversation)?;
    assert!(post.marker, "erased-attachment DM must reach its terminal marker");
    assert_eq!(post.messages, pre.messages + 1, "exactly one effect");
    assert_eq!(post.work, 1);
    assert_eq!(stored_body(&case.b.client, conversation, "erased-dm-one")?, b"erased-ref-text");
    reopen(&mut case.b.client, &case.b.id)?;
    assert_eq!(snap(&case.b.client, &entry, conversation)?, post);
    Ok(())
}

fn cut_effect_error_rollback() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 162)?;
    let mut receiver = Fixture::new("bob", 172)?;
    let entry = bound(&sender, &mut receiver, "effect-err", "effect-one", b"hello", 1)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    let pre = snap(&receiver.client, &entry, "effect-err")?;
    let (_, session, _) = receiver.client.decrypt_legacy_entry("effect-err", &entry)?;
    let db = receiver.client.account_db()?;
    let gate = RamfluxClient::w1_gate(db, &receiver.id)?;
    let failed: Result<(), SdkError> = gate.effect(db, entry.inbox_seq, None, || {
        receiver.client.persist_dm_session(
            "effect-err",
            &entry.envelope.envelope_id,
            "recv",
            &session,
        )?;
        Err(SdkError::LocalBus("legacy content failed".into()))
    });
    match &failed {
        Err(SdkError::LocalBus(text)) if text == "legacy content failed" => {}
        other => panic!("expected original LocalBus, got {other:?}"),
    }
    reopen(&mut receiver.client, &receiver.id)?;
    assert_eq!(snap(&receiver.client, &entry, "effect-err")?, pre);
    Ok(())
}

fn cut_w1_fences() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 182)?;
    let mut receiver = Fixture::new("bob", 192)?;
    let entry = bound(&sender, &mut receiver, "fence", "fence-one", b"hello", 1)?;
    stage_w0(&receiver.client, &receiver.id, &entry)?;
    let db = receiver.client.account_db()?;
    let target = receiver.id.clone();
    let erasure = db.privacy_erasure_generation()?;
    let expected = ReceiveExpectation {
        target: &target,
        incarnation: INCARNATION,
        cursor: 0,
        generation: 1,
        erasure_generation: erasure,
    };
    let generation =
        LegacyW1 { expected: ReceiveExpectation { generation: 9, ..expected }, generation: 1 };
    let generation_err = generation.effect(db, entry.inbox_seq, None, || Ok(()));
    assert!(
        matches!(generation_err, Err(SdkError::Storage(StorageError::AuthorizationRejected))),
        "{generation_err:?}"
    );
    let cursor = LegacyW1 { expected: ReceiveExpectation { cursor: 9, ..expected }, generation: 1 };
    let cur = cursor.effect(db, entry.inbox_seq, None, || Ok(()));
    assert!(matches!(cur, Err(SdkError::Storage(StorageError::AuthorizationRejected))), "{cur:?}");
    let erased = LegacyW1 {
        expected: ReceiveExpectation { erasure_generation: -1, ..expected },
        generation: 1,
    };
    let erase = erased.effect(db, entry.inbox_seq, None, || Ok(()));
    assert!(matches!(erase, Err(SdkError::ObjectErased)), "{erase:?}");
    Ok(())
}

fn attachment_wrapper() -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(&SdkDmAttachmentEnvelope {
        schema: "ramflux.sdk.dm_attachment_envelope.v1".into(),
        version: 1,
        body_base64: ramflux_protocol::encode_base64url(b"inner-text"),
        attachments: Vec::new(),
    })?)
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_w1_attachment_body_matches_live() -> Result<(), SdkError> {
    let wrapper = attachment_wrapper()?;
    let sender = Fixture::new("alice", 203)?;
    let mut w1_receiver = Fixture::new("bob", 213)?;
    let w1_entry = bound(&sender, &mut w1_receiver, "attach-w1", "attach-w1", &wrapper, 1)?;
    stage_w0(&w1_receiver.client, &w1_receiver.id, &w1_entry)?;
    apply_success(&w1_receiver.client, &w1_receiver.id, &w1_entry, "attach-w1")?;
    let w1_body = stored_body(&w1_receiver.client, "attach-w1", &w1_entry.envelope.envelope_id)?;
    assert_eq!(w1_body, b"inner-text", "W1 must store the decoded attachment body");

    let live_sender = Fixture::new("alice", 204)?;
    let mut live_receiver = Fixture::new("bob", 223)?;
    let live_entry =
        bound(&live_sender, &mut live_receiver, "attach-live", "attach-live", &wrapper, 1)?;
    let mut engine = GatewaySessionEngine::with_test_transport(
        live_receiver.config()?,
        Box::new(super::NoNetwork),
    );
    let pool = review::pool()?;
    live_receiver
        .client
        .receive_legacy_entry(
            &mut engine,
            &pool,
            live_entry.clone(),
            LegacyReceive {
                conversation_id: "attach-live",
                auto_fetch_attachments: false,
                relay_service_key_base64: None,
            },
        )
        .await?;
    let live_body =
        stored_body(&live_receiver.client, "attach-live", &live_entry.envelope.envelope_id)?;
    assert_eq!(live_body, w1_body);
    assert_eq!(live_body, b"inner-text");
    Ok(())
}
