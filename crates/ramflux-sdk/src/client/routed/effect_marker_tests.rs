// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `routed_effect_marker_atomic` and the first leg of `receive_stage_redrive`.
#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]
use super::super::native_contact_tests::carrier;
use super::super::receive::commit_fault;
use super::*;
use crate::bus::sync_driver::source::w0::SourceW0;
use crate::client::native_test_support::Fixture as Native;
use ramflux_storage::{ReceiveExpectation, ReceiveStage, ReceiveStageResult};
use std::time::Duration;

const FAULT: &str = "routed commit fault";
/// Standalone runs take about 7 s; the guard only has to catch hangs under the full parallel suite.
const HANG_GUARD: Duration = Duration::from_secs(120);

/// Value-level snapshot: every durable effect row (sender-key, slot, owner, watermark,
/// committed/seen markers, DM rows) plus the decoded direct messages and the receive ledger.
#[derive(Debug, PartialEq, Eq)]
struct Snap {
    seen: bool,
    rows: Vec<String>,
    messages: Vec<DirectMessageRecord>,
    work: i64,
    disposition: Option<String>,
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
            cancelled.recv_timeout(HANG_GUARD),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            // A panic here would only end this detached thread and let the test hang or pass.
            eprintln!("hang guard expired after {HANG_GUARD:?}; aborting the test binary");
            std::process::abort();
        }
    });
    let _guard = HangGuard(Some(cancel));
    future.await
}

fn assert_fault<T>(result: Result<T, SdkError>) {
    match result {
        Err(SdkError::LocalBus(text)) if text == FAULT => {}
        Err(error) => panic!("expected LocalBus({FAULT:?}), got {error}"),
        Ok(_) => panic!("expected LocalBus({FAULT:?}), got Ok"),
    }
}

fn reopen(client: &mut RamfluxClient, id: &str, secret: &[u8]) -> Result<(), SdkError> {
    let root = client.identity_root.clone();
    let branch = client.device_branch.clone();
    client.active_account_db = None;
    client.unlock_account(id, secret)?;
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

fn snap(
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
    conversation: &str,
) -> Result<Snap, SdkError> {
    let db = client.account_db()?;
    let (disposition, work) = db.receive_state_for_test(entry.inbox_seq)?;
    // The v3 replay migration marker commits in its own transaction before the receive ledger
    // (replay_migration.rs), is idempotent, and is not a receive effect, so it is excluded.
    let mut rows = db.durable_rows_for_test()?;
    rows.retain(|row| !row.contains("identity/replay-upgrade/"));
    Ok(Snap {
        seen: client.routed_seen_marker(entry)?.is_some(),
        rows,
        messages: client.direct_messages(conversation)?,
        work,
        disposition,
    })
}

fn stage_w0(
    client: &RamfluxClient,
    target: &str,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(target, "e")?;
    let json = serde_json::to_vec(entry)?;
    let gate = SourceW0 {
        expected: ReceiveExpectation {
            target,
            incarnation: "e",
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
                incarnation: "e",
                sequence: entry.inbox_seq,
                entry_json: &json,
                admission_key: "authenticated-key",
                retain_until: now_unix_timestamp() + 300,
                first_seen: 1,
            },
        )?,
        ReceiveStageResult::Staged
    );
    Ok(())
}

fn engine(receiver: &Fixture) -> Result<GatewaySessionEngine, SdkError> {
    Ok(GatewaySessionEngine::with_test_transport(receiver.config()?, Box::new(NoNetwork)))
}

fn pool() -> Result<ramflux_transport::RelayQuicPool, SdkError> {
    Ok(ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()
            .map_err(|error| invalid(&error.to_string()))?,
    ))
}

async fn apply(receiver: &mut Fixture, entry: &GatewayInboxEntry) -> Result<Delivery, SdkError> {
    let mut session = engine(receiver)?;
    let pool = pool()?;
    receiver.client.apply_routed_entry(&mut session, &pool, entry, false).await
}

fn friend(receiver: &mut Fixture, sender: &Fixture) -> Result<(), SdkError> {
    review::trust(receiver, sender)?;
    review::trust(sender, receiver)?;
    receiver.client.establish_friend_link(
        "link",
        sender.client.own_account_anchor()?.as_str(),
        receiver.client.own_account_anchor()?.as_str(),
    )?;
    Ok(())
}

pub(super) fn group_ready(
    sender: &Fixture,
    receiver: &mut Fixture,
    group: &str,
) -> Result<(), SdkError> {
    friend(receiver, sender)?;
    sender.create_shared_group(group, &format!("{group}-conversation"))?;
    let member =
        receiver.client.owned_group_actor(&receiver.config()?.target_delivery_id)?.identity;
    let state = sender.change_shared_group(
        group,
        ramflux_protocol::GroupStateChange::Add {
            member,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    receiver.client.accept_shared_group_state(&state, &receiver.config()?.target_delivery_id)?;
    Ok(())
}

pub(super) fn group_control_entry(
    sender: &Fixture,
    receiver: &Fixture,
    group: &str,
    conversation: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    let distribution = ramflux_protocol::parse_i_json(
        &sender.client.export_group_sender_key_distribution(group, &sender.id)?,
    )?;
    let epoch = sender
        .client
        .account_db()?
        .shared_group_state(group)?
        .ok_or_else(|| invalid("group state"))?
        .view()
        .epoch;
    let exact = sender.client.generated_group_key_inner(
        conversation,
        epoch,
        &distribution,
        &receiver.client.owned_device_identity()?,
    )?;
    generated_control_entry(sender, receiver, &exact, Route::group_control(group))
}

/// Kill before the named W1 commit, reopen equals pre-state; success then reopen equals post-state.
async fn cut(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
    conversation: &str,
    kind: commit_fault::Kind,
) -> Result<(), SdkError> {
    stage_w0(&receiver.client, &entry.target_delivery_id, entry)?;
    let pre = snap(&receiver.client, entry, conversation)?;
    assert!(!pre.seen);
    assert_eq!(pre.work, 1);
    commit_fault::fail_before(kind);
    assert_fault(apply(receiver, entry).await);
    reopen(&mut receiver.client, &receiver.id, b"native fixture data passphrase")?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, pre);
    apply(receiver, entry).await?;
    let post = snap(&receiver.client, entry, conversation)?;
    assert!(post.seen, "{kind:?} missing seen after commit");
    assert_eq!(post.work, 1);
    assert_eq!(post.disposition.as_deref(), Some("staged"));
    assert_ne!(post.rows, pre.rows, "{kind:?} wrote no durable effect");
    reopen(&mut receiver.client, &receiver.id, b"native fixture data passphrase")?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, post);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn routed_effect_marker_atomic() -> Result<(), SdkError> {
    Box::pin(hang(atomic())).await
}

async fn atomic() -> Result<(), SdkError> {
    let sender = Fixture::native_named("alice", 201).await?;
    let mut receiver = Fixture::native_named("bob", 211).await?;
    friend(&mut receiver, &sender)?;
    let sent = generated_delivery(&sender, &receiver, "first-committed", "private message body")?;
    cut(&mut receiver, &sent.entry, &sent.conversation, commit_fault::Kind::Content).await?;

    let sender = Fixture::native_named("alice", 221).await?;
    let mut receiver = Fixture::native_named("bob", 231).await?;
    friend(&mut receiver, &sender)?;
    let sent = generated_delivery(&sender, &receiver, "pair-committed", "pair body")?;
    cut(&mut receiver, &sent.entry, &sent.conversation, commit_fault::Kind::Pair).await?;

    let sender = Fixture::native_named("alice", 161).await?;
    let mut receiver = Fixture::native_named("bob", 171).await?;
    friend(&mut receiver, &sender)?;
    let entry = reset_entry(&sender, &receiver)?;
    let scope = sender
        .client
        .generated_direct_conversation_id(&receiver.client.owned_device_identity()?)?;
    cut(&mut receiver, &entry, &scope, commit_fault::Kind::Control).await?;

    let sender = Fixture::native_named("alice", 241).await?;
    let mut receiver = Fixture::native_named("bob", 251).await?;
    group_ready(&sender, &mut receiver, "private-group")?;
    let entry =
        group_control_entry(&sender, &receiver, "private-group", "private-group-conversation")?;
    cut(&mut receiver, &entry, "private-group-conversation", commit_fault::Kind::GroupControl)
        .await?;

    bootstrap(commit_fault::Kind::Bootstrap).await?;
    Ok(())
}

async fn bootstrap(kind: commit_fault::Kind) -> Result<(), SdkError> {
    let sender =
        Native::new("native-marker-sender").await.map_err(|error| invalid(&error.to_string()))?;
    let mut target =
        Native::new("native-marker-target").await.map_err(|error| invalid(&error.to_string()))?;
    sender
        .client
        .persist_identity_directory(&target.manifest)
        .map_err(|error| invalid(&error.to_string()))?;
    let bytes = crate::client::contact_requests::native_tests::approve_request(&sender, &target)
        .await
        .map_err(|error| invalid(&error.to_string()))?;
    let entry = carrier(&sender, &target, &bytes, "marker-native-contact")
        .map_err(|error| invalid(&error.to_string()))?;
    let (route, preview) = target
        .client
        .preview_native_contact_request(&entry, &sender.manifest, "primary")?
        .ok_or_else(|| invalid("preview"))?;
    target
        .client
        .prepare_native_contact_control(
            &target.config,
            &entry,
            &route,
            &preview,
            Some(&sender.manifest),
        )
        .await?;
    stage_w0(&target.client, &entry.target_delivery_id, &entry)?;
    let pre = snap(&target.client, &entry, "")?;
    assert!(!pre.seen);
    commit_fault::fail_before(kind);
    assert_fault(target.client.commit_contact_request_bootstrap(
        &entry,
        &sender.manifest,
        "primary",
    ));
    reopen(&mut target.client, "native-marker-target", b"native fixture data passphrase")?;
    assert_eq!(snap(&target.client, &entry, "")?, pre);
    target.client.commit_contact_request_bootstrap(&entry, &sender.manifest, "primary")?;
    let post = snap(&target.client, &entry, "")?;
    assert!(post.seen);
    assert_eq!(post.work, 1);
    assert_eq!(post.disposition.as_deref(), Some("staged"));
    assert_ne!(post.rows, pre.rows);
    let request = target
        .client
        .account_db()?
        .contact_request(&sender.manifest.principal_commitment, "inbound")?
        .ok_or_else(|| invalid("native request"))?;
    assert_eq!(request.state, "pending");
    reopen(&mut target.client, "native-marker-target", b"native fixture data passphrase")?;
    assert_eq!(snap(&target.client, &entry, "")?, post);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn receive_stage_redrive() -> Result<(), SdkError> {
    Box::pin(hang(redrive())).await
}

async fn redrive() -> Result<(), SdkError> {
    let sender = Fixture::native_named("alice", 71).await?;
    let mut receiver = Fixture::native_named("bob", 81).await?;
    friend(&mut receiver, &sender)?;
    let sent = generated_delivery(&sender, &receiver, "redrive-content", "once")?;
    redrive_kind(&mut receiver, &sent.entry, &sent.conversation, commit_fault::Kind::Content)
        .await?;

    let sender = Fixture::native_named("alice", 91).await?;
    let mut receiver = Fixture::native_named("bob", 101).await?;
    friend(&mut receiver, &sender)?;
    let sent = generated_delivery(&sender, &receiver, "redrive-pair", "once")?;
    redrive_kind(&mut receiver, &sent.entry, &sent.conversation, commit_fault::Kind::Pair).await?;

    let sender = Fixture::native_named("alice", 111).await?;
    let mut receiver = Fixture::native_named("bob", 121).await?;
    group_ready(&sender, &mut receiver, "redrive-group")?;
    let entry =
        group_control_entry(&sender, &receiver, "redrive-group", "redrive-group-conversation")?;
    redrive_kind(
        &mut receiver,
        &entry,
        "redrive-group-conversation",
        commit_fault::Kind::GroupControl,
    )
    .await?;

    bootstrap_redrive().await?;
    crate::client::application_outbox::projection_stage_redrive::projection_stage_redrive()?;
    crate::client::reply_outbox::reply_stage_redrive_tests::reply_stage_redrive().await?;
    let sender = Fixture::native_named("alice", 131).await?;
    let mut receiver = Fixture::native_named("bob", 141).await?;
    friend(&mut receiver, &sender)?;
    reply_pair_admit(&sender, &mut receiver)?;
    Ok(())
}

fn pair_admit_request<'a>(
    client: &'a RamfluxClient,
    sequence: u64,
    envelope: ramflux_protocol::Envelope,
    pair: Option<crate::client::reply_outbox::PairLive<'a>>,
) -> crate::client::reply_outbox::AdmitRequest<'a> {
    crate::client::reply_outbox::AdmitRequest {
        sequence,
        auth_key: "pair-live",
        envelope,
        kind: crate::client::reply_outbox::ReplyKind::Pair,
        response_key: None,
        message: None,
        client,
        pair,
        config: None,
        material: None,
    }
}

fn reply_pair_admit(sender: &Fixture, receiver: &mut Fixture) -> Result<(), SdkError> {
    let entry = reset_entry(sender, receiver)?;
    stage_w0(&receiver.client, &entry.target_delivery_id, &entry)?;
    let opened = receiver.client.open_routed(&entry, "bob")?;
    receiver.client.persist_pair(
        &opened.local_device,
        &opened.remote_device,
        &opened.bundle_hash,
        &opened.session,
    )?;
    receiver.client.account_db()?.persist_actor_state(
        &format!(
            "{}/reset-pending",
            crate::RamfluxClient::pair_key(&opened.local_device, &opened.remote_device)?
        ),
        &true,
    )?;
    let config = receiver.config()?;
    let body = opened.body.clone();
    let placeholder =
        crate::client::reply_outbox::reply_outbox_crash_tests::envelope("pair-live-env");
    {
        let db = receiver.client.account_db()?;
        let gate = crate::client::reply_outbox::ReplyOutbox {
            expected: ReceiveExpectation {
                target: &entry.target_delivery_id,
                incarnation: "e",
                cursor: 0,
                generation: 1,
                erasure_generation: db.privacy_erasure_generation()?,
            },
            generation: 1,
        };
        let live =
            crate::client::reply_outbox::PairLive { config: &config, opened: &opened, body: &body };
        match crate::client::reply_outbox::run(
            crate::client::reply_outbox::Fault::BeforeCommit,
            || {
                gate.admit(
                    db,
                    pair_admit_request(
                        &receiver.client,
                        entry.inbox_seq,
                        placeholder.clone(),
                        Some(live),
                    ),
                )
            },
        ) {
            Err(SdkError::Storage(ramflux_storage::StorageError::Integrity(
                "reply outbox before-commit",
            ))) => {}
            other => panic!("expected pair before-commit, got {other:?}"),
        }
        assert!(!db.actor_state_exists("gateway/reply-outbox/pair-live")?);
        let pair_snap = crate::client::reply_outbox::reply_outbox_crash_tests::pair_rows(db)?;
        let _clock = crate::time::FixedClock::set(crate::prelude::now_unix_timestamp());
        let expected = crate::client::routed::with_fixed_pair_control_id("fixed-pair", || {
            receiver.client.prepare_received_pair_reply(&config, &opened, &body)
        })?
        .ok_or_else(|| SdkError::LocalBus("pair expected envelope".into()))?;
        crate::client::reply_outbox::reply_outbox_crash_tests::restore_pair_rows(db, &pair_snap)?;
        let live =
            crate::client::reply_outbox::PairLive { config: &config, opened: &opened, body: &body };
        assert_eq!(
            crate::client::routed::with_fixed_pair_control_id("fixed-pair", || {
                gate.admit(
                    db,
                    pair_admit_request(
                        &receiver.client,
                        entry.inbox_seq,
                        placeholder.clone(),
                        Some(live),
                    ),
                )
            })?,
            crate::client::reply_outbox::Admit::Admitted
        );
        assert!(db.actor_state_exists("gateway/reply-outbox/pair-live")?);
        assert!(db.actor_state_exists("gateway/reply-transferred/pair-live")?);
        let stored: crate::client::reply_outbox::PreparedReply = db
            .load_actor_state("gateway/reply-outbox/pair-live")?
            .ok_or_else(|| SdkError::LocalBus("pair prepared envelope".into()))?;
        assert_eq!(stored.envelope, expected);
        assert_eq!(stored.kind, crate::client::reply_outbox::ReplyKind::Pair);
    }
    reopen(&mut receiver.client, &receiver.id, b"native fixture data passphrase")?;
    {
        let db = receiver.client.account_db()?;
        let gate = crate::client::reply_outbox::ReplyOutbox {
            expected: ReceiveExpectation {
                target: &entry.target_delivery_id,
                incarnation: "e",
                cursor: 0,
                generation: 1,
                erasure_generation: db.privacy_erasure_generation()?,
            },
            generation: 1,
        };
        let live =
            crate::client::reply_outbox::PairLive { config: &config, opened: &opened, body: &body };
        assert_eq!(
            gate.admit(
                db,
                pair_admit_request(
                    &receiver.client,
                    entry.inbox_seq,
                    placeholder.clone(),
                    Some(live)
                ),
            )?,
            crate::client::reply_outbox::Admit::Duplicate
        );
        assert_eq!(
            gate.admit(
                db,
                pair_admit_request(&receiver.client, entry.inbox_seq, placeholder.clone(), None)
            )?,
            crate::client::reply_outbox::Admit::Duplicate
        );
        crate::client::reply_outbox::acknowledge(db, "pair-live")?;
        assert!(!db.actor_state_exists("gateway/reply-outbox/pair-live")?);
        assert!(db.actor_state_exists("gateway/reply-transferred/pair-live")?);
        assert_eq!(
            gate.admit(
                db,
                pair_admit_request(&receiver.client, entry.inbox_seq, placeholder.clone(), None)
            )?,
            crate::client::reply_outbox::Admit::Duplicate
        );
        gate.settle_terminal(db, entry.inbox_seq, "pair-live")?;
        assert!(!db.actor_state_exists("gateway/reply-transferred/pair-live")?);
    }
    Ok(())
}

async fn redrive_kind(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
    conversation: &str,
    kind: commit_fault::Kind,
) -> Result<(), SdkError> {
    stage_w0(&receiver.client, &entry.target_delivery_id, entry)?;
    commit_fault::fail_before(kind);
    assert_fault(apply(receiver, entry).await);
    apply(receiver, entry).await?;
    let once = snap(&receiver.client, entry, conversation)?;
    assert!(once.seen);
    assert_eq!(once.work, 1);
    assert_eq!(once.disposition.as_deref(), Some("staged"));
    reopen(&mut receiver.client, &receiver.id, b"native fixture data passphrase")?;
    apply(receiver, entry).await?;
    let again = snap(&receiver.client, entry, conversation)?;
    assert_eq!(again, once);
    Ok(())
}

async fn bootstrap_redrive() -> Result<(), SdkError> {
    let sender =
        Native::new("native-redrive-sender").await.map_err(|error| invalid(&error.to_string()))?;
    let mut target =
        Native::new("native-redrive-target").await.map_err(|error| invalid(&error.to_string()))?;
    sender
        .client
        .persist_identity_directory(&target.manifest)
        .map_err(|error| invalid(&error.to_string()))?;
    let bytes = crate::client::contact_requests::native_tests::approve_request(&sender, &target)
        .await
        .map_err(|error| invalid(&error.to_string()))?;
    let entry = carrier(&sender, &target, &bytes, "redrive-native-contact")
        .map_err(|error| invalid(&error.to_string()))?;
    let (route, preview) = target
        .client
        .preview_native_contact_request(&entry, &sender.manifest, "primary")?
        .ok_or_else(|| invalid("preview"))?;
    target
        .client
        .prepare_native_contact_control(
            &target.config,
            &entry,
            &route,
            &preview,
            Some(&sender.manifest),
        )
        .await?;
    stage_w0(&target.client, &entry.target_delivery_id, &entry)?;
    commit_fault::fail_before(commit_fault::Kind::Bootstrap);
    assert_fault(target.client.commit_contact_request_bootstrap(
        &entry,
        &sender.manifest,
        "primary",
    ));
    target.client.commit_contact_request_bootstrap(&entry, &sender.manifest, "primary")?;
    let once = snap(&target.client, &entry, "")?;
    assert!(once.seen);
    assert_eq!(once.work, 1);
    reopen(&mut target.client, "native-redrive-target", b"native fixture data passphrase")?;
    target.client.commit_contact_request_bootstrap(&entry, &sender.manifest, "primary")?;
    assert_eq!(snap(&target.client, &entry, "")?, once);
    Ok(())
}

pub(super) fn generated_control_entry(
    sender: &Fixture,
    receiver: &Fixture,
    exact: &[u8],
    route: Route,
) -> Result<GatewayInboxEntry, SdkError> {
    let (identity, _) = RamfluxClient::decode_generated_inner(exact)?;
    let mut request = message("effect-control-wire", &identity.conversation_id);
    request.message_id = ramflux_protocol::encode_base64url(identity.id);
    request.envelope_id = format!("effect-control-{}", request.message_id);
    request.recipient_principal_commitment = Some(receiver.client.own_account_anchor()?);
    request.target_delivery_id = receiver.config()?.target_delivery_id;
    let (mut request, sealed) = seal_native_fixture(sender, receiver, request, exact, route)?;
    let envelope =
        crate::dm::gateway_generated_envelope_from_sealed(&sender.config()?, &mut request, sealed)?;
    Ok(GatewayInboxEntry {
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
        forwarded: false,
        inbox_seq: 1,
    })
}
fn reset_entry(sender: &Fixture, receiver: &Fixture) -> Result<GatewayInboxEntry, SdkError> {
    use ramflux_protocol::message as g;
    let scope = sender
        .client
        .generated_direct_conversation_id(&receiver.client.owned_device_identity()?)?;
    let identity = sender.client.allocate_generated_identity(
        &scope,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Control(g::Control {
                operation: 1,
                payload: Some(g::control::Payload::Reset(g::PairReset {
                    rejected_bootstrap_floor: 0,
                })),
            })),
        },
    )?;
    generated_control_entry(sender, receiver, &exact, Route::control())
}
