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
    receiver.client.establish_friend_link(
        "link",
        sender.client.owned_device_identity()?.root_commitment(),
        receiver.client.owned_device_identity()?.root_commitment(),
    )?;
    Ok(())
}

fn group_ready(sender: &Fixture, receiver: &mut Fixture, group: &str) -> Result<(), SdkError> {
    for client in [&sender.client, &receiver.client] {
        fixture_group(client, group, sender)?;
        fixture_member(client, group, receiver)?;
        let key = ramflux_protocol::encode_base64url(
            sender
                .client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .verifying_key()
                .to_bytes(),
        );
        client.account_db()?.persist_group_member_device_key(
            group,
            &crate::client::identity_authority::test_support::group_device(client, group, "alice")?,
            &key,
        )?;
    }
    Ok(())
}

fn group_control_entry(
    sender: &Fixture,
    receiver: &Fixture,
    group: &str,
    conversation: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    let distribution = sender.client.export_group_sender_key_distribution(group, "alice")?;
    let wrapper = SdkGroupSenderKeyDistributionEnvelope {
        schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".to_owned(),
        version: 1,
        membership_event_base64: None,
        actor_manifest_url: None,
        distribution_base64: ramflux_protocol::encode_base64url(distribution),
    };
    seal_group(
        sender,
        receiver,
        message("group-control", conversation),
        &serde_json::to_vec(&wrapper)?,
    )
}

/// Kill before the named W1 commit, reopen equals pre-state; success then reopen equals post-state.
async fn cut(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
    conversation: &str,
    kind: commit_fault::Kind,
) -> Result<(), SdkError> {
    stage_w0(&receiver.client, &receiver.id, entry)?;
    let pre = snap(&receiver.client, entry, conversation)?;
    assert!(!pre.seen);
    assert_eq!(pre.work, 1);
    commit_fault::fail_before(kind);
    assert_fault(apply(receiver, entry).await);
    reopen(&mut receiver.client, &receiver.id, b"routed-test")?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, pre);
    apply(receiver, entry).await?;
    let post = snap(&receiver.client, entry, conversation)?;
    assert!(post.seen, "{kind:?} missing seen after commit");
    assert_eq!(post.work, 1);
    assert_eq!(post.disposition.as_deref(), Some("staged"));
    assert_ne!(post.rows, pre.rows, "{kind:?} wrote no durable effect");
    reopen(&mut receiver.client, &receiver.id, b"routed-test")?;
    assert_eq!(snap(&receiver.client, entry, conversation)?, post);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn routed_effect_marker_atomic() -> Result<(), SdkError> {
    Box::pin(hang(atomic())).await
}

async fn atomic() -> Result<(), SdkError> {
    let sender = Fixture::new("alice", 201)?;
    let mut receiver = Fixture::new("bob", 211)?;
    friend(&mut receiver, &sender)?;
    let entry = seal(
        &sender,
        &receiver,
        message("first-committed", "unseen-conversation"),
        b"private message body",
    )?;
    cut(&mut receiver, &entry, "unseen-conversation", commit_fault::Kind::Content).await?;

    let sender = Fixture::new("alice", 221)?;
    let mut receiver = Fixture::new("bob", 231)?;
    friend(&mut receiver, &sender)?;
    let entry =
        seal(&sender, &receiver, message("pair-committed", "pair-conversation"), b"pair body")?;
    cut(&mut receiver, &entry, "pair-conversation", commit_fault::Kind::Pair).await?;

    let sender = Fixture::new("alice", 161)?;
    let mut receiver = Fixture::new("bob", 171)?;
    friend(&mut receiver, &sender)?;
    let entry = seal_as(
        &sender,
        &receiver,
        message("control-reset", "control-conversation"),
        br#"{"type":"pair.session.reset.v1"}"#,
        Route::control(),
    )?;
    cut(&mut receiver, &entry, "control-conversation", commit_fault::Kind::Control).await?;

    let sender = Fixture::new("alice", 241)?;
    let mut receiver = Fixture::new("bob", 251)?;
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
    let sender = Fixture::new("alice", 71)?;
    let mut receiver = Fixture::new("bob", 81)?;
    friend(&mut receiver, &sender)?;
    let entry =
        seal(&sender, &receiver, message("redrive-content", "redrive-conversation"), b"once")?;
    redrive_kind(&mut receiver, &entry, "redrive-conversation", commit_fault::Kind::Content)
        .await?;

    let sender = Fixture::new("alice", 91)?;
    let mut receiver = Fixture::new("bob", 101)?;
    friend(&mut receiver, &sender)?;
    let entry = seal(&sender, &receiver, message("redrive-pair", "redrive-pair"), b"once")?;
    redrive_kind(&mut receiver, &entry, "redrive-pair", commit_fault::Kind::Pair).await?;

    let sender = Fixture::new("alice", 111)?;
    let mut receiver = Fixture::new("bob", 121)?;
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
    Ok(())
}

async fn redrive_kind(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
    conversation: &str,
    kind: commit_fault::Kind,
) -> Result<(), SdkError> {
    stage_w0(&receiver.client, &receiver.id, entry)?;
    commit_fault::fail_before(kind);
    assert_fault(apply(receiver, entry).await);
    apply(receiver, entry).await?;
    let once = snap(&receiver.client, entry, conversation)?;
    assert!(once.seen);
    assert_eq!(once.work, 1);
    assert_eq!(once.disposition.as_deref(), Some("staged"));
    reopen(&mut receiver.client, &receiver.id, b"routed-test")?;
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
