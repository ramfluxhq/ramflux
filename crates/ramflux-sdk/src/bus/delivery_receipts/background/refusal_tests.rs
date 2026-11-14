// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::too_many_lines, clippy::unwrap_used, clippy::panic)]
//! `sender_refusal_policy_receipts_contacts`: typed gateway refusals on the delivery-receipt
//! courier (S5) and the contact-control courier (S6), through the real account writer step
//! functions and a real account DB reopen. Every expectation is an exact literal.
use super::*;
use crate::bus::dispatch::surface_transport::fixture::RecordingGateway;
use std::sync::{Arc, Mutex};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Sent = Arc<Mutex<Vec<ramflux_protocol::Envelope>>>;

/// The frozen test clock for the whole row.
pub(crate) const START: i64 = 1_794_100_000;
/// The account id of the fixture; also the receipt key suffix (`status_id` is empty).
pub(crate) const ACCOUNT: &str = "alice";
const STATUS: &str = "delivery-receipt/status/cell";

#[derive(Clone, Copy)]
pub(crate) enum Case {
    Conflict,
    Capacity,
    RetrySafe,
    Uncertain,
}

impl Case {
    pub(crate) const ALL: [Self; 4] =
        [Self::Conflict, Self::Capacity, Self::RetrySafe, Self::Uncertain];

    /// The exact nack reason the scripted gateway sends.
    pub(crate) const fn nack(self) -> &'static str {
        match self {
            Self::Conflict => "idempotency_conflict",
            Self::Capacity => "capacity_retry_after",
            Self::RetrySafe => "aborted_retry_safe",
            Self::Uncertain => "injected target failure",
        }
    }
}

fn recording(nack: Option<&str>) -> (RecordingGateway, Sent) {
    let mut gateway = RecordingGateway::new(Arc::default());
    gateway.nack_reason = nack.map(str::to_owned);
    let attempted = gateway.attempted.clone();
    (gateway, attempted)
}

/// A real reopen: the account DB handle is dropped and unlocked again from disk.
pub(crate) fn reopen(account: &mut LocalBusAccountState) -> TestResult {
    let native = account.client.born_v3_account.is_some();
    account.client.active_account_db = None;
    account.client.unlock_account(
        ACCOUNT,
        if native { b"native fixture data passphrase" } else { b"actor-test-secret" },
    )?;
    if native {
        let custody =
            account.gateway_config.custody.as_ref().ok_or(SdkError::CustodyVaultUnavailable)?;
        account.client.initialize_born_v3_branch_for_fixture(
            &account.gateway_config.device_id,
            custody.vault.as_ref(),
        )?;
    }
    Ok(())
}

fn install(account: &mut LocalBusAccountState, gateway: RecordingGateway) {
    let config = account.gateway_config.clone();
    account.install_test_session(crate::GatewaySessionEngine::with_test_transport(
        config,
        Box::new(gateway),
    ));
}

/// One production pass (prepare, seal, classified submit, complete) with a real account writer.
async fn drive(account: &mut LocalBusAccountState) -> Result<bool, SdkError> {
    let session = account.session_client().await?;
    account.apply_session_metadata(session);
    let context =
        account.connection.as_ref().ok_or(SdkError::GatewaySessionNotEstablished)?.test_context();
    let (writer, mut receive) = mpsc::channel(2);
    let future = pass(&context, &writer);
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return result,
            work = receive.recv() => match work {
                Some(AccountWork::Receipts(work)) => apply(account, *work),
                _ => return Err(SdkError::GatewaySessionNotEstablished),
            }
        }
    }
}

fn journal_failures(
    client: &crate::RamfluxClient,
    reason: Option<&str>,
) -> Result<usize, SdkError> {
    Ok(client
        .account_db()?
        .journal_after(0, 128)?
        .into_iter()
        .filter(|event| {
            event.topic == "message.delivery_receipt.failed"
                && event.body.get("reason").and_then(|r| r.as_str()) == reason
        })
        .count())
}

/// One retained native receipt with a qualified peer target; admission is covered by integration tests.
pub(super) async fn seeded(
    root: &ramflux_test_support::TestPath,
) -> TestResult<(LocalBusAccountState, ramflux_protocol::Envelope)> {
    use crate::client::native_test_support::Fixture;
    use ramflux_protocol::message as g;
    let source =
        Box::pin(Fixture::with_principal_at(root.child(ACCOUNT), ACCOUNT, "device-alice", ACCOUNT))
            .await?;
    let peer = Box::pin(Fixture::new("receipt-peer")).await?;
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
    let own = source.client.owned_device_identity()?;
    let remote = peer.client.owned_device_identity()?;
    let conversation = g::dm_scope::derive(own.root_commitment(), remote.root_commitment())?;
    source.client.account_db()?.persist_client_record("conversation", &conversation,
        &serde_json::json!({"kind":"direct","group_id":null,"participants":[ACCOUNT,"receipt-peer"],"participant_roots":[own.root_commitment(),remote.root_commitment()]}))?;
    let author = g::QualifiedDevice {
        account_anchor: remote.root_commitment().into(),
        device_id: remote.device_id().into(),
        device_epoch: 1,
    };
    let identity = g::EventIdentity {
        id: g::identity::derive(&author, &conversation, 1)?.to_vec(),
        conversation_id: conversation.clone(),
        author: Some(author),
        device_sequence: 1,
        hlc: 1000,
        ..Default::default()
    };
    let target = ramflux_protocol::encode_base64url(&identity.id);
    source.client.account_db()?.persist_message_actor_state(
        &target,
        &format!("routed/generated-identity/{target}"),
        &identity,
    )?;
    let account = source.into_bus();
    let message = GatewayDirectMessage {
        conversation_id: conversation.clone(),
        message_id: "receipt".into(),
        envelope_id: "retained-receipt".into(),
        source_principal_id: ACCOUNT.into(),
        sender_id: own.device_id().into(),
        recipient_device_id: Some(remote.device_id().into()),
        recipient_principal_commitment: Some(remote.root_commitment().into()),
        target_delivery_id: remote.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: crate::offline_retention::RECEIPT_TTL_SECS,
    };
    let packet = retained_receipt_fixture(&account, &message)?;
    let work = Work {
        status_id: String::new(),
        conversation,
        message: target,
        wire_message: None,
        receiver: own.storage_key().into(),
        sender: remote.storage_key().into(),
        root: Some(remote.root_commitment().into()),
        at: now_unix_timestamp(),
        attempts: 0,
        next_at: 0,
        packet: Some(packet.clone()),
    };
    account.client.account_db()?.persist_actor_state(&format!("{PREFIX}cell"), &work)?;
    Ok((account, packet))
}

/// S5: one due receipt, one scripted nack.
async fn receipt_row(case: Case) -> TestResult {
    let root = crate::bus::runtime_tests::root("receipt-refusal-s5");
    let (mut account, packet) = Box::pin(seeded(&root)).await?;
    let start = now_unix_timestamp();
    let _clock = crate::time::FixedClock::set(start);
    let target = account
        .client
        .account_db()?
        .load_actor_state::<Work>(&format!("{PREFIX}cell"))?
        .ok_or("receipt work")?
        .message;
    let key = format!("{PREFIX}cell");
    let (gateway, attempted) = recording(Some(case.nack()));
    install(&mut account, gateway);
    let first = drive(&mut account).await;
    assert_eq!(
        attempted.lock().map_err(|_| "attempted")?.len(),
        1,
        "one submit was written: {first:?}"
    );
    assert_eq!(attempted.lock().map_err(|_| "attempted")?[0], packet);

    let db = account.client.account_db()?;
    match case {
        Case::Conflict => {
            // (a) the existing exhaustion terminal: the work row is gone, the status is
            // `failed` (never `sent`), the journal names the reason, nothing is pending.
            assert!(matches!(first, Ok(true)));
            assert!(!db.actor_state_exists(&key)?);
            let status = db.load_actor_state::<serde_json::Value>(STATUS)?.ok_or("status")?;
            assert_eq!(status["state"], "failed");
            assert_eq!(status["attempts"], 1);
            assert_eq!(status["retry_work"]["message"], target);
            assert_eq!(journal_failures(&account.client, Some("submit_conflict"))?, 1);
            assert_eq!(journal_failures(&account.client, None)?, 0);
        }
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            // (b)-(d) the existing deferral: the row stays with its ciphertext, one attempt
            // charged, the next one 2 s out (attempt 1 backoff, above the 1000 ms floor).
            let text = first.err().ok_or("a deferral is an error")?.to_string();
            let expected = match case {
                Case::Capacity => "gateway session rejected: capacity_retry_after",
                Case::RetrySafe => "gateway session rejected: aborted_retry_safe",
                _ => "gateway session rejected: injected target failure",
            };
            assert_eq!(text, expected);
            let kept = db.load_actor_state::<Work>(&key)?.ok_or("kept row")?;
            assert_eq!(kept.attempts, 1);
            assert_eq!(kept.next_at, start + 2);
            assert_eq!(kept.packet.as_ref(), Some(&packet));
            assert!(!db.actor_state_exists(STATUS)?);
            assert_eq!(journal_failures(&account.client, Some("submit_conflict"))?, 0);
        }
    }

    // Reopen from disk, then a gateway that accepts everything: no submit before the
    // deadline, and a Conflict is never resent.
    reopen(&mut account)?;
    let (gateway, resent) = recording(None);
    install(&mut account, gateway);
    crate::time::FixedClock::advance_to(start + 1);
    assert!(!drive(&mut account).await?);
    assert_eq!(resent.lock().map_err(|_| "resent")?.len(), 0, "no resend before the deadline");
    crate::time::FixedClock::advance_to(start + 2);
    let due = drive(&mut account).await?;
    let resends = resent.lock().map_err(|_| "resent")?.clone();
    let db = account.client.account_db()?;
    match case {
        Case::Conflict => {
            assert!(!due);
            assert!(resends.is_empty(), "a conflict is never resent");
            crate::time::FixedClock::advance_to(start + 700);
            assert!(!drive(&mut account).await?);
            assert_eq!(resent.lock().map_err(|_| "resent")?.len(), 0);
            let status =
                account.client.account_db()?.load_actor_state::<serde_json::Value>(STATUS)?;
            assert_eq!(status.ok_or("status")?["state"], "failed");
        }
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            assert!(due);
            assert_eq!(resends, vec![packet], "exactly one byte-identical resend at the deadline");
            let status = db.load_actor_state::<serde_json::Value>(STATUS)?.ok_or("status")?;
            assert_eq!(status["state"], "sent");
        }
    }
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn sender_refusal_policy_receipts_contacts() -> TestResult {
    for case in Case::ALL {
        receipt_row(case).await?;
    }
    crate::client::contact_requests::refusal_cells().await
}

/// Installs a scripted test session on `account`; returns every envelope the gateway received.
pub(crate) fn script(account: &mut LocalBusAccountState, nack: Option<&str>) -> Sent {
    let (gateway, attempted) = recording(nack);
    install(account, gateway);
    attempted
}
