// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::too_many_lines, clippy::unwrap_used, clippy::panic)]
//! S6 half of `sender_refusal_policy_receipts_contacts`: typed gateway refusals on the
//! contact-control courier. The real `deliver` step runs with a real account writer step
//! function, a classified submit against a scripted gateway and a real account DB reopen.
use super::*;
use crate::bus::delivery_receipts::background::refusal_tests::{
    ACCOUNT, Case, START, reopen, script,
};
use crate::client::contact_requests::{Metadata, delivery_status};
use std::sync::{Arc, atomic::AtomicBool};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PEER: &str = "peer-root-literal";

fn stored(account: &LocalBusAccountState) -> Result<Intent, SdkError> {
    account
        .client
        .account_db()?
        .list_actor_states::<Intent>("contact-request/send/")?
        .pop()
        .ok_or_else(|| SdkError::LocalBus("intent missing".into()))
}

/// One outbound request with its delivery intent, due at `START`.
fn seeded(root: &std::path::Path) -> Result<LocalBusAccountState, SdkError> {
    let account =
        crate::bus::runtime_tests::account(root, ACCOUNT, None, Arc::new(AtomicBool::new(false)))?;
    let own = account.client.owned_device_identity()?.root_commitment().to_owned();
    let metadata =
        Metadata { nonce: "nonce".into(), issued_at: START, note: None, needs_reply: None };
    let db = account.client.account_db()?;
    db.persist_contact_request(&ramflux_storage::ContactRequestRecord {
        contact_identity_commitment: PEER.into(),
        direction: "outbound".into(),
        request_id: "request-1".into(),
        principal_id: "peer".into(),
        link_id: "link".into(),
        state: "pending".into(),
        request_json: metadata.bytes()?,
        expires_at: START + TTL,
        updated_at: START,
    })?;
    let intent = Intent {
        kind: Decision::Request,
        request_id: "request-1".into(),
        requester_root: own,
        target_root: PEER.into(),
        peer_root: PEER.into(),
        note: None,
        expires_at: START + TTL,
        issued_at: START,
        nonce: "nonce".into(),
        attempts: 0,
        next_at: START,
        delivered: std::collections::BTreeSet::new(),
        native_approval: None,
    };
    db.persist_actor_state(&key(&intent), &intent)?;
    Ok(account)
}

/// `deliver` with the seal step answered by the actor test double (no pair material exists
/// for the literal peer) and every other step applied by the real step functions.
async fn deliver_once(
    account: &mut LocalBusAccountState,
    recipient: &RecipientPlan,
) -> Result<Option<Plan>, SdkError> {
    let envelope = crate::dm::gateway_direct_message_envelope(
        &recipient.plan.config,
        &recipient.message,
        None,
    )?;
    let session = account.session_client().await?;
    account.apply_session_metadata(session);
    let context =
        account.connection.as_ref().ok_or(SdkError::GatewaySessionNotEstablished)?.test_context();
    let (writer, mut receive) = mpsc::channel(2);
    let request = SendMaterialRequest { root: None, prekey: None };
    let future = deliver(&context, &writer, recipient, request);
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return result,
            work = receive.recv() => match work {
                Some(AccountWork::Contacts(work)) => match *work {
                    ContactWork::Seal { reply, .. } => {
                        let _ = reply.send(Ok(Some(envelope.clone())));
                    }
                    work => apply(account, work),
                },
                _ => return Err(SdkError::GatewaySessionNotEstablished),
            }
        }
    }
}

async fn contact_row(case: Case) -> TestResult {
    let _clock = crate::time::FixedClock::set(START);
    let root = crate::bus::runtime_tests::root("contact-refusal-s6");
    let mut account = seeded(&root)?;
    let attempted = script(&mut account, Some(case.nack()));
    let plan = prepare(&account)?.ok_or("the due intent is selected")?;
    assert_eq!(plan.intent.attempts, 1);
    assert_eq!(plan.intent.next_at, START + 2);
    let message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "contact-1".into(),
        envelope_id: "contact-1".into(),
        source_principal_id: plan.config.principal_id.clone(),
        sender_id: plan.config.device_id.clone(),
        recipient_device_id: Some("peer-device".into()),
        recipient_principal_commitment: Some(PEER.into()),
        target_delivery_id: "peer-target".into(),
        encrypted_body: b"sealed".to_vec(),
        created_at: START,
        ttl: 600,
    };
    let recipient = RecipientPlan {
        plan,
        message,
        body: Zeroizing::new(Vec::new()),
        material_hash: String::new(),
    };
    let outcome = deliver_once(&mut account, &recipient).await;
    assert_eq!(attempted.lock().map_err(|_| "attempted")?.len(), 1, "one submit was written");

    let kept = stored(&account)?;
    match case {
        Case::Conflict => {
            // (a) the existing exhaustion branch: attempts = 8, the delivery ends, the
            // request reads `failed`, and nothing is marked delivered.
            assert!(matches!(outcome, Ok(None)));
            assert_eq!(kept.attempts, 8);
            assert!(kept.delivered.is_empty());
            assert_eq!(delivery_status(&account.client, PEER)?, "failed");
        }
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            // (b)-(d) the existing deferral: one attempt charged, the next one 2 s out
            // (attempt 1 backoff, above the 1000 ms floor), the request still queued.
            let expected = match case {
                Case::Capacity => "gateway session rejected: capacity_retry_after",
                Case::RetrySafe => "gateway session rejected: aborted_retry_safe",
                _ => "gateway session rejected: injected target failure",
            };
            assert_eq!(outcome.err().ok_or("a deferral is an error")?.to_string(), expected);
            assert_eq!(kept.attempts, 1);
            assert_eq!(kept.next_at, START + 2);
            assert!(kept.delivered.is_empty());
            assert_eq!(delivery_status(&account.client, PEER)?, "queued");
        }
    }

    // A real reopen: nothing is selected before the deadline, and a Conflict never again.
    reopen(&mut account)?;
    crate::time::FixedClock::advance_to(START + 1);
    assert!(prepare(&account)?.is_none());
    crate::time::FixedClock::advance_to(START + 2);
    let due = prepare(&account)?;
    match case {
        Case::Conflict => {
            assert!(due.is_none(), "a conflicted intent is never selected again");
            crate::time::FixedClock::advance_to(START + 700);
            assert!(prepare(&account)?.is_none());
            assert_eq!(stored(&account)?.attempts, 8);
        }
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            assert_eq!(due.ok_or("the deferral is due at the deadline")?.intent.attempts, 2);
        }
    }
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(crate) async fn cells() -> TestResult {
    for case in Case::ALL {
        contact_row(case).await?;
    }
    Ok(())
}
