// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::too_many_lines, clippy::unwrap_used, clippy::panic)]
//! `sender_refusal_policy_reset`: typed gateway refusals of a pair reset submit (S7), at the
//! shared sender (`send_pair_control`) and at the pair-reset courier, through a real account DB
//! reopen and a frozen clock. Every expectation is an exact literal.
use super::r5::settle;
use super::review::pool;
use super::session_record::{Wire, gap};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The frozen test clock for the whole row.
const START: i64 = 1_794_100_000;

#[derive(Clone, Copy)]
enum Case {
    Conflict,
    Capacity,
    RetrySafe,
    Uncertain,
}

impl Case {
    const ALL: [Self; 4] = [Self::Conflict, Self::Capacity, Self::RetrySafe, Self::Uncertain];

    const fn nack(self) -> &'static str {
        match self {
            Self::Conflict => "idempotency_conflict",
            Self::Capacity => "capacity_retry_after",
            Self::RetrySafe => "aborted_retry_safe",
            Self::Uncertain => "injected target failure",
        }
    }

    const fn text(self) -> &'static str {
        match self {
            Self::Conflict => "gateway session rejected: idempotency_conflict",
            Self::Capacity => "gateway session rejected: capacity_retry_after",
            Self::RetrySafe => "gateway session rejected: aborted_retry_safe",
            Self::Uncertain => "gateway session rejected: injected target failure",
        }
    }
}

fn reopen(client: &mut RamfluxClient) -> TestResult {
    client.active_account_db = None;
    client.unlock_account("bob", b"routed-test")?;
    Ok(())
}

fn journal(client: &RamfluxClient, state: &str) -> Result<usize, SdkError> {
    Ok(client
        .account_db()?
        .journal_after(0, 128)?
        .into_iter()
        .filter(|event| event.topic == "session.reset" && event.body["state"] == state)
        .count())
}

/// The bodies of every `pair-reset-refused` journal record.
fn refusals(client: &RamfluxClient) -> Result<Vec<serde_json::Value>, SdkError> {
    Ok(client
        .account_db()?
        .journal_after(0, 128)?
        .into_iter()
        .filter(|event| event.topic == "session.reset" && event.body["state"] == "refused")
        .map(|event| event.body)
        .collect())
}

fn work(client: &RamfluxClient) -> Result<Option<serde_json::Value>, SdkError> {
    let local = client.local_device_identity("bob")?;
    let remote = client.device_identity(&fixture_peer_reference(client, "alice")?)?;
    let key = RamfluxClient::reset_work_key(&local, &remote)?;
    Ok(client.account_db()?.load_actor_state::<serde_json::Value>(&key)?)
}

fn manual(client: &RamfluxClient) -> Result<Option<serde_json::Value>, SdkError> {
    let local = client.local_device_identity("bob")?;
    let remote = client.device_identity(&fixture_peer_reference(client, "alice")?)?;
    Ok(client.account_db()?.load_actor_state::<serde_json::Value>(&format!(
        "{}/manual",
        RamfluxClient::pair_key(&local, &remote)?
    ))?)
}

/// A settled pair whose receive gap started a reset at `START` (accepted on the wire).
async fn pending() -> Result<(Fixture, Fixture), Box<dyn std::error::Error>> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "refusal-gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale, false).await.is_err());
    assert_eq!(sent.lock().map_err(|_| "sent")?.len(), 1, "the first reset was submitted");
    let first = work(&bob.client)?.ok_or("work")?;
    assert_eq!(first["attempts"], 1);
    assert_eq!(first["first_at"], START);
    assert_eq!(first["next_at"], START + 60);
    Ok((alice, bob))
}

/// What a refusal leaves behind (identical for both sites).
fn assert_state(case: Case, client: &RamfluxClient) -> TestResult {
    match case {
        Case::Conflict => {
            // (a) the lifetime-expiry terminal: work gone, manual recovery marked with its exact
            // record, the pair-scoped refusal journalled in the `pair-reset-refused` form, and
            // the retirement checkpoint already run (no pending retired-secret marker).
            assert!(work(client)?.is_none());
            let local = client.local_device_identity("bob")?;
            let remote = client.device_identity(&fixture_peer_reference(client, "alice")?)?;
            assert_eq!(
                manual(client)?.ok_or("manual marker")?,
                serde_json::json!({
                    "local_device_id": local.storage_key(),
                    "device_id": remote.storage_key(),
                    "state": "needs_manual_recovery",
                    "at": START + 61,
                })
            );
            assert_eq!(
                refusals(client)?,
                vec![serde_json::json!({
                    "device_id": remote.storage_key(),
                    "state": "refused",
                    "reason": "submit_conflict",
                })]
            );
            assert_eq!(journal(client, "needs_manual_recovery")?, 1);
            assert!(
                client.account_db()?.load_actor_state::<bool>("secrets/retired")?.is_none(),
                "the retirement checkpoint ran before close"
            );
        }
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            // (b)-(d) the existing schedule: second attempt, next one 120 s out (above the
            // 1000 ms floor), no terminal state.
            let kept = work(client)?.ok_or("kept work")?;
            assert_eq!(kept["attempts"], 2);
            assert_eq!(kept["first_at"], START);
            assert_eq!(kept["next_at"], START + 181);
            assert!(manual(client)?.is_none());
            assert_eq!(journal(client, "refused")?, 0);
        }
    }
    Ok(())
}

fn assert_resend(case: Case, early: usize, due: usize) {
    assert_eq!(early, 0, "nothing is resent before the deadline");
    match case {
        Case::Conflict => assert_eq!(due, 0, "a conflicted reset is never resent"),
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            assert_eq!(due, 1, "exactly one resend at the deadline");
        }
    }
}

fn submitted(sent: &super::session_record::Sent) -> Result<usize, SdkError> {
    Ok(sent.lock().map_err(|_| invalid("sent"))?.len())
}

/// The shared sender `send_pair_control` (via `send_pair_reset`).
async fn sender_row(case: Case) -> TestResult {
    let _clock = crate::time::FixedClock::set(START);
    let (alice, mut bob) = Box::pin(pending()).await?;
    crate::time::FixedClock::advance_to(START + 61);
    let local = bob.client.local_device_identity("bob")?;
    let remote = bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?;
    assert!(bob.client.begin_pair_recovery(&local, &remote, START + 61)?);
    let (mut engine, attempted) = Wire::engine_nacking(&bob, &alice, case.nack())?;
    let error = bob.client.send_pair_reset(&mut engine, &remote).await.err().ok_or("refused")?;
    assert_eq!(error.to_string(), case.text());
    assert_eq!(submitted(&attempted)?, 1, "one refused submit was written");
    assert_state(case, &bob.client)?;

    reopen(&mut bob.client)?;
    assert_state(case, &bob.client)?;
    let (mut accept, resent) = Wire::engine(&bob, &alice)?;
    crate::time::FixedClock::advance_to(START + 100);
    bob.client.retry_pair_resets(&mut accept, START + 100).await?;
    let early = submitted(&resent)?;
    crate::time::FixedClock::advance_to(START + 181);
    bob.client.retry_pair_resets(&mut accept, START + 181).await?;
    assert_resend(case, early, submitted(&resent)?);
    Ok(())
}

/// The pair-reset courier (`couriers/reset.rs`), driven with a real account writer.
async fn courier_row(case: Case) -> TestResult {
    let _clock = crate::time::FixedClock::set(START);
    let (alice, mut bob) = Box::pin(pending()).await?;
    let (refusing, attempted) = Wire::engine_nacking(&bob, &alice, case.nack())?;
    let (accepting, resent) = Wire::engine(&bob, &alice)?;
    let root = bob.client.surface_local_root_commitment()?;
    let mut account =
        crate::prelude::LocalBusAccountState::new(std::mem::take(&mut bob.client), refusing, root);
    crate::time::FixedClock::advance_to(START + 61);
    let result =
        crate::bus::couriers::test_pass::drive(&mut account, crate::bus::couriers::reset::pass)
            .await;
    assert_eq!(result.err().ok_or("refused")?.to_string(), case.text());
    assert_eq!(submitted(&attempted)?, 1, "one refused submit was written");
    assert_state(case, &account.client)?;

    reopen(&mut account.client)?;
    assert_state(case, &account.client)?;
    account.install_test_session(accepting);
    crate::time::FixedClock::advance_to(START + 100);
    assert!(
        !crate::bus::couriers::test_pass::drive(&mut account, crate::bus::couriers::reset::pass)
            .await?
    );
    let early = submitted(&resent)?;
    crate::time::FixedClock::advance_to(START + 181);
    let due =
        crate::bus::couriers::test_pass::drive(&mut account, crate::bus::couriers::reset::pass)
            .await?;
    assert_eq!(due, !matches!(case, Case::Conflict));
    assert_resend(case, early, submitted(&resent)?);
    drop((alice, account));
    Ok(())
}

/// A Conflict that arrives after a confirmed receive cleared the reset work it belongs to is
/// stale: the pair and its secrets stay intact. Without the receive, the terminal applies.
async fn late_conflict_row(confirmed: bool) -> TestResult {
    let _clock = crate::time::FixedClock::set(START);
    let (alice, mut bob) = Box::pin(pending()).await?;
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let (refusing, attempted) =
        Wire::engine_held(&bob, &alice, "idempotency_conflict", entered.clone(), release.clone())?;
    let root = bob.client.surface_local_root_commitment()?;
    let mut account =
        crate::prelude::LocalBusAccountState::new(std::mem::take(&mut bob.client), refusing, root);
    crate::time::FixedClock::advance_to(START + 61);
    let local = account.client.local_device_identity("bob")?;
    let remote =
        account.client.device_identity(&fixture_peer_reference(&account.client, "alice")?)?;
    let before = account.client.active_pair(&local, &remote)?.ok_or("pair")?.0.session_id;
    let session = account.session_client().await?;
    account.apply_session_metadata(session);
    let context = account.connection.as_ref().ok_or("connection")?.test_context();
    let generation = context.generation;
    let (sender, mut receive) = tokio::sync::mpsc::channel(2);
    let future = crate::bus::couriers::reset::pass(
        context,
        crate::bus::couriers::writer::Writer::new(sender, generation),
    );
    tokio::pin!(future);
    let mut released = false;
    let result = loop {
        tokio::select! {
            result = &mut future => break result,
            work = receive.recv() => match work {
                Some(crate::bus::connection_manager::AccountWork::Courier(work))
                    if work.generation == generation => work.apply(&mut account),
                _ => return Err("unexpected account work".into()),
            },
            () = entered.notified(), if !released => {
                // The reset is submitted and held at the gateway.
                assert_eq!(submitted(&attempted)?, 1);
                if confirmed {
                    // A confirmed receive meanwhile: the real confirmation clears the reset work.
                    let (current, _) = account.client.active_pair(&local, &remote)?.ok_or("pair")?;
                    account.client.confirm_pair_record(&local, &remote, &current, false, false)?;
                    assert!(work(&account.client)?.is_none());
                }
                released = true;
                release.notify_one();
            }
        }
    };
    assert_eq!(
        result.err().ok_or("refused")?.to_string(),
        "gateway session rejected: idempotency_conflict"
    );
    let after = account.client.active_pair(&local, &remote)?.map(|(session, _)| session.session_id);
    if confirmed {
        // Stale refusal dropped: pair intact, no manual marker, no refusal record, no retirement.
        assert_eq!(after, Some(before));
        assert!(work(&account.client)?.is_none());
        assert!(manual(&account.client)?.is_none());
        assert_eq!(refusals(&account.client)?, Vec::<serde_json::Value>::new());
        assert_eq!(journal(&account.client, "needs_manual_recovery")?, 0);
        assert!(
            account.client.account_db()?.load_actor_state::<bool>("secrets/retired")?.is_none()
        );
        reopen(&mut account.client)?;
        assert_eq!(
            account.client.active_pair(&local, &remote)?.map(|(session, _)| session.session_id),
            after
        );
        assert!(manual(&account.client)?.is_none());
    } else {
        // Control: no receive in between, so the terminal applies.
        assert_eq!(after, None);
        assert!(manual(&account.client)?.is_some());
        assert_eq!(refusals(&account.client)?.len(), 1);
    }
    drop((alice, account));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn sender_refusal_policy_reset() -> TestResult {
    for case in Case::ALL {
        Box::pin(sender_row(case)).await?;
    }
    for case in Case::ALL {
        Box::pin(courier_row(case)).await?;
    }
    Box::pin(late_conflict_row(true)).await?;
    Box::pin(late_conflict_row(false)).await?;
    Ok(())
}
