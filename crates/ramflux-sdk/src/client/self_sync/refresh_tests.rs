// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refresh barrier, restore re-bootstrap and courier retirement on native accounts.
use crate::client::native_test_support::{Fixture, TestResult};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use serde_json::json;

const THREAD: &str = "refresh-thread";

fn mute(client: &RamfluxClient) -> Result<g::SelfSync, SdkError> {
    client.change_self_sync(THREAD, g::SelfSync { operation: 6, mute: true, ..Default::default() })
}

fn queue_rows(client: &RamfluxClient, id: &str, sealed: bool) -> TestResult {
    let db = client.account_db()?;
    let envelope = if sealed { json!({"sealed": "previous roster"}) } else { json!(null) };
    db.write_transaction(|| {
        db.persist_actor_state(
            &format!("self-sync/pending/{id}/register"),
            &json!({"conversation_id": THREAD, "scope": "scope", "envelope": envelope}),
        )?;
        db.persist_actor_state(
            &format!("self-sync/repair/{id}"),
            &json!({"conversation_id": THREAD, "scope": "scope"}),
        )?;
        db.persist_actor_state(
            &format!("self-sync/repair-sent/{id}"),
            &json!({"conversation_id": THREAD, "scope": "scope"}),
        )?;
        Ok::<(), SdkError>(())
    })?;
    Ok(())
}

fn usage(client: &RamfluxClient, prefix: &str) -> Result<u64, SdkError> {
    Ok(client.account_db()?.actor_state_usage(prefix)?.0)
}

#[tokio::test]
async fn self_sync_refresh_barrier_parks_apply_and_emit_under_older_roster() -> TestResult {
    let own = Fixture::new("self-sync-refresh-behind").await?;
    let first = mute(&own.client)?;
    assert_eq!(first.revision, 1);
    // The device already acted under a newer device set than the one it can verify now.
    own.client.force_self_sync_refresh_barrier(|epoch, _, _| *epoch += 1)?;
    let source = own.client.owned_device_identity()?;
    let update = g::SelfSync { operation: 7, revision: 2, ..Default::default() };
    let db = own.client.account_db()?;
    let applied =
        db.write_transaction(|| own.client.apply_self_sync_in(&source, THREAD, &update));
    assert!(
        matches!(applied, Err(SdkError::InboundPending(_))),
        "an update is parked, not settled, while the roster is behind the barrier"
    );
    assert!(matches!(mute(&own.client), Err(SdkError::InboundPending(_))));
    assert_eq!(
        own.client.self_sync_state(THREAD, &first)?.ok_or("state")?.value.revision,
        1,
        "nothing is applied across the barrier"
    );
    queue_rows(&own.client, "behind", true)?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    assert!(own.client.prepare_self_sync_repair(&own.config)?.is_none(), "nothing is emitted");
    assert_eq!(usage(&own.client, "self-sync/pending/")?, 1, "a parked courier retires nothing");
    Ok(())
}

#[tokio::test]
async fn self_sync_refresh_crossing_retires_envelopes_sealed_for_previous_roster() -> TestResult {
    let own = Fixture::new("self-sync-refresh-crossing").await?;
    mute(&own.client)?;
    queue_rows(&own.client, "sealed", true)?;
    queue_rows(&own.client, "submitted", false)?;
    own.client.force_self_sync_refresh_barrier(|_, head, _| *head = "previous-head".into())?;
    assert!(own.client.enter_self_sync_refresh()?.is_some());
    let db = own.client.account_db()?;
    assert!(!db.actor_state_exists("self-sync/pending/sealed/register")?);
    assert!(
        db.actor_state_exists("self-sync/pending/submitted/register")?,
        "a content-free submission marker keeps deduplicating"
    );
    assert_eq!(usage(&own.client, "self-sync/repair/")?, 2);
    assert_eq!(usage(&own.client, "self-sync/repair-sent/")?, 2);
    // Entering the same generation again is a no-op.
    queue_rows(&own.client, "same-generation", true)?;
    assert!(own.client.enter_self_sync_refresh()?.is_some());
    assert!(db.actor_state_exists("self-sync/pending/same-generation/register")?);
    Ok(())
}

#[tokio::test]
async fn self_sync_restored_incarnation_rebuilds_queues_without_retired_targets() -> TestResult {
    let own = Fixture::new("self-sync-refresh-restore").await?;
    let value = mute(&own.client)?;
    queue_rows(&own.client, "old-incarnation", true)?;
    queue_rows(&own.client, "old-incarnation-submitted", false)?;
    // Restore activation gives the device a new incarnation; the previous one queued these.
    own.client.force_self_sync_refresh_barrier(|_, _, local| *local += 1)?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    assert!(own.client.prepare_self_sync_repair(&own.config)?.is_none());
    for prefix in ["self-sync/pending/", "self-sync/repair/", "self-sync/repair-sent/"] {
        assert_eq!(
            usage(&own.client, prefix)?,
            0,
            "{prefix} of the previous incarnation must not survive; no retired target is re-queued"
        );
    }
    assert_eq!(
        own.client.self_sync_state(THREAD, &value)?.ok_or("state")?.value.revision,
        1,
        "re-bootstrap never changes or re-issues the accepted register"
    );
    Ok(())
}

#[tokio::test]
async fn self_sync_courier_retires_repair_whose_body_left_the_register() -> TestResult {
    let own = Fixture::new("self-sync-refresh-stale-body").await?;
    let value = mute(&own.client)?;
    let local = own.client.owned_device_identity()?;
    let state = own.client.self_sync_state(THREAD, &value)?.ok_or("state")?;
    let scope = own
        .client
        .account_db()?
        .actor_state_keys("self-sync/state/")?
        .pop()
        .ok_or("register scope")?;
    // A restore merge replaced the register below the SDK; the queued body is now stale.
    let stale = g::SelfSync { operation: 7, revision: 1, ..Default::default() }.encode_to_vec();
    assert_ne!(stale, state.exact_body);
    let db = own.client.account_db()?;
    let row = |body: &[u8]| -> Result<serde_json::Value, SdkError> {
        Ok(json!({
            "conversation_id": THREAD, "scope": scope, "target": local.storage_key(),
            "target_epoch": own.client.self_sync_target_epoch(&local)?,
            "target_certificate": own.client.self_sync_target_certificate(&local)?,
            "exact_body": body, "references": [], "read_marker_body": null,
        }))
    };
    db.write_transaction(|| {
        db.persist_actor_state("self-sync/repair/stale", &row(&stale)?)?;
        Ok::<(), SdkError>(())
    })?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    assert!(
        own.client.prepare_self_sync_repair(&own.config)?.is_none(),
        "a stale body is neither sent nor allowed to block the courier"
    );
    assert!(!db.actor_state_exists("self-sync/repair/stale")?);
    // Control: the committed body for the same target is planned.
    db.write_transaction(|| {
        db.persist_actor_state("self-sync/repair/current", &row(&state.exact_body)?)?;
        Ok::<(), SdkError>(())
    })?;
    // Planning may still need pair material; only the retirement rule is under test.
    let _planned = own.client.prepare_self_sync_repair(&own.config);
    assert!(
        db.actor_state_exists("self-sync/repair/current")?,
        "the committed register body is never retired as stale"
    );
    Ok(())
}

#[tokio::test]
async fn self_sync_sent_draft_issues_one_explicit_clear_and_retires_draft_body() -> TestResult {
    let own = Fixture::new("self-sync-draft-sent").await?;
    assert!(own.client.clear_self_sync_draft_after_send(THREAD)?.is_none(), "no draft, no clear");
    let draft = own.client.change_self_sync(
        THREAD,
        g::SelfSync {
            operation: 2,
            draft: Some(g::Message { text: "draft canary text".into(), ..Default::default() }),
            ..Default::default()
        },
    )?;
    assert_eq!(draft.revision, 1);
    let clear = own.client.clear_self_sync_draft_after_send(THREAD)?.ok_or("clear")?;
    assert_eq!((clear.operation, clear.revision), (3, 2));
    let state = own.client.self_sync_state(THREAD, &clear)?.ok_or("state")?;
    assert_eq!(state.value.operation, 3);
    assert!(
        !state.exact_body.windows(17).any(|window| window == b"draft canary text"),
        "the sent draft body does not survive in the register"
    );
    assert!(
        own.client.clear_self_sync_draft_after_send(THREAD)?.is_none(),
        "a repeated send never re-issues a revision"
    );
    assert_eq!(own.client.self_sync_state(THREAD, &clear)?.ok_or("state")?.value.revision, 2);
    Ok(())
}

#[tokio::test]
async fn self_sync_courier_never_forwards_register_with_unauthenticated_reference() -> TestResult {
    let own = Fixture::new("self-sync-courier-reference").await?;
    let id = blake3::hash(b"pinned before arrival").as_bytes().to_vec();
    // The pin target is unknown at first, so the register is stored as received.
    let pin = own.client.change_self_sync(
        THREAD,
        g::SelfSync {
            operation: 4,
            pin: Some(g::MessageRef {
                id: id.clone(),
                conversation_id: THREAD.into(),
                author_anchor: "claimed-root".into(),
            }),
            ..Default::default()
        },
    )?;
    let state = own.client.self_sync_state(THREAD, &pin)?.ok_or("state")?;
    let scope = own
        .client
        .account_db()?
        .actor_state_keys("self-sync/state/")?
        .pop()
        .ok_or("register scope")?;
    let local = own.client.owned_device_identity()?;
    let db = own.client.account_db()?;
    let repair = json!({
        "conversation_id": THREAD, "scope": scope, "target": local.storage_key(),
        "target_epoch": own.client.self_sync_target_epoch(&local)?,
        "target_certificate": own.client.self_sync_target_certificate(&local)?,
        "exact_body": state.exact_body, "references": [], "read_marker_body": null,
    });
    db.write_transaction(|| {
        // The authenticated target arrives and belongs to another author root.
        db.persist_actor_state(
            &format!("routed/generated-identity/{}", ramflux_protocol::encode_base64url(&id)),
            &g::EventIdentity {
                id: id.clone(),
                conversation_id: THREAD.into(),
                author: Some(g::QualifiedDevice {
                    account_anchor: "actual-root".into(),
                    device_id: "peer-device".into(),
                    device_epoch: 1,
                }),
                ..Default::default()
            },
        )?;
        db.persist_actor_state("self-sync/repair/unauthentic", &repair)?;
        Ok::<(), SdkError>(())
    })?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let _planned = own.client.prepare_self_sync_repair(&own.config);
    assert!(
        !db.actor_state_exists("self-sync/repair/unauthentic")?,
        "a register naming a target under the wrong author root is retired, not forwarded"
    );
    Ok(())
}
