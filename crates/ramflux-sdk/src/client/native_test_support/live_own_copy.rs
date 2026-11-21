// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The live generated own-copy worker uses the same native raw-Inner carrier as history.
use super::*;
use crate::client::own_device_copy::OwnMessageInput;
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn native_live_own_copy_uses_generated_outer_and_retains_the_enclosing_control_proof()
-> TestResult {
    super::watchdog::within(exercise(false)).await?
}

pub(crate) async fn exercise(erase: bool) -> TestResult {
    Box::pin(exercise_order(erase, false)).await
}

pub(crate) async fn exercise_order(erase: bool, history_first: bool) -> TestResult {
    let mut source = Fixture::new("live-copy-source").await?;
    let peer = Fixture::new("live-copy-peer").await?;
    let conversation = g::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    source.client.persist_observed_identity_directory_now(&peer.manifest)?;
    source.client.establish_friend_link(
        "authored-link",
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    source
        .client
        .receive_generated_own_contact(&super::authored::authored_contact(&source, &peer)?)?;
    let identity = source.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let owner = ramflux_protocol::encode_base64url(&identity.id);
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "live own-copy body".into(),
                ..Default::default()
            })),
        },
    )?;
    super::authored::capture_before_enrollment(&source, &peer, &conversation, &owner, &exact)?;
    let mut sibling = source.enroll_sibling("live-copy-sibling", "sibling").await?;
    Box::pin(super::authored_edit::deliver_contact(&source, &peer, &mut sibling, &conversation))
        .await?;
    let envelope = seal_live_copy(&source, &sibling, &conversation)?;
    assert_eq!(envelope.schema, g::outer::CANDIDATE_ENVELOPE_SCHEMA);
    assert_eq!(envelope.delivery_class, ramflux_protocol::DeliveryClass::Message);
    let retry = envelope.clone();
    let historical_packet = if history_first {
        Some(Box::pin(import_history(&source, &mut sibling, 2)).await?)
    } else {
        None
    };
    if history_first {
        assert_eq!(
            sibling.client.account_db()?.message_content(&owner)?,
            Some(exact.clone()),
            "generated history did not restore the original authored revision"
        );
        if erase {
            Box::pin(erase_and_replay(&source, &mut sibling, &conversation, &owner, retry)).await?;
            return Ok(());
        }
    }
    sibling.receive(envelope, if history_first { 3 } else { 2 }).await?;
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage(crate::client::delivery_receipts::PREFIX)?.0,
        0,
        "an authenticated same-root copy must not send a peer delivery receipt"
    );
    assert_eq!(
        sibling.client.message_origin(&conversation, &owner)?.ok_or("own provenance")?["direction"],
        "outgoing"
    );
    assert_eq!(sibling.client.account_db()?.message_content(&owner)?, Some(exact.clone()));
    assert_eq!(
        sibling
            .client
            .account_db()?
            .actor_state_keys(&format!("routed/own-sent-attestation/{owner}/"))?
            .len(),
        1
    );
    assert!(
        sibling
            .client
            .export_generated_history_item(&ramflux_protocol::decode_base64url(&owner)?)
            .is_err()
    );
    Box::pin(reconcile_history_after_live_copy(
        &source,
        &mut sibling,
        &conversation,
        &owner,
        &exact,
        historical_packet,
    ))
    .await?;
    if erase {
        erase_and_replay(&source, &mut sibling, &conversation, &owner, retry).await?;
    }
    Ok(())
}

async fn reconcile_history_after_live_copy(
    source: &Fixture,
    target: &mut Fixture,
    conversation: &str,
    owner: &str,
    exact: &[u8],
    historical_packet: Option<ramflux_protocol::Envelope>,
) -> TestResult {
    let before = target.client.generated_message_changes(conversation, 0, 100)?.next_after;
    if let Some(packet) = historical_packet {
        target.receive(packet, 3).await?;
    } else {
        Box::pin(import_history(source, target, 3)).await?;
    }
    assert_eq!(target.client.account_db()?.message_content(owner)?, Some(exact.to_vec()));
    assert_eq!(
        target.client.generated_message_changes(conversation, before, 100)?.changes.len(),
        0
    );
    assert_eq!(
        target
            .client
            .account_db()?
            .actor_state_keys(&format!("routed/own-sent-attestation/{owner}/"))?
            .len(),
        1
    );
    Ok(())
}

async fn erase_and_replay(
    source: &Fixture,
    sibling: &mut Fixture,
    conversation: &str,
    owner: &str,
    retry: ramflux_protocol::Envelope,
) -> TestResult {
    sibling.client.delete_direct_message(
        conversation,
        owner,
        "local",
        &ramflux_protocol::hash_base64url("ramflux.test.local-delete.v1", b"own-copy"),
    )?;
    assert!(sibling.client.account_db()?.message_content(owner)?.is_none());
    assert!(sibling.client.message_origin(conversation, owner)?.is_none());
    let before = sibling.client.generated_message_changes(conversation, 0, 100)?.next_after;
    sibling.receive(retry, 2).await?;
    let view = sibling.client.generated_message_detail(conversation, owner)?.message;
    assert_eq!(view.state, "tombstone", "replayed own copy must preserve the local tombstone");
    assert!(view.text.is_none(), "erased own-copy plaintext must stay absent");
    assert_eq!(
        sibling.client.generated_message_changes(conversation, before, 100)?.changes.len(),
        0,
        "a committed copy replay must not publish a new row or change",
    );
    assert!(sibling.client.account_db()?.message_content(owner)?.is_none());
    assert!(sibling.client.message_origin(conversation, owner)?.is_none());
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage("own-device/sent-event/")?.0,
        1,
        "one content-free private event fence must survive erasure",
    );
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage("own-device/sent-event-body/")?.0,
        0,
        "the body comparison register must be erased with its owner",
    );
    let private = serde_json::to_string(
        &sibling
            .client
            .account_db()?
            .list_actor_states::<serde_json::Value>("own-device/sent-event/")?,
    )?;
    for forbidden in
        [source.config.device_id.as_str(), source.manifest.principal_commitment.as_str(), owner]
    {
        assert!(!private.contains(forbidden), "private replay state retained {forbidden}");
    }
    assert!(!private.contains("live own-copy body"), "erased replay state retained plaintext");
    Ok(())
}

async fn import_history(
    source: &Fixture,
    target: &mut Fixture,
    sequence: u64,
) -> TestResult<ramflux_protocol::Envelope> {
    let plan = source
        .client
        .prepare_authored_history(&source.config)?
        .ok_or("historical copy after live delivery")?;
    let (_, envelope) = source
        .client
        .seal_authored_history(&source.config, plan, source.material_for(target)?)?
        .ok_or("historical envelope")?;
    target.receive(envelope.clone(), sequence).await?;
    Ok(envelope)
}

fn seal_live_copy(
    source: &Fixture,
    sibling: &Fixture,
    conversation: &str,
) -> TestResult<ramflux_protocol::Envelope> {
    let db = source.client.account_db()?;
    let key = db
        .actor_state_keys("own-device/send/")?
        .into_iter()
        .next()
        .ok_or("live own-copy intent")?;
    let queued: serde_json::Value = db.load_actor_state(&key)?.ok_or("queued intent")?;
    let intent = &queued["intent"];
    let bytes = ramflux_protocol::decode_base64url(intent["body"].as_str().ok_or("intent bytes")?)?;
    let draft = source
        .client
        .prepare_own_copy_draft(
            &source.config,
            OwnMessageInput {
                payload_kind: serde_json::from_value(intent["payload_kind"].clone())?,
                id: intent["id"].as_str().ok_or("original envelope")?,
                created_at: intent["created_at"].as_i64().ok_or("authored time")?,
                conversation,
                group: None,
                body: &bytes,
            },
            source.manifest.clone(),
        )?
        .ok_or("live draft")?;
    let copies = source.client.seal_own_copy_generated(
        &source.config,
        draft,
        vec![source.material_for(sibling)?],
    )?;
    assert_eq!(copies.len(), 1);
    let (_, envelope) = copies.into_iter().next().ok_or("copy")?;
    Ok(envelope)
}

#[tokio::test(flavor = "current_thread")]
async fn history_import_then_delete_then_live_copy_keeps_the_original_tombstone() -> TestResult {
    super::watchdog::within(Box::pin(exercise_order(true, true))).await?
}

#[tokio::test(flavor = "current_thread")]
async fn a_late_live_copy_reuses_history_and_preserves_account_deletion() -> TestResult {
    super::watchdog::within(Box::pin(exercise_order(false, true))).await?
}
