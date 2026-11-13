// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The live generated own-copy worker uses the same native raw-Inner carrier as history.
use super::*;
use crate::client::own_device_copy::OwnMessageInput;
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn native_live_own_copy_uses_generated_outer_and_retains_the_enclosing_control_proof()
-> TestResult {
    let mut source = Fixture::new("live-copy-source").await?;
    let peer = Fixture::new("live-copy-peer").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let conversation = g::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
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
                id: intent["id"].as_str().ok_or("original envelope")?,
                created_at: intent["created_at"].as_i64().ok_or("authored time")?,
                conversation: &conversation,
                group: None,
                body: &bytes,
            },
            source.manifest.clone(),
        )?
        .ok_or("live draft")?;
    let copies = source.client.seal_own_copy_generated(
        &source.config,
        draft,
        vec![source.material_for(&sibling)?],
    )?;
    assert_eq!(copies.len(), 1);
    let (_, envelope) = copies.into_iter().next().ok_or("copy")?;
    assert_eq!(envelope.schema, g::outer::CANDIDATE_ENVELOPE_SCHEMA);
    assert_eq!(envelope.delivery_class, ramflux_protocol::DeliveryClass::Message);
    sibling.receive(envelope, 2).await?;
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
    ))
    .await?;
    Ok(())
}

async fn reconcile_history_after_live_copy(
    source: &Fixture,
    target: &mut Fixture,
    conversation: &str,
    owner: &str,
    exact: &[u8],
) -> TestResult {
    let before = target.client.generated_message_changes(conversation, 0, 100)?.next_after;
    let plan = source
        .client
        .prepare_authored_history(&source.config)?
        .ok_or("historical copy after live delivery")?;
    let (_, envelope) = source
        .client
        .seal_authored_history(&source.config, plan, source.material_for(target)?)?
        .ok_or("historical envelope")?;
    target.receive(envelope, 3).await?;
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
