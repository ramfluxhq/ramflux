// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current own Edit stays pending on a later sibling until independent original metadata exists.
use super::*;
use crate::GatewayInboxEntry;
use crate::client::message_mutations::EditContext;
use prost::Message as _;
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn own_authored_current_edit_for_later_third_sibling_stays_pending_without_original_metadata()
-> TestResult {
    let mut source = Fixture::new("authored-edit-source").await?;
    let peer = Fixture::new("authored-edit-peer").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let mut second = source.enroll_sibling("edited-second", "second").await?;
    let (original, exact) = prepare_current_edit(&source, &peer, &second)?;
    let owner = ramflux_protocol::encode_base64url(&original.id);
    Box::pin(deliver_contact(&source, &peer, &mut second, &original.conversation_id)).await?;
    let prepared = source.client.prepare_authored_history(&source.config)?.ok_or("second plan")?;
    let (plan, envelope) = source
        .client
        .seal_authored_history(&source.config, prepared, source.material_for(&second)?)?
        .ok_or("second sealed")?;
    second.receive(envelope, 2).await?;
    assert_pending(&second, &owner, &exact)?;
    source.client.complete_authored_history(&plan)?;
    // A completed delivery to B cannot suppress later enrollment of C.
    let mut third = source.enroll_sibling("edited-third", "third").await?;
    Box::pin(deliver_contact(&source, &peer, &mut third, &original.conversation_id)).await?;
    let prepared = source.client.prepare_authored_history(&source.config)?.ok_or("third plan")?;
    assert_eq!(prepared.target.device_id, third.config.device_id);
    let (_, envelope) = source
        .client
        .seal_authored_history(&source.config, prepared, source.material_for(&third)?)?
        .ok_or("third sealed")?;
    third.receive(envelope, 2).await?;
    assert_pending(&third, &owner, &exact)?;
    assert_eq!(
        third
            .client
            .generated_message_view_page(&original.conversation_id, None, 10)?
            .messages
            .len(),
        0
    );
    Box::pin(super::authored_edit_erasure::retire_and_refuse_redelivery(
        &source, &mut third, &original,
    ))
    .await?;
    Ok(())
}

fn prepare_current_edit(
    source: &Fixture,
    peer: &Fixture,
    target: &Fixture,
) -> TestResult<(g::EventIdentity, Vec<u8>)> {
    let own = source.client.own_account_anchor()?;
    let peer_root = peer.client.own_account_anchor()?;
    let conversation = g::dm_scope::derive(&own, &peer_root)?;
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
    source.client.establish_friend_link("authored-link", &own, &peer_root)?;
    source
        .client
        .receive_generated_own_contact(&super::authored::authored_contact(source, peer)?)?;
    let original = source.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let message = RamfluxClient::encode_generated_inner(
        original.clone(),
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "retired authored original".into(),
                ..Default::default()
            })),
        },
    )?;
    let owner = ramflux_protocol::encode_base64url(&original.id);
    super::authored::capture_before_enrollment(source, peer, &conversation, &owner, &message)?;
    let db = source.client.account_db()?;
    db.replace_generated_message_content(
        &conversation,
        &owner,
        &message,
        &ramflux_storage::MessageMetadata::default(),
    )?;
    db.persist_message_actor_state(
        &owner,
        &format!("routed/generated-identity/{owner}"),
        &original,
    )?;
    let old = source.client.prepare_authored_history(&source.config)?.ok_or("queued original")?;
    let (old, _) = source
        .client
        .seal_authored_history(&source.config, old, source.material_for(target)?)?
        .ok_or("cached original")?;
    let exact = encoded_edit(source, &original, &message)?;
    let entry = GatewayInboxEntry {
        envelope: source.seal_inner_to(peer, &message)?,
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: peer.config.target_delivery_id.clone(),
    };
    // Apply the locally authored semantic change before capturing/sealing the new revision.
    // The sibling forwarding below independently authenticates the enclosing Control's C.
    assert!(source.client.apply_generated_edit_authorized(
        EditContext {
            entry: &entry,
            source: &source.client.owned_device_identity()?,
            imported: None,
            own_sent: false
        },
        &conversation,
        &exact,
        None
    )?);
    let _ = source.seal_inner_to(peer, &exact)?;
    assert!(
        source
            .client
            .seal_authored_history(
                &source.config,
                old,
                crate::client::routed::SendMaterial { manifest: None, bundle: None }
            )?
            .is_none(),
        "Edit invalidates the captured original's cached ciphertext"
    );
    Ok((original, exact))
}

pub(super) async fn deliver_contact(
    source: &Fixture,
    peer: &Fixture,
    target: &mut Fixture,
    conversation: &str,
) -> TestResult {
    let control = crate::client::generated_control::control_from_payload(
        g::control::Payload::OwnContactSync(super::authored::authored_contact(source, peer)?),
    )?;
    let identity = source.client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        true,
    )?;
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content { value: Some(g::content::Value::Control(control)) },
    )?;
    target.receive(source.seal_inner_to(target, &exact)?, 1).await
}

fn assert_pending(target: &Fixture, owner: &str, exact: &[u8]) -> TestResult {
    let db = target.client.account_db()?;
    assert!(db.message_content(owner)?.is_none());
    assert!(!db.actor_state_exists(&format!("routed/generated-identity/{owner}"))?);
    assert!(!db.actor_state_exists(&format!("routed/original-header/{owner}"))?);
    assert_eq!(db.actor_state_keys(&format!("routed/pending-edit/{owner}/"))?.len(), 1);
    let edit = g::Inner::decode(exact)?;
    let copy = format!(
        "early-edit/{owner}/{}",
        ramflux_protocol::encode_base64url(edit.identity.ok_or("Edit identity")?.id)
    );
    assert_eq!(db.raw_inner_copy(&copy)?.ok_or("pending exact Edit")?.bytes, exact);
    Ok(())
}

fn encoded_edit(
    source: &Fixture,
    original: &g::EventIdentity,
    message: &[u8],
) -> TestResult<Vec<u8>> {
    let target = g::MessageRef {
        id: original.id.clone(),
        conversation_id: original.conversation_id.clone(),
        author_anchor: source.client.own_account_anchor()?,
    };
    let digest = crate::client::message_mutations::previous_content_digest(&target, message)?;
    let identity = source.client.allocate_generated_identity(
        &original.conversation_id,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Edit(g::Edit {
                target: Some(target),
                revision: 1,
                previous_content_digest: digest.to_vec(),
                replacement: Some(g::Message {
                    text: "current authored Edit".into(),
                    ..Default::default()
                }),
            })),
        },
    )?;
    Ok(exact)
}
