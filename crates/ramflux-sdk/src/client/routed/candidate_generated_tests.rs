// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use prost::Message as _;
use ramflux_protocol::message as g;

fn generated_identity(sender: &Fixture, id: &str) -> Result<g::EventIdentity, SdkError> {
    let source = sender.client.owned_device_identity()?;
    let author = g::QualifiedDevice { account_anchor: source.root_commitment().into(), device_id: source.device_id().into(), device_epoch: 1 };
    let mut sequence_bytes = [0; 8];
    sequence_bytes.copy_from_slice(&blake3::hash(id.as_bytes()).as_bytes()[..8]);
    let sequence = u64::from_be_bytes(sequence_bytes).max(1);
    Ok(g::EventIdentity {
        id: g::identity::derive(&author, "c", sequence).map_err(|_| invalid("test identity"))?.to_vec(), conversation_id: "c".into(),
        author: Some(author), device_sequence: sequence, hlc: 1, ..Default::default()
    })
}

fn seal(a: &Fixture, b: &Fixture, message: GatewayDirectMessage, body: &[u8]) -> Result<GatewayInboxEntry, SdkError> {
    seal_as(a, b, message, body, Route::direct())
}
fn seal_as(a: &Fixture, b: &Fixture, mut message: GatewayDirectMessage, body: &[u8], route: Route) -> Result<GatewayInboxEntry, SdkError> {
    if let Ok(inner) = g::Inner::decode(body) && let Some(identity) = inner.identity {
        message.message_id = ramflux_protocol::encode_base64url(identity.id);
    }
    super::super::seal_as(a, b, message, body, route)
}

fn unknown_inner(sender: &Fixture, id: &str) -> Result<Vec<u8>, SdkError> {
    Ok(g::Inner { layer: 2, kind: 900, identity: Some(generated_identity(sender, id)?), body: vec![0xff, 0, 0x80] }.encode_to_vec())
}

fn commit_content<'a>(a: &'a Fixture, b: &'a mut Fixture, id: &'a str, mut value: g::content::Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<GatewayInboxEntry, SdkError>> + 'a>> {
    Box::pin(async move {
        let identity = generated_identity(a, id)?;
        match &mut value {
            g::content::Value::Delete(delete) => { delete.tombstone_id = g::identity::delete_tombstone(&identity.id).map_err(|_| invalid("test Delete id"))?.to_vec(); },
            g::content::Value::Reaction(reaction) => reaction.operation_id.clone_from(&identity.id),
            _ => (),
        }
        let raw = RamfluxClient::encode_generated_inner(identity, &g::Content { value: Some(value) })?;
        let entry = seal(a, b, message(id, "c"), &raw)?;
        apply(b, &entry).await?;
        Ok(entry)
    })
}

fn edit(target: &g::MessageRef, revision: u64, digest: [u8; 32], text: &str) -> g::content::Value {
    g::content::Value::Edit(g::Edit {
        target: Some(target.clone()), revision, previous_content_digest: digest.to_vec(),
        replacement: Some(g::Message { text: text.into(), ..Default::default() }),
    })
}

#[tokio::test(flavor = "current_thread")]
async fn generated_edit_reaction_delete_preserves_exact_digest_and_erase_links() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(239, 241)?;
    commit_content(&a, &mut b, "target", g::content::Value::Message(g::Message { text: "original".into(), ..Default::default() })).await?;
    let target = g::MessageRef { id: generated_identity(&a, "target")?.id, conversation_id: "c".into(), author_anchor: a.client.own_account_anchor()? };
    let original = b.client.account_db()?.message_content(&ramflux_protocol::encode_base64url(&target.id))?.ok_or_else(|| invalid("original missing"))?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &original)?;
    let first = commit_content(&a, &mut b, "edit-one", edit(&target, 1, digest, "edited one")).await?;
    let stored = b.client.account_db()?.message_content(&ramflux_protocol::encode_base64url(&target.id))?.ok_or_else(|| invalid("replacement missing"))?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &stored)?;
    commit_content(&a, &mut b, "gap", edit(&target, 3, digest, "edited three")).await?;
    commit_content(&a, &mut b, "edit-two", edit(&target, 2, digest, "edited two")).await?;
    commit_content(&a, &mut b, "stale", edit(&target, 1, [0; 32], "stale must not apply")).await?;
    let page = b.client.generated_message_page("c")?;
    assert!(page.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content { value: Some(g::content::Value::Message(message)) })) if message.text == "edited three")));
    commit_content(&a, &mut b, "react", g::content::Value::Reaction(g::Reaction {
        target: Some(target.clone()), token: "👍".into(), operation_id: b"reaction-one".to_vec(), remove: false,
    })).await?;
    assert_eq!(b.client.direct_messages("c")?.len(), 1);
    commit_content(&a, &mut b, "delete", g::content::Value::Delete(g::Delete {
        targets: vec![target.clone()], scope: g::DeleteScope::Everyone as i32, tombstone_id: b"delete-one".to_vec(), native_group_authorization: Vec::new(),
    })).await?;
    let db = b.client.account_db()?;
    assert!(db.message_content(&ramflux_protocol::encode_base64url(&target.id))?.is_none());
    let key = b.client.authenticated_committed_key(crate::client::identity_authority::HeadUse::NewAuthorization, &first)?;
    assert!(db.load_actor_state::<super::super::super::Committed>(&key)?.is_none());
    assert!(b.client.event_body(&format!("gateway/delivery/v2/{key}"))?.is_none());
    assert_eq!(db.actor_state_usage("routed/reaction/")?.0, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_kind_is_acked_and_kept_with_raw_bytes() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(211, 213)?;
    let raw = unknown_inner(&a, "unknown-wire")?;
    let entry = seal(&a, &b, message("unknown-wire", "c"), &raw)?;
    let (engine, writes) = super::super::review::Inbox::engine(b.config()?, vec![entry.clone()])?;
    let mut account = LocalBusAccountState::new(std::mem::take(&mut b.client), engine, b.id.clone());
    crate::bus::sync_driver::run(&mut account).await?;
    b.client = account.client;
    let copy_id = b.client.authenticated_committed_key(crate::client::identity_authority::HeadUse::NewAuthorization, &entry)?;
    let retained = b.client.account_db()?.raw_inner_copy(&copy_id)?.ok_or_else(|| invalid("exact raw missing"))?;
    assert_eq!(retained.bytes, raw);
    assert!(writes.lock().map_err(|_| invalid("writes mutex"))?.iter().any(|frame| frame["frame_type"] == "ack"));
    let page = b.client.generated_message_page("c")?;
    assert!(matches!(page.first().and_then(|update| update.state.as_ref()), Some(g::message_update::State::Unsupported(_))));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_field_entity_layer_and_signed_payload_keep_exact_bytes() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(215, 217)?;
    let mut body = g::Message { text: "exact unknown field".into(), ..Default::default() }.encode_to_vec();
    body.extend_from_slice(&[0xfa, 0x07, 1, 0x42]);
    let raw = g::Inner { layer: 2, kind: 1, identity: Some(generated_identity(&a, "field-wire")?), body }.encode_to_vec();
    let entry = seal(&a, &b, message("field-wire", "c"), &raw)?;
    apply(&mut b, &entry).await?;
    let copy_id = b.client.authenticated_committed_key(crate::client::identity_authority::HeadUse::NewAuthorization, &entry)?;
    assert_eq!(b.client.account_db()?.raw_inner_copy(&copy_id)?.ok_or_else(|| invalid("raw missing"))?.bytes, raw);
    assert!(b.client.account_db()?.message_content(&ramflux_protocol::encode_base64url(generated_identity(&a, "field-wire")?.id))?.is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_cannot_bypass_native_group_or_own_origin_authority() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(219, 221)?;
    let mut control = g::Control {
        operation: 15, payload: Some(g::control::Payload::OwnMessageCopy(g::OwnMessageCopy::default())),
    }.encode_to_vec();
    control.extend_from_slice(&[0xf8, 0x07, 1]);
    let raw = g::Inner { layer: 2, kind: 8, identity: Some(generated_identity(&a, "forged-own")?), body: control }.encode_to_vec();
    let entry = seal_as(&a, &b, message("forged-own", "c"), &raw, Route::control())?;
    assert!(apply(&mut b, &entry).await.is_err());
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    assert_eq!(projected(&b, "c")?, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn message_page_projects_generated_content_and_unsupported() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(223, 225)?;
    let known = RamfluxClient::encode_generated_inner(generated_identity(&a, "known-wire")?, &g::Content {
        value: Some(g::content::Value::Message(g::Message { text: "hello 😀".into(), ..Default::default() })),
    })?;
    let known_entry = seal(&a, &b, message("known-wire", "c"), &known)?;
    apply(&mut b, &known_entry).await?;
    let unknown = unknown_inner(&a, "unknown-wire")?;
    let unknown_entry = seal(&a, &b, message("unknown-wire", "c"), &unknown)?;
    apply(&mut b, &unknown_entry).await?;
    let page = b.client.generated_message_page("c")?;
    assert!(page.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content { value: Some(g::content::Value::Message(message)) })) if message.text == "hello 😀")));
    assert!(page.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Unsupported(_)))));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn raw_inner_crash_commit_precedes_ack() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(231, 233)?;
    let raw = unknown_inner(&a, "crash-wire")?;
    let entry = seal(&a, &b, message("crash-wire", "c"), &raw)?;
    let key = b.client.authenticated_committed_key(crate::client::identity_authority::HeadUse::NewAuthorization, &entry)?;
    super::super::super::receive::commit_fault::fail_before(super::super::super::receive::commit_fault::Kind::Pair);
    assert!(apply(&mut b, &entry).await.is_err());
    assert!(b.client.account_db()?.raw_inner_copy(&key)?.is_none());
    assert!(b.client.account_db()?.load_actor_state::<super::super::super::Committed>(&key)?.is_none());
    assert_eq!(projected(&b, "c")?, 0);
    let (engine, writes) = super::super::review::Inbox::engine(b.config()?, vec![entry])?;
    let mut account = LocalBusAccountState::new(std::mem::take(&mut b.client), engine, b.id.clone());
    crate::bus::sync_driver::run(&mut account).await?;
    b.client = account.client;
    assert_eq!(b.client.account_db()?.raw_inner_copy(&key)?.ok_or_else(|| invalid("retry raw missing"))?.bytes, raw);
    assert!(writes.lock().map_err(|_| invalid("writes mutex"))?.iter().any(|frame| frame["frame_type"] == "ack"));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn reparse_is_idempotent_and_erased_raw_stays_tombstoned() -> Result<(), SdkError> {
    use ramflux_storage::{RawInnerCopyWrite, RawInnerCopyKind, DirectMessageWrite, MessageMetadata};
    use crate::client::routed::generated_receive::Provenance;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(235, 237)?;
    let raw = RamfluxClient::encode_generated_inner(generated_identity(&a, "upgrade-target")?, &g::Content {
        value: Some(g::content::Value::Message(g::Message { text: "upgraded content".into(), ..Default::default() })),
    })?;
    let entry = seal(&a, &b, message("upgrade-target", "c"), &raw)?;
    let source = a.client.owned_device_identity()?;
    let metadata = serde_json::to_vec(&Provenance {
        source: source.storage_key().into(), conversation: "c".into(), message: "upgrade-target".into(),
        envelope_id: entry.envelope.envelope_id.clone(), payload_hash: entry.envelope.payload_hash.clone(), expires_at: i64::MAX, original_mode: "durable".into(), source_epoch: 1,
        original_route: "direct".into(), outer_receipt_key: "upgrade-copy".into(), received_erasure_generation: 0,
    })?;
    let db = b.client.account_db()?;
    db.write_transaction(|| -> Result<(), SdkError> {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "upgrade-target", verified_source_anchor: source.root_commitment(), copy_id: "upgrade-copy",
            kind: RawInnerCopyKind::OuterInner, bytes: &raw, bounded_metadata: &metadata,
        })?;
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "c", message_id: "upgrade-target", sender_id: "alice", encrypted_body: &[],
            metadata: &MessageMetadata::default(), created_at: 1,
        })?;
        Ok(())
    })?;
    assert_eq!(b.client.reparse_raw_inner_page(&mut Vec::new())?.projected, 1);
    let head = b.client.account_db()?.journal_bounds()?.head_seq;
    assert_eq!(b.client.reparse_raw_inner_page(&mut Vec::new())?.projected, 0);
    assert_eq!(b.client.account_db()?.journal_bounds()?.head_seq, head);
    b.client.delete_direct_message("c", "upgrade-target", "local", "erase-upgrade")?;
    let db = b.client.account_db()?;
    assert!(db.write_transaction(|| db.put_unsupported_raw_copy(RawInnerCopyWrite {
        owner_id: "upgrade-target", verified_source_anchor: source.root_commitment(), copy_id: "upgrade-copy",
        kind: RawInnerCopyKind::OuterInner, bytes: &raw, bounded_metadata: &metadata,
    })).is_err());
    assert_eq!(b.client.reparse_raw_inner_page(&mut Vec::new())?.projected, 0);
    Ok(())
}


async fn group_authority_case(change: &str) -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(231, 233)?;
    super::super::fixture_group(&a.client, "generated-group", &a)?;
    super::super::fixture_member(&a.client, "generated-group", &b)?;
    super::super::fixture_group(&b.client, "generated-group", &b)?;
    super::super::fixture_member(&b.client, "generated-group", &a)?;
    b.client.import_group_sender_key_distribution(&a.client.export_group_sender_key_distribution("generated-group", "alice")?)?;
    let mut message = a.client.encrypt_generated_group_message("generated-group", "alice", &g::Message { text: "group content".into(), ..Default::default() })?;
    let group = message.sealed_group.as_mut().ok_or_else(|| invalid("group fixture missing"))?;
    match change {
        "author" => { group.author.as_mut().ok_or_else(|| invalid("author missing"))?.account_anchor = b.client.own_account_anchor()?; },
        "member" => { b.client.remove_group_member("generated-group", "bob", "alice")?; }
        "epoch" => group.key_epoch += 1,
        "proof" => group.native_authority_proof = vec![1],
        "head" => group.group_state_hash = vec![9; 32],
        "valid" => (),
        _ => return Err(invalid("unknown group test case")),
    }
    let mut body = message.encode_to_vec();
    // Unknown field forces the Unsupported branch; authority still has to run first.
    if change != "valid" { body.extend_from_slice(&[0xfa, 0x07, 1, 0x42]); }
    let mut identity = generated_identity(&a, change)?;
    identity.group_id = Some("generated-group".into());
    identity.group_epoch = message.sealed_group.as_ref().map(|group| group.key_epoch);
    let raw = g::Inner { layer: 2, kind: 1, identity: Some(identity), body }.encode_to_vec();
    let entry = seal_as(&a, &b, super::super::message(change, "c"), &raw, Route::group_message("generated-group"))?;
    ramflux_node_core::check_entry_bound(&entry.envelope).map_err(|error| invalid(&error.to_string()))?;
    let result = apply(&mut b, &entry).await;
    if change == "valid" {
        result?;
        let updates = b.client.generated_message_page("c")?;
        assert!(updates.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content { value: Some(g::content::Value::Message(message)) })) if message.text == "group content")));
    } else {
        assert!(result.is_err(), "{change} must be refused before retention");
        assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
        assert_eq!(projected(&b, "c")?, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_group_author_must_equal_pair_peer() -> Result<(), SdkError> { Box::pin(group_authority_case("author")).await }
#[tokio::test(flavor = "current_thread")]
async fn generated_group_author_must_be_current_member() -> Result<(), SdkError> { Box::pin(group_authority_case("member")).await }
#[tokio::test(flavor = "current_thread")]
async fn generated_group_requires_pinned_key_epoch() -> Result<(), SdkError> { Box::pin(group_authority_case("epoch")).await }
#[tokio::test(flavor = "current_thread")]
async fn generated_group_refuses_nonempty_authority_proof() -> Result<(), SdkError> { Box::pin(group_authority_case("proof")).await }
#[tokio::test(flavor = "current_thread")]
async fn generated_group_requires_pinned_state_hash() -> Result<(), SdkError> { Box::pin(group_authority_case("head")).await }
#[tokio::test(flavor = "current_thread")]
async fn generated_group_decrypts_with_outer_authority() -> Result<(), SdkError> { Box::pin(group_authority_case("valid")).await }


#[tokio::test(flavor = "current_thread")]
async fn generated_refusals_settle_and_never_stage_locally() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for kind in [3, 4, 5, 7] {
        let (a, mut b) = pair(201, 203)?;
        // A known malformed payload has no target/replacement/operation. This is peer input.
        let bad_bytes = g::Inner { layer: 2, kind, identity: Some(generated_identity(&a, "bad")?), body: Vec::new() }.encode_to_vec();
        let first = seal(&a, &b, message("bad", "c"), &bad_bytes)?;
        let good = RamfluxClient::encode_generated_inner(generated_identity(&a, "good")?, &g::Content {
            value: Some(g::content::Value::Message(g::Message { text: "after refusal".into(), ..Default::default() })),
        })?;
        let mut second = seal(&a, &b, message("good", "c"), &good)?;
        second.inbox_seq = 2;
        let (engine, writes) = super::super::review::Inbox::engine(b.config()?, vec![first, second])?;
        let mut account = LocalBusAccountState::new(std::mem::take(&mut b.client), engine, b.id.clone());
        crate::bus::sync_driver::run(&mut account).await?;
        b.client = account.client;
        assert!(b.client.account_db()?.message_content(&ramflux_protocol::encode_base64url(generated_identity(&a, "good")?.id))?.is_some(), "kind {kind} stalled receive");
        assert!(b.client.account_db()?.message_content(&ramflux_protocol::encode_base64url(generated_identity(&a, "bad")?.id))?.is_none());
        assert!(writes.lock().map_err(|_| invalid("writes mutex"))?.iter().any(|frame| frame["frame_type"] == "ack"));
    }
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn edit_before_target_is_committed_without_transport_retry_expiry() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(207, 209)?;
    let target = g::MessageRef { id: generated_identity(&a, "late-target")?.id, conversation_id: "c".into(), author_anchor: a.client.own_account_anchor()? };
    let original = RamfluxClient::encode_generated_inner(generated_identity(&a, "late-target")?, &g::Content { value: Some(g::content::Value::Message(g::Message { text: "original late".into(), ..Default::default() })) })?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &original)?;
    let early = commit_content(&a, &mut b, "early-edit", edit(&target, 9, digest, "late edit wins")).await?;
    let committed = b.client.authenticated_committed_key(crate::client::identity_authority::HeadUse::NewAuthorization, &early)?;
    assert!(b.client.account_db()?.load_actor_state::<super::super::super::Committed>(&committed)?.is_some());
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 1);
    // No transport retry row owns this work: its exact bytes remain after ordinary retry expiry.
    let _clock = crate::time::FixedClock::set(crate::time::now_unix_timestamp() + 31 * 86400);
    commit_content(&a, &mut b, "late-target", g::content::Value::Message(g::Message { text: "original late".into(), ..Default::default() })).await?;
    let page = b.client.generated_message_page("c")?;
    assert!(page.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content { value: Some(g::content::Value::Message(message)) })) if message.text == "late edit wins")));
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    Ok(())
}
