// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use prost::Message as _;
use ramflux_protocol::message as g;

fn generated_identity(sender: &Fixture, id: &str) -> Result<g::EventIdentity, SdkError> {
    let source = sender.client.owned_device_identity()?;
    Ok(g::EventIdentity {
        id: id.as_bytes().to_vec(), conversation_id: "c".into(),
        author: Some(g::QualifiedDevice {
            account_anchor: source.root_commitment().into(), device_id: source.device_id().into(), device_epoch: 1,
        }), device_sequence: 1, hlc: 1, ..Default::default()
    })
}

fn unknown_inner(sender: &Fixture, id: &str) -> Result<Vec<u8>, SdkError> {
    Ok(g::Inner { layer: 2, kind: 900, identity: Some(generated_identity(sender, id)?), body: vec![0xff, 0, 0x80] }.encode_to_vec())
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
    assert!(b.client.account_db()?.message_content("field-wire")?.is_none());
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
        envelope_id: entry.envelope.envelope_id.clone(), payload_hash: entry.envelope.payload_hash.clone(), expires_at: i64::MAX,
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
