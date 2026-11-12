// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use prost::Message as _;
use ramflux_protocol::message as g;

fn generated_identity(sender: &Fixture, id: &str) -> Result<g::EventIdentity, SdkError> {
    let source = sender.client.owned_device_identity()?;
    let author = g::QualifiedDevice {
        account_anchor: source.root_commitment().into(),
        device_id: source.device_id().into(),
        device_epoch: 1,
    };
    let mut sequence_bytes = [0; 8];
    sequence_bytes.copy_from_slice(&blake3::hash(id.as_bytes()).as_bytes()[..8]);
    let sequence = u64::from_be_bytes(sequence_bytes).max(1);
    Ok(g::EventIdentity {
        id: g::identity::derive(&author, "c", sequence)
            .map_err(|_| invalid("test identity"))?
            .to_vec(),
        conversation_id: "c".into(),
        author: Some(author),
        device_sequence: sequence,
        hlc: 1,
        ..Default::default()
    })
}

fn seal(
    a: &Fixture,
    b: &Fixture,
    message: GatewayDirectMessage,
    body: &[u8],
) -> Result<GatewayInboxEntry, SdkError> {
    seal_as(a, b, message, body, Route::direct())
}
fn seal_as(
    a: &Fixture,
    b: &Fixture,
    mut message: GatewayDirectMessage,
    body: &[u8],
    route: Route,
) -> Result<GatewayInboxEntry, SdkError> {
    if let Ok(inner) = g::Inner::decode(body)
        && let Some(identity) = inner.identity
    {
        if identity.conversation_id == "c"
            && identity.group_id.is_none()
            && b.client.account_db()?.client_record("conversation", "c")?.is_none()
            && route.kind == Kind::Direct
        {
            b.client.account_db()?.persist_client_record("conversation", "c", &serde_json::json!({
                "kind":"direct", "group_id":null,
                "participants":[a.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id, b.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id],
                "participant_roots":[a.client.own_account_anchor()?, b.client.own_account_anchor()?],
            }))?;
        }
        message.message_id = ramflux_protocol::encode_base64url(identity.id);
    }
    super::super::seal_as(a, b, message, body, route)
}

fn unknown_inner(sender: &Fixture, id: &str) -> Result<Vec<u8>, SdkError> {
    Ok(g::Inner {
        layer: 2,
        kind: 900,
        identity: Some(generated_identity(sender, id)?),
        body: vec![0xff, 0, 0x80],
    }
    .encode_to_vec())
}

fn commit_content<'a>(
    a: &'a Fixture,
    b: &'a mut Fixture,
    id: &'a str,
    mut value: g::content::Value,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<GatewayInboxEntry, SdkError>> + 'a>>
{
    Box::pin(async move {
        let identity = generated_identity(a, id)?;
        match &mut value {
            g::content::Value::Delete(delete) => {
                delete.tombstone_id = g::identity::delete_tombstone(&identity.id)
                    .map_err(|_| invalid("test Delete id"))?
                    .to_vec();
            }
            g::content::Value::Reaction(reaction) => reaction.operation_id.clone_from(&identity.id),
            _ => (),
        }
        let raw =
            RamfluxClient::encode_generated_inner(identity, &g::Content { value: Some(value) })?;
        let entry = seal(a, b, message(id, "c"), &raw)?;
        apply(b, &entry).await?;
        Ok(entry)
    })
}

fn edit(target: &g::MessageRef, revision: u64, digest: [u8; 32], text: &str) -> g::content::Value {
    g::content::Value::Edit(g::Edit {
        target: Some(target.clone()),
        revision,
        previous_content_digest: digest.to_vec(),
        replacement: Some(g::Message { text: text.into(), ..Default::default() }),
    })
}

#[tokio::test(flavor = "current_thread")]
async fn retired_original_redelivery_never_replaces_current_edit() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(185, 187)?;
    commit_content(
        &a,
        &mut b,
        "retired-target",
        g::content::Value::Message(g::Message {
            text: "erased original".into(),
            ..Default::default()
        }),
    )
    .await?;
    let target = g::MessageRef {
        id: generated_identity(&a, "retired-target")?.id,
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    let id = ramflux_protocol::encode_base64url(&target.id);
    let original =
        b.client.account_db()?.message_content(&id)?.ok_or_else(|| invalid("original"))?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &original)?;
    commit_content(&a, &mut b, "retiring-edit", edit(&target, 1, digest, "current edit")).await?;
    let current = b.client.account_db()?.message_content(&id)?.ok_or_else(|| invalid("current"))?;
    // A fresh pair packet/envelope with the same logical original is still a retired copy.
    let replay = seal(&a, &b, message("fresh-original-copy", "c"), &original)?;
    apply(&mut b, &replay).await?;
    let receipt = b.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &replay,
    )?;
    let committed = b
        .client
        .account_db()?
        .load_actor_state::<super::super::super::Committed>(&receipt)?
        .ok_or_else(|| invalid("redelivery receipt"))?;
    assert!(
        committed.entry.envelope.encrypted_payload.is_empty(),
        "retired ciphertext must not be retained again"
    );
    // A different outer event id must also honor the nested target's retirement fence.
    let referenced = commit_content(
        &a,
        &mut b,
        "retired-target-reaction",
        g::content::Value::Reaction(g::Reaction {
            target: Some(target.clone()),
            token: "👍".into(),
            ..Default::default()
        }),
    )
    .await?;
    let referenced_receipt = b.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &referenced,
    )?;
    let retained = b
        .client
        .account_db()?
        .load_actor_state::<super::super::super::Committed>(&referenced_receipt)?
        .ok_or_else(|| invalid("referenced receipt"))?;
    assert!(
        retained.entry.envelope.encrypted_payload.is_empty(),
        "a distinct enclosing event must honor its referenced original's retirement fence"
    );
    assert!(b.client.event_body(&format!("gateway/delivery/v2/{referenced_receipt}"))?.is_none());
    assert_eq!(b.client.account_db()?.message_content(&id)?, Some(current.clone()));
    assert_eq!(
        b.client.direct_message_by_id(&id)?.ok_or_else(|| invalid("projection"))?.encrypted_body,
        current
    );
    assert!(matches!(
        b.client.selected_franking_evidence_for_direct_message("c", &id),
        Err(SdkError::HistoryEvidence(g::original_header::EvidenceError::ReportOpeningRetired))
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_edit_reaction_delete_preserves_exact_digest_and_erase_links()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(239, 241)?;
    commit_content(
        &a,
        &mut b,
        "target",
        g::content::Value::Message(g::Message { text: "original".into(), ..Default::default() }),
    )
    .await?;
    let target = g::MessageRef {
        id: generated_identity(&a, "target")?.id,
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    let original = b
        .client
        .account_db()?
        .message_content(&ramflux_protocol::encode_base64url(&target.id))?
        .ok_or_else(|| invalid("original missing"))?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &original)?;
    let first =
        commit_content(&a, &mut b, "edit-one", edit(&target, 1, digest, "edited one")).await?;
    let stored = b
        .client
        .account_db()?
        .message_content(&ramflux_protocol::encode_base64url(&target.id))?
        .ok_or_else(|| invalid("replacement missing"))?;
    let projection = b
        .client
        .direct_message_by_id(&ramflux_protocol::encode_base64url(&target.id))?
        .ok_or_else(|| invalid("edited projection missing"))?;
    assert_eq!(
        projection.encrypted_body, stored,
        "old content must not survive in the second body store"
    );
    let digest = crate::client::message_mutations::previous_content_digest(&target, &stored)?;
    commit_content(&a, &mut b, "gap", edit(&target, 3, digest, "edited three")).await?;
    commit_content(&a, &mut b, "edit-two", edit(&target, 2, digest, "edited two")).await?;
    commit_content(&a, &mut b, "stale", edit(&target, 1, [0; 32], "stale must not apply")).await?;
    let page = b.client.generated_message_page("c", None, 100)?.messages;
    assert!(page.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content { value: Some(g::content::Value::Message(message)) })) if message.text == "edited three")));
    commit_content(
        &a,
        &mut b,
        "react",
        g::content::Value::Reaction(g::Reaction {
            target: Some(target.clone()),
            token: "👍".into(),
            operation_id: b"reaction-one".to_vec(),
            remove: false,
        }),
    )
    .await?;
    assert_eq!(b.client.direct_messages("c")?.len(), 1);
    commit_content(
        &a,
        &mut b,
        "delete",
        g::content::Value::Delete(g::Delete {
            targets: vec![target.clone()],
            scope: g::DeleteScope::Everyone as i32,
            tombstone_id: b"delete-one".to_vec(),
            native_group_authorization: Vec::new(),
        }),
    )
    .await?;
    let db = b.client.account_db()?;
    assert!(db.message_content(&ramflux_protocol::encode_base64url(&target.id))?.is_none());
    let key = b.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &first,
    )?;
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
    let mut account =
        LocalBusAccountState::new(std::mem::take(&mut b.client), engine, b.id.clone());
    crate::bus::sync_driver::run(&mut account).await?;
    b.client = account.client;
    let copy_id = b.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &entry,
    )?;
    let retained = b
        .client
        .account_db()?
        .raw_inner_copy(&copy_id)?
        .ok_or_else(|| invalid("exact raw missing"))?;
    assert_eq!(retained.bytes, raw);
    assert!(
        writes
            .lock()
            .map_err(|_| invalid("writes mutex"))?
            .iter()
            .any(|frame| frame["frame_type"] == "ack")
    );
    let page = b.client.generated_message_page("c", None, 100)?.messages;
    let Some(g::message_update::State::Unsupported(view)) =
        page.first().and_then(|update| update.state.as_ref())
    else {
        return Err(invalid("Unsupported view missing"));
    };
    assert_eq!(view.reason, "unknown_kind");
    assert_eq!(view.raw_handle.len(), 16, "Unsupported view leaked private raw locator");
    assert_eq!(usize::try_from(view.raw_length).map_err(|_| invalid("raw length"))?, raw.len());
    let handle_key =
        format!("routed/raw-handle/{}", ramflux_protocol::encode_base64url(&view.raw_handle));
    assert_eq!(
        b.client.account_db()?.load_actor_state::<String>(&handle_key)?,
        Some(copy_id.clone())
    );
    apply(&mut b, &entry).await?;
    let duplicate = b.client.generated_message_page("c", None, 100)?.messages;
    assert_eq!(
        duplicate.first().and_then(|update| update.state.as_ref()),
        page.first().and_then(|update| update.state.as_ref())
    );
    let owner = ramflux_protocol::encode_base64url(generated_identity(&a, "unknown-wire")?.id);
    b.client.delete_direct_message("c", &owner, "local", "erase-unsupported-handle")?;
    assert!(
        !b.client.account_db()?.actor_state_exists(&handle_key)?,
        "erasure retained private handle mapping"
    );
    assert!(b.client.account_db()?.raw_inner_copy(&copy_id)?.is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_field_entity_layer_and_signed_payload_keep_exact_bytes() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(215, 217)?;
    let mut body =
        g::Message { text: "exact unknown field".into(), ..Default::default() }.encode_to_vec();
    body.extend_from_slice(&[0xfa, 0x07, 1, 0x42]);
    let raw =
        g::Inner { layer: 2, kind: 1, identity: Some(generated_identity(&a, "field-wire")?), body }
            .encode_to_vec();
    let entry = seal(&a, &b, message("field-wire", "c"), &raw)?;
    apply(&mut b, &entry).await?;
    let copy_id = b.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &entry,
    )?;
    assert_eq!(
        b.client
            .account_db()?
            .raw_inner_copy(&copy_id)?
            .ok_or_else(|| invalid("raw missing"))?
            .bytes,
        raw
    );
    assert!(
        b.client
            .account_db()?
            .message_content(&ramflux_protocol::encode_base64url(
                generated_identity(&a, "field-wire")?.id
            ))?
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_cannot_bypass_native_group_or_own_origin_authority() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(219, 221)?;
    let mut control = g::Control {
        operation: 15,
        payload: Some(g::control::Payload::OwnMessageCopy(g::OwnMessageCopy::default())),
    }
    .encode_to_vec();
    control.extend_from_slice(&[0xf8, 0x07, 1]);
    let raw = g::Inner {
        layer: 2,
        kind: 8,
        identity: Some(generated_identity(&a, "forged-own")?),
        body: control,
    }
    .encode_to_vec();
    let entry = seal_as(&a, &b, message("forged-own", "c"), &raw, Route::control())?;
    assert!(apply(&mut b, &entry).await.is_err());
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    assert_eq!(projected(&b, "c")?, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn message_page_preserves_unicode_and_unsupported_projection() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(223, 225)?;
    let known = RamfluxClient::encode_generated_inner(
        generated_identity(&a, "known-wire")?,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "hello 😀".into(),
                ..Default::default()
            })),
        },
    )?;
    let known_entry = seal(&a, &b, message("known-wire", "c"), &known)?;
    apply(&mut b, &known_entry).await?;
    let unknown = unknown_inner(&a, "unknown-wire")?;
    let unknown_entry = seal(&a, &b, message("unknown-wire", "c"), &unknown)?;
    apply(&mut b, &unknown_entry).await?;
    let page = b.client.generated_message_page("c", None, 100)?.messages;
    assert!(page.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content { value: Some(g::content::Value::Message(message)) })) if message.text == "hello 😀")));
    assert!(page.iter().any(|update| matches!(
        update.state.as_ref(),
        Some(g::message_update::State::Unsupported(_))
    )));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn raw_inner_crash_commit_precedes_ack() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(231, 233)?;
    let raw = unknown_inner(&a, "crash-wire")?;
    let entry = seal(&a, &b, message("crash-wire", "c"), &raw)?;
    let key = b.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &entry,
    )?;
    super::super::super::receive::commit_fault::fail_before(
        super::super::super::receive::commit_fault::Kind::Pair,
    );
    assert!(apply(&mut b, &entry).await.is_err());
    assert!(b.client.account_db()?.raw_inner_copy(&key)?.is_none());
    assert!(
        b.client.account_db()?.load_actor_state::<super::super::super::Committed>(&key)?.is_none()
    );
    assert_eq!(projected(&b, "c")?, 0);
    let (engine, writes) = super::super::review::Inbox::engine(b.config()?, vec![entry])?;
    let mut account =
        LocalBusAccountState::new(std::mem::take(&mut b.client), engine, b.id.clone());
    crate::bus::sync_driver::run(&mut account).await?;
    b.client = account.client;
    assert_eq!(
        b.client
            .account_db()?
            .raw_inner_copy(&key)?
            .ok_or_else(|| invalid("retry raw missing"))?
            .bytes,
        raw
    );
    assert!(
        writes
            .lock()
            .map_err(|_| invalid("writes mutex"))?
            .iter()
            .any(|frame| frame["frame_type"] == "ack")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn reparse_is_idempotent_and_erased_raw_stays_tombstoned() -> Result<(), SdkError> {
    use crate::client::routed::generated_receive::Provenance;
    use ramflux_storage::{
        DirectMessageWrite, MessageMetadata, RawInnerCopyKind, RawInnerCopyWrite,
    };
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(235, 237)?;
    let identity = generated_identity(&a, "upgrade-target")?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let raw = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "upgraded content".into(),
                ..Default::default()
            })),
        },
    )?;
    let entry = seal(&a, &b, message("upgrade-target", "c"), &raw)?;
    let opened = b.client.open_routed(&entry, &b.id)?;
    let copy_id = b.client.authenticated_committed_key(HeadUse::HistoricalRead, &entry)?;
    let receipt = crate::client::routed::Committed {
        routing: opened.routing.clone(),
        entry: entry.clone(),
        projected: true,
        erasure_targets: Vec::new(),
    };
    let source = a.client.owned_device_identity()?;
    let metadata = serde_json::to_vec(&Provenance {
        source: source.storage_key().into(),
        conversation: "c".into(),
        message: id.clone(),
        envelope_id: entry.envelope.envelope_id.clone(),
        payload_hash: entry.envelope.payload_hash.clone(),
        expires_at: entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl)),
        original_mode: "durable".into(),
        source_epoch: 1,
        original_route: serde_json::to_string(&opened.routing)?,
        outer_receipt_key: copy_id.clone(),
        source_evidence_copy: None,
        received_erasure_generation: b.client.account_db()?.privacy_erasure_generation()?,
    })?;
    let db = b.client.account_db()?;
    db.write_transaction(|| -> Result<(), SdkError> {
        db.persist_message_actor_state(&id, &copy_id, &receipt)?;
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: &id,
            verified_source_anchor: source.root_commitment(),
            copy_id: &copy_id,
            kind: RawInnerCopyKind::OuterInner,
            bytes: &raw,
            bounded_metadata: &metadata,
        })?;
        b.client.persist_generated_unsupported_view(
            &id,
            &copy_id,
            &g::validation::scan_inner(&raw).map_err(|_| invalid("fixture scan"))?,
        )?;
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "c",
            message_id: &id,
            sender_id: "alice",
            encrypted_body: &[],
            metadata: &MessageMetadata::default(),
            created_at: 1,
        })?;
        Ok(())
    })?;
    assert_eq!(b.client.reparse_raw_inner_page()?.projected, 1);
    assert_reparsed_content_and_handle_retirement(&b.client, &id, &raw)?;
    let head = b.client.account_db()?.journal_bounds()?.head_seq;
    retain_redundant_reparse_copy(&b.client, &id, source.root_commitment(), &raw, &metadata)?;
    assert_eq!(b.client.reparse_raw_inner_page()?.projected, 0);
    assert_eq!(b.client.account_db()?.journal_bounds()?.head_seq, head);
    assert!(b.client.account_db()?.raw_inner_copy("redundant-known-copy")?.is_none());
    b.client.delete_direct_message("c", &id, "local", "erase-upgrade")?;
    let db = b.client.account_db()?;
    assert!(
        db.write_transaction(|| db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: &id,
            verified_source_anchor: source.root_commitment(),
            copy_id: &copy_id,
            kind: RawInnerCopyKind::OuterInner,
            bytes: &raw,
            bounded_metadata: &metadata,
        }))
        .is_err()
    );
    assert_eq!(b.client.reparse_raw_inner_page()?.projected, 0);
    Ok(())
}

fn assert_reparsed_content_and_handle_retirement(
    client: &RamfluxClient,
    id: &str,
    raw: &[u8],
) -> Result<(), SdkError> {
    assert_eq!(client.account_db()?.message_content(id)?.as_deref(), Some(raw));
    assert_eq!(
        client.direct_message_by_id(id)?.ok_or_else(|| invalid("projection"))?.encrypted_body,
        raw
    );
    let page = client.generated_message_page("c", None, 10)?;
    assert!(page.messages.first().is_some_and(|row| matches!(
        row.state.as_ref(),
        Some(g::message_update::State::Content(_))
    )));
    assert_schema_update_cursor(client, id)?;
    assert_eq!(
        client.account_db()?.actor_state_keys("routed/raw-handle/")?,
        Vec::<String>::new(),
        "reparse retained a stale raw handle"
    );
    Ok(())
}

fn retain_redundant_reparse_copy(
    client: &RamfluxClient,
    id: &str,
    source: &str,
    raw: &[u8],
    metadata: &[u8],
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: id,
            verified_source_anchor: source,
            copy_id: "redundant-known-copy",
            kind: ramflux_storage::RawInnerCopyKind::OuterInner,
            bytes: raw,
            bounded_metadata: metadata,
        })
        .map_err(SdkError::from)
    })
}

fn assert_schema_update_cursor(client: &RamfluxClient, id: &str) -> Result<(), SdkError> {
    let events = client.account_db()?.journal_after(0, 64)?;
    let event = events
        .iter()
        .find(|event| event.topic == "message.schema.updated")
        .ok_or_else(|| invalid("typed schema update absent"))?;
    let update: g::MessageUpdate = serde_json::from_value(event.body["update"].clone())?;
    assert!(update.journal_sequence > 0, "durable schema update used transient sequence zero");
    assert_eq!(update.journal_sequence, event.seq);
    assert_eq!(
        update.identity.as_ref().map(|identity| ramflux_protocol::encode_base64url(&identity.id)),
        Some(id.to_owned())
    );
    Ok(())
}

fn assert_group_authority_guard(
    a: &Fixture,
    b: &Fixture,
    entry: &GatewayInboxEntry,
    message: &g::Message,
    change: &str,
) -> Result<(), SdkError> {
    let wrapper = message.sealed_group.as_ref().ok_or_else(|| invalid("sealed fixture"))?;
    let source = a.client.owned_device_identity()?;
    match change {
        "author" | "proof" | "head" => assert!(
            b.client.check_generated_group_source(wrapper, &source, entry).is_err(),
            "native group source guard must reject {change}"
        ),
        "member" | "epoch" => assert!(
            b.client
                .require_generated_group_epoch("generated-group", &source, wrapper.key_epoch, false)
                .is_err(),
            "native current/named role guard must reject {change}"
        ),
        "valid" => b.client.check_generated_group_source(wrapper, &source, entry)?,
        _ => return Err(invalid("unknown group guard case")),
    }
    Ok(())
}

async fn group_authority_case(change: &str) -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(231, 233)?;
    for client in [&a.client, &b.client] {
        for peer in [&a, &b] {
            let manifest = crate::client::identity_authority::test_support::manifest(&peer.client)?;
            client.observe_device_manifest_json(
                serde_json::to_value(&manifest)?,
                &manifest.principal_commitment,
            )?;
        }
    }
    b.client.shared_group_create("generated-group", "c", None, "target-bob")?;
    let alice = a.client.owned_group_actor("target-alice")?;
    let state = b.client.shared_group_change(
        "generated-group",
        "target-bob",
        ramflux_protocol::group_state::GroupStateChange::Add {
            member: alice.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    a.client.accept_shared_group_state(&state, "target-alice")?;
    b.client.import_group_sender_key_distribution(
        &a.client.export_group_sender_key_distribution("generated-group", "alice")?,
    )?;
    let mut message = a.client.encrypt_generated_group_message(
        "generated-group",
        "alice",
        &g::Message {
            text: "group content".into(),
            erasure_nonce: vec![51; 32],
            ..Default::default()
        },
    )?;
    let group = message.sealed_group.as_mut().ok_or_else(|| invalid("group fixture missing"))?;
    match change {
        "author" => {
            group.author.as_mut().ok_or_else(|| invalid("author missing"))?.account_anchor =
                b.client.own_account_anchor()?;
        }
        "member" => {
            b.client.shared_group_change(
                "generated-group",
                "target-bob",
                ramflux_protocol::group_state::GroupStateChange::Remove {
                    root_commitment: a.client.own_account_anchor()?,
                    device_id: "alice".into(),
                },
            )?;
        }
        "epoch" => group.key_epoch += 1,
        "proof" => group.native_authority_proof = vec![1],
        "head" => group.group_state_hash = vec![9; 32],
        "valid" => (),
        _ => return Err(invalid("unknown group test case")),
    }
    let mut body = message.encode_to_vec();
    // Unknown field forces the Unsupported branch; authority still has to run first.
    if change != "valid" {
        body.extend_from_slice(&[0xfa, 0x07, 1, 0x42]);
    }
    let mut identity = generated_identity(&a, change)?;
    identity.group_id = Some("generated-group".into());
    identity.group_epoch = message.sealed_group.as_ref().map(|group| group.key_epoch);
    let raw = g::Inner { layer: 2, kind: 1, identity: Some(identity), body }.encode_to_vec();
    let entry = seal_as(
        &a,
        &b,
        super::super::message(change, "c"),
        &raw,
        Route::group_message("generated-group"),
    )?;
    assert_group_authority_guard(&a, &b, &entry, &message, change)?;
    ramflux_node_core::check_entry_bound(&entry.envelope)
        .map_err(|error| invalid(&error.to_string()))?;
    let result = apply(&mut b, &entry).await;
    if change == "valid" {
        result?;
        let updates = b.client.generated_message_page("c", None, 100)?.messages;
        assert!(updates.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content { value: Some(g::content::Value::Message(message)) })) if message.text == "group content")));
    } else {
        assert!(result.is_err(), "{change} must be refused before retention");
        assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
        assert_eq!(projected(&b, "c")?, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_group_author_must_equal_pair_peer() -> Result<(), SdkError> {
    Box::pin(group_authority_case("author")).await
}
#[tokio::test(flavor = "current_thread")]
async fn generated_group_author_must_be_current_member() -> Result<(), SdkError> {
    Box::pin(group_authority_case("member")).await
}
#[tokio::test(flavor = "current_thread")]
async fn generated_group_requires_pinned_key_epoch() -> Result<(), SdkError> {
    Box::pin(group_authority_case("epoch")).await
}
#[tokio::test(flavor = "current_thread")]
async fn generated_group_refuses_nonempty_authority_proof() -> Result<(), SdkError> {
    Box::pin(group_authority_case("proof")).await
}
#[tokio::test(flavor = "current_thread")]
async fn generated_group_requires_pinned_state_hash() -> Result<(), SdkError> {
    Box::pin(group_authority_case("head")).await
}
#[tokio::test(flavor = "current_thread")]
async fn generated_group_decrypts_with_outer_authority() -> Result<(), SdkError> {
    Box::pin(group_authority_case("valid")).await
}

#[tokio::test(flavor = "current_thread")]
async fn generated_refusals_settle_and_never_stage_locally()
-> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for kind in [3, 4, 5, 7, 108, 110] {
        let (a, mut b) = pair(201, 203)?;
        // A known malformed payload has no target/replacement/operation. This is peer input.
        let bad_bytes = g::Inner {
            layer: 2,
            kind: if kind >= 100 { 8 } else { kind },
            identity: Some(generated_identity(&a, "bad")?),
            body: match kind {
                108 => g::Control {
                    operation: 8,
                    payload: Some(g::control::Payload::HomeMigration(g::HomeMigrationControl {
                        proposal: Some(g::NativeHomeAuthorization { canonical: vec![1] }),
                    })),
                }
                .encode_to_vec(),
                110 => g::Control {
                    operation: 10,
                    payload: Some(g::control::Payload::LivePresence(g::LivePresence {
                        epoch: 1,
                        subjects: vec![generated_identity(&a, "bad")?.author.ok_or("author")?],
                    })),
                }
                .encode_to_vec(),
                _ => Vec::new(),
            },
        }
        .encode_to_vec();
        let first = seal(&a, &b, message("bad", "c"), &bad_bytes)?;
        let good = RamfluxClient::encode_generated_inner(
            generated_identity(&a, "good")?,
            &g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: "after refusal".into(),
                    ..Default::default()
                })),
            },
        )?;
        let mut second = seal(&a, &b, message("good", "c"), &good)?;
        second.inbox_seq = 2;
        let (engine, writes) =
            super::super::review::Inbox::engine(b.config()?, vec![first, second])?;
        let mut account =
            LocalBusAccountState::new(std::mem::take(&mut b.client), engine, b.id.clone());
        crate::bus::sync_driver::run(&mut account).await?;
        b.client = account.client;
        let codes = b.client.account_db()?.journal_after(0, 64)?;
        assert!(
            b.client
                .account_db()?
                .message_content(&ramflux_protocol::encode_base64url(
                    generated_identity(&a, "good")?.id
                ))?
                .is_some(),
            "kind {kind} stalled receive; codes={codes:?}; retries={:?}, cursor={}, writes={:?}",
            b.client.account_db()?.due_inbox_retries(i64::MAX)?,
            b.client.gateway_receive_cursor("bob")?,
            writes.lock().map_err(|_| invalid("writes mutex"))?
        );
        assert!(
            b.client
                .account_db()?
                .message_content(&ramflux_protocol::encode_base64url(
                    generated_identity(&a, "bad")?.id
                ))?
                .is_none()
        );
        assert!(
            writes
                .lock()
                .map_err(|_| invalid("writes mutex"))?
                .iter()
                .any(|frame| frame["frame_type"] == "ack")
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn edit_before_target_is_committed_without_transport_retry_expiry() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(207, 209)?;
    let target = g::MessageRef {
        id: generated_identity(&a, "late-target")?.id,
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    let original = RamfluxClient::encode_generated_inner(
        generated_identity(&a, "late-target")?,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "original late".into(),
                ..Default::default()
            })),
        },
    )?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &original)?;
    let early =
        commit_content(&a, &mut b, "early-edit", edit(&target, 9, digest, "late edit wins"))
            .await?;
    let committed = b.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &early,
    )?;
    assert!(
        b.client
            .account_db()?
            .load_actor_state::<super::super::super::Committed>(&committed)?
            .is_some()
    );
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 1);
    // No transport retry row owns this work: its exact bytes remain after ordinary retry expiry.
    let _clock = crate::time::FixedClock::set(crate::time::now_unix_timestamp() + 31 * 86400);
    super::super::review::trust(&b, &a)?;
    super::super::review::trust(&a, &b)?;
    commit_content(
        &a,
        &mut b,
        "late-target",
        g::content::Value::Message(g::Message {
            text: "original late".into(),
            ..Default::default()
        }),
    )
    .await?;
    let page = b.client.generated_message_page("c", None, 100)?.messages;
    assert!(page.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content { value: Some(g::content::Value::Message(message)) })) if message.text == "late edit wins")));
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn message_receipt_requires_matching_metadata_commitment() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for row in 0..3 {
        let (a, mut b) = pair(199, 201)?;
        let identity = generated_identity(&a, "header-receipt")?;
        let value = if row == 2 {
            g::content::Value::Reaction(g::Reaction {
                target: Some(g::MessageRef {
                    id: vec![8; 32],
                    conversation_id: "c".into(),
                    author_anchor: a.client.own_account_anchor()?,
                }),
                token: "👍".into(),
                operation_id: identity.id.clone(),
                ..Default::default()
            })
        } else {
            g::content::Value::Message(g::Message {
                text: "must not project".into(),
                ..Default::default()
            })
        };
        let bytes =
            RamfluxClient::encode_generated_inner(identity, &g::Content { value: Some(value) })?;
        let mut entry = seal(&a, &b, message("header-receipt", "c"), &bytes)?;
        let key = g::original_header::EXT_KEY;
        if row == 0 {
            entry.envelope.ext.ext.remove(key);
        } else {
            entry
                .envelope
                .ext
                .ext
                .insert(key.into(), serde_json::json!(ramflux_protocol::encode_base64url([0; 32])));
        }
        super::resign(&a, &mut entry.envelope)?;
        let error =
            apply(&mut b, &entry).await.err().ok_or_else(|| invalid("bad header accepted"))?;
        let expected = if row == 0 {
            crate::error::GeneratedRefusalCode::OriginEvidenceMissing
        } else {
            crate::error::GeneratedRefusalCode::OriginCommitmentMismatch
        };
        assert!(
            matches!(error, SdkError::GeneratedRefused { code, .. } if code == expected),
            "{error}"
        );
        assert_eq!(projected(&b, "c")?, 0);
        assert_eq!(
            b.client.account_db()?.list_actor_states::<serde_json::Value>("routed/unsupported/")?,
            Vec::<serde_json::Value>::new()
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn full_message_edit_drops_reply_forward_and_two_media() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(195, 197)?;
    let reference = g::MessageRef {
        id: vec![7; 32],
        conversation_id: "old-reply-conversation-canary".into(),
        author_anchor: "old-reply-author-canary".into(),
    };
    let original = g::Message {
        text: "old-message-body-canary".into(),
        reply_to: Some(reference.clone()),
        forward: Some(g::Forward {
            original: Some(reference),
            original_display_name: Some("old-forward-name-canary".into()),
            origin_assertion: Vec::new(),
        }),
        media: (0..2)
            .map(|index| g::MediaRef {
                object_id: format!("old-media-{index}-canary"),
                manifest_digest: vec![8; 32],
                mime_type: "image/png".into(),
                size: 100,
                key_slots: vec![g::MediaKeySlot {
                    encrypted_key: format!("old-key-{index}-canary").into_bytes(),
                    format: 1,
                    ..Default::default()
                }],
                inline_thumbnail: Some(g::Thumbnail {
                    mime_type: "image/png".into(),
                    width: 1,
                    height: 1,
                    encoded_image: format!("old-thumb-{index}-canary").into_bytes(),
                }),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    commit_content(&a, &mut b, "body-free-target", g::content::Value::Message(original)).await?;
    let target = g::MessageRef {
        id: generated_identity(&a, "body-free-target")?.id,
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    let id = ramflux_protocol::encode_base64url(&target.id);
    let old = b.client.account_db()?.message_content(&id)?.ok_or_else(|| invalid("old body"))?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &old)?;
    commit_content(&a, &mut b, "drop-all-body-fields", edit(&target, 1, digest, "current body"))
        .await?;
    let body =
        b.client.account_db()?.message_content(&id)?.ok_or_else(|| invalid("current body"))?;
    let message = g::Message::decode(
        g::exact_content::message_in_force(&body).map_err(|_| invalid("current Message"))?,
    )
    .map_err(|_| invalid("decode"))?;
    assert_eq!(message.text, "current body");
    assert_eq!(message.media, Vec::<g::MediaRef>::new());
    assert!(message.reply_to.is_none());
    assert!(message.forward.is_none());
    assert!(matches!(
        b.client.selected_franking_evidence_for_direct_message("c", &id),
        Err(SdkError::HistoryEvidence(g::original_header::EvidenceError::ReportOpeningRetired))
    ));
    for prefix in ["routed/group-content/", "own-copy/prepared/", "history/page/"] {
        assert_eq!(b.client.account_db()?.actor_state_keys(prefix)?, Vec::<String>::new());
    }
    Ok(())
}

async fn reaction_at(
    a: &Fixture,
    b: &mut Fixture,
    target: &g::MessageRef,
    token: &str,
    hlc: u64,
    remove: bool,
) -> Result<(), SdkError> {
    let name = format!("reaction-{token}-{hlc}-{remove}");
    let mut identity = generated_identity(a, &name)?;
    identity.hlc = hlc;
    let reaction = g::Reaction {
        target: Some(target.clone()),
        token: token.into(),
        operation_id: identity.id.clone(),
        remove,
    };
    let bytes = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content { value: Some(g::content::Value::Reaction(reaction)) },
    )?;
    let entry = seal(a, b, message(&name, "c"), &bytes)?;
    apply(b, &entry).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn reaction_signed_order_advances_absent_noops_and_bounds_visible_tokens()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(181, 183)?;
    commit_content(
        &a,
        &mut b,
        "reaction-target",
        g::content::Value::Message(g::Message { text: "target".into(), ..Default::default() }),
    )
    .await?;
    let target = g::MessageRef {
        id: generated_identity(&a, "reaction-target")?.id,
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    let id = ramflux_protocol::encode_base64url(&target.id);
    reaction_at(&a, &mut b, &target, "👍", 30, true).await?;
    reaction_at(&a, &mut b, &target, "👍", 50, true).await?;
    reaction_at(&a, &mut b, &target, "👍", 40, false).await?;
    assert!(
        b.client.generated_visible_reactions(&id)?.is_empty(),
        "a greater absent no-op must defeat an older add"
    );
    reaction_at(&a, &mut b, &target, "👍", 60, false).await?;
    reaction_at(&a, &mut b, &target, "👍", 55, true).await?;
    assert_eq!(b.client.generated_visible_reactions(&id)?.len(), 1);
    for (index, token) in ["😀", "😁", "😂", "😃", "😄", "😅", "😆", "😉"].into_iter().enumerate()
    {
        reaction_at(&a, &mut b, &target, token, 100 + index as u64, false).await?;
    }
    let visible = b.client.generated_visible_reactions(&id)?;
    assert_eq!(visible.len(), 8);
    assert!(
        visible.iter().all(|reaction| reaction.token != "👍"),
        "visible selection uses greatest immutable signed order"
    );
    assert_eq!(b.client.account_db()?.message_actor_keys(&id, "routed/reaction/")?.len(), 9);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn reaction_register_capacity_counts_absent_markers_and_allows_existing_updates()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(177, 179)?;
    commit_content(
        &a,
        &mut b,
        "capacity-target",
        g::content::Value::Message(g::Message { text: "target".into(), ..Default::default() }),
    )
    .await?;
    let target = g::MessageRef {
        id: generated_identity(&a, "capacity-target")?.id,
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    let id = ramflux_protocol::encode_base64url(&target.id);
    reaction_at(&a, &mut b, &target, "👍", 10, true).await?;
    // Seed an already full store to exercise admission without sending 2048 pair packets.
    let db = b.client.account_db()?;
    let marker = db
        .message_actor_entries::<serde_json::Value>(&id, "routed/reaction/")?
        .into_iter()
        .next()
        .ok_or_else(|| invalid("absent marker"))?
        .1;
    db.write_transaction(|| -> Result<(), SdkError> {
        for index in 1..2048 {
            db.persist_message_actor_state(
                &id,
                &format!("routed/reaction/capacity-slot-{index}"),
                &marker,
            )?;
        }
        Ok(())
    })?;
    assert!(
        matches!(
            reaction_at(&a, &mut b, &target, "😀", 20, true).await,
            Err(SdkError::GeneratedRefused { .. })
        ),
        "new absent keys also consume register capacity"
    );
    reaction_at(&a, &mut b, &target, "👍", 30, false).await?;
    assert_eq!(b.client.generated_visible_reactions(&id)?.len(), 1);
    assert_eq!(b.client.account_db()?.message_actor_keys(&id, "routed/reaction/")?.len(), 2048);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn message_logical_id_refuses_changed_body_or_hlc_without_retaining_a_body_digest()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(173, 175)?;
    commit_content(
        &a,
        &mut b,
        "immutable-target",
        g::content::Value::Message(g::Message { text: "immutable".into(), ..Default::default() }),
    )
    .await?;
    let id = ramflux_protocol::encode_base64url(generated_identity(&a, "immutable-target")?.id);
    let original =
        b.client.account_db()?.message_content(&id)?.ok_or_else(|| invalid("original"))?;
    for change_hlc in [false, true] {
        let mut inner = g::Inner::decode(original.as_slice()).map_err(|_| invalid("inner"))?;
        if change_hlc {
            inner.identity.as_mut().ok_or_else(|| invalid("identity"))?.hlc += 1;
        } else {
            inner.body = g::Message { text: "forged replacement".into(), ..Default::default() }
                .encode_to_vec();
        }
        let entry = seal(&a, &b, message("changed-logical-id", "c"), &inner.encode_to_vec())?;
        assert!(matches!(apply(&mut b, &entry).await, Err(SdkError::ReplayMismatch)));
        assert_eq!(b.client.account_db()?.message_content(&id)?, Some(original.clone()));
    }
    Ok(())
}

fn moderator_group_fixture() -> Result<(Fixture, Fixture, Fixture, u64), SdkError> {
    let (a, b) = pair(141, 143)?;
    let c = Fixture::new("carol", 145)?;
    b.client.establish_friend_link(
        "carol-link",
        &c.client.own_account_anchor()?,
        &b.client.own_account_anchor()?,
    )?;
    for client in [&a.client, &b.client, &c.client] {
        for peer in [&a, &b, &c] {
            let manifest = crate::client::identity_authority::test_support::manifest(&peer.client)?;
            client.observe_device_manifest_json(
                serde_json::to_value(&manifest)?,
                &manifest.principal_commitment,
            )?;
        }
    }
    b.client.shared_group_create("moderator-group", "c", None, "target-bob")?;
    for (peer, role, target) in [
        (&a, ramflux_protocol::SharedGroupRole::Admin, "target-alice"),
        (&c, ramflux_protocol::SharedGroupRole::Member, "target-carol"),
    ] {
        b.client.shared_group_change(
            "moderator-group",
            "target-bob",
            ramflux_protocol::group_state::GroupStateChange::Add {
                member: peer.client.owned_group_actor(target)?.identity,
                role,
            },
        )?;
    }
    let state = b
        .client
        .account_db()?
        .shared_group_state("moderator-group")?
        .ok_or_else(|| invalid("moderator group state"))?;
    let epoch = state.snapshot().epoch;
    a.client.accept_shared_group_state(&state, "target-alice")?;
    c.client.accept_shared_group_state(&state, "target-carol")?;
    b.client.import_group_sender_key_distribution(
        &c.client.export_group_sender_key_distribution("moderator-group", "carol")?,
    )?;
    Ok((a, b, c, epoch))
}

fn moderator_delete_entry(
    a: &Fixture,
    b: &Fixture,
    epoch: u64,
    target: &g::MessageRef,
) -> Result<GatewayInboxEntry, SdkError> {
    let mut delete_identity = generated_identity(a, "pending-moderator-delete")?;
    delete_identity.group_id = Some("moderator-group".into());
    delete_identity.group_epoch = Some(epoch);
    let delete = g::Delete {
        targets: vec![target.clone()],
        scope: g::DeleteScope::Everyone as i32,
        tombstone_id: g::identity::delete_tombstone(&delete_identity.id)
            .map_err(|_| invalid("tombstone"))?
            .to_vec(),
        ..Default::default()
    };
    let raw = RamfluxClient::encode_generated_inner(
        delete_identity,
        &g::Content { value: Some(g::content::Value::Delete(delete)) },
    )?;
    let entry = seal_as(
        a,
        b,
        super::super::message("moderator-delete", "c"),
        &raw,
        Route::group_message("moderator-group"),
    )?;
    Ok(entry)
}

#[tokio::test(flavor = "current_thread")]
async fn pending_moderator_delete_is_ignored_after_demotion_without_poisoning_target()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b, c, epoch) = moderator_group_fixture()?;
    let mut target_identity = generated_identity(&c, "late-moderated-target")?;
    target_identity.group_id = Some("moderator-group".into());
    target_identity.group_epoch = Some(epoch);
    let target = g::MessageRef {
        id: target_identity.id.clone(),
        conversation_id: "c".into(),
        author_anchor: c.client.own_account_anchor()?,
    };
    let entry = moderator_delete_entry(&a, &b, epoch, &target)?;
    apply(&mut b, &entry).await?;
    b.client.shared_group_change(
        "moderator-group",
        "target-bob",
        ramflux_protocol::group_state::GroupStateChange::SetRole {
            root_commitment: a.client.own_account_anchor()?,
            device_id: "alice".into(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let message = c.client.encrypt_generated_group_message(
        "moderator-group",
        "carol",
        &g::Message {
            text: "late target survives".into(),
            erasure_nonce: vec![52; 32],
            ..Default::default()
        },
    )?;
    let raw = RamfluxClient::encode_generated_inner(
        target_identity,
        &g::Content { value: Some(g::content::Value::Message(message)) },
    )?;
    let mut draft = super::super::message("late-moderated-target", "c");
    draft.source_principal_id = "carol".into();
    draft.sender_id = "carol".into();
    let entry = seal_as(&c, &b, draft, &raw, Route::group_message("moderator-group"))?;
    apply(&mut b, &entry).await?;
    let id = ramflux_protocol::encode_base64url(&target.id);
    assert!(!b.client.account_db()?.message_is_deleted(&id)?);
    assert!(b.client.generated_message_page("c", None, 100)?.messages.iter().any(|update| matches!(update.state.as_ref(),
        Some(g::message_update::State::Content(g::Content {value:Some(g::content::Value::Message(message))}))
        if message.text=="late target survives")));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn typed_tombstones_preserve_raw_identity_recorded_scope_and_invalidate_actual_cache()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(131, 133)?;
    let mut cache = crate::typed_messages::MessageCache::default();
    for (name, local) in [("everyone-reader", false), ("local-reader", true)] {
        commit_content(
            &a,
            &mut b,
            name,
            g::content::Value::Message(g::Message {
                text: "preview that must disappear".into(),
                ..Default::default()
            }),
        )
        .await?;
        let original = generated_identity(&a, name)?;
        let id = ramflux_protocol::encode_base64url(&original.id);
        let page = b.client.generated_message_page("c", None, 100)?.messages;
        let update = page
            .into_iter()
            .find(|update| {
                update.identity.as_ref().is_some_and(|identity| identity.id == original.id)
            })
            .ok_or_else(|| invalid("live typed row missing"))?;
        cache.apply(update);
        if local {
            let tombstone =
                g::identity::delete_tombstone(&generated_identity(&b, "local-reader-delete")?.id)
                    .map_err(|_| invalid("tombstone"))?;
            b.client.delete_direct_message(
                "c",
                &id,
                "local",
                &ramflux_protocol::encode_base64url(tombstone),
            )?;
        } else {
            commit_content(
                &a,
                &mut b,
                "everyone-reader-delete",
                g::content::Value::Delete(g::Delete {
                    targets: vec![g::MessageRef {
                        id: original.id.clone(),
                        conversation_id: "c".into(),
                        author_anchor: a.client.own_account_anchor()?,
                    }],
                    scope: g::DeleteScope::Everyone as i32,
                    ..Default::default()
                }),
            )
            .await?;
        }
        let page = b.client.generated_message_page("c", None, 100)?.messages;
        let update = page
            .into_iter()
            .find(|update| {
                update.identity.as_ref().is_some_and(|identity| identity.id == original.id)
            })
            .ok_or_else(|| invalid("typed tombstone identity changed"))?;
        let Some(g::message_update::State::Tombstone(delete)) = update.state.as_ref() else {
            return Err(invalid("typed tombstone missing"));
        };
        assert_eq!(update.identity.as_ref(), Some(&original));
        assert_eq!(
            delete.scope,
            if local { g::DeleteScope::Local } else { g::DeleteScope::Everyone } as i32
        );
        assert_eq!(
            delete.targets.first().ok_or_else(|| invalid("target"))?.author_anchor,
            a.client.own_account_anchor()?
        );
        assert_eq!(delete.tombstone_id.len(), 32);
        cache.apply(update);
        let cached = cache.get("c", &original.id).ok_or_else(|| invalid("cache entry"))?;
        assert!(matches!(cached.state, Some(g::message_update::State::Tombstone(_))));
        assert!(!serde_json::to_string(cached)?.contains("preview that must disappear"));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn typed_identity_retention_never_preserves_payload_shadows_or_unbound_headers()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(127, 129)?;
    for case in 0..7 {
        let name = format!("invalid-header-{case}");
        commit_content(
            &a,
            &mut b,
            &name,
            g::content::Value::Message(g::Message {
                text: "retired header canary".into(),
                ..Default::default()
            }),
        )
        .await?;
        let original = generated_identity(&a, &name)?;
        let id = ramflux_protocol::encode_base64url(&original.id);
        let key = format!("routed/generated-identity/{id}");
        let mut header = serde_json::to_value(&original)?;
        match case {
            0 => header["retired_body"] = serde_json::json!("retired header canary"),
            1 => header["author"]["retired_body"] = serde_json::json!("retired header canary"),
            2 => header["id"] = serde_json::json!("unbound"),
            3 => header["conversationId"] = serde_json::json!("another-conversation"),
            4 => header["author"] = serde_json::Value::Null,
            5 => header["hlc"] = serde_json::json!({"retired_body":"retired header canary"}),
            _ => header["deviceSequence"] = serde_json::json!("retired header canary"),
        }
        b.client.account_db()?.persist_message_actor_state(&id, &key, &header)?;
        let tombstone =
            g::identity::delete_tombstone(&[8; 32]).map_err(|_| invalid("tombstone"))?;
        b.client.delete_direct_message(
            "c",
            &id,
            "local",
            &ramflux_protocol::encode_base64url(tombstone),
        )?;
        assert!(
            !b.client.account_db()?.actor_state_exists(&key)?,
            "invalid header {case} survived erasure"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn message_page_projects_generated_content_and_unsupported() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(151, 153)?;
    let mut expected = Vec::new();
    for index in 0..8 {
        let name = format!("paged-{index}");
        if index == 3 {
            let raw = unknown_inner(&a, &name)?;
            let entry = seal(&a, &b, message(&name, "c"), &raw)?;
            apply(&mut b, &entry).await?;
        } else {
            commit_content(
                &a,
                &mut b,
                &name,
                g::content::Value::Message(g::Message {
                    text: format!("page text {index}"),
                    ..Default::default()
                }),
            )
            .await?;
        }
        let identity = generated_identity(&a, &name)?;
        let event=b.client.account_db()?.append_journal(&format!("page-{index}"),"message.updated",&serde_json::json!({"message_id":ramflux_protocol::encode_base64url(&identity.id),"conversation_id":"c"}),100,None)?;
        expected.push((
            g::identity::order_key(&identity).map_err(|_| invalid("order"))?,
            identity,
            event.seq,
        ));
    }
    let head = b
        .client
        .account_db()?
        .append_journal("unrelated-head", "sync.status", &serde_json::json!({}), 100, None)?
        .seq;
    // Row sequences survive pruning; a new snapshot sequence must never replace them.
    b.client.account_db()?.retain_journal(1000, 0, 0)?;
    expected.sort_unstable_by(|left, right| right.0.cmp(&left.0));
    let mut actual = Vec::new();
    let mut before = None;
    let mut pages = 0;
    loop {
        let page = b.client.generated_message_page("c", before.as_ref(), 3)?;
        assert!(page.messages.len() <= 3);
        assert_eq!(page.snapshot_sequence, head);
        actual.extend(page.messages);
        pages += 1;
        before = page.next_before;
        if before.is_none() {
            break;
        }
        assert!(pages < 4, "cursor must make progress");
    }
    assert_eq!(pages, 3);
    assert_eq!(actual.len(), 8);
    for (row, (_, identity, seq)) in actual.iter().zip(&expected) {
        assert_eq!(row.identity.as_ref(), Some(identity));
        assert_eq!(row.journal_sequence, *seq);
        assert!(row.journal_sequence < head);
    }
    assert!(
        actual
            .iter()
            .any(|row| matches!(row.state, Some(g::message_update::State::Unsupported(_))))
    );
    let json = serde_json::to_string(&actual)?;
    assert!(
        !json.contains("exact_inner")
            && !json.contains("report_opening")
            && !json.contains("source_evidence")
    );
    assert!(b.client.generated_message_page("c", None, 0).is_err());
    assert!(b.client.generated_message_page("c", None, 101).is_err());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn message_page_respects_encoded_byte_cap_and_continuation() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(161, 163)?;
    for index in 0..4 {
        commit_content(
            &a,
            &mut b,
            &format!("large-page-{index}"),
            g::content::Value::Message(g::Message {
                text: "x".repeat(256 * 1024),
                ..Default::default()
            }),
        )
        .await?;
    }
    let first = b.client.generated_message_page("c", None, 100)?;
    assert_eq!(first.messages.len(), 2);
    assert!(serde_json::to_vec(&first)?.len() <= 768 * 1024);
    let second = b.client.generated_message_page("c", first.next_before.as_ref(), 100)?;
    assert_eq!(second.messages.len(), 2);
    assert!(second.next_before.is_none());
    let first_ids = first
        .messages
        .iter()
        .filter_map(|row| row.identity.as_ref())
        .map(|id| &id.id)
        .collect::<Vec<_>>();
    assert!(
        second
            .messages
            .iter()
            .filter_map(|row| row.identity.as_ref())
            .all(|id| !first_ids.contains(&&id.id))
    );
    Ok(())
}

#[tokio::test]
async fn ordinary_dm_binds_verified_roots_and_refuses_conflicting_scope() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for ordinal in 0..7 {
        // Each refusal is independent; the receive-pass settlement regression covers
        // ratchet progress after refused peer input on the same pair.
        let (a, mut b) = pair(201, 203)?;
        let scope =
            g::dm_scope::derive(&a.client.own_account_anchor()?, &b.client.own_account_anchor()?)
                .map_err(|_| invalid("fixture DM roots"))?;
        let conversation = if ordinal == 0 { "unbound-arbitrary" } else { scope.as_str() };
        let fence_key = format!(
            "self-sync/erase/{}",
            ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&(
                b.client.own_account_anchor()?,
                &scope
            ))?)
        );
        let fence = serde_json::json!({"conversation_id":scope,"erased":true});
        b.client.account_db()?.persist_actor_state(&fence_key, &fence)?;
        let mut identity = generated_identity(&a, &format!("dm-{ordinal}"))?;
        identity.conversation_id = conversation.into();
        identity.id = g::identity::derive(
            identity.author.as_ref().ok_or_else(|| invalid("author"))?,
            conversation,
            identity.device_sequence,
        )
        .map_err(|_| invalid("fixture id"))?
        .to_vec();
        let id = ramflux_protocol::encode_base64url(&identity.id);
        let raw = RamfluxClient::encode_generated_inner(
            identity,
            &g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: "DM".into(),
                    ..Default::default()
                })),
            },
        )?;
        if ordinal == 2 {
            let bound = serde_json::json!({"kind":"direct","group_id":null,"participants":["alice","bob"],"participant_roots":[b.client.own_account_anchor()?,ramflux_protocol::encode_base64url([99;32])]});
            b.client.account_db()?.persist_client_record("conversation", &scope, &bound)?;
        } else if ordinal == 3 {
            b.client.account_db()?.persist_client_record(
                "conversation",
                &scope,
                &serde_json::json!({"kind":"group", "group_id":"squat"}),
            )?;
        }
        if ordinal == 4 {
            b.client.account_db()?.persist_client_record("conversation", &scope, &serde_json::json!({"kind":"direct","group_id":null,"participants":["alice","mallory"]}))?;
        }
        if ordinal >= 5 {
            let mut bound =
                serde_json::json!({"kind":"direct","group_id":null,"participants":["alice","bob"]});
            bound["participant_roots"] = if ordinal == 5 {
                serde_json::json!("not-a-root-array")
            } else {
                serde_json::json!([b.client.own_account_anchor()?, null])
            };
            b.client.account_db()?.persist_client_record("conversation", &scope, &bound)?;
        }
        let entry = seal(&a, &b, message(&format!("dm-{ordinal}"), conversation), &raw)?;
        let result = apply(&mut b, &entry).await;
        if ordinal == 1 {
            result?;
            let bound = b
                .client
                .account_db()?
                .client_record("conversation", &scope)?
                .ok_or_else(|| invalid("binding"))?;
            assert_eq!(bound["participant_roots"].as_array().map(Vec::len), Some(2));
            assert!(b.client.account_db()?.message_content(&id)?.is_some());
            assert_eq!(
                b.client.generated_direct_conversation_id(&a.client.owned_device_identity()?)?,
                scope
            );
        } else {
            assert!(result.is_err(), "accepted conflicting scope {ordinal}");
            assert!(b.client.account_db()?.message_content(&id)?.is_none());
        }
        assert_eq!(
            b.client.account_db()?.load_actor_state::<serde_json::Value>(&fence_key)?,
            Some(fence)
        );
        assert!(
            b.client.account_db()?.client_record("conversation", "unbound-arbitrary")?.is_none()
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn early_edit_register_is_qualified_by_original_author_root() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(173, 175)?;
    let c = Fixture::new("carol", 177)?;
    b.client.establish_friend_link(
        "carol-link",
        &c.client.own_account_anchor()?,
        &b.client.own_account_anchor()?,
    )?;
    let target = g::MessageRef {
        id: generated_identity(&a, "qualified-target")?.id,
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    commit_content(&a, &mut b, "qualified-edit", edit(&target, 1, [0; 32], "rightful edit"))
        .await?;
    // A different direct conversation lets an accepted foreign peer name the same
    // opaque target id without claiming membership in Alice's direct conversation.
    let mut identity = generated_identity(&c, "foreign-edit")?;
    identity.conversation_id = "foreign".into();
    identity.id = g::identity::derive(
        identity.author.as_ref().ok_or_else(|| invalid("author"))?,
        "foreign",
        identity.device_sequence,
    )
    .map_err(|_| invalid("foreign identity"))?
    .to_vec();
    let claimed = g::MessageRef {
        id: target.id.clone(),
        conversation_id: "foreign".into(),
        author_anchor: c.client.own_account_anchor()?,
    };
    let raw = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content { value: Some(edit(&claimed, 1_000_000, [0; 32], "foreign poisoning")) },
    )?;
    let mut draft = message("foreign-edit", "foreign");
    draft.source_principal_id = "carol".into();
    draft.sender_id = "carol".into();
    b.client.account_db()?.persist_client_record(
        "conversation",
        "foreign",
        &serde_json::json!({
            "kind":"direct", "group_id":null, "participants":["bob","carol"],
            "participant_roots":[b.client.own_account_anchor()?,c.client.own_account_anchor()?],
        }),
    )?;
    let incoming = seal(&c, &b, draft, &raw)?;
    apply(&mut b, &incoming).await?;
    assert_eq!(
        b.client.account_db()?.unsupported_raw_quota(None)?.owners,
        2,
        "foreign root replaced the legitimate pending Edit"
    );
    commit_content(
        &a,
        &mut b,
        "qualified-target",
        g::content::Value::Message(g::Message { text: "original".into(), ..Default::default() }),
    )
    .await?;
    let page = b.client.generated_message_page("c", None, 100)?.messages;
    assert!(page.iter().any(|update| matches!(update.state.as_ref(), Some(g::message_update::State::Content(g::Content {
        value:Some(g::content::Value::Message(message))
    })) if message.text=="rightful edit")), "foreign root replaced the legitimate pending Edit");
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    Ok(())
}

#[path = "candidate_reparse_edit_tests.rs"]
mod reparse_edit;

#[path = "candidate_control_executor_tests.rs"]
mod control_executor;

#[path = "candidate_native_control_tests.rs"]
mod native_control;

#[tokio::test(flavor = "current_thread")]
async fn stale_self_sync_draft_retains_only_content_free_delivery_receipt() -> Result<(), SdkError>
{
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let a = Fixture::owned("alice", "sync-receipt-owner", 231, 232)?;
    let mut b = Fixture::owned("bob", "sync-receipt-owner", 231, 234)?;
    let value = a.client.change_self_sync(
        "c",
        g::SelfSync {
            operation: 2,
            draft: Some(g::Message { text: "obsolete private draft".into(), ..Default::default() }),
            ..Default::default()
        },
    )?;
    let raw = a
        .client
        .account_db()?
        .write_transaction(|| a.client.self_sync_publication_inner("c", &value))?;
    for _ in 0..2 {
        b.client.change_self_sync("c", g::SelfSync { operation: 3, ..Default::default() })?;
    }
    let mut draft = message("stale-sync-delivery", "c");
    draft.source_principal_id = a.config()?.principal_id;
    let entry = seal_as(&a, &b, draft, &raw, Route::control())?;
    apply(&mut b, &entry).await?;
    let receipt = b.client.authenticated_committed_key(HeadUse::NewAuthorization, &entry)?;
    let committed = b
        .client
        .account_db()?
        .load_actor_state::<super::super::super::Committed>(&receipt)?
        .ok_or_else(|| invalid("SelfSync receipt missing"))?;
    assert!(
        committed.entry.envelope.encrypted_payload.is_empty(),
        "a cleared draft cannot survive as recoverable pair ciphertext"
    );
    assert!(b.client.event_body(&format!("gateway/delivery/v2/{receipt}"))?.is_none());
    let state = b.client.self_sync_state("c", &value)?.ok_or_else(|| invalid("SelfSync state"))?;
    assert_eq!(state.value.operation, 3);
    assert_eq!(state.value.revision, 2);
    assert_eq!(b.client.account_db()?.actor_state_usage("self-sync/repair/")?.0, 1);
    Ok(())
}

#[test]
fn cleared_self_sync_register_discards_a_prepared_courier_plan_before_ratchet_work()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let a = Fixture::owned("alice", "sync-plan-owner", 221, 222)?;
    let b = Fixture::owned("bob", "sync-plan-owner", 221, 224)?;
    super::review::trust(&a, &b)?;
    let target = b.client.owned_device_identity()?;
    let value = a.client.change_self_sync(
        "c",
        g::SelfSync {
            operation: 2,
            draft: Some(g::Message { text: "erase queued draft".into(), ..Default::default() }),
            ..Default::default()
        },
    )?;
    a.client.bootstrap_self_sync(&target)?;
    let config = a.config()?;
    let plan = a.client.prepare_self_sync_repair(&config)?.ok_or_else(|| invalid("repair plan"))?;
    a.client.change_self_sync("c", g::SelfSync { operation: 3, ..Default::default() })?;
    let before = a.client.account_db()?.test_table_fingerprints(&[])?;
    assert!(
        a.client
            .seal_self_sync_repair(
                &config,
                plan,
                super::super::super::SendMaterial { manifest: None, bundle: None }
            )?
            .is_none()
    );
    assert_eq!(
        a.client.account_db()?.test_table_fingerprints(&[])?,
        before,
        "obsolete plan cannot allocate an identity or advance the ratchet"
    );
    assert!(
        a.client
            .self_sync_state("c", &value)?
            .ok_or_else(|| invalid("clear"))?
            .value
            .draft
            .is_none()
    );
    Ok(())
}
