// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Module gate rows for the unified read model.
//! Ciphertext, sender authority, the committed binding and pair crypto are real; the node entry
//! check runs before every apply. The process-level rows live in `apps/rf/tests`.
use super::*;

fn text(value: &str) -> g::content::Value {
    g::content::Value::Message(g::Message { text: value.into(), ..Default::default() })
}

fn view<'a>(
    views: &'a [crate::typed_read_model::MessageView],
    id: &[u8],
) -> Result<&'a crate::typed_read_model::MessageView, SdkError> {
    let id = ramflux_protocol::encode_base64url(id);
    views.iter().find(|view| view.id == id).ok_or_else(|| invalid("view missing"))
}

fn assert_detail_and_missing_ids(
    client: &RamfluxClient,
    target_id: &str,
    sequence: u64,
) -> Result<(), SdkError> {
    let detail = client.generated_message_detail("c", target_id)?;
    assert_eq!(detail.message.text.as_deref(), Some("edited one"));
    assert_eq!(detail.message.journal_sequence, sequence);
    let missing = ramflux_protocol::encode_base64url([9_u8; 32]);
    for (id, code) in [
        (missing.as_str(), crate::bindings::GeneratedErrorCode::TargetNotFound),
        ("short", crate::bindings::GeneratedErrorCode::InvalidArgument),
    ] {
        let error = client.generated_message_detail("c", id).err().ok_or_else(|| invalid("id"))?;
        assert_eq!(crate::bindings::AdapterError::from_sdk(&error).code, code as i32);
    }

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn read_model_serves_page_changes_and_detail_from_the_durable_store() -> Result<(), SdkError>
{
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(211, 213)?;
    commit_content(&a, &mut b, "target", text("first body zq")).await?;
    let target = g::MessageRef {
        id: generated_identity(&a, "target")?.id,
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    let target_id = ramflux_protocol::encode_base64url(&target.id);
    let original = b
        .client
        .account_db()?
        .message_content(&target_id)?
        .ok_or_else(|| invalid("original missing"))?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &original)?;
    commit_content(&a, &mut b, "edit-one", edit(&target, 1, digest, "edited one")).await?;
    commit_content(
        &a,
        &mut b,
        "react",
        g::content::Value::Reaction(g::Reaction {
            target: Some(target.clone()),
            token: "👍".into(),
            operation_id: Vec::new(),
            remove: false,
        }),
    )
    .await?;
    let unknown = unknown_inner(&a, "unknown-wire")?;
    let unknown_id = g::Inner::decode(unknown.as_slice())
        .map_err(|_| invalid("Inner"))?
        .identity
        .ok_or_else(|| invalid("identity"))?
        .id;
    let unknown_entry = seal(&a, &b, message("unknown-wire", "c"), &unknown)?;
    apply(&mut b, &unknown_entry).await?;

    let page = b.client.generated_message_view_page("c", None, 100)?;
    assert_eq!(page.schema, crate::typed_read_model::READ_MODEL_SCHEMA);
    assert_eq!(page.messages.len(), 2, "Edit and Reaction are state of the target, not rows");
    let edited = view(&page.messages, &target.id)?;
    assert_eq!(
        (edited.state, edited.kind, edited.text.as_deref(), edited.revision, edited.edited),
        ("content", "message", Some("edited one"), 1, true)
    );
    assert_eq!(
        edited.reactions,
        vec![crate::typed_read_model::ReactionView { token: "👍".into(), count: 1 }]
    );
    assert!(!edited.is_own && edited.erasure.is_none() && edited.unsupported.is_none());
    let placeholder = view(&page.messages, &unknown_id)?;
    assert_eq!((placeholder.state, placeholder.kind), ("unsupported", "unsupported"));
    assert!(placeholder.content.is_none() && placeholder.text.is_none());
    assert_eq!(placeholder.unsupported.as_ref().map(|view| view.kind), Some(900));
    let encoded = serde_json::to_string(&page)?;
    assert!(!encoded.contains("first body zq"), "replaced body leaked into the read model");

    assert_detail_and_missing_ids(&b.client, &target_id, edited.journal_sequence)?;

    let snapshot = b.client.generated_message_changes("c", 0, 100)?;
    assert_eq!(snapshot.changes.len(), 2);
    assert!(!snapshot.more);
    assert!(
        snapshot
            .changes
            .windows(2)
            .all(|pair| pair[0].journal_sequence <= pair[1].journal_sequence)
    );
    assert_eq!(snapshot.next_after, snapshot.snapshot_sequence);
    let idle = b.client.generated_message_changes("c", snapshot.next_after, 100)?;
    assert!(idle.changes.is_empty() && !idle.more);
    assert_eq!(idle.next_after, snapshot.next_after);

    commit_content(
        &a,
        &mut b,
        "delete",
        g::content::Value::Delete(g::Delete {
            targets: vec![target.clone()],
            scope: g::DeleteScope::Everyone as i32,
            tombstone_id: Vec::new(),
            native_group_authorization: Vec::new(),
        }),
    )
    .await?;
    let erased = b.client.generated_message_changes("c", snapshot.next_after, 100)?;
    assert_eq!(erased.changes.len(), 1, "only the deleted row changed after the cursor");
    let tombstone = view(&erased.changes, &target.id)?;
    assert_eq!((tombstone.state, tombstone.kind), ("tombstone", "tombstone"));
    assert_eq!(tombstone.erasure.as_ref().map(|erasure| erasure.scope), Some("everyone"));
    assert!(tombstone.text.is_none() && tombstone.content.is_none());
    assert!(tombstone.reactions.is_empty() && tombstone.receipts.is_empty());
    assert_eq!((tombstone.revision, tombstone.edited), (0, false));
    let encoded = serde_json::to_string(&erased)?;
    assert!(!encoded.contains("edited one") && !encoded.contains("👍"));
    assert!(erased.next_after > snapshot.next_after);

    assert_cursor_bounds(&b.client, erased.snapshot_sequence)?;
    Ok(())
}

/// Regression for the delivery-page loss: more unread rows than the old 64-entry page are all
/// served, in commit order, by durable change batches alone.
#[tokio::test(flavor = "current_thread")]
async fn durable_changes_serve_a_backlog_larger_than_the_delivery_page() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(215, 217)?;
    let total = 70_usize;
    for index in 0..total {
        commit_content(&a, &mut b, &format!("bulk-{index}"), text(&format!("body {index}")))
            .await?;
    }
    let mut cursor = 0;
    let mut seen = std::collections::BTreeSet::new();
    let mut batches = 0;
    loop {
        let batch = b.client.generated_message_changes("c", cursor, 32)?;
        assert!(batch.next_after >= cursor, "cursor moved backwards");
        for change in &batch.changes {
            assert!(cursor == 0 || change.journal_sequence > cursor);
            assert!(seen.insert(change.id.clone()), "row delivered twice");
        }
        cursor = batch.next_after;
        batches += 1;
        if !batch.more {
            break;
        }
        assert!(batches < 16, "change batches do not terminate");
    }
    assert_eq!(seen.len(), total, "a committed message was not served");
    assert!(batches >= 3);
    for index in [0, 63, 64, total - 1] {
        let id = ramflux_protocol::encode_base64url(
            generated_identity(&a, &format!("bulk-{index}"))?.id,
        );
        assert_eq!(
            b.client.generated_message_detail("c", &id)?.message.text,
            Some(format!("body {index}"))
        );
    }
    Ok(())
}

/// Tampered committed-binding row: an entry whose bound outer fields were altered is refused
/// and nothing reaches the read model. Calibration: the untouched entry is served.
#[tokio::test(flavor = "current_thread")]
async fn tampered_committed_binding_is_refused_and_never_served() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(219, 221)?;
    commit_content(&a, &mut b, "calibration", text("calibration body")).await?;
    assert_eq!(b.client.generated_message_changes("c", 0, 100)?.changes.len(), 1);

    let raw = RamfluxClient::encode_generated_inner(
        generated_identity(&a, "tampered")?,
        &g::Content { value: Some(text("must never be served")) },
    )?;
    let entry = seal(&a, &b, message("tampered", "c"), &raw)?;
    let mut variants = Vec::new();
    let mut changed = entry.clone();
    changed.envelope.payload_hash = ramflux_protocol::encode_base64url([0x5a_u8; 32]);
    variants.push(("payload hash", changed));
    let mut changed = entry.clone();
    changed.envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0_u8; 32]));
    variants.push(("collapse tag", changed));
    let mut changed = entry.clone();
    changed.envelope.delivery_mode = Some("ephemeral".into());
    variants.push(("delivery mode", changed));
    for (name, tampered) in variants {
        assert!(apply(&mut b, &tampered).await.is_err(), "tampered {name} was accepted");
        let served = b.client.generated_message_changes("c", 0, 100)?;
        assert_eq!(served.changes.len(), 1, "tampered {name} reached the read model");
        assert!(!serde_json::to_string(&served)?.contains("must never be served"));
        assert_eq!(b.client.generated_message_view_page("c", None, 100)?.messages.len(), 1);
    }
    Ok(())
}

fn assert_cursor_bounds(client: &RamfluxClient, sequence: u64) -> Result<(), SdkError> {
    let future = client.generated_message_changes("c", sequence + 1_000, 100);
    let error = future.err().ok_or_else(|| invalid("future cursor accepted"))?;
    assert_eq!(
        crate::bindings::AdapterError::from_sdk(&error).code,
        crate::bindings::GeneratedErrorCode::ResyncRequired as i32
    );
    for limit in [0, 101] {
        assert!(client.generated_message_changes("c", 0, limit).is_err());
    }
    Ok(())
}
