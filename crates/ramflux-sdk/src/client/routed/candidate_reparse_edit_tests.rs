// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Upgrade-install regressions using the dormant generation-zero receipt fixture.
//! Ciphertext, sender authority, C and pair crypto are real; decoder upgrade is staged locally.
use super::*;

fn retain_original_for_upgrade(a: &Fixture, b: &Fixture, raw: &[u8]) -> Result<String, SdkError> {
    let identity = g::Inner::decode(raw)
        .map_err(|_| invalid("Inner"))?
        .identity
        .ok_or_else(|| invalid("identity"))?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let entry = seal(a, b, message("upgrade-opaque-original", "c"), raw)?;
    let opened = b.client.open_routed(&entry, &b.id)?;
    let copy = b.client.authenticated_committed_key(HeadUse::HistoricalRead, &entry)?;
    let source = &opened.remote_device;
    let provenance = crate::client::routed::generated_receive::Provenance {
        source: source.storage_key().into(),
        conversation: "c".into(),
        message: id.clone(),
        envelope_id: entry.envelope.envelope_id.clone(),
        payload_hash: entry.envelope.payload_hash.clone(),
        expires_at: entry.envelope.created_at + i64::from(entry.envelope.ttl),
        original_mode: "durable".into(),
        source_epoch: 1,
        original_route: serde_json::to_string(&opened.routing)?,
        outer_receipt_key: copy.clone(),
        source_evidence_copy: None,
        received_erasure_generation: b.client.account_db()?.privacy_erasure_generation()?,
    };
    let receipt = crate::client::routed::Committed {
        routing: opened.routing.clone(),
        entry: entry.clone(),
        projected: true,
        erasure_targets: Vec::new(),
    };
    let db = b.client.account_db()?;
    db.write_transaction(|| -> Result<(), SdkError> {
        b.client.persist_pair(
            &opened.local_device,
            source,
            &opened.bundle_hash,
            &opened.session,
        )?;
        db.persist_message_actor_state(&id, &copy, &receipt)?;
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: &id,
            verified_source_anchor: source.root_commitment(),
            copy_id: &copy,
            kind: ramflux_storage::RawInnerCopyKind::OuterInner,
            bytes: raw,
            bounded_metadata: &serde_json::to_vec(&provenance)?,
        })?;
        db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {
            conversation_id: "c",
            message_id: &id,
            sender_id: "alice",
            encrypted_body: &[],
            metadata: &ramflux_storage::MessageMetadata::default(),
            created_at: entry.envelope.created_at,
        })?;
        db.persist_message_actor_state(&id, &format!("routed/generated-identity/{id}"), &identity)?;
        db.persist_message_actor_state(
            &id,
            &crate::client::delivery_receipts::origin_key("c", &id)?,
            &serde_json::json!({"sender_root_commitment":source.root_commitment()}),
        )?;
        b.client.persist_generated_unsupported_view(
            &id,
            &copy,
            &g::validation::scan_inner(raw).map_err(|_| invalid("scan"))?,
        )?;
        Ok(())
    })?;
    Ok(id)
}

#[tokio::test(flavor = "current_thread")]
async fn reparse_message_resolves_parked_edit_before_publishing_content_in_force()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(165, 167)?;
    commit_content(
        &a,
        &mut b,
        "upgrade-bootstrap",
        g::content::Value::Message(g::Message { text: "bootstrap".into(), ..Default::default() }),
    )
    .await?;
    let identity = generated_identity(&a, "upgrade-opaque-original")?;
    let target = g::MessageRef {
        id: identity.id.clone(),
        conversation_id: "c".into(),
        author_anchor: a.client.own_account_anchor()?,
    };
    let raw = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "original body retired by parked edit".into(),
                ..Default::default()
            })),
        },
    )?;
    let id = retain_original_for_upgrade(&a, &b, &raw)?;
    let digest = crate::client::message_mutations::previous_content_digest(&target, &raw)?;
    commit_content(
        &a,
        &mut b,
        "upgrade-parked-edit",
        edit(&target, 1, digest, "replacement after upgrade"),
    )
    .await?;
    b.client
        .account_db()?
        .write_transaction(|| b.client.resolve_generated_pending_edit("c", &id))?;
    assert_eq!(
        b.client.account_db()?.unsupported_raw_quota(None)?.owners,
        2,
        "opaque target consumed its pending Edit"
    );
    assert!(
        b.client.account_db()?.message_content(&id)?.is_none(),
        "Edit must park while target content is opaque"
    );
    assert_eq!(b.client.reparse_raw_inner_page()?.projected, 1);
    let event = b
        .client
        .account_db()?
        .journal_after(0, 128)?
        .into_iter()
        .find(|event| event.topic == "message.schema.updated")
        .ok_or_else(|| invalid("schema update"))?;
    let update: g::MessageUpdate = serde_json::from_value(event.body["update"].clone())?;
    assert!(
        matches!(update.state.as_ref(),Some(g::message_update::State::Content(g::Content {
        value:Some(g::content::Value::Message(message))
    })) if message.text=="replacement after upgrade"),
        "reparse published original instead of parked Edit"
    );
    assert_eq!(update.identity.as_ref().map(|identity| &identity.id), Some(&target.id));
    assert_eq!(update.journal_sequence, event.seq);
    assert!(
        !serde_json::to_string(&b.client.generated_message_page("c", None, 100)?)?
            .contains("original body retired")
    );
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    assert_eq!(b.client.reparse_raw_inner_page()?.projected, 0);
    Ok(())
}
