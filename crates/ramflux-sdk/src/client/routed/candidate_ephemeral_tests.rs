// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native authority, real pair crypto and SQLite; no transport delivery claim.
use super::*;
use crate::client::native_test_support::{Fixture as Native, TestResult};
use crate::typing::{TypingOutcome, TypingReceiver};
use prost::Message as _;
use ramflux_protocol::message as g;
use std::time::Instant;

fn draft(a: &Native, b: &Native, id: &str, ttl: u32) -> TestResult<GatewayDirectMessage> {
    Ok(GatewayDirectMessage {
        conversation_id: g::dm_scope::derive(
            &a.client.own_account_anchor()?,
            &b.client.own_account_anchor()?,
        )?,
        message_id: id.into(),
        envelope_id: id.into(),
        source_principal_id: a.manifest.principal_id.clone(),
        sender_id: "primary".into(),
        recipient_device_id: Some("primary".into()),
        recipient_principal_commitment: Some(b.client.own_account_anchor()?),
        target_delivery_id: b.client.owned_device_identity()?.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl,
    })
}
fn next_identity(a: &Native, conversation: &str) -> TestResult<g::EventIdentity> {
    Ok(a.client
        .account_db()?
        .write_transaction(|| a.client.allocate_generated_identity(conversation, 1000, false))?)
}
async fn establish(a: &Native, b: &mut Native, id: &str) -> TestResult {
    let mut message = draft(a, b, id, 300)?;
    let identity = next_identity(a, &message.conversation_id)?;
    message.message_id = ramflux_protocol::encode_base64url(&identity.id);
    let body = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "bootstrap".into(),
                ..Default::default()
            })),
        },
    )?;
    let source = a.client.owned_device_identity()?;
    let remote = b.client.owned_device_identity()?;
    let (mut session, header, bundle) =
        if let Some((session, header, bundle)) = a.client.sendable_pair(&source, &remote)? {
            (session, header, bundle)
        } else {
            a.client.new_send_pair(
                &source,
                &message,
                b.client.load_x3dh_private_state(&remote)?.bundle,
            )?
        };
    let sealed = a.client.seal_routed_with_route(
        &message,
        &body,
        Route::direct(),
        SealPair {
            local: "primary",
            remote: remote.storage_key(),
            session: &mut session,
            header,
            bundle,
        },
    )?;
    message.encrypted_body = serde_json::to_vec(&sealed.packet)?;
    let mut envelope = gateway_direct_message_envelope_sealed(
        &a.config,
        &message,
        None,
        sealed.committed_a0.as_deref(),
    )?;
    crate::dm::add_message_metadata_commitment(
        &a.config,
        &mut envelope,
        sealed.metadata_commitment,
    )?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: message.target_delivery_id,
        envelope,
    };
    let mut engine =
        GatewaySessionEngine::with_test_transport(b.config.clone(), Box::new(NoNetwork));
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    b.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    Ok(())
}
pub(crate) async fn native_pair() -> TestResult<(Native, Native)> {
    let mut a = Native::new("ephemeral-source").await?;
    let mut b = Native::new("ephemeral-receiver").await?;
    // Install the fixture's completed current-directory results. These endpoint tests
    // make no claim about the network lookup or freshness transport itself.
    a.client.persist_fetched_identity_directory(&b.manifest)?;
    b.client.persist_fetched_identity_directory(&a.manifest)?;
    for (receiver, sender) in [(&a, &b), (&b, &a)] {
        receiver.client.establish_friend_link(
            "native-ephemeral-link",
            &sender.client.own_account_anchor()?,
            &receiver.client.own_account_anchor()?,
        )?;
    }
    Box::pin(establish(&a, &mut b, "native-bootstrap")).await?;
    Box::pin(establish(&b, &mut a, "native-reply")).await?;
    Ok((a, b))
}
fn seal_content(
    a: &Native,
    b: &Native,
    id: &str,
    unknown: bool,
) -> TestResult<ramflux_protocol::Envelope> {
    let message = draft(a, b, id, 5)?;
    let identity = next_identity(a, &message.conversation_id)?;
    let raw = if unknown {
        g::Inner { layer: 2, kind: 900, identity: Some(identity), body: vec![0xff, 0, 0x80] }
            .encode_to_vec()
    } else {
        RamfluxClient::encode_generated_inner(
            identity,
            &g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: "must not persist".into(),
                    ..Default::default()
                })),
            },
        )?
    };
    seal_raw(a, b, &message, &raw)
}
fn seal_raw(
    a: &Native,
    b: &Native,
    message: &GatewayDirectMessage,
    raw: &[u8],
) -> TestResult<ramflux_protocol::Envelope> {
    let source = a.client.owned_device_identity()?;
    let remote = b.client.owned_device_identity()?;
    let mut engine =
        GatewaySessionEngine::with_test_transport(a.config.clone(), Box::new(NoNetwork));
    Ok(a.client.account_db()?.write_transaction(|| {
        a.client.seal_ephemeral_inner(&mut engine, message, &source, &remote, raw)
    })?)
}
fn allowed_receiver_state(b: &Native, a: &Native) -> TestResult<Vec<String>> {
    let local = b.client.owned_device_identity()?;
    let remote = a.client.owned_device_identity()?;
    let id = b.client.sendable_pair(&local, &remote)?.ok_or("pair")?.0.session_id;
    Ok(vec![format!("dm-pair/session/{id}")])
}

#[tokio::test(flavor = "current_thread")]
async fn ephemeral_unknown_is_retained_and_known_non_typing_is_dropped() -> TestResult {
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = Box::pin(native_pair()).await?;
    let allowed = allowed_receiver_state(&b, &a)?;
    let before = b.client.account_db()?.test_table_fingerprints(&allowed)?;
    let known = seal_content(&a, &b, "known-on-ephemeral", false)?;
    let now = u64::try_from(known.created_at)? * 1000;
    let mut receiver = TypingReceiver::default();
    assert!(matches!(
        receiver.receive(&b.client, &known, "primary", now, Instant::now())?,
        TypingOutcome::Dropped(_)
    ));
    assert_tables_unchanged(&b.client, &allowed, &before)?;
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    let unknown = seal_content(&a, &b, "unknown-on-ephemeral", true)?;
    let before = b.client.account_db()?.journal_bounds()?;
    assert_eq!(
        receiver.receive(&b.client, &unknown, "primary", now, Instant::now())?,
        TypingOutcome::RetainedUnsupported
    );
    assert_eq!(b.client.account_db()?.journal_bounds()?, before);
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 1);
    let page = b.client.account_db()?.raw_inner_reparse_page("inspect")?;
    assert_eq!(page.len(), 2, "raw and native evidence share one owner");
    let row = page
        .iter()
        .find(|row| row.copy.kind == ramflux_storage::RawInnerCopyKind::OuterInner)
        .ok_or("raw")?;
    let provenance: super::super::generated_receive::Provenance =
        serde_json::from_slice(&row.metadata)?;
    assert_eq!(provenance.original_mode, "ephemeral");
    assert!(provenance.source_evidence_copy.is_some());
    assert!(b.client.direct_message_by_id(&row.copy.owner_id)?.is_none());
    let source = a.client.own_account_anchor()?;
    fill_source_quota(&b.client, &source)?;
    let blocked = seal_content(&a, &b, "quota-held-ephemeral", true)?;
    let snapshot = b.client.account_db()?.test_table_fingerprints(&[])?;
    assert!(receiver.receive(&b.client, &blocked, "primary", now, Instant::now()).is_err());
    assert_tables_unchanged(&b.client, &[], &snapshot)?;
    b.client.active_account_db = None;
    b.client.unlock_account("ephemeral-receiver", b"native fixture data passphrase")?;
    b.client.initialize_born_v3_branch("primary", b.vault.clone()).await?;
    b.client.persist_fetched_identity_directory(&a.manifest)?;
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 16);
    assert_fault_rollback_and_retry(&b.client, &mut receiver, &blocked, now)?;
    Ok(())
}
fn assert_fault_rollback_and_retry(
    client: &RamfluxClient,
    receiver: &mut TypingReceiver,
    blocked: &ramflux_protocol::Envelope,
    now: u64,
) -> TestResult {
    let db = client.account_db()?;
    db.write_transaction(|| db.finish_raw_inner_reparse("other-unknown-0"))?;
    let snapshot = db.test_table_fingerprints(&[])?;
    let (result, commits) = db.reject_next_sqlite_commit(|| {
        receiver.receive(client, blocked, "primary", now, Instant::now())
    })?;
    assert_eq!(commits, 1, "must reach the real SQLite commit: {result:?}");
    assert!(result.is_err(), "unknown content escaped a failed commit");
    assert_tables_unchanged(client, &[], &snapshot)?;
    assert_eq!(
        receiver.receive(client, blocked, "primary", now, Instant::now())?,
        TypingOutcome::RetainedUnsupported
    );
    assert_eq!(db.unsupported_raw_quota(None)?.owners, 16);
    Ok(())
}
fn fill_source_quota(client: &RamfluxClient, source: &str) -> TestResult {
    let db = client.account_db()?;
    db.write_transaction(|| -> TestResult {
        for index in 0..15 {
            let id = format!("other-unknown-{index}");
            db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
                owner_id: &id,
                verified_source_anchor: source,
                copy_id: &id,
                kind: ramflux_storage::RawInnerCopyKind::OuterInner,
                bytes: b"other retained unknown",
                bounded_metadata: b"{}",
            })?;
        }
        Ok(())
    })?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn typing_native_endpoint_lifetime_has_no_unexpected_table_writes() -> TestResult {
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = Box::pin(native_pair()).await?;
    let mut config = a.config.clone();
    config.capability_scope.push(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.into());
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(NoNetwork));
    engine.ephemeral_negotiated = true;
    let local = a.client.owned_device_identity()?;
    let remote = b.client.owned_device_identity()?;
    let session = a.client.sendable_pair(&local, &remote)?.ok_or("pair")?.0;
    let allowed = vec![
        format!("dm-pair/session/{}", session.session_id),
        format!("dm-pair/ephemeral-seals/{}", session.session_id),
    ];
    let before = a.client.account_db()?.test_table_fingerprints(&allowed)?;
    let message = draft(&a, &b, "native-typing", 5)?;
    let envelope = a.client.prepare_typing_delivery(&mut engine, &message, true)?;
    assert_tables_unchanged(&a.client, &allowed, &before)?;
    let allowed = allowed_receiver_state(&b, &a)?;
    let before = b.client.account_db()?.test_table_fingerprints(&allowed)?;
    let now = u64::try_from(message.created_at)? * 1000;
    let mono = Instant::now();
    let mut receiver = TypingReceiver::default();
    assert_eq!(
        receiver.receive(&b.client, &envelope, "primary", now, mono)?,
        TypingOutcome::Visible
    );
    assert_eq!(
        receiver.receive(&b.client, &envelope, "primary", now + 1, mono)?,
        TypingOutcome::Duplicate
    );
    assert_tables_unchanged(&b.client, &allowed, &before)?;
    // Native authentication and decryption feed the same generated update consumed
    // by every binding, without allocating a durable cursor or operation receipt.
    let updates = receiver.drain_message_updates("ephemeral-receiver")?;
    assert_eq!(updates.len(), 1);
    let frame = crate::bindings::transient_message_frame(&updates[0])?;
    assert_eq!(frame.method, g::TRANSIENT_TOPIC);
    assert_eq!(frame.seq, Some(0));
    assert_eq!(frame.request_id, "");
    assert_eq!(crate::bindings::decode_message_update(&frame.body)?, updates[0]);
    let mut invalid = updates[0].clone();
    invalid.journal_sequence = 1;
    assert!(crate::bindings::transient_message_frame(&invalid).is_err());
    invalid.journal_sequence = 0;
    invalid.identity.as_mut().ok_or("identity")?.device_sequence = 1;
    assert!(crate::bindings::transient_message_frame(&invalid).is_err());
    receiver.poll(now + 5000, mono + Duration::from_secs(5));
    assert!(receiver.drain_message_updates("").is_err());
    let updates = receiver.drain_message_updates("ephemeral-receiver")?;
    assert_eq!(updates.len(), 1);
    let frame = crate::bindings::transient_message_frame(&updates[0])?;
    assert_eq!(frame.seq, Some(0));
    assert!(matches!(
        updates[0].state.as_ref(),
        Some(g::message_update::State::Content(g::Content {
            value: Some(g::content::Value::Typing(g::Typing { active: false, .. }))
        }))
    ));
    let expired = a.client.prepare_typing_delivery(
        &mut engine,
        &draft(&a, &b, "expired-typing", 5)?,
        true,
    )?;
    let before = b.client.account_db()?.test_table_fingerprints(&[])?;
    assert!(matches!(
        receiver.receive(
            &b.client,
            &expired,
            "primary",
            u64::try_from(expired.created_at + 5)? * 1000,
            mono + Duration::from_secs(5)
        )?,
        TypingOutcome::Dropped(_)
    ));
    assert_tables_unchanged(&b.client, &[], &before)?;
    b.client.active_account_db = None;
    b.client.unlock_account("ephemeral-receiver", b"native fixture data passphrase")?;
    assert_tables_unchanged(&b.client, &[], &before)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ephemeral_unknown_edit_target_erase_retires_raw_and_native_opening() -> TestResult {
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = Box::pin(native_pair()).await?;
    let message = draft(&a, &b, "future-edit", 5)?;
    let target = b
        .client
        .direct_messages(&message.conversation_id)?
        .into_iter()
        .find(|row| !row.is_own)
        .ok_or("target")?;
    let identity = next_identity(&a, &message.conversation_id)?;
    let owner = ramflux_protocol::encode_base64url(&identity.id);
    let raw = g::Inner {
        layer: g::registry::COMPILED_LAYER + 1,
        kind: 3,
        identity: Some(identity),
        body: g::Edit {
            target: Some(g::MessageRef {
                id: ramflux_protocol::decode_base64url(&target.message_id)?,
                conversation_id: message.conversation_id.clone(),
                author_anchor: a.client.own_account_anchor()?,
            }),
            revision: 1,
            previous_content_digest: vec![1; 32],
            replacement: Some(g::Message {
                text: "retained replacement".into(),
                ..Default::default()
            }),
        }
        .encode_to_vec(),
    }
    .encode_to_vec();
    let envelope = seal_raw(&a, &b, &message, &raw)?;
    let now = u64::try_from(message.created_at)? * 1000;
    let mut receiver = TypingReceiver::default();
    assert_eq!(
        receiver.receive(&b.client, &envelope, "primary", now, Instant::now())?,
        TypingOutcome::RetainedUnsupported
    );
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 1);
    b.client.delete_direct_message(
        &message.conversation_id,
        &target.message_id,
        "local",
        "erase-future-edit",
    )?;
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    assert!(
        b.client
            .account_db()?
            .raw_inner_reparse_page("after-erase")?
            .iter()
            .all(|row| row.copy.owner_id != owner)
    );
    assert_eq!(b.client.reparse_raw_inner_page()?.projected, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ephemeral_inner_author_epoch_must_match_verified_peer() -> TestResult {
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = Box::pin(native_pair()).await?;
    let message = draft(&a, &b, "wrong-inner-epoch", 5)?;
    let source = a.client.owned_device_identity()?;
    let raw = g::Inner {
        layer: g::registry::COMPILED_LAYER,
        kind: 7,
        identity: Some(g::EventIdentity {
            id: ramflux_crypto::random_32()?.to_vec(),
            conversation_id: message.conversation_id.clone(),
            author: Some(g::QualifiedDevice {
                account_anchor: source.root_commitment().into(),
                device_id: source.device_id().into(),
                device_epoch: 2,
            }),
            ..Default::default()
        }),
        body: g::Typing { active: true, expires_at: u64::try_from(message.created_at + 5)? }
            .encode_to_vec(),
    }
    .encode_to_vec();
    let envelope = seal_raw(&a, &b, &message, &raw)?;
    let before = b.client.account_db()?.test_table_fingerprints(&[])?;
    let mut receiver = TypingReceiver::default();
    assert!(
        receiver
            .receive(
                &b.client,
                &envelope,
                "primary",
                u64::try_from(message.created_at)? * 1000,
                Instant::now()
            )
            .is_err()
    );
    assert_tables_unchanged(&b.client, &[], &before)?;
    assert_eq!(receiver.drain_updates().len(), 0);
    let mut forged = g::Inner::decode(raw.as_slice())?;
    forged.kind = 900;
    forged.body = vec![0xff];
    let identity = forged.identity.as_mut().ok_or("identity")?;
    identity.author.as_mut().ok_or("author")?.device_epoch = 1;
    identity.device_sequence = 2;
    identity.id = vec![77; 32];
    let mut message = message;
    message.envelope_id = "wrong-inner-id".into();
    let envelope = seal_raw(&a, &b, &message, &forged.encode_to_vec())?;
    assert!(
        receiver
            .receive(
                &b.client,
                &envelope,
                "primary",
                u64::try_from(message.created_at)? * 1000,
                Instant::now()
            )
            .is_err()
    );
    assert_tables_unchanged(&b.client, &[], &before)?;
    Ok(())
}

fn assert_tables_unchanged(
    client: &RamfluxClient,
    allowed: &[String],
    expected: &std::collections::BTreeMap<String, Vec<[u8; 32]>>,
) -> TestResult {
    let actual = client.account_db()?.test_table_fingerprints(allowed)?;
    let keys = actual.keys().chain(expected.keys()).collect::<std::collections::BTreeSet<_>>();
    let changed =
        keys.into_iter().filter(|key| actual.get(*key) != expected.get(*key)).collect::<Vec<_>>();
    assert_eq!(changed, Vec::<&String>::new(), "unexpected persistent table changes");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn account_transient_generation_reset_and_durable_message_clear() -> TestResult {
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = Box::pin(native_pair()).await?;
    let mut config = a.config.clone();
    config.capability_scope.push(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.into());
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(NoNetwork));
    engine.ephemeral_negotiated = true;
    let first = draft(&a, &b, "held-before-generation-end", 5)?;
    let envelope = a.client.prepare_typing_delivery(&mut engine, &first, true)?;
    let now = u64::try_from(first.created_at)? * 1000;
    let mono = Instant::now();
    assert_eq!(
        b.client.receive_transient_content(&envelope, "primary", now - 1000, mono)?,
        TypingOutcome::Held
    );
    b.client.reset_transient_content();
    assert_eq!(
        b.client.drain_transient_updates(
            "ephemeral-receiver",
            now,
            mono + Duration::from_secs(1)
        )?,
        Vec::<g::MessageUpdate>::new()
    );
    let message = draft(&a, &b, "visible-before-message", 5)?;
    let now = u64::try_from(message.created_at)? * 1000;
    let envelope = a.client.prepare_typing_delivery(&mut engine, &message, true)?;
    assert_eq!(
        b.client.receive_transient_content(&envelope, "primary", now, mono)?,
        TypingOutcome::Visible
    );
    assert_eq!(b.client.drain_transient_updates("ephemeral-receiver", now, mono)?.len(), 1);
    Box::pin(establish(&a, &mut b, "message-clears-typing")).await?;
    let updates = b.client.drain_transient_updates("ephemeral-receiver", now, mono)?;
    assert_eq!(updates.len(), 1, "durable Message must clear visible author state after commit");
    assert_eq!(updates[0].journal_sequence, 0);
    assert!(matches!(
        updates[0].state.as_ref(),
        Some(g::message_update::State::Content(g::Content {
            value: Some(g::content::Value::Typing(g::Typing { active: false, .. }))
        }))
    ));
    let before = b.client.account_db()?.test_table_fingerprints(&[])?;
    b.client.reset_transient_content();
    assert_eq!(
        b.client.drain_transient_updates(
            "ephemeral-receiver",
            now + 5000,
            mono + Duration::from_secs(5)
        )?,
        Vec::<g::MessageUpdate>::new()
    );
    assert_tables_unchanged(&b.client, &[], &before)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn typing_missing_negotiated_echo_refuses_before_ratchet_or_allowance_write() -> TestResult {
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = Box::pin(native_pair()).await?;
    let mut config = a.config.clone();
    config.capability_scope.push(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.into());
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(NoNetwork));
    let before = a.client.account_db()?.test_table_fingerprints(&[])?;
    assert!(
        a.client.prepare_typing_delivery(&mut engine, &draft(&a, &b, "no-echo", 5)?, true).is_err()
    );
    assert_tables_unchanged(&a.client, &[], &before)?;
    assert_eq!(engine.wire_writes, 0);
    Ok(())
}

pub(crate) fn native_typing_delivery(
    a: &Native,
    b: &Native,
) -> TestResult<(ramflux_protocol::Envelope, Vec<String>)> {
    let mut config = a.config.clone();
    config.capability_scope.push(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.into());
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(NoNetwork));
    engine.ephemeral_negotiated = true;
    let message = draft(a, b, "native-host-typing", 5)?;
    Ok((
        a.client.prepare_typing_delivery(&mut engine, &message, true)?,
        allowed_receiver_state(b, a)?,
    ))
}
