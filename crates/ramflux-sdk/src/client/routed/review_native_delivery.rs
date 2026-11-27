// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]
//! Authenticated attribution and replay through generated Message delivery and public reads.
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_protocol::message as g;

fn authored(
    source: &Fixture,
    target: &Fixture,
    text: &str,
) -> TestResult<(crate::GatewayDirectMessage, ramflux_protocol::Envelope)> {
    let mut message = crate::GatewayDirectMessage {
        conversation_id: g::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?,
        message_id: "same-caller-operation".into(),
        envelope_id: "same-caller-envelope".into(),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.client.own_account_anchor()?),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 300,
    };
    let prepared = source.client.prepare_authored_message(
        &mut message,
        None,
        &g::Message { text: text.into(), ..Default::default() },
    )?;
    let envelope = source.seal_inner_to_with_id(target, &prepared.wire, &message.envelope_id)?;
    source.client.project_authored_message(&message, &prepared.exact, &[])?;
    Ok((message, envelope))
}

pub(super) async fn duplicate_attribution() -> TestResult {
    let alice = Fixture::new("attribution-alice").await?;
    let carol = Fixture::new("attribution-carol").await?;
    let mut bob = Fixture::new("attribution-bob").await?;
    for source in [&alice, &carol] {
        source.accept_peer(&bob)?;
        bob.accept_peer(source)?;
    }
    let (original, envelope) = authored(&alice, &bob, "Alice original body")?;
    bob.receive(envelope.clone(), 1).await?;
    let before =
        bob.client.generated_message_detail(&original.conversation_id, &original.message_id)?;
    let owner = bob
        .client
        .direct_message_by_id(&original.message_id)?
        .ok_or("test: original row")?
        .sender_id;
    let (independent, own_frame) = authored(&carol, &bob, "Carol independent body")?;
    assert_ne!(
        original.message_id, independent.message_id,
        "independent native authors sharing operation labels must allocate distinct event ids"
    );
    bob.receive(own_frame, 2).await?;
    let mut forged = envelope.clone();
    forged.source_principal_id = carol.config.principal_id.clone();
    assert!(
        bob.receive(forged, 3).await.is_err(),
        "a changed sender replaced authenticated attribution"
    );
    bob.receive(envelope, 1).await?;
    let after =
        bob.client.generated_message_detail(&original.conversation_id, &original.message_id)?;
    assert_eq!(
        serde_json::to_value(&after.message)?,
        serde_json::to_value(&before.message)?,
        "independent delivery or a forged duplicate changed the original read model"
    );
    assert_eq!(after.schema, before.schema, "the detail response changed its read-model contract");
    assert!(
        after.snapshot_sequence >= before.snapshot_sequence,
        "independent delivery moved the read-model snapshot backwards"
    );
    assert_eq!(
        bob.client
            .direct_message_by_id(&original.message_id)?
            .ok_or("test: original row")?
            .sender_id,
        owner,
        "the committed original sender was replaced"
    );
    assert_eq!(
        bob.client
            .generated_message_detail(&independent.conversation_id, &independent.message_id)?
            .message
            .text
            .as_deref(),
        Some("Carol independent body"),
        "refusing the forged duplicate must preserve unrelated authenticated content"
    );
    Ok(())
}



pub(super) async fn transient_lookup() -> TestResult {
    use crate::client::routed::tests::{native_pair_tests, review::Inbox};
    let alice = Fixture::with_principal("backoff-alice", "alice", "alice").await?;
    let carol = Fixture::with_principal("backoff-carol", "carol", "carol").await?;
    let mut bob = Fixture::with_principal("backoff-bob", "bob", "bob").await?;
    alice.accept_peer(&bob)?;
    bob.accept_peer(&alice)?;
    carol.accept_peer(&bob)?;
    let carol_root = carol.client.own_account_anchor()?;
    bob.client.establish_friend_link(
        "carol-friend",
        &bob.client.own_account_anchor()?,
        &carol_root,
    )?;
    // Accepting a root is consent, not a fetched native publication or fresh authority.
    let pending = native_pair_tests::entry(
        &carol,
        &bob,
        &native_pair_tests::text(&carol, &bob, "retry me")?,
    )?;
    let mut good = native_pair_tests::entry(
        &alice,
        &bob,
        &native_pair_tests::text(&alice, &bob, "later good message")?,
    )?;
    good.inbox_seq = 2;
    let scope = g::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )?;
    let (engine, _) = Inbox::engine(bob.config.clone(), vec![pending.clone(), good])?;
    let target = bob.config.target_delivery_id.clone();
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "backoff-bob".into(),
    );
    let now = crate::time::now_unix_timestamp();
    crate::bus::sync_driver::run_at(&mut account, now).await?;
    assert_eq!(
        account.client.direct_messages(&scope)?.len(),
        1,
        "missing sender lookup stalled later traffic"
    );
    assert_eq!(account.client.gateway_receive_cursor(&target)?, 2);
    let db = account.client.account_db()?;
    assert_eq!(db.due_inbox_retries(now + 1)?.len(), 0);
    assert_eq!(db.due_inbox_retries(now + 2)?.len(), 1);
    assert!(!db.journal_after(0, 100)?.iter().any(|event| event.topic == "message.undeliverable"));
    let key = account.client.inbox_admission_key(&pending)?;
    assert_eq!(db.defer_inbox_entry(&key, &serde_json::to_vec(&pending)?, now + 3)?, 2);
    let (engine, _) = Inbox::engine(account.gateway_config.clone(), vec![pending])?;
    account.install_test_session(engine);
    crate::bus::sync_driver::run_at(&mut account, now + 3).await?;
    assert_eq!(account.client.account_db()?.due_inbox_retries(now + 6)?.len(), 0);
    assert_eq!(account.client.account_db()?.due_inbox_retries(now + 7)?.len(), 1);
    Ok(())
}
