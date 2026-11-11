// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::typing::{TypingOutcome, TypingReceiver};
use std::time::Instant;

async fn prepared_pair() -> Result<(Fixture, Fixture), SdkError> {
    let (mut a, mut b) = pair(227, 229)?;
    friend(&mut a, &b)?;
    let bootstrap = seal(&a, &b, message("bootstrap", "c"), b"bootstrap")?;
    apply(&mut b, &bootstrap).await?;
    let mut reply_message = message("bootstrap-reply", "c");
    reply_message.source_principal_id = "bob".into();
    reply_message.sender_id = "bob".into();
    reply_message.recipient_device_id = Some(a.id.clone());
    reply_message.target_delivery_id = a.id.clone();
    let reply = seal(&b, &a, reply_message, b"reply")?;
    apply(&mut a, &reply).await?;
    Ok((a, b))
}

fn typing_envelope(
    a: &Fixture,
    b: &Fixture,
    id: &str,
    ttl: u32,
) -> Result<ramflux_protocol::Envelope, SdkError> {
    typing_envelope_active(a, b, id, ttl, true)
}

fn typing_envelope_active(
    a: &Fixture,
    b: &Fixture,
    id: &str,
    ttl: u32,
    active: bool,
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let mut config = a.config()?;
    config.capability_scope.push(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.into());
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(NoNetwork));
    let mut draft = message(id, "c");
    draft.created_at = 100;
    draft.ttl = ttl;
    draft.recipient_device_id = Some(b.id.clone());
    draft.recipient_principal_commitment = Some(b.client.own_account_anchor()?);
    draft.target_delivery_id.clone_from(&b.id);
    a.client.prepare_typing_delivery(&mut engine, &draft, active)
}

#[tokio::test(flavor = "current_thread")]
async fn typing_lifetime_at_most_five_seconds_and_ttl_is_bounded() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = Box::pin(prepared_pair()).await?;
    for ttl in [0, 1, 2, 3, 4, 6] {
        assert!(typing_envelope(&a, &b, "refused", ttl).is_err());
    }
    let ttl = 5;
    let envelope = typing_envelope(&a, &b, &format!("event-{ttl}"), ttl)?;
    assert_eq!(envelope.delivery_mode.as_deref(), Some("ephemeral"));
    assert_eq!(envelope.priority, ramflux_protocol::Priority::Low);
    let mut receiver = TypingReceiver::default();
    let start = Instant::now();
    assert_eq!(
        receiver.receive(&b.client, &envelope, &b.id, 100_000, start)?,
        TypingOutcome::Visible
    );
    assert!(receiver.drain_updates().first().is_some_and(|update| update.typing.active));
    assert_eq!(
        receiver.receive(&b.client, &envelope, &b.id, 100_001, start)?,
        TypingOutcome::Duplicate
    );
    receiver.poll(100_000 + u64::from(ttl) * 1000, start + Duration::from_secs(u64::from(ttl)));
    assert!(receiver.drain_updates().first().is_some_and(|update| !update.typing.active));
    assert!(typing_envelope_active(&a, &b, "invalid-clear", 5, false).is_err());
    let clear = typing_envelope_active(&a, &b, "clear", 1, false)?;
    let (_, typing) = b.client.open_typing_delivery(&clear, &b.id)?;
    assert!(!typing.active);
    assert_eq!(typing.expires_at, 101);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn receiver_ephemeral_future_tolerance_uses_local_clock() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = Box::pin(prepared_pair()).await?;
    let envelope = typing_envelope(&a, &b, "future-event", 5)?;
    let mut receiver = TypingReceiver::default();
    let start = Instant::now();
    assert!(matches!(
        receiver.receive(&b.client, &envelope, &b.id, 97_999, start)?,
        TypingOutcome::Dropped(_)
    ));
    assert_eq!(receiver.receive(&b.client, &envelope, &b.id, 98_000, start)?, TypingOutcome::Held);
    assert!(receiver.drain_updates().is_empty());
    receiver.poll(99_999, start + Duration::from_millis(1999));
    assert!(receiver.drain_updates().is_empty());
    receiver.poll(100_000, start + Duration::from_secs(2));
    assert!(receiver.drain_updates().first().is_some_and(|update| update.typing.active));
    receiver.poll(105_000, start + Duration::from_secs(7));
    assert!(receiver.drain_updates().first().is_some_and(|update| !update.typing.active));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn typing_is_generated_transient_content_not_plaintext_kind() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = Box::pin(prepared_pair()).await?;
    let envelope = typing_envelope(&a, &b, "transient-event", 5)?;
    let db = b.client.account_db()?;
    let before = (
        db.journal_bounds()?,
        db.actor_state_usage("routed/")?,
        b.client.direct_messages("c")?.len(),
    );
    let wire = serde_json::to_value(&envelope)?;
    assert!(wire.get("typing").is_none());
    assert!(wire.get("kind").is_none());
    let mut receiver = TypingReceiver::default();
    assert_eq!(
        receiver.receive(&b.client, &envelope, &b.id, 100_000, Instant::now())?,
        TypingOutcome::Visible
    );
    let after = (
        db.journal_bounds()?,
        db.actor_state_usage("routed/")?,
        b.client.direct_messages("c")?.len(),
    );
    assert_eq!(before, after);
    assert_eq!(db.unsupported_raw_quota(None)?.owners, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn typing_cannot_exhaust_skipped_keys_or_bootstrap() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (mut a, mut b) = pair(181, 183)?;
    friend(&mut a, &b)?;
    assert!(typing_envelope(&a, &b, "no-session", 5).is_err());
    let bootstrap = seal(&a, &b, message("establish", "c"), b"establish")?;
    assert!(typing_envelope(&a, &b, "unconfirmed", 5).is_err());
    assert!(
        b.client.open_typing_delivery(&bootstrap.envelope, &b.id).is_err(),
        "ephemeral bootstrap refused before pair state changes"
    );
    apply(&mut b, &bootstrap).await?;
    let mut reply_message = message("establish-reply", "c");
    reply_message.source_principal_id = "bob".into();
    reply_message.sender_id = "bob".into();
    reply_message.recipient_device_id = Some(a.id.clone());
    reply_message.target_delivery_id = a.id.clone();
    let reply = seal(&b, &a, reply_message, b"reply")?;
    apply(&mut a, &reply).await?;
    let local = a.client.owned_device_identity()?;
    let remote = a.client.device_identity(&b.reference()?)?;
    let (session, _, _) = a
        .client
        .sendable_pair(&local, &remote)?
        .ok_or_else(|| invalid("established pair missing"))?;
    let budget_key = format!("dm-pair/ephemeral-seals/{}", session.session_id);
    for batch in 0..4 {
        for event in 0..64 {
            let _dropped_offline = typing_envelope(&a, &b, &format!("lost-{batch}-{event}"), 5)?;
        }
        // Sealing durable traffic, receiving its acknowledgement and reopening must not reset the budget.
        let durable =
            seal(&a, &b, message(&format!("durable-{batch}"), "c"), b"durable after lost typing")?;
        apply(&mut b, &durable).await?;
        let mut reply_message = message(&format!("reply-{batch}"), "c");
        reply_message.source_principal_id = "bob".into();
        reply_message.sender_id = "bob".into();
        reply_message.recipient_device_id = Some(a.id.clone());
        reply_message.target_delivery_id = a.id.clone();
        let reply = seal(&b, &a, reply_message, b"peer reply")?;
        apply(&mut a, &reply).await?;
        a.client.active_account_db = None;
        a.client.unlock_account("alice", b"routed-test")?;
        assert_eq!(
            a.client.account_db()?.load_actor_state::<u16>(&budget_key)?,
            Some((batch + 1) * 64)
        );
    }
    for event in 256..300 {
        assert!(typing_envelope(&a, &b, &format!("exhausted-{event}"), 5).is_err());
    }
    let final_message =
        seal(&a, &b, message("latest-durable", "c"), b"latest durable still decrypts")?;
    apply(&mut b, &final_message).await?;
    assert_eq!(a.client.account_db()?.load_actor_state::<u16>(&budget_key)?, Some(256));
    Ok(())
}
