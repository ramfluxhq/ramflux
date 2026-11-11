// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::inbox_failure::deterministic;
use ramflux_crypto::CryptoError;
use ramflux_protocol::message::outer::{
    CandidateDeliveryClass, candidate_report_a0_from_envelope, encode_candidate_report_a0,
};

#[path = "candidate_generated_tests.rs"]
mod generated;
#[path = "candidate_typing_tests.rs"]
mod typing;

struct OmitDirectReport;
impl Drop for OmitDirectReport {
    fn drop(&mut self) {
        super::super::report::set_omit_direct_report(false);
    }
}

fn omit_direct_report() -> OmitDirectReport {
    super::super::report::set_omit_direct_report(true);
    OmitDirectReport
}

fn pair(alice: u8, bob: u8) -> Result<(Fixture, Fixture), SdkError> {
    let a = Fixture::new("alice", alice)?;
    let mut b = Fixture::new("bob", bob)?;
    friend(&mut b, &a)?;
    Ok((a, b))
}

fn friend(receiver: &mut Fixture, sender: &Fixture) -> Result<(), SdkError> {
    receiver.client.establish_friend_link(
        "link",
        sender.client.owned_device_identity()?.root_commitment(),
        receiver.client.owned_device_identity()?.root_commitment(),
    )?;
    Ok(())
}

fn pool() -> Result<ramflux_transport::RelayQuicPool, SdkError> {
    Ok(ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()
            .map_err(|error| invalid(&error.to_string()))?,
    ))
}

async fn apply(receiver: &mut Fixture, entry: &GatewayInboxEntry) -> Result<Delivery, SdkError> {
    ramflux_node_core::check_entry_bound(&entry.envelope)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut session =
        GatewaySessionEngine::with_test_transport(receiver.config()?, Box::new(NoNetwork));
    let pool = pool()?;
    receiver.client.apply_routed_entry(&mut session, &pool, entry, false).await
}

fn projected(receiver: &Fixture, conversation: &str) -> Result<usize, SdkError> {
    Ok(receiver.client.direct_messages(conversation)?.len())
}

fn opened_kind(delivery: &Delivery, want: &Kind) -> Result<(), SdkError> {
    match &delivery.routing {
        Some(routing) if routing.kind == *want => Ok(()),
        other => Err(invalid(&format!("kind {want:?}, got {other:?}"))),
    }
}

async fn settle_through(
    receiver: &mut Fixture,
    entries: Vec<GatewayInboxEntry>,
) -> Result<(), SdkError> {
    let (engine, _) = super::review::Inbox::engine(receiver.config()?, entries)?;
    let mut account = LocalBusAccountState::new(
        std::mem::take(&mut receiver.client),
        engine,
        receiver.id.clone(),
    );
    crate::bus::sync_driver::run(&mut account).await?;
    receiver.client = account.client;
    Ok(())
}

fn crypto(result: Result<Delivery, SdkError>, want: &str) -> Result<(), SdkError> {
    match result {
        Err(error @ SdkError::Crypto(_)) if error.to_string().contains(want) => {
            assert_eq!(deterministic(&error), Some("authentication_failed"));
            Ok(())
        }
        Err(error) => Err(invalid(&format!("exact crypto {want}, got {error}"))),
        Ok(_) => Err(invalid(&format!("exact crypto {want}, got Ok"))),
    }
}

fn rejected(result: Result<Delivery, SdkError>, want: &str) -> Result<(), SdkError> {
    match result {
        Err(SdkError::InboundRejected(text)) if text.contains(want) => Ok(()),
        Err(error) => Err(invalid(&format!("exact rejected {want}, got {error}"))),
        Ok(_) => Err(invalid(&format!("exact rejected {want}, got Ok"))),
    }
}

fn resign(sender: &Fixture, envelope: &mut ramflux_protocol::Envelope) -> Result<(), SdkError> {
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        envelope,
    )?;
    Ok(())
}

fn rewrite_nested_commitment(
    entry: &mut GatewayInboxEntry,
    commitment: &str,
) -> Result<(), SdkError> {
    let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut sidecar: serde_json::Value = serde_json::from_slice(compact.sidecar)?;
    sidecar["report_commitment"] = serde_json::Value::String(commitment.to_owned());
    let rebuilt = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    entry.envelope.encrypted_payload = ramflux_protocol::encode_base64url(&rebuilt);
    entry.envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        entry.envelope.encrypted_payload.as_bytes(),
    );
    Ok(())
}

fn reply_to(alice: &str) -> GatewayDirectMessage {
    let mut reply = message("report-reply", "c");
    reply.source_principal_id = "bob".to_owned();
    reply.sender_id = "bob".to_owned();
    reply.recipient_device_id = Some(alice.to_owned());
    reply.target_delivery_id = alice.to_owned();
    reply
}

#[tokio::test(flavor = "current_thread")]
async fn direct_seal_writes_tag_and_commitment_and_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(141, 142)?;
    let entry = seal(&a, &b, message("report-ok", "c"), b"report-body")?;
    let tag = ramflux_protocol::decode_base64url(
        entry.envelope.collapse_tag.as_deref().ok_or_else(|| invalid("collapse_tag"))?,
    )
    .map_err(|_| invalid("collapse_tag"))?;
    let commitment = ramflux_protocol::decode_base64url(
        entry.envelope.report_commitment.as_deref().ok_or_else(|| invalid("report_commitment"))?,
    )
    .map_err(|_| invalid("report_commitment"))?;
    assert_eq!(tag.len(), 32);
    assert_eq!(commitment.len(), 32);
    assert_eq!(entry.envelope.delivery_mode.as_deref(), Some("durable"));
    let opened = apply(&mut b, &entry).await?;
    assert!(opened.plaintext.is_some());
    assert_eq!(projected(&b, "c")?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn tampered_opening_refused_and_next_message_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(143, 144)?;
    let first = seal(&a, &b, message("report-bootstrap", "c"), b"first-body")?;
    apply(&mut b, &first).await?;
    let second = seal(&a, &b, message("report-tamper", "c"), b"tamper-body")?;
    let mut tampered = second.clone();
    tampered.inbox_seq = 2;
    tampered.envelope.created_at = tampered.envelope.created_at.saturating_add(1);
    resign(&a, &mut tampered.envelope)?;
    crypto(apply(&mut b, &tampered).await, "report opening commitment mismatch")?;
    assert_eq!(projected(&b, "c")?, 1);
    let mut next = seal(&a, &b, message("report-next", "c"), b"next-body")?;
    next.inbox_seq = 3;
    Box::pin(settle_through(&mut b, vec![tampered, next])).await?;
    assert_eq!(projected(&b, "c")?, 2);
    assert_eq!(b.client.gateway_receive_cursor("bob")?, 3);
    assert!(
        b.client
            .account_db()?
            .journal_after(0, 100)?
            .iter()
            .any(|event| event.topic == "message.undeliverable")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn redelivery_after_uncommitted_open_still_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(149, 150)?;
    let entry = seal(&a, &b, message("report-redeliver", "c"), b"once")?;
    super::super::receive::commit_fault::fail_before(
        super::super::receive::commit_fault::Kind::Content,
    );
    match apply(&mut b, &entry).await {
        Err(SdkError::LocalBus(text)) if text == "routed commit fault" => {}
        Err(error) => return Err(invalid(&format!("exact commit fault, got {error}"))),
        Ok(_) => return Err(invalid("exact commit fault, got Ok")),
    }
    assert_eq!(projected(&b, "c")?, 0);
    let opened = apply(&mut b, &entry).await?;
    assert!(opened.plaintext.is_some());
    assert_eq!(projected(&b, "c")?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn collapse_tag_stable_across_dh_step() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (mut a, mut b) = pair(151, 152)?;
    friend(&mut a, &b)?;
    let first = seal(&a, &b, message("report-dh-1", "c"), b"one")?;
    let tag = first.envelope.collapse_tag.clone();
    apply(&mut b, &first).await?;
    let reply = seal(&b, &a, reply_to("alice"), b"reply")?;
    apply(&mut a, &reply).await?;
    let mut second = seal(&a, &b, message("report-dh-2", "c"), b"two")?;
    second.inbox_seq = 2;
    assert_eq!(second.envelope.collapse_tag, tag);
    apply(&mut b, &second).await?;
    assert_eq!(projected(&b, "c")?, 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn missing_direct_commitment_refused_under_gate() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(153, 154)?;
    let _omit = omit_direct_report();
    let entry = seal(&a, &b, message("report-omit", "c"), b"evade")?;
    assert!(entry.envelope.report_commitment.is_none());
    rejected(apply(&mut b, &entry).await, "report_commitment must be 32 bytes")?;
    assert_eq!(projected(&b, "c")?, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a0_from_signed_envelope_uses_device_key_id_and_delivery_class() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(155, 156)?;
    let entry = seal(&a, &b, message("report-a0", "c"), b"a0-body")?;
    assert_eq!(entry.envelope.signed.signing_key_id, "device:alice");
    assert_eq!(entry.envelope.delivery_class, ramflux_protocol::DeliveryClass::OpaqueEvent);
    let a0 = candidate_report_a0_from_envelope(&entry.envelope)
        .map_err(|error| invalid(&error.to_string()))?;
    assert_eq!(a0.signing_key_id, "device:alice");
    assert_eq!(a0.delivery_class, CandidateDeliveryClass::Message);
    apply(&mut b, &entry).await?;
    assert_eq!(projected(&b, "c")?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn payload_outer_commitment_mismatch_is_refused() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(157, 158)?;
    let entry = seal(&a, &b, message("report-l5", "c"), b"l5")?;
    let mut tampered = entry.clone();
    tampered.envelope.report_commitment = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    resign(&a, &mut tampered.envelope)?;
    rejected(apply(&mut b, &tampered).await, "payload report fields must match outer")?;
    assert_eq!(projected(&b, "c")?, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ad_binds_report_commitment_so_matched_c_tamper_fails_aead() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(159, 160)?;
    let entry = seal(&a, &b, message("report-ad", "c"), b"ad")?;
    let forged = ramflux_protocol::encode_base64url([0x00_u8; 32]);
    let mut tampered = entry.clone();
    rewrite_nested_commitment(&mut tampered, &forged)?;
    tampered.envelope.report_commitment = Some(forged);
    resign(&a, &mut tampered.envelope)?;
    crypto(apply(&mut b, &tampered).await, "aead operation failed")?;
    assert_eq!(projected(&b, "c")?, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn two_direct_sends_produce_fresh_commitments() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(145, 146)?;
    let first = seal(&a, &b, message("report-fresh-1", "c"), b"one")?;
    let mut second = seal(&a, &b, message("report-fresh-2", "c"), b"two")?;
    second.inbox_seq = 2;
    let first_c = first.envelope.report_commitment.as_deref().ok_or_else(|| invalid("first C"))?;
    let second_c =
        second.envelope.report_commitment.as_deref().ok_or_else(|| invalid("second C"))?;
    assert_ne!(first_c, second_c);
    apply(&mut b, &first).await?;
    apply(&mut b, &second).await?;
    assert_eq!(projected(&b, "c")?, 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn gate_off_omits_report_fields_and_legacy_bytes_open() -> Result<(), SdkError> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let (a, mut b) = pair(147, 148)?;
    let entry = seal(&a, &b, message("report-legacy", "c"), b"legacy-body")?;
    assert_eq!(entry.envelope.collapse_tag, None);
    assert_eq!(entry.envelope.report_commitment, None);
    let json = serde_json::to_vec(&entry.envelope)?;
    assert!(!json.windows(b"report_commitment".len()).any(|w| w == b"report_commitment"));
    assert!(!json.windows(b"collapse_tag".len()).any(|w| w == b"collapse_tag"));
    let opened = apply(&mut b, &entry).await?;
    assert!(opened.plaintext.is_some());
    assert_eq!(projected(&b, "c")?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn gate_on_control_route_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(161, 162)?;
    let entry = seal_as(
        &a,
        &b,
        message("report-control", "c"),
        br#"{"type":"pair.session.reset.v1"}"#,
        Route::control(),
    )?;
    ramflux_node_core::check_entry_bound(&entry.envelope)
        .map_err(|error| invalid(&error.to_string()))?;
    opened_kind(&apply(&mut b, &entry).await?, &Kind::Control)
}

#[tokio::test(flavor = "current_thread")]
async fn gate_on_receipt_route_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (mut a, mut b) = pair(163, 164)?;
    friend(&mut a, &b)?;
    a.client.send_direct_message("c", "outgoing", "alice", b"hello")?;
    a.client.account_db()?.persist_client_record(
        "conversation",
        "c",
        &serde_json::json!({"kind":"direct","participants":["alice","bob"]}),
    )?;
    let outgoing = seal(&a, &b, message("outgoing", "c"), b"hello")?;
    apply(&mut b, &outgoing).await?;
    let body = serde_json::to_vec(&serde_json::json!({
        "schema":"ramflux.sdk.receipt_event.v1","version":1,"receipt_id":"report-receipt",
        "event_seq":1,"nonce":"nonce","reader_device_id":"bob",
        "event":{"type":"ReceiptDelivered","conversation_id":"c","message_id":"outgoing",
            "delivered_at":1,"receiver_device_id":"bob","scope":"device","ttl_seconds":3600}
    }))?;
    let mut receipt = reply_to("alice");
    receipt.envelope_id = "report-receipt".into();
    receipt.message_id = "report-receipt".into();
    receipt.conversation_id = "c".into();
    let entry = seal_as(&b, &a, receipt, &body, Route::receipt())?;
    ramflux_node_core::check_entry_bound(&entry.envelope)
        .map_err(|error| invalid(&error.to_string()))?;
    opened_kind(&apply(&mut a, &entry).await?, &Kind::Receipt)
}

#[tokio::test(flavor = "current_thread")]
async fn gate_on_group_message_route_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(165, 166)?;
    super::fixture_group(&a.client, "report-group", &a)?;
    super::fixture_group(&b.client, "report-group", &a)?;
    super::fixture_member(&a.client, "report-group", &b)?;
    super::fixture_member(&b.client, "report-group", &b)?;
    b.client.import_group_sender_key_distribution(
        &a.client.export_group_sender_key_distribution("report-group", "alice")?,
    )?;
    let body = a.client.encrypt_group_message("report-group", "alice", b"group-body")?;
    let entry = seal_as(
        &a,
        &b,
        message("report-group-msg", "c"),
        &body,
        Route::group_message("report-group"),
    )?;
    ramflux_node_core::check_entry_bound(&entry.envelope)
        .map_err(|error| invalid(&error.to_string()))?;
    opened_kind(&apply(&mut b, &entry).await?, &Kind::GroupMessage)
}

#[tokio::test(flavor = "current_thread")]
async fn gate_on_opaque_own_device_body_builds_envelope() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, _) = pair(167, 168)?;
    let mut packet = crate::client::own_device_copy::PREFIX.to_vec();
    packet.extend(br#"{"schema":"ramflux.sdk.own_device_message.v2","id":"opaque"}"#);
    let mut message = message("report-opaque", "c");
    message.encrypted_body = packet.clone();
    let envelope = gateway_direct_message_envelope(&a.config()?, &message, None)?;
    let payload = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    assert!(payload.starts_with(crate::client::own_device_copy::PREFIX));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn gate_on_compact_rewrap_body_builds_and_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(169, 170)?;
    let entry = seal(&a, &b, message("report-compact", "c"), b"compact-body")?;
    let compact = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    ramflux_protocol::message::outer::decode_compact_cryptobox(&compact)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut message = message("report-compact", "c");
    message.envelope_id.clone_from(&entry.envelope.envelope_id);
    message.source_principal_id.clone_from(&entry.envelope.source_principal_id);
    message.sender_id.clone_from(&entry.envelope.source_device_id);
    message.target_delivery_id.clone_from(&entry.envelope.target_delivery_id);
    message.encrypted_body = compact;
    message.created_at = entry.envelope.created_at;
    message.ttl = entry.envelope.ttl;
    let committed = encode_candidate_report_a0(
        &candidate_report_a0_from_envelope(&entry.envelope)
            .map_err(|error| invalid(&error.to_string()))?,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    let envelope =
        gateway_direct_message_envelope_sealed(&a.config()?, &message, None, Some(&committed))?;
    let nested = decode(&envelope)?;
    assert!(nested.collapse_tag.is_some());
    assert!(nested.report_commitment.is_some());
    let mut rewrapped = entry.clone();
    rewrapped.envelope = envelope;
    let opened = apply(&mut b, &rewrapped).await?;
    assert!(opened.plaintext.is_some());
    assert_eq!(projected(&b, "c")?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn abandoned_direct_seal_does_not_fail_later_control_send() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = pair(171, 172)?;
    let _abandoned = super::seal_nested(
        &a,
        &b,
        message("report-abandoned", "c"),
        b"abandoned-body",
        Route::direct(),
    )?;
    let (c, mut d) = pair(175, 176)?;
    let entry = seal_as(
        &c,
        &d,
        message("report-control-after-abandon", "c"),
        br#"{"type":"pair.session.reset.v1"}"#,
        Route::control(),
    )?;
    opened_kind(&apply(&mut d, &entry).await?, &Kind::Control)
}

#[tokio::test(flavor = "current_thread")]
async fn a0_drift_is_a_send_error() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = pair(173, 174)?;
    let (mut message, sealed) =
        super::seal_nested(&a, &b, message("report-a0-drift", "c"), b"drift", Route::direct())?;
    message.encrypted_body = serde_json::to_vec(&sealed.packet)?;
    message.ttl = message.ttl.saturating_add(1);
    match gateway_direct_message_envelope_sealed(
        &a.config()?,
        &message,
        None,
        sealed.committed_a0.as_deref(),
    ) {
        Err(SdkError::InboundRejected(text)) if text.contains("report a0 drifted") => Ok(()),
        Err(error) => Err(invalid(&format!("exact a0 drift, got {error}"))),
        Ok(_) => Err(invalid("exact a0 drift, got Ok")),
    }
}

fn helper_a0_drift(alice: u8, bob: u8, id: &str) -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = pair(alice, bob)?;
    let (mut message, sealed) =
        super::seal_nested(&a, &b, message(id, "c"), b"drift", Route::direct())?;
    message.ttl = message.ttl.saturating_add(1);
    match gateway_envelope_from_sealed(&a.config()?, &mut message, sealed, None) {
        Err(SdkError::InboundRejected(text)) if text.contains("report a0 drifted") => Ok(()),
        Err(error) => Err(invalid(&format!("exact a0 drift, got {error}"))),
        Ok(_) => Err(invalid("exact a0 drift, got Ok")),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn helper_a0_drift_task_transport() -> Result<(), SdkError> {
    helper_a0_drift(181, 182, "report-task-a0-drift")
}

#[tokio::test(flavor = "current_thread")]
async fn helper_a0_drift_group() -> Result<(), SdkError> {
    helper_a0_drift(183, 184, "report-group-a0-drift")
}

#[tokio::test(flavor = "current_thread")]
async fn helper_a0_drift_outbox() -> Result<(), SdkError> {
    helper_a0_drift(185, 186, "report-outbox-a0-drift")
}

#[tokio::test(flavor = "current_thread")]
async fn none_wrapper_refuses_direct_payload() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = pair(187, 188)?;
    let (mut message, sealed) = super::seal_nested(
        &a,
        &b,
        message("report-wrapper-direct", "c"),
        b"direct",
        Route::direct(),
    )?;
    message.encrypted_body = serde_json::to_vec(&sealed.packet)?;
    match gateway_direct_message_envelope(&a.config()?, &message, None) {
        Err(SdkError::InboundRejected(text))
            if text.contains("direct payload requires committed a0") =>
        {
            Ok(())
        }
        Err(error) => Err(invalid(&format!("exact wrapper guard, got {error}"))),
        Ok(_) => Err(invalid("exact wrapper guard, got Ok")),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn task_transport_prepared_a0_drift_is_a_send_error() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (mut a, b) = pair(189, 190)?;
    if a.client
        .account_db()?
        .client_record("device", &b.client.local_device_reference(&b.id)?)?
        .is_none()
    {
        super::review::trust(&a, &b)?;
    }
    let identity = b.client.owned_device_identity()?;
    let bundle = b.client.load_x3dh_private_state(&b.client.local_device_identity(&b.id)?)?.bundle;
    let engine = GatewaySessionEngine::with_test_transport(a.config()?, Box::new(NoNetwork));
    let account = LocalBusAccountState::new(std::mem::take(&mut a.client), engine, a.id.clone());
    let target = crate::bus::dispatch::task_transport::Target {
        device: b.id.clone(),
        identity,
        delivery: b.id.clone(),
        federation: None,
        own: false,
    };
    let mut draft = crate::bus::dispatch::task_transport::prepared::Draft::new(
        &account,
        target,
        "c",
        b"prepared-drift",
        Route::direct(),
    )?;
    draft.drift_ttl = true;
    match draft.seal(
        &account,
        crate::client::routed::SendMaterial { manifest: None, bundle: Some(bundle) },
    ) {
        Err(SdkError::InboundRejected(text)) if text.contains("report a0 drifted") => Ok(()),
        Err(error) => Err(invalid(&format!("exact prepared a0 drift, got {error}"))),
        Ok(_) => Err(invalid("exact prepared a0 drift, got Ok")),
    }
}

fn uniform_tag_and_commitment(envelope: &ramflux_protocol::Envelope) -> Result<(), SdkError> {
    let tag = ramflux_protocol::decode_base64url(
        envelope.collapse_tag.as_deref().ok_or_else(|| invalid("collapse_tag"))?,
    )
    .map_err(|_| invalid("collapse_tag"))?;
    let commitment = ramflux_protocol::decode_base64url(
        envelope.report_commitment.as_deref().ok_or_else(|| invalid("report_commitment"))?,
    )
    .map_err(|_| invalid("report_commitment"))?;
    if tag.len() != 32 || commitment.len() != 32 {
        return Err(invalid("tag and commitment must be 32 bytes"));
    }
    ramflux_node_core::check_entry_bound(envelope).map_err(|error| invalid(&error.to_string()))?;
    Ok(())
}

fn own_message_copy_inner(sender: &Fixture, receiver: &Fixture) -> Result<Vec<u8>, SdkError> {
    let source = ramflux_protocol::message::QualifiedDevice {
        account_anchor: sender.client.own_account_anchor()?,
        device_id: sender.id.clone(),
        device_epoch: 1,
    };
    let target = ramflux_protocol::message::QualifiedDevice {
        account_anchor: sender.client.own_account_anchor()?,
        device_id: receiver.id.clone(),
        device_epoch: 1,
    };
    let control = crate::client::generated_control::control_from_payload(
        ramflux_protocol::message::control::Payload::OwnMessageCopy(
            ramflux_protocol::message::OwnMessageCopy {
                source: Some(source.clone()),
                target: Some(target),
                created_at: 1,
                expires_at: 2,
                payload: Some(ramflux_protocol::message::own_message_copy::Payload::Sent(
                    ramflux_protocol::message::OwnSentMessage {
                        envelope_id: "own-env".into(),
                        message_id: "own-msg".into(),
                        sender_id: sender.id.clone(),
                        original_recipients: Vec::new(),
                        ciphertext_digest: Some(vec![1; 32]),
                        authored_at: Some(1),
                        exact_inner: vec![7; 8],
                        ..Default::default()
                    },
                )),
            },
        ),
    )?;
    let mut stream = crate::client::generated_content::GeneratedEventStream::new("c", source);
    RamfluxClient::encode_generated_control(&mut stream, b"own-copy".to_vec(), control)
}

fn receipt_body(id: &str, message_id: &str) -> Result<Vec<u8>, SdkError> {
    serde_json::to_vec(&serde_json::json!({
        "schema":"ramflux.sdk.receipt_event.v1","version":1,"receipt_id":id,
        "event_seq":1,"nonce":"nonce","reader_device_id":"bob",
        "event":{"type":"ReceiptDelivered","conversation_id":"c","message_id":message_id,
            "delivered_at":1,"receiver_device_id":"bob","scope":"device","ttl_seconds":3600}
    }))
    .map_err(SdkError::from)
}

fn receipt_message(id: &str) -> GatewayDirectMessage {
    let mut receipt = reply_to("alice");
    receipt.envelope_id = id.into();
    receipt.message_id = id.into();
    receipt.conversation_id = "c".into();
    receipt
}

#[tokio::test(flavor = "current_thread")]
async fn every_envelope_has_uniform_tag_and_commitment() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = pair(189, 190)?;
    uniform_tag_and_commitment(&seal(&a, &b, message("t07-direct", "c"), b"direct")?.envelope)?;
    let (a, b) = pair(191, 192)?;
    uniform_tag_and_commitment(
        &seal_as(
            &a,
            &b,
            message("t07-control", "c"),
            br#"{"type":"pair.session.reset.v1"}"#,
            Route::control(),
        )?
        .envelope,
    )?;
    let (a, b) = pair(193, 194)?;
    super::fixture_group(&a.client, "t07-group", &a)?;
    super::fixture_group(&b.client, "t07-group", &a)?;
    super::fixture_member(&a.client, "t07-group", &b)?;
    super::fixture_member(&b.client, "t07-group", &b)?;
    b.client.import_group_sender_key_distribution(
        &a.client.export_group_sender_key_distribution("t07-group", "alice")?,
    )?;
    let group_body = a.client.encrypt_group_message("t07-group", "alice", b"group-body")?;
    uniform_tag_and_commitment(
        &seal_as(
            &a,
            &b,
            message("t07-group-msg", "c"),
            &group_body,
            Route::group_message("t07-group"),
        )?
        .envelope,
    )?;
    let (a, b) = pair(195, 196)?;
    uniform_tag_and_commitment(
        &seal_as(
            &b,
            &a,
            receipt_message("t07-receipt"),
            &receipt_body("t07-receipt", "t07-outgoing")?,
            Route::receipt(),
        )?
        .envelope,
    )?;
    let (a, b) = pair(197, 198)?;
    uniform_tag_and_commitment(
        &seal_as(
            &a,
            &b,
            message("t07-own", "c"),
            &own_message_copy_inner(&a, &b)?,
            Route::control(),
        )?
        .envelope,
    )?;
    let _omit = omit_direct_report();
    let (a, b) = pair(199, 200)?;
    let omitted = seal_as(
        &b,
        &a,
        receipt_message("t07-omit"),
        &receipt_body("t07-omit", "t07-outgoing")?,
        Route::receipt(),
    )?;
    match uniform_tag_and_commitment(&omitted.envelope) {
        Err(_) => Ok(()),
        Ok(()) => Err(invalid("omit Receipt commitment must fail the T07 assertion")),
    }
}

#[test]
fn report_mismatch_maps_to_authentication_failed() {
    assert_eq!(
        deterministic(&SdkError::Crypto(CryptoError::ReportCommitmentMismatch)),
        Some("authentication_failed")
    );
    assert_eq!(
        deterministic(&SdkError::Crypto(CryptoError::ReportCommitmentMissing)),
        Some("authentication_failed")
    );
    assert_eq!(
        SdkError::Crypto(CryptoError::ReportCommitmentMismatch).to_string(),
        "crypto error: report opening commitment mismatch"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn refused_first_c_does_not_strand_pair_successor() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(187, 189)?;
    let mut bad = seal(&a, &b, message("bad-first-c", "c"), b"must not project")?;
    // Signed issue time is in C's A0, while the pair AEAD still authenticates this exact ciphertext.
    bad.envelope.created_at = bad.envelope.created_at.saturating_add(1);
    resign(&a, &mut bad.envelope)?;
    let mut next = seal(&a, &b, message("after-first-c-refusal", "c"), b"next message")?;
    next.inbox_seq = 2;
    Box::pin(settle_through(&mut b, vec![bad, next])).await?;
    assert_eq!(b.client.gateway_receive_cursor("bob")?, 2);
    assert_eq!(projected(&b, "c")?, 1);
    assert!(b.client.direct_message_by_id("bad-first-c")?.is_none());
    assert!(b.client.direct_message_by_id("after-first-c-refusal")?.is_some());
    Ok(())
}
