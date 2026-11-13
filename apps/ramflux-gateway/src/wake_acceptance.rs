// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Call-intent admission and opaque wake identity on the production gateway path.
use ramflux_protocol::{
    CallIntentAction, CallIntentKind, CallIntentV1, DeliveryClass, GATEWAY_CALL_INTENT_AUDIENCE,
    SignedCallIntentV1, WakeClass, WakeSignatureAlg, call_intent_digest, call_intent_signing_bytes,
};

fn open_store(
    name: &str,
) -> Result<(ramflux_node_core::GatewayRedbStore, tempfile::TempDir), Box<dyn std::error::Error>> {
    let temp = tempfile::Builder::new().prefix(name).tempdir()?;
    let store = ramflux_node_core::GatewayRedbStore::open(temp.path().join("gateway.redb"))?;
    Ok((store, temp))
}

struct Caller {
    branch: ramflux_crypto::DeviceBranch,
    key_id: String,
    sender: ramflux_crypto::RootQualifiedDeviceRef,
    callee: ramflux_crypto::RootQualifiedDeviceRef,
}

fn caller() -> Result<Caller, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("principal-call", [9_u8; 32]);
    let branch = ramflux_crypto::DeviceBranch {
        principal_id: "principal-call".to_owned(),
        device_id: "phone".to_owned(),
        device_epoch: 3,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[5_u8; 32]),
    };
    let key_id = ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let sender = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
    let callee = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "tablet")?;
    Ok(Caller { branch, key_id, sender, callee })
}

fn runtime(caller: &Caller) -> crate::state::GatewaySessionRuntime {
    crate::state::GatewaySessionRuntime {
        call_session_generation: None,
        session_push: None,
        ephemeral: false,
        push_limit: 1,
        source_identity: caller.sender.clone(),
        session_id: "session-call".to_owned(),
        resume_token: "resume-call".to_owned(),
        principal_id: "principal-call".to_owned(),
        device_id: "phone".to_owned(),
        target_delivery_id: "callee-delivery".to_owned(),
        branch_public_key: caller.key_id.clone(),
        device_epoch: caller.branch.device_epoch,
        supports_forward_ack: false,
        ephemeral_rate: std::sync::Arc::new(crate::ephemeral::EphemeralRate::default()),
    }
}

fn envelope(
    id: &str,
    class: DeliveryClass,
    now: u64,
    ttl: u32,
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    Ok(ramflux_protocol::Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "test-envelope-key".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "test-envelope-signature".to_owned(),
        },
        envelope_id: id.to_owned(),
        source_principal_id: "principal-call".to_owned(),
        source_device_id: "phone".to_owned(),
        target_delivery_id: "callee-delivery".to_owned(),
        routing_set_id: None,
        delivery_class: class,
        priority: ramflux_protocol::Priority::Normal,
        ttl,
        created_at: i64::try_from(now).map_err(|_| "envelope time does not fit")?,
        encrypted_payload: "ciphertext-sentinel".to_owned(),
        payload_hash: "hash-sentinel".to_owned(),
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
    })
}

fn intent_body(
    caller: &Caller,
    action: CallIntentAction,
    seq: u64,
    event_id: &str,
    now: u64,
    start_digest: Option<String>,
) -> CallIntentV1 {
    CallIntentV1 {
        version: 1,
        signing_key_id: caller.key_id.clone(),
        signature_alg: WakeSignatureAlg::Ed25519,
        audience: GATEWAY_CALL_INTENT_AUDIENCE.to_owned(),
        sender_device: caller.sender.storage_key().to_owned(),
        sender_epoch: caller.branch.device_epoch,
        target_device: caller.callee.storage_key().to_owned(),
        target_epoch: 4,
        target_delivery_id: "callee-delivery".to_owned(),
        call_ref: ramflux_protocol::encode_base64url([3_u8; 16]),
        source_event_id: event_id.to_owned(),
        kind: CallIntentKind::OneToOne,
        action,
        seq,
        created_at: now,
        issued_at: now,
        expires_at: now.saturating_add(30),
        start_digest,
    }
}

fn sign_intent(
    caller: &Caller,
    body: CallIntentV1,
) -> Result<SignedCallIntentV1, Box<dyn std::error::Error>> {
    let bytes = call_intent_signing_bytes(&body)?;
    let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(&bytes, &caller.branch);
    Ok(SignedCallIntentV1 { body, signature })
}

fn signer() -> ramflux_node_core::NodeServiceSigningKey {
    ramflux_node_core::NodeServiceSigningKey::from_seed([6_u8; 32])
}

#[test]
fn call_intent_forged_missing_noncall_and_cancel_rows() -> Result<(), Box<dyn std::error::Error>> {
    let caller = caller()?;
    let session = runtime(&caller);
    let now = ramflux_node_core::now_unix_seconds();
    let start = sign_intent(
        &caller,
        intent_body(&caller, CallIntentAction::Start, 0, "env-start", now, None),
    )?;
    let digest = call_intent_digest(&start)?;
    let mut forged = start.clone();
    forged.signature = ramflux_protocol::encode_base64url([7_u8; 64]);
    let call = envelope("env-start", DeliveryClass::OpaqueEvent, now, 86_400)?;
    let owner = caller.callee.storage_key();
    assert!(
        crate::call_intent::verify_submission(&session, &call, &forged, 4, owner, now).is_err()
    );
    let non_call = envelope("env-start", DeliveryClass::SelfDeviceControl, now, 86_400)?;
    assert!(
        crate::call_intent::verify_submission(&session, &non_call, &start, 4, owner, now).is_err()
    );
    crate::call_intent::verify_submission(&session, &call, &start, 4, owner, now)?;
    let (kept, _path) = open_store("call-intent")?;
    let missing = envelope("env-missing", DeliveryClass::OpaqueEvent, now, 86_400)?;
    let unsigned = crate::notify_wake::signed_offline_wake(
        &kept,
        &signer(),
        &crate::notify_wake::OfflineWakeInput {
            source_identity: caller.sender.storage_key(),
            source_epoch: caller.branch.device_epoch,
            target_owner_epoch: 4,
            target_delivery_id: "callee-delivery",
            envelope: &missing,
            now,
        },
    )?;
    let missing_wake = unsigned.ok_or("missing intent must still send a message wake")?;
    assert_eq!(missing_wake.body.class, WakeClass::Message);
    assert!(missing_wake.body.call_intent_digest.is_none());
    let (cancel_store, _path) = open_store("call-intent-cancel")?;
    let cancel = sign_intent(
        &caller,
        intent_body(&caller, CallIntentAction::Cancel, 1, "env-start", now, Some(digest.clone())),
    )?;
    let cancelled =
        cancel_store.admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
            signed: &cancel,
            start_digest: &digest,
            envelope_id: "env-cancel",
            source_identity: caller.sender.storage_key(),
            source_epoch: caller.branch.device_epoch,
            encrypted_invite: b"invite",
        })?;
    assert!(matches!(cancelled, ramflux_node_core::CallIntentEffect::Cancelled { wake_id: None }));
    let reopened =
        cancel_store.admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
            signed: &start,
            start_digest: &digest,
            envelope_id: "env-start",
            source_identity: caller.sender.storage_key(),
            source_epoch: caller.branch.device_epoch,
            encrypted_invite: b"invite",
        })?;
    assert!(matches!(reopened, ramflux_node_core::CallIntentEffect::Cancelled { .. }));
    let grant = cancel_store.call_grant(
        caller.sender.storage_key(),
        caller.branch.device_epoch,
        "env-start",
        "callee-delivery",
        now,
    )?;
    assert_eq!(grant, ramflux_node_core::CallGrant::Silent);
    Ok(())
}

fn wake_input<'a>(
    identity: &'a str,
    envelope: &'a ramflux_protocol::Envelope,
    now: u64,
) -> crate::notify_wake::OfflineWakeInput<'a> {
    crate::notify_wake::OfflineWakeInput {
        source_identity: identity,
        source_epoch: 3,
        target_owner_epoch: 4,
        target_delivery_id: "callee-delivery",
        envelope,
        now,
    }
}

#[test]
fn wake_identity_is_opaque_stable_for_retry_and_recovery() -> Result<(), Box<dyn std::error::Error>>
{
    let caller = caller()?;
    let now = ramflux_node_core::now_unix_seconds();
    let signer = signer();
    let (kept, path) = open_store("wake-identity")?;
    let first_envelope = envelope("env-one", DeliveryClass::OpaqueEvent, now, 86_400)?;
    let second_envelope = envelope("env-two", DeliveryClass::OpaqueEvent, now, 86_400)?;
    let first = crate::notify_wake::signed_offline_wake(
        &kept,
        &signer,
        &wake_input(caller.sender.storage_key(), &first_envelope, now),
    )?
    .ok_or("first wake was not admitted")?;
    let second = crate::notify_wake::signed_offline_wake(
        &kept,
        &signer,
        &wake_input(caller.sender.storage_key(), &second_envelope, now),
    )?
    .ok_or("second wake was not admitted")?;
    assert_ne!(first.body.wake_id, second.body.wake_id);
    assert_ne!(first.body.wake_id, format!("wake_{}", first_envelope.envelope_id));
    assert!(!first.body.wake_id.contains("env-one"));
    assert_eq!(ramflux_protocol::decode_base64url(&first.body.wake_id)?.len(), 16);
    let retried = crate::notify_wake::signed_offline_wake(
        &kept,
        &signer,
        &wake_input(caller.sender.storage_key(), &first_envelope, now),
    )?
    .ok_or("retry dropped the wake")?;
    assert_eq!(retried.body.wake_id, first.body.wake_id);
    assert_eq!(retried.body.expires_at, first.body.expires_at);
    drop(kept);
    let reopened = ramflux_node_core::GatewayRedbStore::open(path.path().join("gateway.redb"))?;
    let restored = crate::notify_wake::signed_offline_wake(
        &reopened,
        &signer,
        &wake_input(caller.sender.storage_key(), &first_envelope, now),
    )?
    .ok_or("reopen dropped the wake")?;
    assert_eq!(restored.body.wake_id, first.body.wake_id);
    assert_eq!(restored.body.expires_at, first.body.expires_at);
    Ok(())
}

#[test]
fn call_wake_deadline_is_thirty_seconds_across_dispatch_and_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let caller = caller()?;
    let session = runtime(&caller);
    let now = ramflux_node_core::now_unix_seconds();
    let mut short = intent_body(&caller, CallIntentAction::Start, 0, "env-deadline", now, None);
    short.expires_at = now.saturating_add(10);
    let start = sign_intent(&caller, short)?;
    let digest = call_intent_digest(&start)?;
    let call = envelope("env-deadline", DeliveryClass::OpaqueEvent, now, 10)?;
    crate::call_intent::verify_submission(
        &session,
        &call,
        &start,
        4,
        caller.callee.storage_key(),
        now,
    )?;
    let (kept, _path) = open_store("call-deadline")?;
    assert!(matches!(
        kept.admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
            signed: &start,
            start_digest: &digest,
            envelope_id: "env-deadline",
            source_identity: caller.sender.storage_key(),
            source_epoch: caller.branch.device_epoch,
            encrypted_invite: call.encrypted_payload.as_bytes(),
        })?,
        ramflux_node_core::CallIntentEffect::Authorized
    ));
    let signed = crate::notify_wake::signed_offline_wake(
        &kept,
        &signer(),
        &wake_input(caller.sender.storage_key(), &call, now),
    )?
    .ok_or("bounded call wake was dropped")?;
    assert_eq!(signed.body.class, WakeClass::CallWake);
    assert_eq!(signed.body.created_at, now);
    assert_eq!(signed.body.expires_at, now.saturating_add(10));
    assert_ne!(signed.body.expires_at, now.saturating_add(30));
    assert_ne!(signed.body.expires_at, now.saturating_add(86_400));
    let wide = envelope("env-wide", DeliveryClass::OpaqueEvent, now, 86_400)?;
    let wide_start = sign_intent(
        &caller,
        intent_body(&caller, CallIntentAction::Start, 0, "env-wide", now, None),
    )?;
    let wide_digest = call_intent_digest(&wide_start)?;
    kept.admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
        signed: &wide_start,
        start_digest: &wide_digest,
        envelope_id: "env-wide",
        source_identity: caller.sender.storage_key(),
        source_epoch: caller.branch.device_epoch,
        encrypted_invite: wide.encrypted_payload.as_bytes(),
    })?;
    let wide_wake = crate::notify_wake::signed_offline_wake(
        &kept,
        &signer(),
        &wake_input(caller.sender.storage_key(), &wide, now),
    )?
    .ok_or("thirty second call wake was dropped")?;
    assert_eq!(wide_wake.body.expires_at, now.saturating_add(30));
    let replay = crate::notify_wake::signed_offline_wake(
        &kept,
        &signer(),
        &wake_input(caller.sender.storage_key(), &wide, now),
    )?
    .ok_or("deadline replay was dropped")?;
    assert_eq!(replay.body.wake_id, wide_wake.body.wake_id);
    assert_eq!(replay.body.expires_at, wide_wake.body.expires_at);
    let expired = envelope("env-old", DeliveryClass::OpaqueEvent, now.saturating_sub(100), 10)?;
    assert!(
        crate::notify_wake::signed_offline_wake(
            &kept,
            &signer(),
            &wake_input(caller.sender.storage_key(), &expired, now),
        )?
        .is_none()
    );
    Ok(())
}

#[test]
fn owner_resolution_rejects_a_stranger_and_answer_ends_the_wake()
-> Result<(), Box<dyn std::error::Error>> {
    let caller = caller()?;
    let now = ramflux_node_core::now_unix_seconds();
    let start = sign_intent(
        &caller,
        intent_body(&caller, CallIntentAction::Start, 0, "env-resolve", now, None),
    )?;
    let digest = call_intent_digest(&start)?;
    let (store, _path) = open_store("resolve")?;
    store.admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
        signed: &start,
        start_digest: &digest,
        envelope_id: "env-resolve",
        source_identity: caller.sender.storage_key(),
        source_epoch: caller.branch.device_epoch,
        encrypted_invite: b"invite-ciphertext",
    })?;
    let stranger = ramflux_node_core::WakeOwnerLookup {
        owner_device: "stranger",
        owner_epoch: 4,
        wake_id: None,
        call_ref: Some(&start.body.call_ref),
        now,
    };
    assert!(store.resolve_wake_for_owner(&stranger)?.is_none());
    let owner = ramflux_node_core::WakeOwnerLookup {
        owner_device: caller.callee.storage_key(),
        owner_epoch: start.body.target_epoch,
        wake_id: None,
        call_ref: Some(&start.body.call_ref),
        now,
    };
    let resolved = store.resolve_wake_for_owner(&owner)?.ok_or("callee resolve missing")?;
    assert!(resolved.media_allowed);
    assert!(!resolved.terminal);
    assert_eq!(resolved.encrypted_invite, b"invite-ciphertext");
    store.bind_call_wake_id(
        caller.sender.storage_key(),
        caller.branch.device_epoch,
        "env-resolve",
        &start.body.target_delivery_id,
        "wake-answer",
    )?;
    let owner = ramflux_node_core::WakeOwnerLookup {
        owner_device: caller.callee.storage_key(),
        owner_epoch: start.body.target_epoch,
        wake_id: None,
        call_ref: Some(&start.body.call_ref),
        now,
    };
    assert_eq!(store.apply_owner_terminal(&owner, "answer")?.as_deref(), Some("wake-answer"));
    assert_eq!(store.apply_owner_terminal(&owner, "answer")?.as_deref(), Some("wake-answer"));
    let later = ramflux_node_core::WakeOwnerLookup {
        owner_device: caller.callee.storage_key(),
        owner_epoch: start.body.target_epoch,
        wake_id: None,
        call_ref: Some(&start.body.call_ref),
        now: now.saturating_add(120),
    };
    let answered = store.resolve_wake_for_owner(&later)?.ok_or("answered resolve missing")?;
    assert!(answered.terminal);
    assert!(answered.media_allowed);
    assert!(store.apply_owner_terminal(&owner, "reject").is_err());
    assert!(store.apply_owner_terminal(&owner, "end")?.is_some());
    let ended = store.resolve_wake_for_owner(&owner)?.ok_or("ended resolve missing")?;
    assert!(ended.terminal);
    assert!(!ended.media_allowed);
    assert!(matches!(
        store.call_grant(
            caller.sender.storage_key(),
            caller.branch.device_epoch,
            "env-resolve",
            &start.body.target_delivery_id,
            now,
        )?,
        ramflux_node_core::CallGrant::Silent
    ));
    Ok(())
}

#[test]
fn cancel_uses_the_stored_start_when_the_envelope_is_later()
-> Result<(), Box<dyn std::error::Error>> {
    let caller = caller()?;
    let session = runtime(&caller);
    let now = ramflux_node_core::now_unix_seconds();
    let start = sign_intent(
        &caller,
        intent_body(&caller, CallIntentAction::Start, 0, "env-later", now, None),
    )?;
    let digest = call_intent_digest(&start)?;
    let mut later = envelope("env-later", DeliveryClass::OpaqueEvent, now, 86_400)?;
    later.created_at = later.created_at.saturating_add(1);
    let owner = caller.callee.storage_key();
    assert!(
        crate::call_intent::verify_submission(&session, &later, &start, 4, owner, now).is_err()
    );
    let cancel = sign_intent(
        &caller,
        intent_body(&caller, CallIntentAction::Cancel, 1, "env-later", now, Some(digest.clone())),
    )?;
    crate::call_intent::verify_submission(
        &session,
        &later,
        &cancel,
        4,
        owner,
        now.saturating_add(1),
    )?;
    let (store, _path) = open_store("cancel-later")?;
    store.admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
        signed: &start,
        start_digest: &digest,
        envelope_id: "env-later",
        source_identity: caller.sender.storage_key(),
        source_epoch: caller.branch.device_epoch,
        encrypted_invite: b"invite",
    })?;
    let mut shifted =
        intent_body(&caller, CallIntentAction::Cancel, 1, "env-later", now, Some(digest.clone()));
    shifted.created_at = now.saturating_add(1);
    shifted.issued_at = now.saturating_add(1);
    let shifted = sign_intent(&caller, shifted)?;
    assert!(
        store
            .admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
                signed: &shifted,
                start_digest: &digest,
                envelope_id: "env-later-shifted",
                source_identity: caller.sender.storage_key(),
                source_epoch: caller.branch.device_epoch,
                encrypted_invite: b"invite",
            })
            .is_err()
    );
    let admitted = store.admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
        signed: &cancel,
        start_digest: &digest,
        envelope_id: "env-later-cancel",
        source_identity: caller.sender.storage_key(),
        source_epoch: caller.branch.device_epoch,
        encrypted_invite: b"invite",
    })?;
    assert!(matches!(admitted, ramflux_node_core::CallIntentEffect::Cancelled { .. }));
    Ok(())
}

struct ResolutionSink(std::sync::Arc<std::sync::Mutex<Vec<ramflux_node_core::GatewayServerFrame>>>);

impl ramflux_transport::GatewaySessionFrameSink for ResolutionSink {
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }

    fn send_frame<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), ramflux_transport::TransportError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.0
                .lock()
                .map_err(|_| ramflux_transport::TransportError::Quic("test sink mutex".into()))?
                .push(serde_json::from_slice(body)?);
            Ok(())
        })
    }
}

fn native_owner_call(
    path: &std::path::Path,
    now: u64,
) -> Result<
    (
        ramflux_node_core::test_support::notification_authority::NativeScenario,
        Caller,
        SignedCallIntentV1,
    ),
    Box<dyn std::error::Error>,
> {
    use ramflux_node_core::test_support::notification_authority::{NativeDevice, NativeScenario};
    let scenario = NativeScenario::new(path).map_err(|error| error.to_string())?;
    let source = NativeDevice::new("caller.example", 10, now)?;
    let target = NativeDevice::new("callee.example", 30, now)?;
    scenario.publish(&source, now).map_err(|error| error.to_string())?;
    scenario.publish(&target, now).map_err(|error| error.to_string())?;
    let start = source.call_start(&target, "env-router", 71, now)?;
    let source_record =
        ramflux_crypto::custody::verify_record(&source.publication.record, now, None, None)?;
    let target_record =
        ramflux_crypto::custody::verify_record(&target.publication.record, now, None, None)?;
    let sender =
        ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(&source_record, "primary")?;
    let callee =
        ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(&target_record, "primary")?;
    let key_id =
        ramflux_protocol::encode_base64url(source.branch.signing_key.verifying_key().to_bytes());
    Ok((scenario, Caller { branch: source.branch, key_id, sender, callee }, start))
}

fn owner_answer_submit(
    caller: &Caller,
    start: &SignedCallIntentV1,
    digest: &str,
    now: u64,
) -> Result<
    (crate::state::GatewaySessionRuntime, ramflux_node_core::GatewaySubmitFrame),
    Box<dyn std::error::Error>,
> {
    let mut runtime = runtime(caller);
    runtime.source_identity = caller.callee.clone();
    runtime.device_epoch = start.body.target_epoch;
    runtime.call_session_generation = Some(ramflux_protocol::encode_base64url([19; 32]));
    let mut submit = crate::session::submit_fixtures::signed_submit(&runtime, i64::try_from(now)?)?;
    submit.call_ref = Some(start.body.call_ref.clone());
    submit.call_terminal = Some("answer".to_owned());
    submit.call_context = Some(ramflux_protocol::CallSubmitContext {
        version: 1,
        call_ref: start.body.call_ref.clone(),
        start_digest: digest.into(),
        request_id: submit.signed_request.request_id.clone(),
        envelope_id: submit.envelope.envelope_id.clone(),
        session_id: runtime.session_id.clone(),
        session_generation: runtime
            .call_session_generation
            .clone()
            .ok_or("test: call generation")?,
    });
    Ok((runtime, submit))
}

#[tokio::test]
async fn answer_is_stored_only_after_the_router_accepts() -> Result<(), Box<dyn std::error::Error>>
{
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        Box::pin(async {
            let temp = tempfile::TempDir::new()?;
            let now = ramflux_node_core::now_unix_seconds();
            let (native, caller, start) = native_owner_call(temp.path(), now)?;
            let digest = call_intent_digest(&start)?;
            let mut context =
                crate::session::tests::test_gateway_context_at(&temp.path().join("context.redb"))?;
            context.store = std::sync::Arc::clone(&native.gateway);
            context.store.admit_verified_call_intent(&ramflux_node_core::CallIntentAdmission {
                signed: &start,
                start_digest: &digest,
                envelope_id: "env-router",
                source_identity: caller.sender.storage_key(),
                source_epoch: caller.branch.device_epoch,
                encrypted_invite: b"invite",
            })?;
            let (runtime, submit) = owner_answer_submit(&caller, &start, &digest, now)?;
            let frames = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let send = std::sync::Arc::new(tokio::sync::Mutex::new(Box::new(ResolutionSink(
                frames.clone(),
            ))
                as Box<dyn ramflux_transport::GatewaySessionFrameSink + Send>));
            let lookup = ramflux_node_core::WakeOwnerLookup {
                owner_device: caller.callee.storage_key(),
                owner_epoch: start.body.target_epoch,
                wake_id: None,
                call_ref: Some(&start.body.call_ref),
                now,
            };
            assert!(
                crate::session::enforce_call_resolution(&send, &context, &runtime, &submit).await?,
                "the complete owner context was refused before router submission"
            );
            let preview =
                context.store.resolve_wake_for_owner(&lookup)?.ok_or("preview missing")?;
            assert!(
                !preview.terminal,
                "preview committed the owner action before router acceptance"
            );
            assert!(
                crate::session::commit_owner_resolution(
                    &send,
                    &context,
                    &runtime,
                    &submit,
                    "aborted_retry_safe",
                )
                .await?,
                "a retry-safe router refusal should leave the call eligible for retry"
            );
            let refused =
                context.store.resolve_wake_for_owner(&lookup)?.ok_or("refused missing")?;
            assert!(!refused.terminal, "router refusal committed the owner action");
            assert!(
                crate::session::commit_owner_resolution(
                    &send, &context, &runtime, &submit, "online"
                )
                .await?,
                "router acceptance failed to commit the verified owner action"
            );
            let answered =
                context.store.resolve_wake_for_owner(&lookup)?.ok_or("answer missing")?;
            assert!(answered.terminal, "accepted Answer failed to resolve its wake");
            assert!(answered.media_allowed, "accepted Answer denied its selected media");
            let frames = frames.lock().map_err(|_| "frame mutex")?;
            assert!(
                matches!(
                    frames.first(),
                    Some(ramflux_node_core::GatewayServerFrame::CallResolved {
                        media_allowed: true,
                        wake_resolved: true,
                        ..
                    })
                ),
                "gateway omitted the matching accepted Answer decision"
            );
            Ok(())
        }),
    )
    .await?
}
