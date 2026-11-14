// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::test_support::notification_authority::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn native_router_gateway_notify_permit_cancellation_and_rotation() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let system = NativeScenario::new(temp.path())?;
    let (_, target, prepared) = system.prepared()?;
    let mut issued = 0;
    system.notify.issue_provider_push(&prepared, || {
        issued += 1;
        Ok(())
    })?;
    assert_eq!(issued, 1, "the exact native authority positive control never issued");
    system.route(&target, "token-two", crate::now_unix_seconds())?;
    assert!(
        system
            .notify
            .issue_provider_push(&prepared, || {
                issued += 1;
                Ok(())
            })
            .is_err(),
        "a replaced route issued its old token"
    );
    assert_eq!(issued, 1, "the refused old route reached the handoff closure");
    system.notify.cancel_pending_wake(&prepared.payload.wake_id)?;
    assert!(
        system
            .notify
            .issue_provider_push(&prepared, || {
                issued += 1;
                Ok(())
            })
            .is_err(),
        "a terminal wake regained a permit"
    );
    assert_eq!(issued, 1, "cancellation reached the handoff closure");
    Ok(())
}

#[test]
fn native_owner_revocation_fences_a_prepared_provider() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let system = NativeScenario::new(temp.path())?;
    let (_, target, prepared) = system.prepared()?;
    let now = crate::now_unix_seconds();
    system.router.publish_custody_record(&target.revoked(now)?, now, &system.router_store)?;
    let mut issued = false;
    assert!(
        system
            .notify
            .issue_provider_push(&prepared, || {
                issued = true;
                Ok(())
            })
            .is_err(),
        "committed native revocation left the old owner open"
    );
    assert!(!issued, "revoked owner reached provider issue");
    Ok(())
}

#[test]
fn native_terminal_components_retire_before_root_capacity_is_reused() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let system = NativeScenario::new(temp.path())?;
    system
        .notify
        .send_authority()
        .configure_origins(3, &[ROUTER.into(), GATEWAY.into(), NOTIFY.into()])?;
    let (_, target, prepared) = system.prepared()?;
    system.notify.issue_provider_push(&prepared, || Ok(()))?;
    let now = crate::now_unix_seconds();
    let next = NativeDevice::new("next.example", 100, now)?;
    system.publish(&next, now)?;
    assert!(
        system.route(&next, "next-token", now).is_err(),
        "full notify quota admitted a second simultaneous root"
    );
    let reference = ramflux_protocol::encode_base64url([71; 16]);
    system.gateway.apply_owner_terminal_with_expiry(
        &crate::WakeOwnerLookup {
            owner_device: &target.target,
            owner_epoch: 1,
            wake_id: Some(&prepared.payload.wake_id),
            call_ref: Some(&reference),
            now,
        },
        "reject",
        now + 600,
    )?;
    system.notify.cancel_pending_wake(&prepared.payload.wake_id)?;
    let authority =
        system.router.mvp1_device_auth_key_checked(&target.target)?.ok_or("test: native owner")?;
    system.notify.delete_authenticated_push_routes(&authority, None)?;
    system.router.publish_custody_record(&target.revoked(now)?, now, &system.router_store)?;
    assert!(
        system.route(&next, "next-token", now).is_err(),
        "deletion alone released required denial and high-water state"
    );
    let future = now + 604_800 + 121;
    system.network.set_time(future);
    assert_eq!(
        system.gateway.prune_call_authority(future)?,
        1,
        "closed call did not retire at its fixed horizon"
    );
    assert!(
        system.notify.prune_notification_authority(future)? >= 1,
        "notify's empty component never acknowledged retirement"
    );
    assert_eq!(
        system.router_store.prune_notify_owner(future)?,
        1,
        "denied router owner never retired"
    );
    system.route(&next, "next-token", now)?;
    let mut sent = false;
    assert!(
        system
            .notify
            .issue_provider_push(&prepared, || {
                sent = true;
                Ok(())
            })
            .is_err(),
        "retired tuple reopened a prepared provider request"
    );
    assert!(!sent, "retired request reached the handoff");
    Ok(())
}

#[test]
fn custodian_change_fences_native_participant_owner_during_lookup() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let system = NativeScenario::new(temp.path())?;
    let now = crate::now_unix_seconds();
    let human = NativeDevice::new("human.example", 20, now)?;
    let participant = NativeDevice::with_custodian(
        "participant.example",
        40,
        now,
        Some(human.publication.record.body.master_certificate.body.primary_device_ref.clone()),
    )?;
    system.publish(&human, now)?;
    system.publish(&participant, now)?;
    system.notify.update_provider_credential(&crate::ProviderCredential::Apns(
        crate::ApnsProviderCredential {
            credential_id: "apns".into(),
            team_id: "team".into(),
            key_id: "key".into(),
            p8_key_ref: "literal:fixture".into(),
            topic: "test.example".into(),
            sandbox: true,
            provider_ca_pem_ref: None,
        },
    ))?;
    system.route(&participant, "participant-token", now)?;
    let body = ramflux_protocol::WakeV2 {
        version: 2,
        signing_key_id: ramflux_protocol::encode_base64url(
            participant.branch.signing_key.verifying_key().to_bytes(),
        ),
        signature_alg: ramflux_protocol::WakeSignatureAlg::Ed25519,
        audience: ramflux_protocol::NOTIFY_WAKE_AUDIENCE.into(),
        action: ramflux_protocol::WakeAction::Enqueue,
        wake_id: ramflux_protocol::encode_base64url([81; 16]),
        target_delivery_id: participant.target.clone(),
        target_owner_epoch: 1,
        source_event_id: "message".into(),
        class: ramflux_protocol::WakeClass::Message,
        created_at: now,
        expires_at: now + 60,
        call_intent_digest: None,
    };
    let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::wake_signing_bytes(&body)?,
        &participant.branch,
    );
    let signed = ramflux_protocol::SignedWakeV2 { body, signature };
    system.notify.claim_signed_wake(&signed, now + 60)?;
    let projected = crate::project_wake_v2(&signed, now)?;
    let (_, mut pushes) =
        system.notify.queue_wake_for_push(&participant.target, &projected, now, false)?;
    let prepared = pushes.pop().ok_or("test: participant provider")?;
    assert!(
        system.notify.begin_wake_send(&prepared.payload.wake_id)?,
        "fixture did not claim its attempt"
    );
    system.notify.issue_provider_push(&prepared, || Ok(()))?;
    let router = std::sync::Arc::downgrade(&system.router);
    let store = std::sync::Arc::downgrade(&system.router_store);
    let revoked = human.revoked(now)?;
    let target = participant.target.clone();
    let once = std::sync::atomic::AtomicBool::new(false);
    system.network.observe_reads(move|query,_| {
        if matches!(&query.scope,super::AuthorityScope::Owner {target_delivery_id} if target_delivery_id==&target) && !once.swap(true,std::sync::atomic::Ordering::SeqCst) {
            let router=router.upgrade().ok_or_else(|| crate::NodeCoreError::Redb("test: native router closed".into()))?;
            let store=store.upgrade().ok_or_else(|| crate::NodeCoreError::Redb("test: native owner store closed".into()))?;
            router.publish_custody_record(&revoked,now,&store)?;
        }
        Ok(())
    })?;
    let mut issued = false;
    assert!(
        system
            .notify
            .issue_provider_push(&prepared, || {
                issued = true;
                Ok(())
            })
            .is_err(),
        "participant's derived owner survived a committed custodian revocation"
    );
    assert!(!issued, "custodian revocation reached the handoff closure");
    Ok(())
}

#[test]
fn native_call_slot_capacity_refuses_sixty_fifth_without_stalling_existing_calls() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let system = NativeScenario::new(temp.path())?;
    let now = crate::now_unix_seconds();
    let caller = NativeDevice::new("caller.example", 10, now)?;
    let target = NativeDevice::new("callee.example", 30, now)?;
    system.publish(&caller, now)?;
    system.publish(&target, now)?;
    for number in 0..64u8 {
        let event = format!("invite-{number}");
        let start = caller.call_start(&target, &event, number, now)?;
        let digest = ramflux_protocol::call_intent_digest(&start)?;
        system.gateway.admit_verified_call_intent(&crate::CallIntentAdmission {
            signed: &start,
            start_digest: &digest,
            envelope_id: &event,
            source_identity: &caller.target,
            source_epoch: 1,
            encrypted_invite: b"encrypted invite",
        })?;
    }
    let start = caller.call_start(&target, "overflow", 64, now)?;
    let digest = ramflux_protocol::call_intent_digest(&start)?;
    assert!(
        system
            .gateway
            .admit_verified_call_intent(&crate::CallIntentAdmission {
                signed: &start,
                start_digest: &digest,
                envelope_id: "overflow",
                source_identity: &caller.target,
                source_epoch: 1,
                encrypted_invite: b"encrypted invite"
            })
            .is_err(),
        "a sixty-fifth live logical call borrowed another slot"
    );
    let first = caller.call_start(&target, "invite-0", 0, now)?;
    let digest = ramflux_protocol::call_intent_digest(&first)?;
    system.gateway.admit_verified_call_intent(&crate::CallIntentAdmission {
        signed: &first,
        start_digest: &digest,
        envelope_id: "invite-0",
        source_identity: &caller.target,
        source_epoch: 1,
        encrypted_invite: b"encrypted invite",
    })?;
    Ok(())
}

#[test]
fn failed_native_lookup_retains_funded_original_monotonic_deadline() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let system = NativeScenario::new(temp.path())?;
    let (_, _, signed) = system.call_wake()?;
    system.network.observe_reads(|_, _| Err(super::SendAuthorityError::Closed.into()))?;
    assert!(
        system.notify.claim_signed_wake(&signed, signed.body.expires_at).is_err(),
        "unavailable real origin lookup unexpectedly completed admission"
    );
    let digest = ramflux_protocol::wake_request_digest(&signed)?;
    let original = system.notify.send_authority().wake_deadline(&signed.body.wake_id, &digest)?;
    system.network.observe_reads(|_, _| Ok(()))?;
    system.notify.send_authority().set_test_clock(None, std::time::Duration::from_secs(31))?;
    assert!(
        system.notify.claim_signed_wake(&signed, signed.body.expires_at).is_err(),
        "retry reminted a call budget after its original monotonic deadline"
    );
    assert!(
        system.notify.send_authority().wake_deadline(&signed.body.wake_id, &digest).is_err(),
        "elapsed funded admission returned a fresh deadline"
    );
    assert!(
        original > std::time::Instant::now(),
        "test failed to isolate monotonic expiry from wall-clock expiry"
    );
    Ok(())
}

#[test]
fn restarted_notify_refuses_preboot_call_even_with_new_wake_identity() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let (caller, target, mut signed) = {
        let system = NativeScenario::new(temp.path())?;
        system.call_wake()?
    };
    let system = NativeScenario::new(temp.path())?;
    signed.body.wake_id = ramflux_protocol::encode_base64url([74; 16]);
    signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::wake_signing_bytes(&signed.body)?,
        &caller.branch,
    );
    assert!(
        system.notify.claim_signed_wake(&signed, signed.body.expires_at).is_err(),
        "new wake identity revived a ringing call admitted before notify boot"
    );
    let now = crate::now_unix_seconds();
    let start = caller.call_start(&target, "fresh-invite", 75, now)?;
    let digest = ramflux_protocol::call_intent_digest(&start)?;
    system.gateway.admit_verified_call_intent_with_expiry(
        &crate::CallIntentAdmission {
            signed: &start,
            start_digest: &digest,
            envelope_id: "fresh-invite",
            source_identity: &caller.target,
            source_epoch: 1,
            encrypted_invite: b"fresh encrypted invite",
        },
        now + 600,
    )?;
    signed.body.wake_id = ramflux_protocol::encode_base64url([76; 16]);
    signed.body.source_event_id = "fresh-invite".into();
    signed.body.created_at = now;
    signed.body.expires_at = start.body.expires_at;
    signed.body.call_intent_digest = Some(digest);
    system.gateway.bind_call_wake_id(
        &caller.target,
        1,
        "fresh-invite",
        &target.target,
        &signed.body.wake_id,
    )?;
    signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::wake_signing_bytes(&signed.body)?,
        &caller.branch,
    );
    assert!(
        system.notify.claim_signed_wake(&signed, signed.body.expires_at)?.is_some(),
        "fresh postboot call could not use the same actual origin and reservation service"
    );
    let wake = crate::project_wake_v2(&signed, now)?;
    let (_, mut pushes) = system.notify.queue_wake_for_push(&target.target, &wake, now, false)?;
    let prepared = pushes.pop().ok_or("test: restored provider route missing")?;
    assert!(system.notify.begin_wake_send(&signed.body.wake_id)?, "postboot attempt was refused");
    let mut issued = false;
    system.notify.issue_provider_push(&prepared, || {
        issued = true;
        Ok(())
    })?;
    assert!(issued, "restored and funded local scopes could not issue a fresh native call");
    Ok(())
}

#[test]
fn native_call_permit_refuses_wall_clock_rollback_without_reminting() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let system = NativeScenario::new(temp.path())?;
    let (_, _, prepared) = system.prepared()?;
    system.notify.issue_provider_push(&prepared, || Ok(()))?;
    let older = u128::from(crate::now_unix_seconds().saturating_sub(2)) * 1_000_000_000;
    system.notify.send_authority().set_test_clock(Some(older), std::time::Duration::ZERO)?;
    let mut issued = false;
    assert!(
        system
            .notify
            .issue_provider_push(&prepared, || {
                issued = true;
                Ok(())
            })
            .is_err(),
        "rollback below the sampled durable floor authorized a ringing call"
    );
    assert!(!issued, "rollback reached the actual provider handoff closure");
    Ok(())
}

#[test]
fn native_gateway_accepts_maximum_invite_and_refuses_one_extra_byte() -> TestResult {
    const MAX_INVITE: usize = 32 * 1024;
    let temp = tempfile::TempDir::new()?;
    let system = NativeScenario::new(temp.path())?;
    let now = crate::now_unix_seconds();
    let caller = NativeDevice::new("caller.example", 10, now)?;
    let target = NativeDevice::new("callee.example", 30, now)?;
    system.publish(&caller, now)?;
    system.publish(&target, now)?;
    let start = caller.call_start(&target, "maximum-invite", 0, now)?;
    let digest = ramflux_protocol::call_intent_digest(&start)?;
    let maximum = vec![42; MAX_INVITE];
    system.gateway.admit_verified_call_intent(&crate::CallIntentAdmission {
        signed: &start,
        start_digest: &digest,
        envelope_id: "maximum-invite",
        source_identity: &caller.target,
        source_epoch: 1,
        encrypted_invite: &maximum,
    })?;
    let overflow_start = caller.call_start(&target, "oversized-invite", 1, now)?;
    let overflow_digest = ramflux_protocol::call_intent_digest(&overflow_start)?;
    let overflow = vec![42; MAX_INVITE + 1];
    let result = system.gateway.admit_verified_call_intent(&crate::CallIntentAdmission {
        signed: &overflow_start,
        start_digest: &overflow_digest,
        envelope_id: "oversized-invite",
        source_identity: &caller.target,
        source_epoch: 1,
        encrypted_invite: &overflow,
    });
    assert!(
        matches!(result, Err(crate::NodeCoreError::PayloadTooLarge)),
        "gateway failed to enforce the original invite byte ceiling: {result:?}"
    );
    Ok(())
}
