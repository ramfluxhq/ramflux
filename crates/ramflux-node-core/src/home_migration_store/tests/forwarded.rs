// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Forwarded proof reconstruction uses the sealed destination state, including after restart.
use super::*;
use crate::RouterSubmitOutcome;

fn proof(s: &Scenario, op: &MigrationOperation) -> TestResult<Signed<CommitProof>> {
    let HomeRecord::Committed { commit_proof, .. } = s.commit(op)?.record else {
        return Err("committed record required".into());
    };
    Ok(*commit_proof)
}

#[test]
fn forwarded_commit_proof_reconstructs_sealed_evidence_after_restart() -> TestResult {
    let mut s = Scenario::prepared()?;
    let op = s.seal()?;
    let proof = proof(&s, &op)?;
    s.b.restart()?;
    for _ in 0..2 {
        s.b.store()?.activate_forwarded_target(&s.b.node, &s.target, Some(&proof), NOW + 2)?;
        assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    }
    s.b.restart()?;
    assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    Ok(())
}

#[test]
fn forward_evidence_for_wrong_destination_or_tampered_proof_is_refused_without_activation()
-> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let valid = proof(&s, &op)?;
    let mut wrong = valid.body.clone();
    wrong.destination_node = "C".into();
    let wrong = crypto::sign_node(wrong, "A", &signing(8))?;
    let forged = crypto::sign_node(valid.body.clone(), "A", &signing(44))?;
    for invalid in [&wrong, &forged] {
        assert!(
            s.b.store()?
                .activate_forwarded_target(&s.b.node, &s.target, Some(invalid), NOW + 2)
                .is_err()
        );
        assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    }
    s.b.store()?.activate_forwarded_target(&s.b.node, &s.target, Some(&valid), NOW + 2)?;
    assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    Ok(())
}

#[test]
fn forwarded_proof_with_mismatched_seal_or_target_is_refused_without_activation() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let valid = proof(&s, &op)?;
    let mut wrong = valid.body.clone();
    wrong.seal_hash = hash(99);
    let wrong = crypto::sign_node(wrong, "A", &signing(8))?;
    assert!(
        s.b.store()?
            .activate_forwarded_target(&s.b.node, &s.target, Some(&wrong), NOW + 2)
            .is_err()
    );
    assert!(
        s.b.store()?
            .activate_forwarded_target(&s.b.node, "unsealed-target", Some(&valid), NOW + 2)
            .is_err()
    );
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    s.b.store()?.activate_forwarded_target(&s.b.node, &s.target, Some(&valid), NOW + 2)?;
    assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    Ok(())
}

#[test]
fn forwarded_activation_without_proof_refuses_dormant_but_allows_active_target() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    assert!(matches!(
        s.b.store()?.activate_forwarded_target(&s.b.node, &s.target, None, NOW + 2),
        Err(NodeCoreError::HomeMigration(Refusal::DormantInbox))
    ));
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    let valid = proof(&s, &op)?;
    s.b.store()?.activate_forwarded_target(&s.b.node, &s.target, Some(&valid), NOW + 2)?;
    s.b.store()?.activate_forwarded_target(&s.b.node, &s.target, None, NOW + 2)?;
    Ok(())
}

pub(super) fn sender(target: &str) -> TestResult<crate::ForwardedEnvelopeRequest> {
    sender_with_seed(target, 70)
}
fn sender_with_seed(target: &str, seed: u8) -> TestResult<crate::ForwardedEnvelopeRequest> {
    use ramflux_crypto::custody::{GenesisInput, MasterKey, RecoveryPhrase, create_genesis};
    let now = crate::now_unix_seconds();
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[seed; 32])?)?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([seed + 1; 32]));
    let branch = ramflux_crypto::create_device_branch(
        &format!("forward-sender-{seed}"),
        "primary",
        1,
        [seed + 2; 32],
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([seed + 3; 32]);
    let record = create_genesis(
        &master,
        &primary,
        &branch,
        &agreement,
        GenesisInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            display_name: "Sender".into(),
            issued_at: now,
            master_cert_id: hash(74),
            branch_cert_id: hash(75),
            external_human_primary: None,
        },
    )?;
    let mut envelope = ramflux_protocol::Envelope {
        schema: "ramflux.envelope.v1".into(),
        version: 1,
        domain: "ramflux.envelope.v1".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
            signing_key_id: "sender".into(),
        },
        envelope_id: "forward-test".into(),
        source_principal_id: branch.principal_id.clone(),
        source_device_id: branch.device_id.clone(),
        target_delivery_id: target.into(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Normal,
        ttl: 3600,
        created_at: i64::try_from(now)?,
        encrypted_payload: "ciphertext".into(),
        payload_hash: hash(76),
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
    };
    envelope.ext.ext.insert("source_root_commitment".into(), json!(record.body.account_anchor));
    envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(&branch, &envelope)?;
    let a = TestNode::with_registration("sender", 80, false, false)?;
    a.core.publish_custody_record(
        &crate::CustodyPublication { record, compacted_ids: None },
        now,
        a.store()?,
    )?;
    a.core.refresh_registered_envelope_authority(&mut envelope)?;
    Ok(crate::ForwardedEnvelopeRequest {
        peer_node_id: "test-peer".into(),
        envelope,
        migration_evidence: None,
    })
}

#[test]
fn forwarded_delivery_with_commit_proof_activates_dormant_inbox_then_queues_once() -> TestResult {
    let mut s = Scenario::prepared()?;
    let op = s.seal()?;
    let valid = proof(&s, &op)?;
    let mut request = sender(&s.target)?;
    let bytes = serde_json::to_vec(&request.envelope)?;
    request.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: Some(valid),
        retain_until: i64::try_from(crate::now_unix_seconds())? + 600,
        floors: vec![],
    });
    let first = s.b.core.submit_forwarded_envelope(
        s.b.store()?,
        Some(&s.b.node),
        request.clone(),
        crate::now_unix_seconds(),
    )?;
    assert!(matches!(first, crate::RouterSubmitOutcome::OfflineQueued(_)));
    assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    s.b.restart()?;
    let second = s.b.core.submit_forwarded_envelope(
        s.b.store()?,
        Some(&s.b.node),
        request,
        crate::now_unix_seconds(),
    )?;
    assert!(
        matches!(second, crate::RouterSubmitOutcome::OfflineQueued(ref queued) if queued.entry.inbox_seq == 1)
    );
    let entries = s.b.core.resume(&s.target, 0, 10);
    assert_eq!(entries.len(), 1);
    assert_eq!(serde_json::to_vec(&entries[0].envelope)?, bytes);
    Ok(())
}

#[test]
fn forwarded_delivery_without_proof_to_dormant_inbox_is_retryable_and_not_acked() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let mut request = sender(&s.target)?;
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            request.clone(),
            crate::now_unix_seconds()
        ),
        Err(NodeCoreError::HomeMigration(Refusal::DormantInbox))
    ));
    assert_eq!(s.b.core.resume(&s.target, 0, 10), []);
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    request.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: Some(proof(&s, &op)?),
        retain_until: i64::try_from(crate::now_unix_seconds())? + 600,
        floors: vec![],
    });
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            request,
            crate::now_unix_seconds()
        )?,
        crate::RouterSubmitOutcome::OfflineQueued(_)
    ));
    Ok(())
}

#[test]
fn ordinary_forward_to_active_home_without_migration_proof_is_accepted() -> TestResult {
    let mut b = TestNode::with_registration("B", 9, false, false)?;
    let request = sender("active-recipient")?;
    let now = crate::now_unix_seconds();
    assert!(matches!(
        b.core.submit_forwarded_envelope(b.store()?, None, request.clone(), now)?,
        crate::RouterSubmitOutcome::OfflineQueued(_)
    ));
    b.restart()?;
    assert!(matches!(
        b.core.submit_forwarded_envelope(b.store()?, None, request, now)?,
        crate::RouterSubmitOutcome::OfflineQueued(ref queued) if queued.entry.inbox_seq == 1
    ));
    Ok(())
}

#[test]
fn forwarded_entry_keeps_a_original_retain_until_at_b() -> TestResult {
    let mut b = TestNode::with_registration("B", 9, false, false)?;
    let now = crate::now_unix_seconds();
    let deadline = i64::try_from(now)? + 30;
    let mut request = sender("retained-recipient")?;
    request.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: None,
        retain_until: deadline,
        floors: vec![],
    });
    b.core.submit_forwarded_envelope(b.store()?, None, request, now)?;
    let entry = b.core.resume("retained-recipient", 0, 10)[0].clone();
    assert_eq!(b.core.inbox_snapshot().retain_until(&entry), deadline);
    b.restart()?;
    assert_eq!(b.core.inbox_snapshot().retain_until(&entry), deadline);
    assert_eq!(b.core.sweep_delivery_retention(deadline - 1), 0);
    assert_eq!(b.core.sweep_delivery_retention(deadline), 1);
    Ok(())
}

#[test]
fn foreign_forwarded_senders_do_not_consume_local_registration_budget_or_account_cap() -> TestResult
{
    let b = TestNode::with_registration("B", 9, false, false)?;
    let now = crate::now_unix_seconds();
    let before = serde_json::to_value(b.store()?.custody_publication_budgets()?)?;
    let local = serde_json::to_vec(&b.core.mvp1_identities_snapshot())?;
    for seed in 80..92 {
        let request = sender_with_seed("recipient", seed)?;
        let (_, source) =
            crate::DeviceAuthKeyResponse::forwarded_envelope_source(&request.envelope)?;
        assert!(matches!(
            b.core.submit_forwarded_envelope(b.store()?, None, request, now)?,
            crate::RouterSubmitOutcome::OfflineQueued(_)
        ));
        assert_eq!(serde_json::to_value(b.store()?.custody_publication_budgets()?)?, before);
        assert!(b.core.custody_record(source.root_commitment(), now)?.is_none());
    }
    assert_eq!(serde_json::to_value(b.store()?.custody_publication_budgets()?)?, before);
    assert_eq!(serde_json::to_vec(&b.core.mvp1_identities_snapshot())?, local);
    assert_eq!(b.store()?.custody_publication_write_count(), 0);
    // A local enrollment still has its full budget after the foreign traffic.
    b.core.publish_custody_record(&publication()?, NOW, b.store()?)?;
    assert_eq!(b.store()?.custody_publication_write_count(), 1);
    Ok(())
}

#[test]
fn plain_envelope_path_refuses_unregistered_foreign_sender_as_on_main() -> TestResult {
    let b = TestNode::with_registration("B", 9, false, false)?;
    let request = sender("recipient")?;
    assert!(
        b.core
            .authenticated_envelope_source_from(
                &request.envelope,
                Some(b.store()?),
                crate::RouterEnvelopeOrigin::Federation
            )
            .is_err()
    );
    assert!(matches!(
        b.core.submit_forwarded_envelope(b.store()?, None, request, crate::now_unix_seconds())?,
        crate::RouterSubmitOutcome::OfflineQueued(_)
    ));
    Ok(())
}

#[test]
fn refused_forward_does_not_persist_sender_pins_before_valid_proof() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let valid = proof(&s, &op)?;
    let mut request = sender(&s.target)?;
    let (_, source) = crate::DeviceAuthKeyResponse::forwarded_envelope_source(&request.envelope)?;
    assert!(
        s.b.core
            .submit_forwarded_envelope(
                s.b.store()?,
                Some(&s.b.node),
                request.clone(),
                crate::now_unix_seconds()
            )
            .is_err()
    );
    assert!(s.b.store()?.foreign_custody_state(source.root_commitment())?.is_none());
    let mut forged = valid.clone();
    forged.body.destination_node = "C".into();
    request.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: Some(forged),
        retain_until: i64::try_from(crate::now_unix_seconds())? + 600,
        floors: vec![],
    });
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            request.clone(),
            crate::now_unix_seconds()
        ),
        Err(NodeCoreError::HomeMigration(Refusal::BaseMismatch))
    ));
    assert!(s.b.store()?.foreign_custody_state(source.root_commitment())?.is_none());
    request.migration_evidence.as_mut().ok_or("evidence")?.commit_proof = Some(valid);
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            request,
            crate::now_unix_seconds()
        )?,
        crate::RouterSubmitOutcome::OfflineQueued(_)
    ));
    assert!(s.b.store()?.foreign_custody_state(source.root_commitment())?.is_some());
    Ok(())
}

fn federation_request(
    request: crate::ForwardedEnvelopeRequest,
    forwarder: &str,
) -> TestResult<crate::FederatedEnvelopeForwardRequest> {
    let mut request = crate::FederatedEnvelopeForwardRequest {
        signed: crate::default_federation_forward_signed_fields(),
        admin_token: String::new(),
        source_node_id: forwarder.into(),
        target_node_id: "B".into(),
        delivery_class: "opaque_event".into(),
        required_capability: "opaque_delivery".into(),
        envelope: request.envelope,
        migration_evidence: request.migration_evidence,
    };
    crate::sign_federated_envelope_forward(&mut request, [81; 32])?;
    Ok(request)
}

fn verified_forward(
    request: &crate::FederatedEnvelopeForwardRequest,
) -> TestResult<crate::ForwardedEnvelopeRequest> {
    crate::verify_federated_envelope_forward(
        request,
        &ramflux_crypto::public_key_base64url_from_seed([81; 32]),
    )?;
    Ok(crate::ForwardedEnvelopeRequest {
        peer_node_id: "test-peer".into(),
        envelope: request.envelope.clone(),
        migration_evidence: request.migration_evidence.clone(),
    })
}

#[test]
fn altered_federation_migration_evidence_fails_request_signature_and_activates_nothing()
-> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let mut body = sender(&s.target)?;
    body.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: Some(proof(&s, &op)?),
        retain_until: i64::try_from(crate::now_unix_seconds())? + 600,
        floors: vec![],
    });
    let valid = federation_request(body, "A")?;
    let mut altered = valid.clone();
    altered.migration_evidence.as_mut().ok_or("missing evidence")?.retain_until += 1;
    let mut proof_altered = valid.clone();
    proof_altered
        .migration_evidence
        .as_mut()
        .ok_or("missing evidence")?
        .commit_proof
        .as_mut()
        .ok_or("missing proof")?
        .body
        .destination_node = "C".into();
    let mut floors_altered = valid.clone();
    floors_altered
        .migration_evidence
        .as_mut()
        .ok_or("missing evidence")?
        .floors
        .push(publication()?);
    for invalid in [&altered, &proof_altered, &floors_altered] {
        assert!(verified_forward(invalid).is_err());
        assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
        assert_eq!(s.b.core.resume(&s.target, 0, 10), []);
    }
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            verified_forward(&valid)?,
            crate::now_unix_seconds()
        )?,
        crate::RouterSubmitOutcome::OfflineQueued(_)
    ));
    Ok(())
}

#[test]
fn tampered_sender_signed_extension_on_forward_fails_v3_verification_at_b() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let mut body = sender(&s.target)?;
    body.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: Some(proof(&s, &op)?),
        retain_until: i64::try_from(crate::now_unix_seconds())? + 600,
        floors: vec![],
    });
    body.envelope.ext.ext.insert(crate::HOME_NODE_FORWARD_COUNT_EXT_KEY.into(), json!(1));
    let mut tampered = body.clone();
    tampered.envelope.ext.ext.insert("sender_signed_application".into(), json!("changed"));
    let tampered = federation_request(tampered, "A")?;
    assert!(
        s.b.core
            .submit_forwarded_envelope(
                s.b.store()?,
                Some(&s.b.node),
                verified_forward(&tampered)?,
                crate::now_unix_seconds()
            )
            .is_err()
    );
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    assert_eq!(s.b.core.resume(&s.target, 0, 10), []);
    let valid = federation_request(body, "A")?;
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            verified_forward(&valid)?,
            crate::now_unix_seconds()
        )?,
        crate::RouterSubmitOutcome::OfflineQueued(_)
    ));
    Ok(())
}

#[test]
fn backlog_forward_and_direct_retry_via_other_node_store_one_inbox_entry_after_restart()
-> TestResult {
    let mut s = Scenario::prepared()?;
    let op = s.seal()?;
    let mut body = sender(&s.target)?;
    let original = serde_json::to_vec(&body.envelope)?;
    body.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: Some(proof(&s, &op)?),
        retain_until: i64::try_from(crate::now_unix_seconds())? + 600,
        floors: vec![],
    });
    let backlog = federation_request(body.clone(), "A")?;
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            verified_forward(&backlog)?,
            crate::now_unix_seconds()
        )?,
        crate::RouterSubmitOutcome::OfflineQueued(_)
    ));
    s.b.restart()?;
    body.migration_evidence = None;
    let direct = federation_request(body, "C")?;
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            verified_forward(&direct)?,
            crate::now_unix_seconds()
        )?,
        crate::RouterSubmitOutcome::OfflineQueued(ref queued) if queued.entry.inbox_seq == 1
    ));
    s.b.restart()?;
    let entries = s.b.core.resume(&s.target, 0, 10);
    assert_eq!(entries.len(), 1);
    assert_eq!(serde_json::to_vec(&entries[0].envelope)?, original);
    Ok(())
}

#[test]
fn local_forwarded_sender_does_not_copy_local_custody_into_foreign_pins() -> TestResult {
    let b = TestNode::with_registration("B", 9, false, false)?;
    let request = sender("recipient")?;
    let (authority, source) =
        crate::DeviceAuthKeyResponse::forwarded_envelope_source(&request.envelope)?;
    let evidence = authority.custody_authority.ok_or("native")?;
    let publication = crate::CustodyPublication {
        record: evidence.publication.record,
        compacted_ids: evidence.publication.compacted_ids,
    };
    let now = crate::now_unix_seconds();
    b.core.publish_custody_record(&publication, now, b.store()?)?;
    assert!(matches!(
        b.core.submit_forwarded_envelope(b.store()?, None, request, now)?,
        crate::RouterSubmitOutcome::OfflineQueued(_)
    ));
    assert!(b.store()?.foreign_custody_state(source.root_commitment())?.is_none());
    Ok(())
}

#[test]
fn one_peer_cannot_exhaust_foreign_pin_bytes_for_others_via_protected_pins() -> TestResult {
    let s = Scenario::prepared()?;
    let commit = proof(&s, &s.seal()?)?;
    let mut request = sender_with_seed(&s.target, 170)?;
    request.peer_node_id = "peer-A".into();
    request.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: Some(commit),
        retain_until: i64::try_from(crate::now_unix_seconds() + 3600)?,
        floors: vec![],
    });
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            request.clone(),
            crate::now_unix_seconds()
        )?,
        RouterSubmitOutcome::OfflineQueued(_)
    ));
    let (_, source) = crate::DeviceAuthKeyResponse::forwarded_envelope_source(&request.envelope)?;
    // Keep a real, durably referenced pin just below the per-row cap. JSON whitespace
    // preserves its authenticated state and permits a bounded byte-quota fixture.
    {
        let tx = s.b.store()?.migration_db().begin_write()?;
        let table = redb::TableDefinition::<&str, &[u8]>::new("foreign_custody_pins_v1");
        let mut pins = tx.open_table(table)?;
        let mut bytes = pins.get(source.root_commitment())?.ok_or("accepted pin")?.value().to_vec();
        bytes.resize(1024 * 1024 - 1, b' ');
        pins.insert(source.root_commitment(), bytes.as_slice())?;
        drop(pins);
        tx.commit()?;
    }
    let mut next = sender_with_seed(&s.target, 180)?;
    next.peer_node_id = "peer-A".into();
    next.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: None,
        retain_until: i64::try_from(crate::now_unix_seconds() + 3600)?,
        floors: vec![],
    });
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            next.clone(),
            crate::now_unix_seconds()
        ),
        Err(NodeCoreError::Capacity { .. })
    ));
    next.peer_node_id = "peer-B".into();
    assert!(matches!(
        s.b.core.submit_forwarded_envelope(
            s.b.store()?,
            Some(&s.b.node),
            next,
            crate::now_unix_seconds()
        )?,
        RouterSubmitOutcome::OfflineQueued(_)
    ));
    assert!(s.b.store()?.foreign_custody_state(source.root_commitment())?.is_some());
    Ok(())
}

#[test]
fn forwarded_sender_retry_attaches_without_releasing_foreign_pin_protection() -> TestResult {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    for mode in 0..3 {
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!(
                "forward-retry-{mode}-{}",
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
            ));
        let store = crate::publication::open_durability_fixture(&root, mode)?;
        let router = RouterCore::new();
        store.bootstrap_router(&router)?;
        let request = sender_with_seed("retry-target", 130 + mode)?;
        let (_, source) =
            crate::DeviceAuthKeyResponse::forwarded_envelope_source(&request.envelope)?;
        let now = crate::now_unix_seconds();
        let (entered, arrived) = mpsc::sync_channel(1);
        let (attached, attachment) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let wait = Mutex::new(wait);
        let once = AtomicBool::new(false);
        let observer = crate::durability_test_hooks::observe(
            root.to_path_buf(),
            Arc::new(move |_, op, done| {
                if op == "retry_attached" && done {
                    let _ = attached.try_send(());
                }
                if op == "reserved_assignment" && done && !once.swap(true, Ordering::Relaxed) {
                    entered.send(()).map_err(std::io::Error::other)?;
                    wait.lock()
                        .map_err(|_| std::io::Error::other("lock"))?
                        .recv_timeout(std::time::Duration::from_secs(30))
                        .map_err(std::io::Error::other)?;
                }
                Ok(())
            }),
        );
        std::thread::scope(|scope| -> TestResult {
            let first = scope
                .spawn(|| router.submit_forwarded_envelope(&store, None, request.clone(), now));
            arrived.recv_timeout(std::time::Duration::from_secs(30))?;
            assert!(crate::forwarded_delivery::pin_referenced(source.root_commitment()));
            let second = scope
                .spawn(|| router.submit_forwarded_envelope(&store, None, request.clone(), now));
            attachment.recv_timeout(std::time::Duration::from_secs(30))?;
            release.send(())?;
            for result in [
                first.join().map_err(|_| "original panic")??,
                second.join().map_err(|_| "retry panic")??,
            ] {
                assert!(
                    matches!(result, RouterSubmitOutcome::OfflineQueued(ref queued) if queued.entry.inbox_seq == 1),
                    "{result:?}"
                );
            }
            Ok(())
        })?;
        assert!(!crate::forwarded_delivery::pin_referenced(source.root_commitment()));
        drop(observer);
        assert!(
            matches!(router.submit_forwarded_envelope(&store, None, request.clone(), now)?, RouterSubmitOutcome::OfflineQueued(ref queued) if queued.entry.inbox_seq == 1)
        );
        assert_eq!(store.inbox_status("retry-target")?.1, 1);
        assert_eq!(router.resume("retry-target", 0, 10).len(), 1);
        drop(router);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
