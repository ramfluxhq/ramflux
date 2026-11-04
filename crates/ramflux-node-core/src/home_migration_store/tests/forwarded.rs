// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Forwarded proof reconstruction uses the sealed destination state, including after restart.
use super::*;

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

fn sender(target: &str) -> TestResult<crate::ForwardedEnvelopeRequest> {
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
    Ok(crate::ForwardedEnvelopeRequest { envelope, migration_evidence: None })
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
    assert!(matches!(second, crate::RouterSubmitOutcome::DuplicateFederatedForward { .. }));
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
        crate::RouterSubmitOutcome::DuplicateFederatedForward { .. }
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
