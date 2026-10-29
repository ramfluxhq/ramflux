// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real signed replies and historical proofs across encrypted journal reopen boundaries.
use super::*;

impl Fixture {
    fn reopen(&self) -> Result<AccountDb> {
        Ok(AccountDb::open(&self.index, "human", &self.key)?)
    }
    fn authorize(&self) -> Result<wire::Signed<wire::Authorization>> {
        let digest = self.offer()?;
        let plan = self.journal()?.approval_plan(&hash(1), &digest)?;
        self.vault.approve_next_migration_for_test();
        Ok(self.journal()?.authorize(plan.sign(&self.vault, NOW)?, NOW)?)
    }
    fn seal_request(&self) -> Result<wire::Request> {
        // The empty vault cannot load a branch or approve a management signature.
        let db = self.reopen()?;
        let journal = HomeMigrationJournal::new(&db, &self.index, &self.account)?;
        match journal.resume(&hash(1), &MemoryPrimaryVault::default(), NOW)? {
            MigrationResumption::Seal(request) => Ok(*request),
            _ => Err("expected saved seal request".into()),
        }
    }
    fn reply(
        &self,
        control: &wire::Signed<wire::Control>,
        phase: wire::Phase,
    ) -> Result<wire::Signed<wire::Receipt>> {
        let job = self.journal()?.load(&hash(1))?;
        let body = wire::Receipt {
            version: 1,
            action: control.body.action,
            migration_id: hash(1),
            account_anchor: self.actor.account_anchor.clone(),
            node_id: "destination".into(),
            request_hash: wire::message_hash(control)?,
            request_nonce: control.body.nonce.clone(),
            authorization_hash: job.authorization.as_ref().map(wire::message_hash).transpose()?,
            seal_hash: job.authorization.as_ref().map(|_| hash(80)),
            home_record_hash: None,
            phase,
            state_version: 2,
            sealed_at: job.authorization.as_ref().map(|_| NOW),
            commit_deadline: job.authorization.as_ref().map(|_| NOW + 600),
            commit_proof_hash: None,
            response_payload_hash: ramflux_protocol::custody::framed_hash(
                ramflux_protocol::domain::HOME_RECEIPT,
                &serde_json::json!({"offer": null, "commit_proof": null, "noncommit_fence": null,
                    "resolve_result": null, "backlog_progress": null, "attestation": null}),
            )?,
            issued_at: NOW,
            expires_at: NOW + 300,
            reason_code: None,
        };
        Ok(crypto::sign_node(body, "destination", &ramflux_crypto::fixture_signing_key())?)
    }
    fn sealed(&self) -> Result<wire::Signed<wire::Receipt>> {
        self.authorize()?;
        let request = self.seal_request()?;
        let reply = self.reply(&request.control, wire::Phase::Sealed)?;
        self.journal()?.sealed(&hash(1), reply.clone(), NOW)?;
        Ok(reply)
    }
    fn committed_home(&self, seal_hash: String, at: u64) -> Result<crypto::VerifiedHome> {
        let job = self.journal()?.load(&hash(1))?;
        let authorization = job.authorization.ok_or("authorization")?;
        let a = &authorization.body;
        let proof = crypto::sign_node(
            wire::CommitProof {
                version: 1,
                migration_id: hash(1),
                account_anchor: a.account_anchor.clone(),
                old_node: a.old_node.clone(),
                destination_node: a.destination_node.clone(),
                destination_key: a.destination_key.clone(),
                previous_home_hash: a.previous_home_hash.clone(),
                next_home_epoch: a.next_home_epoch,
                authority_record_hash: a.authority_record_hash.clone(),
                authorization_hash: wire::message_hash(&authorization)?,
                offer_hash: a.offer_hash.clone(),
                seal_hash,
                commit_deadline: NOW + 600,
                committed_at: at,
                forward_until: at + wire::FORWARD_SECONDS,
                backlog_manifest_hash: hash(81),
            },
            "source",
            &ramflux_crypto::fixture_signing_key(),
        )?;
        let authority = self.account.record();
        let evidence = wire::RecordEvidence {
            authority: job.authority,
            record: wire::HomeRecord::Committed {
                authorization: Box::new(authorization),
                commit_proof: Box::new(proof),
            },
            management_certificate_chain: vec![authority.body.master_certificate.clone()],
            actor_certificate: authority.body.devices[0].branch_certificate.clone(),
            node_record: self.home.evidence().node_record.clone(),
        };
        Ok(crypto::verify_home_chain(
            &wire::ResolveResult { home: evidence, predecessors: vec![] },
            &crypto::HomeTrust {
                account_anchor: &self.actor.account_anchor,
                node_id: "source",
                node_key: self.home.home().1,
                home_epoch: 0,
                home_hash: Some(self.home.hash()),
                cached_manager_range: authority.body.master_certificate.body.range_index,
                cached_manager_certificate_hash: Some(&object_hash(
                    &authority.body.master_certificate,
                )?),
            },
            at,
        )?)
    }
    fn fence(&self) -> Result<wire::Signed<wire::NoncommitFence>> {
        let job = self.journal()?.load(&hash(1))?;
        Ok(crypto::sign_node(
            wire::NoncommitFence {
                version: 1,
                migration_id: hash(1),
                authorization_hash: wire::message_hash(&job.authorization.ok_or("authorization")?)?,
                seal_hash: job.seal_hash,
                fenced_at: NOW,
            },
            "source",
            &ramflux_crypto::fixture_signing_key(),
        )?)
    }
}

#[test]
fn home_migration_saved_prepare_and_seal_resume_byte_identically_without_vault_access() -> Result {
    let f = Fixture::new()?;
    let original_prepare = f.prepare()?;
    let prepare_bytes = serde_json::to_vec(&original_prepare)?;
    let db = f.reopen()?;
    let recovered = HomeMigrationJournal::new(&db, &f.index, &f.account)?;
    let seq = recovered.status(&hash(1))?.seq;
    let MigrationResumption::Prepare(prepare) =
        recovered.resume(&hash(1), &MemoryPrimaryVault::default(), NOW)?
    else {
        return Err("prepare resume".into());
    };
    assert_eq!(serde_json::to_vec(&prepare)?, prepare_bytes);
    assert_eq!(recovered.status(&hash(1))?.seq, seq);
    let digest = f.accept_prepare(&prepare)?;
    let plan = recovered.approval_plan(&hash(1), &digest)?;
    f.vault.approve_next_migration_for_test();
    let auth = recovered.authorize(plan.sign(&f.vault, NOW)?, NOW)?;
    let original = recovered.load(&hash(1))?;
    let request = f.seal_request()?;
    assert_eq!(
        serde_json::to_vec(request.evidence.authorization.as_ref().ok_or("auth")?)?,
        serde_json::to_vec(&auth)?
    );
    assert_eq!(
        serde_json::to_vec(&request.control)?,
        serde_json::to_vec(original.seal_control.as_ref().ok_or("control")?)?
    );
    assert_eq!(serde_json::to_vec(&f.seal_request()?)?, serde_json::to_vec(&request)?);
    assert_eq!(f.journal()?.status(&hash(1))?.seq, original.progress.seq);
    let reply = f.reply(&request.control, wire::Phase::Sealed)?;
    f.journal()?.sealed(&hash(1), reply, NOW)?;
    let home = f.committed_home(hash(80), NOW)?;
    f.journal()?.committed(&hash(1), &home, NOW)?;
    f.journal()?.activation_evidence(&hash(1))?;
    Ok(())
}

#[test]
fn home_migration_fresh_seal_reply_and_commit_use_durable_seal_hash_through_activation() -> Result {
    let f = Fixture::new()?;
    let reply = f.sealed()?;
    assert_ne!(wire::message_hash(&reply)?, hash(80));
    let db = f.reopen()?;
    let recovered = HomeMigrationJournal::new(&db, &f.index, &f.account)?;
    assert_eq!(recovered.commit_payload(&hash(1))?.seal_hash, hash(80));
    assert!(recovered.commit_evidence(&hash(1), NOW)?.seal_receipt.is_none());
    let home = f.committed_home(hash(80), NOW + 1)?;
    let progress = recovered.committed(&hash(1), &home, NOW + 1)?;
    assert_eq!(progress.commit_deadline, Some(NOW + 600));
    assert_eq!(progress.forward_until, Some(NOW + 1 + wire::FORWARD_SECONDS));
    let db2 = f.reopen()?;
    let recovered2 = HomeMigrationJournal::new(&db2, &f.index, &f.account)?;
    assert_eq!(recovered2.status(&hash(1))?, progress);
    assert_eq!(recovered2.committed(&hash(1), &home, NOW + 2)?, progress);
    let evidence = recovered2.activation_evidence(&hash(1))?;
    assert_eq!(evidence.home_record.as_ref(), Some(&home.evidence().record));
    assert_eq!(recovered2.status(&hash(1))?.phase, MigrationPhase::ActivateSent);
    let activated = recovered2.status(&hash(1))?;
    assert_eq!(recovered2.committed(&hash(1), &home, NOW + 3)?, activated);
    crypto::activation_allowed(
        &home,
        &crypto::SealedBinding {
            destination_node: "destination",
            destination_key: home.home().1,
            authorization_hash: &wire::message_hash(
                evidence.authorization.as_ref().ok_or("auth")?,
            )?,
            offer_hash: &evidence.authorization.as_ref().ok_or("auth")?.body.offer_hash,
            seal_hash: &hash(80),
            previous_home_hash: f.home.hash(),
            next_home_epoch: 1,
            home_floor: None,
        },
    )?;
    assert!(matches!(
        recovered2.noncommit(&hash(1), f.fence()?, NOW + 3),
        Err(SdkError::HomeMigrationRefused(wire::Refusal::IdempotencyConflict))
    ));
    Ok(())
}

#[test]
fn home_migration_late_commit_after_cancel_is_typed_and_keeps_uncertainty_guard() -> Result {
    let f = Fixture::new()?;
    f.sealed()?;
    f.journal()?.cancel(&hash(1), NOW)?;
    let home = f.committed_home(hash(80), NOW)?;
    let db = f.reopen()?;
    let journal = HomeMigrationJournal::new(&db, &f.index, &f.account)?;
    assert!(matches!(
        journal.committed(&hash(1), &home, NOW),
        Err(SdkError::HomeMigrationRefused(wire::Refusal::IdempotencyConflict))
    ));
    assert!(journal.require_recovery_allowed().is_err());
    assert!(journal.activation_evidence(&hash(1)).is_err());
    assert_eq!(journal.status(&hash(1))?.phase, MigrationPhase::NeedsAttention);
    Ok(())
}

#[test]
fn home_migration_fence_wins_and_only_a_different_seal_hash_is_a_fork() -> Result {
    let f = Fixture::new()?;
    f.sealed()?;
    let wrong = f.committed_home(hash(82), NOW)?;
    assert!(matches!(
        f.journal()?.committed(&hash(1), &wrong, NOW),
        Err(SdkError::HomeMigrationRefused(wire::Refusal::HomeFork))
    ));
    let home = f.committed_home(hash(80), NOW)?;
    let progress = f.journal()?.noncommit(&hash(1), f.fence()?, NOW)?;
    assert_eq!(progress.phase, MigrationPhase::Expired);
    let db = f.reopen()?;
    let recovered = HomeMigrationJournal::new(&db, &f.index, &f.account)?;
    assert!(matches!(
        recovered.committed(&hash(1), &home, NOW),
        Err(SdkError::HomeMigrationRefused(wire::Refusal::IdempotencyConflict))
    ));
    assert_eq!(recovered.status(&hash(1))?, progress);
    recovered.require_recovery_allowed()?;
    Ok(())
}

#[test]
fn home_migration_changed_proof_with_same_seal_is_a_conflict_not_a_fork() -> Result {
    let f = Fixture::new()?;
    f.sealed()?;
    let home = f.committed_home(hash(80), NOW)?;
    f.journal()?.committed(&hash(1), &home, NOW)?;
    let different = f.committed_home(hash(80), NOW + 1)?;
    assert!(matches!(
        f.journal()?.committed(&hash(1), &different, NOW + 1),
        Err(SdkError::HomeMigrationRefused(wire::Refusal::IdempotencyConflict))
    ));
    Ok(())
}

#[test]
fn home_migration_seal_reply_checks_signature_control_nonce_bounds_and_cancel_race() -> Result {
    let f = Fixture::new()?;
    let auth = f.authorize()?;
    let request = f.seal_request()?;
    let good = f.reply(&request.control, wire::Phase::Sealed)?;
    let mut invalid = good.clone();
    invalid.body.seal_hash = Some(hash(83));
    assert!(f.journal()?.sealed(&hash(1), invalid, NOW).is_err());
    for n in 0..9 {
        let mut r = good.body.clone();
        match n {
            0 => r.request_hash = wire::message_hash(&auth)?,
            1 => r.request_nonce = auth.body.nonce.clone(),
            2 => r.authorization_hash = Some(hash(90)),
            3 => r.seal_hash = None,
            4 => r.commit_deadline = Some(NOW + 601),
            5 => r.phase = wire::Phase::Prepared,
            6 => r.expires_at = NOW - 1,
            7 => r.node_id = "other".into(),
            _ => r.seal_hash = Some("invalid".into()),
        }
        let bad = crypto::sign_node(r, "destination", &ramflux_crypto::fixture_signing_key())?;
        assert!(f.journal()?.sealed(&hash(1), bad, NOW).is_err());
    }
    f.journal()?.cancel(&hash(1), NOW)?;
    let progress = f.journal()?.sealed(&hash(1), good.clone(), NOW)?;
    assert_eq!(progress.phase, MigrationPhase::NeedsAttention);
    assert_eq!(f.journal()?.sealed(&hash(1), good, NOW)?, progress);
    assert!(f.journal()?.commit_evidence(&hash(1), NOW).is_err());
    Ok(())
}

#[test]
fn home_migration_preseal_cancel_resumes_destination_abort_and_requires_bound_release() -> Result {
    let f = Fixture::new()?;
    f.offer()?;
    assert_eq!(f.journal()?.cancel(&hash(1), NOW)?.phase, MigrationPhase::AbortPending);
    let MigrationResumption::AbortPrepared(request) =
        f.journal()?.resume(&hash(1), &f.vault, NOW)?
    else {
        return Err("abort plan".into());
    };
    assert_eq!(request.control.body.audience_node, "destination");
    assert!(request.evidence.authorization.is_none());
    let db = f.reopen()?;
    let recovered = HomeMigrationJournal::new(&db, &f.index, &f.account)?;
    let MigrationResumption::AbortPrepared(replayed) =
        recovered.resume(&hash(1), &MemoryPrimaryVault::default(), NOW)?
    else {
        return Err("saved abort".into());
    };
    assert_eq!(serde_json::to_vec(&request)?, serde_json::to_vec(&replayed)?);
    let mut next = Fixture::intent()?;
    next.operation_id = hash(91);
    assert!(recovered.begin(next.clone(), f.actor.clone(), &f.home, NOW).is_err());
    let mut wrong = f.reply(&request.control, wire::Phase::Aborted)?.body;
    wrong.request_nonce = hash(92);
    assert!(
        recovered
            .reservation_aborted(
                &hash(1),
                crypto::sign_node(wrong, "destination", &ramflux_crypto::fixture_signing_key())?,
                NOW
            )
            .is_err()
    );
    let ack = f.reply(&request.control, wire::Phase::Aborted)?;
    let progress = recovered.reservation_aborted(&hash(1), ack.clone(), NOW)?;
    assert_eq!(progress.phase, MigrationPhase::Aborted);
    assert_eq!(recovered.reservation_aborted(&hash(1), ack, NOW)?, progress);
    recovered.begin(next, f.actor.clone(), &f.home, NOW)?;
    Ok(())
}

#[test]
fn home_migration_expired_offer_releases_account_lock_and_invalidates_pending_approval() -> Result {
    let f = Fixture::new()?;
    let digest = f.offer()?;
    let plan = f.journal()?.approval_plan(&hash(1), &digest)?;
    f.vault.approve_next_migration_for_test();
    let result = plan.sign(&f.vault, NOW)?;
    let db = f.reopen()?;
    let recovered = HomeMigrationJournal::new(&db, &f.index, &f.account)?;
    let mut next = Fixture::intent()?;
    next.operation_id = hash(93);
    recovered.begin(next, f.actor.clone(), &f.home, NOW + 601)?;
    assert_eq!(recovered.status(&hash(1))?.phase, MigrationPhase::Expired);
    assert!(recovered.authorize(result, NOW + 601).is_err());
    assert!(recovered.approval_plan(&hash(1), &digest).is_err());
    recovered.require_recovery_allowed()?;
    Ok(())
}

#[test]
fn home_migration_cancel_before_offer_still_returns_destination_reservation_abort() -> Result {
    let f = Fixture::new()?;
    f.prepare()?;
    f.journal()?.cancel(&hash(1), NOW)?;
    let MigrationResumption::AbortPrepared(request) =
        f.journal()?.resume(&hash(1), &f.vault, NOW)?
    else {
        return Err("lost offer must abort reservation".into());
    };
    assert_eq!(request.control.body.audience_node, "destination");
    assert!(request.evidence.offer.is_none());
    assert!(request.evidence.authorization.is_none());
    f.journal()?.reservation_aborted(
        &hash(1),
        f.reply(&request.control, wire::Phase::Aborted)?,
        NOW,
    )?;
    assert!(f.db.active_home_migration()?.is_none());
    Ok(())
}

#[test]
fn home_migration_retry_timeout_keeps_the_original_seal_resumable_without_presence() -> Result {
    let f = Fixture::new()?;
    f.authorize()?;
    let original = f.seal_request()?;
    f.journal()?.retry_later(&hash(1), NOW)?;
    assert_eq!(f.journal()?.status(&hash(1))?.phase, MigrationPhase::NeedsAttention);
    assert_eq!(serde_json::to_vec(&f.seal_request()?)?, serde_json::to_vec(&original)?);
    f.journal()?.expire_offer(&hash(1), NOW + 900)?;
    assert!(f.journal()?.require_recovery_allowed().is_err());
    Ok(())
}

#[test]
fn home_migration_first_offer_received_after_expiry_terminates_the_prepare_job() -> Result {
    let f = Fixture::new()?;
    let prepare = f.prepare()?;
    let offer = Fixture::offer_reply(&prepare)?;
    assert!(matches!(
        f.journal()?.offer(&hash(1), offer, NOW + 601),
        Err(SdkError::HomeMigrationRefused(wire::Refusal::AdmissionExpired))
    ));
    assert_eq!(f.journal()?.status(&hash(1))?.phase, MigrationPhase::Expired);
    assert!(f.db.active_home_migration()?.is_none());
    Ok(())
}

#[test]
fn home_migration_expired_abort_control_is_renewed_without_a_management_approval() -> Result {
    let f = Fixture::new()?;
    f.prepare()?;
    f.journal()?.cancel(&hash(1), NOW)?;
    let MigrationResumption::AbortPrepared(original) =
        f.journal()?.resume(&hash(1), &f.vault, NOW)?
    else {
        return Err("original abort".into());
    };
    let db = f.reopen()?;
    let recovered = HomeMigrationJournal::new(&db, &f.index, &f.account)?;
    let MigrationResumption::AbortPrepared(renewed) =
        recovered.resume(&hash(1), &f.vault, NOW + 301)?
    else {
        return Err("renewed abort".into());
    };
    assert_eq!(original.payload, renewed.payload);
    assert_ne!(original.control.body.nonce, renewed.control.body.nonce);
    assert!(renewed.evidence.authorization.is_none());
    let mut body = f.reply(&renewed.control, wire::Phase::Aborted)?.body;
    body.issued_at = NOW + 301;
    body.expires_at = NOW + 601;
    recovered.reservation_aborted(
        &hash(1),
        crypto::sign_node(body, "destination", &ramflux_crypto::fixture_signing_key())?,
        NOW + 301,
    )?;
    assert!(db.active_home_migration()?.is_none());
    Ok(())
}
