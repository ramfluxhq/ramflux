// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner controls drive stored seals, proof-only activation and terminal cancellation.
use super::*;
use ramflux_protocol::home_migration::{ActivatePayload, CommitPayload, SealPayload};
fn control_request(
    action: Action,
    payload: ActionPayload,
    evidence: Evidence,
    audience: &str,
    now: u64,
) -> TestResult<Request> {
    let mut control = owner_request()?.control.body;
    control.action = action;
    control.audience_node = audience.into();
    control.nonce = hash(95);
    control.issued_at = now;
    control.expires_at = now + 60;
    control.payload_hash = control_payload_hash(action, &payload, evidence.authorization.as_ref())?;
    let authority = verify_record(&publication()?.record, now, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    Ok(Request {
        control: crypto::sign_actor(control, &branch, &authority, now)?,
        payload,
        evidence,
    })
}
#[test]
fn owner_seal_and_commit_use_the_stored_immutable_seal_and_fresh_response_bindings() -> TestResult {
    let s = Scenario::prepared()?;
    let service = service(&s.b, s.a)?;
    let seal = control_request(
        Action::Seal,
        ActionPayload::Seal(SealPayload {
            authorization_hash: message_hash(&s.authorization)?,
            offer_hash: message_hash(&s.offer)?,
        }),
        Evidence { authorization: Some(s.authorization.clone()), ..Evidence::default() },
        "B",
        NOW + 1,
    )?;
    let sealed = service
        .execute(&s.b.core, s.b.store()?, seal.clone(), caller()?, NOW + 1)
        .map_err(|e| format!("seal {e:?}"))?;
    let op =
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or("op")?;
    let immutable_hash = message_hash(op.seal.as_ref().ok_or("seal")?)?;
    assert_eq!(sealed.receipt.body.seal_hash.as_deref(), Some(immutable_hash.as_str()));
    assert_eq!(sealed.receipt.body.request_hash, message_hash(&seal.control)?);
    assert_eq!(sealed.payload_hash()?, sealed.receipt.body.response_payload_hash);
    let commit = control_request(
        Action::Commit,
        ActionPayload::Commit(CommitPayload {
            authorization_hash: message_hash(&s.authorization)?,
            offer_hash: message_hash(&s.offer)?,
            seal_hash: immutable_hash,
        }),
        Evidence::default(),
        "B",
        NOW + 2,
    )?;
    let committed = service
        .execute(&s.b.core, s.b.store()?, commit.clone(), caller()?, NOW + 2)
        .map_err(|e| format!("commit {e:?}"))?;
    assert_eq!(committed.receipt.body.phase, Phase::Active);
    assert!(committed.commit_proof.is_some());
    assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    assert_eq!(committed.receipt.body.request_hash, message_hash(&commit.control)?);
    Ok(())
}
#[test]
fn owner_commit_never_sends_a_late_commit_or_activates_on_a_local_deadline() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let late = op.seal.as_ref().and_then(|s| s.body.commit_deadline).ok_or("deadline")? + 1;
    let service = service(&s.b, s.a)?;
    let request = control_request(
        Action::Commit,
        ActionPayload::Commit(CommitPayload {
            authorization_hash: message_hash(&s.authorization)?,
            offer_hash: message_hash(&s.offer)?,
            seal_hash: message_hash(op.seal.as_ref().ok_or("seal")?)?,
        }),
        Evidence::default(),
        "B",
        late,
    )?;
    assert!(matches!(
        service.execute(&s.b.core, s.b.store()?, request, caller()?, late),
        Err(ramflux_protocol::custody::CustodyRefusal::HomeMigration {
            reason: Refusal::CommitExpired,
            ..
        })
    ));
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    Ok(())
}
#[test]
fn client_relayed_commit_proof_activates_but_a_tampered_proof_cannot() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let committed = s.commit(&op)?;
    let HomeRecord::Committed { commit_proof, .. } = &committed.record else {
        return Err("proof".into());
    };
    let payload = ActivatePayload {
        home_record_hash: record_hash(&committed.record)?,
        commit_proof_hash: message_hash(commit_proof)?,
    };
    let request = control_request(
        Action::Activate,
        ActionPayload::Activate(payload),
        Evidence {
            home_record: Some(committed.record.clone()),
            authority: Some(committed.authority.clone()),
            node_identity_record: Some(committed.node_record.clone()),
            ..Evidence::default()
        },
        "B",
        NOW + 2,
    )?;
    let service = service(&s.b, s.a)?;
    let mut changed = request.clone();
    let Some(HomeRecord::Committed { commit_proof, .. }) = &mut changed.evidence.home_record else {
        return Err("proof".into());
    };
    commit_proof.body.backlog_manifest_hash = hash(96);
    assert!(service.execute(&s.b.core, s.b.store()?, changed, caller()?, NOW + 2).is_err());
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    let response = service
        .execute(&s.b.core, s.b.store()?, request, caller()?, NOW + 2)
        .map_err(|e| format!("activate {e:?}"))?;
    assert_eq!(response.receipt.body.phase, Phase::Active);
    assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    Ok(())
}

#[test]
fn source_cancel_without_a_seal_reply_returns_a_terminal_signed_fence() -> TestResult {
    let s = Scenario::prepared()?;
    let request = control_request(
        Action::Abort,
        ActionPayload::Operation(ramflux_protocol::home_migration::OperationPayload {
            account_anchor: s.anchor.clone(),
            migration_id: s.authorization.body.migration_id.clone(),
        }),
        Evidence { authorization: Some(s.authorization.clone()), ..Evidence::default() },
        "A",
        NOW + 2,
    )?;
    let service = service(&s.a, s.b)?;
    let response = service
        .execute(&s.a.core, s.a.store()?, request.clone(), caller()?, NOW + 2)
        .map_err(|e| format!("cancel {e:?}"))?;
    assert_eq!(response.receipt.body.phase, Phase::Expired);
    assert_eq!(
        response.receipt.body.authorization_hash.as_deref(),
        Some(message_hash(&s.authorization)?.as_str())
    );
    assert_eq!(response.receipt.body.request_hash, message_hash(&request.control)?);
    let fence = response.noncommit_fence.ok_or("fence")?;
    crypto::verify_node(&fence, "A", &public(8))?;
    Ok(())
}
