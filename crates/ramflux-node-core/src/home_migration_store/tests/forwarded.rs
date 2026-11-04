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
