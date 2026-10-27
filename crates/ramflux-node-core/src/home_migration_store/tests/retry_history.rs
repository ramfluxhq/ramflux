// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Activation retains ancestry, and a verified terminal fence releases only its own attempt.
use super::*;
#[test]
fn activated_destination_resolves_the_original_pinned_home_after_restart() -> TestResult {
    let mut s = Scenario::prepared()?;
    let op = s.seal()?;
    let record = s.commit(&op)?;
    s.b.store()?.activate_home_migration(
        &s.b.node,
        &ResolveResult { home: record, predecessors: vec![] },
        NOW + 2,
    )?;
    s.b.restart()?;
    let history = s.b.store()?.resolve_migration_home(&s.anchor, None, 64)?;
    assert_eq!(history.predecessors.len(), 1);
    assert_eq!(record_hash(&history.predecessors[0].record)?, s.base.hash());
    let verified = crypto::verify_home_chain(&history, s.base.evidence(), NOW + 3)?;
    assert_eq!(verified.home(), ("B", public(9).as_str()));
    Ok(())
}
fn next_attempt(s: &Scenario, previous: &MigrationOperation) -> TestResult<Signed<Authorization>> {
    let mut prepare = previous.prepare.body.clone();
    prepare.migration_id = hash(83);
    prepare.nonce = hash(84);
    prepare.issued_at = NOW + 3;
    prepare.expires_at = NOW + 303;
    let authority = verify_record(&publication()?.record, NOW + 3, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let prepare = crypto::sign_actor(prepare, &branch, &authority, NOW + 3)?;
    let attested = s.a.core.attest_home_migration(
        s.a.store()?,
        &s.a.node,
        AttestMigration { request: &attest_request(&s.anchor, "B", &hash(84), NOW + 3)? },
        NOW + 3,
    )?;
    let offer = s.b.core.prepare_home_migration(
        s.b.store()?,
        &s.b.node,
        PrepareMigration {
            prepare: &prepare,
            attestation: &attested.attestation,
            base: &s.base,
            delivery_map: &attested.delivery_map,
        },
        NOW + 3,
    )?;
    let mut auth = s.authorization.body.clone();
    auth.migration_id = prepare.body.migration_id.clone();
    auth.nonce = prepare.body.nonce.clone();
    auth.issued_at = NOW + 3;
    auth.offer_hash = message_hash(&offer)?;
    auth.seal_until = offer.body.accept_until;
    Ok(SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32])).sign_home_authorization(
        auth,
        &branch,
        &authority,
        NOW + 3,
    )?)
}
#[test]
fn terminal_fence_allows_fresh_same_epoch_attempt_without_reopening_the_old_one() -> TestResult {
    let mut s = Scenario::prepared()?;
    let old = s.seal()?;
    let FenceOutcome::Fenced(fence) = s.a.core.fence_home_authorization(
        s.a.store()?,
        &s.a.node,
        &s.authorization,
        NOW + 2,
        Some(&cancel_request(&s, NOW + 2)?),
    )?
    else {
        return Err("fence".into());
    };
    s.b.store()?.accept_home_noncommit_fence(&fence, &s.anchor, NOW + 2)?;
    s.b.restart()?;
    let next = next_attempt(&s, &old)?;
    s.b.core.seal_home_migration(s.b.store()?, &s.b.node, &next, NOW + 3)?;
    // Replaying the previous terminal outcome cannot rewrite the new attempt's target routes.
    s.b.store()?.accept_home_noncommit_fence(&fence, &s.anchor, NOW + 3)?;
    let tx = s.b.store()?.migration_db().begin_read()?;
    let routes = tx.open_table(TARGETS)?;
    let route: InboxRoute = decode(routes.get(s.target.as_str())?.ok_or("route")?.value())?;
    assert_eq!(route.migration_id, next.body.migration_id);
    assert!(!route.active);
    assert!(!route.released);
    assert!(matches!(
        s.a.core.commit_home_migration(
            s.a.store()?,
            &s.a.node,
            CommitMigration {
                sealed: &old.sealed_evidence()?,
                peer: MigrationPeer { node_id: "B", node_key: &public(9) }
            },
            NOW + 3
        ),
        Err(NodeCoreError::HomeMigration(Refusal::CommitExpired))
    ));
    Ok(())
}
#[test]
fn preparation_rejects_mismatching_discovery_and_branch_certificate_fields() -> TestResult {
    let s = Scenario::prepared()?;
    let authority = verify_record(&publication()?.record, NOW, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let attested = s.a.core.attest_home_migration(
        s.a.store()?,
        &s.a.node,
        AttestMigration { request: &attest_request(&s.anchor, "B", &hash(85), NOW)? },
        NOW,
    )?;
    let old =
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or("op")?;
    for discovery in [true, false] {
        let mut body = old.prepare.body.clone();
        body.migration_id = hash(86);
        body.nonce = hash(85);
        if discovery {
            body.discovery_hash = hash(87);
        } else {
            body.branch_certificate_hash = hash(87);
        }
        let prepare = crypto::sign_actor(body, &branch, &authority, NOW)?;
        assert!(matches!(
            s.b.core.prepare_home_migration(
                s.b.store()?,
                &s.b.node,
                PrepareMigration {
                    prepare: &prepare,
                    attestation: &attested.attestation,
                    base: &s.base,
                    delivery_map: &attested.delivery_map,
                },
                NOW
            ),
            Err(NodeCoreError::HomeMigration(Refusal::AuthorityUpdateRequired))
        ));
    }
    Ok(())
}
