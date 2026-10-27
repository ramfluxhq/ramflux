// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Missing-seal cancellation, signed retention and stored-base proof authentication.
use super::*;
#[test]
fn missing_seal_reply_can_cancel_by_authorization_and_late_courier_loses() -> TestResult {
    let s = Scenario::prepared()?;
    // B persists the seal, but the owner's request below uses only its authorization.
    let sealed = s.seal()?;
    let result = s.a.core.fence_home_authorization(
        s.a.store()?,
        &s.a.node,
        &s.authorization,
        NOW + 2,
        true,
    )?;
    let FenceOutcome::Fenced(fence) = result else {
        return Err("commit".into());
    };
    assert_eq!(fence.body.seal_hash, None);
    s.b.store()?.accept_home_noncommit_fence(&fence, &s.anchor, NOW + 2)?;
    // The unsigned peer row cannot shorten A's fence retention.
    s.a.store()?.cleanup_home_migrations(NOW + 3)?;
    assert!(s.commit(&sealed).is_err());
    let deadline = crypto::hard_deadline(&s.authorization.body)?;
    s.a.store()?.cleanup_home_migrations(deadline + 1)?;
    let terminal = s.a.core.fence_home_authorization(
        s.a.store()?,
        &s.a.node,
        &s.authorization,
        deadline + 1,
        false,
    )?;
    let FenceOutcome::Fenced(expired) = terminal else {
        return Err("commit".into());
    };
    crypto::verify_node(&expired, "A", &public(8))?;
    assert_eq!(expired.body.authorization_hash, message_hash(&s.authorization)?);
    assert!(s.commit(&sealed).is_err());
    Ok(())
}
#[test]
fn activation_rejects_a_proof_verified_under_an_attacker_supplied_source_pin() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let mut evidence = s.commit(&sealed)?;
    let HomeRecord::Committed { commit_proof, .. } = &mut evidence.record else {
        return Err("commit".into());
    };
    **commit_proof = crypto::sign_node(commit_proof.body.clone(), "A", &signing(44))?;
    let mut descriptor = evidence.node_record.body.clone();
    descriptor.node_signing_public_key = public(44);
    evidence.node_record =
        ramflux_crypto::custody::sign_node_identity_record(&signing(44), descriptor)?;
    let raw = ResolveResult { home: evidence, predecessors: vec![] };
    // This was possible with the old public API: a caller chose its own cached-base pin.
    crypto::verify_home_chain(
        &raw,
        &crypto::HomeTrust {
            account_anchor: &s.anchor,
            node_id: "A",
            node_key: &public(44),
            home_epoch: 0,
            home_hash: Some(s.base.hash()),
            cached_manager_range: 1,
            cached_manager_certificate_hash: Some(&object_hash(
                &publication()?.record.body.master_certificate,
            )?),
        },
        NOW + 2,
    )?;
    assert!(s.b.store()?.activate_home_migration(&s.b.node, &raw, NOW + 2).is_err());
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    Ok(())
}
#[test]
fn activation_releases_live_budget_and_compaction_keeps_permanent_proof() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let committed = s.commit(&sealed)?;
    s.b.store()?.activate_home_migration(
        &s.b.node,
        &ResolveResult { home: committed.clone(), predecessors: vec![] },
        NOW + 2,
    )?;
    for node in [&s.a, &s.b] {
        let tx = node.store()?.migration_db().begin_read()?;
        assert_eq!(tx.open_table(BUDGETS)?.get("live")?.ok_or("live")?.value(), 0);
    }
    {
        let tx = s.b.store()?.migration_db().begin_read()?;
        assert!(tx.open_table(COURIER)?.iter()?.next().is_none());
    }
    assert_eq!(s.b.store()?.cleanup_home_migrations(NOW + 1802)?, 1);
    assert_eq!(s.a.store()?.cleanup_home_migrations(NOW + FORWARD_SECONDS + 3)?, 1);
    {
        let tx = s.a.store()?.migration_db().begin_read()?;
        assert!(tx.open_table(BACKLOG)?.iter()?.next().is_none());
        assert!(tx.open_table(BUSINESS)?.iter()?.next().is_none());
        assert!(tx.open_table(PROOFS)?.iter()?.next().is_some());
    }
    assert_eq!(s.commit(&sealed)?, committed);
    Ok(())
}
#[test]
fn completed_source_can_admit_and_seal_a_return_move_after_window() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let base = s.verify(s.commit(&sealed)?)?;
    let now = NOW + FORWARD_SECONDS + 3;
    let record = publication()?.record;
    let authority = verify_record(&record, now, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let mut prepare = sealed.prepare.body.clone();
    prepare.migration_id = hash(70);
    prepare.old_node = "B".into();
    prepare.destination_node = "A".into();
    prepare.destination_key = public(8);
    prepare.previous_home_hash = base.hash().into();
    prepare.previous_home_epoch = 1;
    prepare.nonce = hash(71);
    prepare.issued_at = now;
    prepare.expires_at = now + 300;
    let prepare = crypto::sign_actor(prepare, &branch, &authority, now)?;
    let mut attest = sealed.attestation.body.clone();
    attest.audience_node = "A".into();
    attest.previous_home_hash = base.hash().into();
    attest.nonce = prepare.body.nonce.clone();
    attest.issued_at = now;
    attest.expires_at = now + 60;
    let attest = crypto::sign_node(attest, "B", &signing(9))?;
    let offer = s.a.core.prepare_home_migration(
        s.a.store()?,
        &s.a.node,
        PrepareMigration {
            prepare: &prepare,
            attestation: &attest,
            base: &base,
            delivery_map: &sealed.delivery_map,
        },
        now,
    )?;
    let mut auth = s.authorization.body.clone();
    auth.migration_id = prepare.body.migration_id.clone();
    auth.old_node = "B".into();
    auth.destination_node = "A".into();
    auth.destination_key = public(8);
    auth.previous_home_hash = base.hash().into();
    auth.next_home_epoch = 2;
    auth.offer_hash = message_hash(&offer)?;
    auth.issued_at = now;
    auth.seal_until = offer.body.accept_until;
    auth.nonce = prepare.body.nonce;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
    let auth = primary.sign_home_authorization(auth, &branch, &authority, now)?;
    s.a.core.seal_home_migration(s.a.store()?, &s.a.node, &auth, now)?;
    assert!(s.a.store()?.home_migration_blocks_recovery(&s.anchor)?);
    Ok(())
}
#[test]
fn second_unsealed_reservation_for_one_root_is_refused_without_charging_budget() -> TestResult {
    let s = Scenario::prepared()?;
    let mut prepare =
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or("prepared")?
            .prepare
            .body;
    prepare.migration_id = hash(72);
    let authority = verify_record(&publication()?.record, NOW, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let prepare = crypto::sign_actor(prepare, &branch, &authority, NOW)?;
    let op =
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or("prepared")?;
    assert!(matches!(
        s.b.core.prepare_home_migration(
            s.b.store()?,
            &s.b.node,
            PrepareMigration {
                prepare: &prepare,
                attestation: &op.attestation,
                base: &s.base,
                delivery_map: &op.delivery_map
            },
            NOW
        ),
        Err(NodeCoreError::HomeMigration(Refusal::CapacityRefused))
    ));
    let tx = s.b.store()?.migration_db().begin_read()?;
    assert_eq!(tx.open_table(BUDGETS)?.get("live")?.ok_or("budget")?.value(), 1);
    Ok(())
}
#[test]
fn attestation_requires_owners_signed_control_bound_to_destination() -> TestResult {
    let s = Scenario::prepared()?;
    let mut request = attest_request(&s.anchor, "B", &hash(73), NOW)?;
    request.payload.destination_node = "C".into();
    assert!(
        s.a.core
            .attest_home_migration(
                s.a.store()?,
                &s.a.node,
                AttestMigration { request: &request },
                NOW
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn source_budget_survives_held_backlog_and_releases_exactly_once_when_settled() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let queued = super::wal_barrier::entry(&s.target);
    s.a.store()?.record_submission_increment("pending-drain", i64::MAX / 2, Some(&queued))?;
    s.commit(&sealed)?;
    assert!(
        s.a.store()?
            .finish_home_migration_backlog(&s.anchor, &s.authorization.body.migration_id, NOW + 3)
            .is_err()
    );
    // A forwarding-window expiry is not a delivery ACK and must not delete held cursors.
    assert_eq!(s.a.store()?.cleanup_home_migrations(NOW + FORWARD_SECONDS + 3)?, 0);
    let key = serde_json::to_string(&(&s.anchor, &s.authorization.body.migration_id, &s.target))?;
    let tx = s.a.store()?.migration_db().begin_write()?;
    let mut cursor: MigrationBacklogCursor = read(&tx, BACKLOG, &key)?.ok_or("cursor")?;
    assert_eq!(cursor.progress.remaining, 1);
    cursor.progress.remaining = 0;
    cursor.progress.forwarded = 1;
    cursor.progress.receiver_acked = 1;
    write(&tx, BACKLOG, &key, &cursor)?;
    tx.commit()?;
    for _ in 0..2 {
        s.a.store()?.finish_home_migration_backlog(
            &s.anchor,
            &s.authorization.body.migration_id,
            NOW + FORWARD_SECONDS + 4,
        )?;
    }
    let tx = s.a.store()?.migration_db().begin_read()?;
    assert_eq!(tx.open_table(BUDGETS)?.get("live")?.ok_or("live")?.value(), 0);
    Ok(())
}
#[test]
fn authorization_only_terminal_query_survives_recovery_before_commit() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    s.a.core.publish_custody_record(&recovery_record()?, NOW + 2, s.a.store()?)?;
    assert!(s.commit(&sealed).is_err());
    let FenceOutcome::Fenced(fence) = s.a.core.fence_home_authorization(
        s.a.store()?,
        &s.a.node,
        &s.authorization,
        NOW + 3,
        true,
    )?
    else {
        return Err("uncommitted move".into());
    };
    s.b.store()?.accept_home_noncommit_fence(&fence, &s.anchor, NOW + 3)?;
    assert!(!s.b.store()?.home_migration_blocks_recovery(&s.anchor)?);
    s.a.store()?.cleanup_home_migrations(NOW + 3601)?;
    assert!(matches!(
        s.a.core.fence_home_authorization(
            s.a.store()?,
            &s.a.node,
            &s.authorization,
            NOW + 3601,
            false
        )?,
        FenceOutcome::Fenced(_)
    ));
    assert!(s.commit(&sealed).is_err());
    Ok(())
}
