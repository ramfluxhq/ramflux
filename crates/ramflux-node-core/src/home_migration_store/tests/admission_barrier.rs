// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cutover performs only account-scoped work and terminal queries survive custody removal.
use super::*;
fn poison(store: &RouterRedbStore, target: &str) -> TestResult {
    let tx = store.migration_db().begin_write()?;
    let key = format!("delivery/v1/{}/{:020}", ramflux_protocol::encode_base64url(target), 99);
    tx.open_table(crate::ROUTER_INBOX_ENTRY_TABLE)?.insert(key.as_str(), b"broken".as_slice())?;
    tx.commit()?;
    Ok(())
}
#[test]
fn unrelated_poisoned_mailbox_is_not_visited_and_duplicate_commit_does_not_scan() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    poison(s.a.store()?, "unrelated-account")?;
    let committed = s.commit(&sealed)?;
    poison(s.a.store()?, &s.target)?;
    assert_eq!(s.commit(&sealed)?, committed);
    Ok(())
}
#[test]
fn forged_authorization_is_rejected_before_reading_even_its_own_mailbox() -> TestResult {
    let s = Scenario::prepared()?;
    let mut sealed = s.seal()?.sealed_evidence()?;
    sealed.authorization.signatures[0] = "forged".into();
    poison(s.a.store()?, &s.target)?;
    let error =
        s.a.core
            .commit_home_migration(
                s.a.store()?,
                &s.a.node,
                CommitMigration {
                    sealed: &sealed,
                    peer: MigrationPeer { node_id: "B", node_key: &public(9) },
                },
                NOW + 2,
            )
            .err()
            .ok_or("forged request accepted")?;
    assert!(
        !matches!(error, NodeCoreError::Redb(_)),
        "must reject authorization before scanning: {error}"
    );
    Ok(())
}
#[test]
fn migrated_refusal_is_signed_and_repeated_sends_never_change_the_mailbox() -> TestResult {
    let mut s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let committed = s.commit(&sealed)?;
    for restart in [false, true] {
        if restart {
            s.a.restart()?;
        }
        // Startup loads the inactive-target projection; it never needs a DB read for active targets.
        for _ in 0..16 {
            let queued = super::wal_barrier::entry(&s.target);
            let Err(NodeCoreError::HomeMigration(reason)) =
                s.a.store()?.acquire_submission(&s.target)
            else {
                return Err("migrated route accepted".into());
            };
            assert_eq!(reason, Refusal::HomeMigrated);
            let response = s.a.core.migration_submission_refusal(
                s.a.store()?,
                &queued.envelope,
                reason,
                NOW + 3,
            )?;
            assert_eq!(response.migration_refusal, Some(reason));
            assert_eq!(response.inbox_seq, None);
            let nack = response.nack.ok_or("signed migrated nack")?;
            assert_eq!(nack.proof_hash, Some(record_hash(&committed.record)?));
            assert_eq!(nack.new_home_node_hint.as_deref(), Some("B"));
            ramflux_crypto::verify_canonical_signature(
                &ramflux_protocol::signed_bytes(&nack)?,
                &nack.signed.signature,
                &public(8),
            )?;
        }
        assert_eq!(s.a.core.resume(&s.target, 0, 10).len(), 0);
    }
    Ok(())
}
#[test]
fn cancellation_requires_fresh_owner_control_bound_to_exact_authorization() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let valid = cancel_request(&s, NOW + 2)?;
    for bad in [
        {
            let mut c = valid.body.clone();
            c.payload_hash = hash(99);
            c
        },
        {
            let mut c = valid.body.clone();
            c.audience_node = "B".into();
            c
        },
        {
            let mut c = valid.body.clone();
            c.issued_at = NOW - 400;
            c.expires_at = NOW - 100;
            c
        },
    ] {
        let authority = verify_record(&publication()?.record, NOW, None, None)?;
        let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
        let bad = crypto::sign_actor(bad, &branch, &authority, NOW)?;
        assert!(
            s.a.core
                .fence_home_authorization(
                    s.a.store()?,
                    &s.a.node,
                    &s.authorization,
                    NOW + 2,
                    Some(&bad)
                )
                .is_err()
        );
    }
    s.commit(&sealed)?;
    Ok(())
}
#[test]
fn permanent_outcomes_do_not_require_former_home_custody_registration() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let committed = s.commit(&sealed)?;
    let former = RouterCore::new();
    assert_eq!(
        former.commit_home_migration(
            s.a.store()?,
            &s.a.node,
            CommitMigration {
                sealed: &sealed.sealed_evidence()?,
                peer: MigrationPeer { node_id: "B", node_key: &public(9) },
            },
            NOW + 10
        )?,
        committed
    );
    assert!(matches!(
        former.fence_home_authorization(
            s.a.store()?,
            &s.a.node,
            &s.authorization,
            NOW + 10,
            None
        )?,
        FenceOutcome::Committed(_)
    ));
    let s = Scenario::prepared()?;
    s.a.core.fence_home_authorization(
        s.a.store()?,
        &s.a.node,
        &s.authorization,
        NOW + 2,
        Some(&cancel_request(&s, NOW + 2)?),
    )?;
    assert!(matches!(
        former.fence_home_authorization(
            s.a.store()?,
            &s.a.node,
            &s.authorization,
            NOW + 3,
            None
        )?,
        FenceOutcome::Fenced(_)
    ));
    Ok(())
}

#[test]
fn cutover_waits_for_receiver_ack_and_uses_the_settled_view() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let queued = super::wal_barrier::entry(&s.target);
    let store = s.a.store()?;
    store.record_submission_increment("before-ack", i64::MAX / 2, Some(&queued))?;
    let lease = store.acquire_acknowledgement(&s.target)?;
    assert!(
        matches!(s.commit(&sealed), Err(error) if error.to_string().contains("MigrationInProgress") || error.to_string().contains("migration_in_progress"))
    );
    store.record_leased_ack(
        &crate::CursorAckState {
            target_delivery_id: s.target.clone(),
            inbox_seq: 7,
            issued_inbox_seq: 7,
            settled_inbox_seq: 7,
            last_acknowledged_inbox_seq: Some(7),
            ..Default::default()
        },
        &queued.envelope.envelope_id,
        lease,
    )?;
    s.commit(&sealed)?;
    let progress = store.migration_backlog_progress(
        &s.anchor,
        &s.authorization.body.migration_id,
        MigrationRole::Source,
    )?;
    assert_eq!(progress.scheduled, 0);
    assert_eq!(progress.remaining, 0);
    Ok(())
}
