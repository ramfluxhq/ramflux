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

#[test]
fn indexed_barrier_counts_each_delivery_once_and_preserves_settled_replay_receipts() -> TestResult {
    let mut s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let mut queued = super::wal_barrier::entry(&s.target);
    for sequence in 1..=64 {
        queued.inbox_seq = sequence;
        queued.envelope.envelope_id = format!("indexed-{sequence}");
        s.a.store()?.record_submission_increment_for_sender(
            &format!("replay-{sequence}"),
            i64::MAX / 2,
            Some(&queued),
            Some("verified-sender"),
        )?;
        s.a.store()?.record_inbox_entry(&queued)?;
    }
    s.a.store()?.record_ack_increment(
        &crate::CursorAckState {
            target_delivery_id: s.target.clone(),
            inbox_seq: 60,
            issued_inbox_seq: 64,
            settled_inbox_seq: 32,
            // A raw settled candidate is not retirement authority. Persist the
            // actual prefix dispositions in this same receiver transaction.
            retired_inbox_seqs: (1..=32).collect(),
            last_acknowledged_inbox_seq: Some(60),
            acked_inbox_seqs: [60].into(),
            ..Default::default()
        },
        "indexed-60",
    )?;
    for restart in [false, true] {
        if restart {
            s.a.restart()?;
        }
        let cursors = s.a.store()?.migration_backlog_barrier(
            &s.anchor,
            &s.authorization.body.migration_id,
            &sealed.delivery_map,
            NOW + 2,
        )?;
        assert_eq!(cursors[0].high_water, 64);
        assert_eq!(cursors[0].progress.scheduled, 31);
        assert!(s.a.store()?.has_local_delivery_envelope(
            "verified-sender",
            "indexed-10",
            &s.target,
            i64::try_from(NOW + 2)?
        )?);
    }
    Ok(())
}

#[test]
fn source_rechecks_commit_deadline_after_waiting_for_the_database_writer() -> TestResult {
    let mut s = Scenario::prepared()?;
    let authority = verify_record(&publication()?.record, NOW + 1, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let mut auth = s.authorization.body.clone();
    auth.max_commit_delay = 1;
    s.authorization = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]))
        .sign_home_authorization(auth, &branch, &authority, NOW + 1)?;
    let sealed = s.seal()?.sealed_evidence()?;
    let writer = s.a.store()?.migration_db().begin_write()?;
    std::thread::scope(|scope| -> TestResult {
        let worker = scope.spawn(|| {
            s.a.core.commit_home_migration(
                s.a.store().map_err(storage)?,
                &s.a.node,
                CommitMigration {
                    sealed: &sealed,
                    peer: MigrationPeer { node_id: "B", node_key: &public(9) },
                },
                NOW + 2,
            )
        });
        let limit = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if matches!(
                s.a.store()?.acquire_acknowledgement(&s.target),
                Err(NodeCoreError::HomeMigration(Refusal::MigrationInProgress))
            ) {
                break;
            }
            if std::time::Instant::now() >= limit {
                return Err("cutover writer did not arrive".into());
            }
            std::thread::yield_now();
        }
        // The actual production cutover holds the target writer while it waits on redb.
        // Advancing elapsed trusted time must invalidate the original exact-deadline check.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        drop(writer);
        assert!(matches!(
            worker.join().map_err(|_| "commit worker panicked")?,
            Err(NodeCoreError::HomeMigration(Refusal::CommitExpired))
        ));
        Ok(())
    })?;
    assert_eq!(s.a.store()?.migration_home(&s.anchor)?.ok_or("head")?.record.epoch(), 0);
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    Ok(())
}

#[test]
fn staged_and_former_home_root_gates_cover_devices_outside_the_sealed_map() -> TestResult {
    let mut s = Scenario::prepared()?;
    let sibling = ramflux_protocol::qualified_device_id(&s.anchor, "added-later")?;
    for restart in [false, true] {
        if restart {
            s.b.restart()?;
        }
        assert!(matches!(
            s.b.store()?.acquire_home_operation(&s.anchor),
            Err(NodeCoreError::HomeMigration(Refusal::DormantInbox))
        ));
        assert!(matches!(
            s.b.store()?.acquire_submission(&sibling),
            Err(NodeCoreError::HomeMigration(Refusal::DormantInbox))
        ));
        assert!(!s.b.store()?.home_migration_target_active(&sibling)?);
    }
    let op = s.seal()?;
    let proof = s.commit(&op)?;
    for restart in [false, true] {
        if restart {
            s.a.restart()?;
        }
        assert!(matches!(
            s.a.store()?.acquire_home_operation(&s.anchor),
            Err(NodeCoreError::HomeMigration(Refusal::HomeMigrated))
        ));
        assert!(matches!(
            s.a.store()?.acquire_submission(&sibling),
            Err(NodeCoreError::HomeMigration(Refusal::HomeMigrated))
        ));
        let mut entry = super::wal_barrier::entry(&sibling);
        entry.envelope.target_delivery_id = sibling.clone();
        let refusal = s.a.core.migration_submission_refusal(
            s.a.store()?,
            &entry.envelope,
            Refusal::HomeMigrated,
            NOW + 3,
        )?;
        let nack = refusal.nack.ok_or("signed new-device refusal")?;
        assert_eq!(nack.proof_hash, Some(record_hash(&proof.record)?));
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&nack)?,
            &nack.signed.signature,
            &public(8),
        )?;
    }
    let actor = s.authorization.body.actor.clone();
    let ramflux_protocol::custody::CustodyRefusal::HomeMigration { nack: Some(nack), .. } = s
        .a
        .core
        .migration_owner_refusal(s.a.store()?, &actor, &hash(91), Refusal::HomeMigrated, NOW + 3)?
    else {
        return Err("signed owner refusal".into());
    };
    assert_eq!(nack.envelope_id, hash(91));
    assert_eq!(nack.proof_hash, Some(record_hash(&proof.record)?));
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(&*nack)?,
        &nack.signed.signature,
        &public(8),
    )?;
    s.b.store()?.activate_home_migration(
        &s.b.node,
        &ResolveResult { home: proof, predecessors: vec![] },
        NOW + 3,
    )?;
    s.b.restart()?;
    drop(s.b.store()?.acquire_home_operation(&s.anchor)?);
    drop(s.b.store()?.acquire_submission(&sibling)?);
    Ok(())
}

#[test]
fn root_cutover_waits_for_an_unmapped_device_submission() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let sibling = ramflux_protocol::qualified_device_id(&s.anchor, "new-device")?;
    let lease = s.a.store()?.acquire_submission(&sibling)?;
    assert!(matches!(
        s.a.core.commit_home_migration(
            s.a.store()?,
            &s.a.node,
            CommitMigration {
                sealed: &op.sealed_evidence()?,
                peer: MigrationPeer { node_id: "B", node_key: &public(9) }
            },
            NOW + 2
        ),
        Err(NodeCoreError::HomeMigration(Refusal::MigrationInProgress))
    ));
    drop(lease);
    s.commit(&op)?;
    Ok(())
}

#[test]
fn retained_records_refuse_missing_or_rotated_runtime_signer_after_restart() -> TestResult {
    let mut s = Scenario::prepared()?;
    for node in [&mut s.a, &mut s.b] {
        node.restart()?;
        node.store()?
            .validate_home_migration_runtime(Some((node.node.node_id(), node.node.public_key())))?;
        assert!(node.store()?.validate_home_migration_runtime(None).is_err());
        assert!(
            node.store()?
                .validate_home_migration_runtime(Some((node.node.node_id(), &public(99))))
                .is_err()
        );
        assert!(
            node.store()?
                .validate_home_migration_runtime(Some(("replacement-node", node.node.public_key())))
                .is_err()
        );
    }
    let empty = TestNode::new("unused", 44, false)?;
    empty.store()?.validate_home_migration_runtime(None)?;
    empty.store()?.validate_home_migration_runtime(Some(("new-unused", &public(45))))?;
    Ok(())
}

#[test]
fn foreign_prepare_cannot_demote_an_already_registered_unattested_local_root() -> TestResult {
    let s = Scenario::prepared()?;
    let existing = TestNode::new("B", 9, true)?;
    let pending =
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or("pending")?;
    assert!(matches!(
        existing.core.prepare_home_migration(
            existing.store()?,
            &existing.node,
            PrepareMigration {
                prepare: &pending.prepare,
                attestation: &pending.attestation,
                base: &s.base,
                delivery_map: &pending.delivery_map
            },
            NOW
        ),
        Err(NodeCoreError::HomeMigration(Refusal::HomeFork))
    ));
    assert!(existing.store()?.migration_home(&s.anchor)?.is_none());
    assert!(
        existing
            .store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination
            )?
            .is_none()
    );
    drop(existing.store()?.acquire_home_operation(&s.anchor)?);
    Ok(())
}

#[test]
fn migration_enabled_startup_refuses_without_matching_node_signer() -> TestResult {
    let s = Scenario::prepared()?;
    let mut config: crate::NodeServiceConfig = serde_json::from_value(json!({
        "node_id": "A", "service_id": "ramflux-router", "redb_path": "unused.redb",
        "mesh": {
            "listen_addr": "127.0.0.1:0", "ca_cert": "unused.pem",
            "service_cert": "unused.pem", "service_key": "unused.key",
            "allowed_service_ids": [], "endpoints": {}
        }
    }))?;
    assert!(crate::require_node_service_signing_key(&config).is_err());
    config.node_service_signing_seed_b64url =
        Some(crate::RedactedString::new(ramflux_protocol::encode_base64url([9; 32])));
    // A valid encoding containing the wrong seed still fails descriptor binding.
    let wrong = crate::require_node_service_signing_key(&config)?;
    let record = s.base.evidence().node_record.clone();
    let endpoints = || MigrationEndpoints {
        gateway_tcp_addr: "127.0.0.1:9000".into(),
        federation_endpoint: "https://peer.example".into(),
        discovery_hash: hash(19),
        server_record_hash: hash(19),
    };
    assert!(wrong.home_migration_node(record.clone(), endpoints(), NOW).is_err());
    config.node_service_signing_seed_b64url =
        Some(crate::RedactedString::new(ramflux_protocol::encode_base64url([8; 32])));
    let signer = crate::require_node_service_signing_key(&config)?;
    let node = signer.home_migration_node(record, endpoints(), NOW)?;
    s.a.store()?.validate_home_migration_runtime(Some((node.node_id(), node.public_key())))?;
    assert!(s.a.store()?.validate_home_migration_runtime(None).is_err());
    assert!(
        s.a.store()?
            .validate_home_migration_runtime(Some((node.node_id(), wrong.public_key_base64url())))
            .is_err()
    );
    Ok(())
}
