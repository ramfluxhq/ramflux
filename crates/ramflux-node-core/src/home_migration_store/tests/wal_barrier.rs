// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cutover covers acknowledged WAL submissions and excludes subsequent old-home writes.
use super::*;
use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
pub(super) fn entry(target: &str) -> crate::InboxEntry {
    crate::InboxEntry {
        inbox_seq: 7,
        target_delivery_id: target.into(),
        envelope: Envelope {
            schema: ramflux_protocol::domain::ENVELOPE.into(),
            version: 1,
            domain: ramflux_protocol::domain::ENVELOPE.into(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "test".into(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".into(),
            },
            envelope_id: "queued-before-cutover".into(),
            source_principal_id: "sender".into(),
            source_device_id: "device".into(),
            target_delivery_id: target.into(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Normal,
            ttl: 3600,
            created_at: 1_700_000_100,
            encrypted_payload: "opaque".into(),
            payload_hash: hash(43),
        },
    }
}
#[test]
fn acknowledged_wal_only_submission_is_in_signed_cutover_manifest() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let entry = entry(&s.target);
    s.a.store()?.record_submission_increment("wal-barrier", i64::MAX / 2, Some(&entry))?;
    let cursors = s.a.store()?.migration_backlog_barrier(
        &s.anchor,
        &s.authorization.body.migration_id,
        &sealed.delivery_map,
        NOW + 2,
    )?;
    assert_eq!(cursors.iter().map(|c| c.progress.scheduled).sum::<u64>(), 1);
    assert_eq!(cursors.iter().map(|c| c.high_water).max(), Some(7));
    let committed = s.commit(&sealed)?;
    let verified = s.verify(committed)?;
    let HomeRecord::Committed { commit_proof, .. } = &verified.evidence().record else {
        return Err("expected commit proof".into());
    };
    assert_eq!(
        commit_proof.body.backlog_manifest_hash,
        ramflux_protocol::custody::framed_hash(
            ramflux_protocol::domain::HOME_BACKLOG_MANIFEST,
            &cursors
        )?
    );
    assert!(s.a.store()?.record_submission_increment("late", i64::MAX / 2, Some(&entry)).is_err());
    Ok(())
}
#[test]
fn in_flight_submission_serializes_before_commit_and_late_append_is_refused() -> TestResult {
    let s = Scenario::prepared()?;
    let sealed = s.seal()?;
    let entry = entry(&s.target);
    // Hold the exact production lease retained across append/fsync/ACK. The cutover
    // must retry rather than block the executor or snapshot before that ACK.
    let store = s.a.store()?;
    let pending = store.submission_permit(Some(&entry))?;
    assert!(s.commit(&sealed).is_err());
    store.record_submission_increment("racing", i64::MAX / 2, Some(&entry))?;
    drop(pending);
    s.commit(&sealed)?;
    assert!(store.record_inbox_entry(&entry).is_err());
    assert!(store.record_submission_increment("late", i64::MAX / 2, Some(&entry)).is_err());
    let cursors = store.migration_backlog_barrier(
        &s.anchor,
        &s.authorization.body.migration_id,
        &sealed.delivery_map,
        NOW + 2,
    )?;
    assert_eq!(cursors.iter().map(|c| c.high_water).max(), Some(7));
    Ok(())
}
#[test]
fn actual_wal_append_racing_cutover_is_included_or_refused_before_ack() -> TestResult {
    for _ in 0..4 {
        let s = Scenario::prepared()?;
        let sealed = s.seal()?;
        let queued = entry(&s.target);
        let store = s.a.store()?;
        let start = std::sync::Barrier::new(2);
        let (submitted, committed) = std::thread::scope(|scope| {
            let append = scope.spawn(|| {
                start.wait();
                store.record_submission_increment("race", i64::MAX / 2, Some(&queued))
            });
            start.wait();
            let committed = s.commit(&sealed);
            (append.join(), committed)
        });
        let submitted = submitted.map_err(|_| "submission worker panicked")?;
        if committed.is_err() {
            assert!(submitted.is_ok(), "a durable submission must own the retry barrier");
            s.commit(&sealed)?;
        }
        let cursors = store.migration_backlog_barrier(
            &s.anchor,
            &s.authorization.body.migration_id,
            &sealed.delivery_map,
            NOW + 2,
        )?;
        if submitted.is_ok() {
            assert_eq!(cursors.iter().map(|c| c.high_water).max(), Some(7));
            assert_eq!(cursors.iter().map(|c| c.progress.remaining).sum::<u64>(), 1);
        } else {
            assert!(committed.is_ok(), "a refused append requires a successful cutover");
            assert_eq!(cursors.iter().map(|c| c.high_water).max(), Some(0));
        }
    }
    Ok(())
}
