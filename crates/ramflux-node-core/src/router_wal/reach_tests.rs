// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persistence coverage for opaque reach proofs; admission authentication has its own tests.
use super::*;
use ramflux_protocol::{
    contact_reach::{self as wire, DeliveryReach, Route, Traffic},
    custody::{DeviceRef, Envelope as Signed},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn digest(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn entry() -> Result<InboxEntry, Box<dyn std::error::Error>> {
    let target = ramflux_protocol::qualified_device_id(&digest(2), "phone")?;
    let envelope = crate::test_support::federation_fixtures::envelope(
        "reach-persistence",
        &target,
        ramflux_protocol::DeliveryClass::OpaqueEvent,
    );
    let route = Route {
        version: 1,
        source: DeviceRef {
            account_anchor: digest(1),
            device_id: envelope.source_device_id.clone(),
            device_epoch: 1,
        },
        recipient_root: digest(2),
        conversation_id: ramflux_protocol::message::dm_scope::derive(&digest(1), &digest(2))?,
        traffic: Traffic::Dm,
        envelope_hash: ramflux_protocol::custody::framed_hash(
            wire::ENVELOPE_HASH_DOMAIN,
            &envelope,
        )?,
        authority_head_hash: digest(3),
        issued_at: 1_760_000_000,
        expires_at: 1_760_003_600,
    };
    Ok(InboxEntry {
        inbox_seq: 1,
        target_delivery_id: target,
        envelope,
        reach: Some(Box::new(DeliveryReach {
            route: Signed { body: route, signature: ramflux_protocol::encode_base64url([4; 64]) },
            cost: None,
        })),
    })
}
#[test]
fn cr_inbox_metadata_survives_redb_and_wal_reopen() -> TestResult {
    let root = tempfile::TempDir::new()?;
    let entry = entry()?;
    let path = root.path().join("redb");
    {
        let store = crate::RouterRedbStore::open_without_wal(&path)?;
        store.record_inbox_entry(&entry)?;
    }
    {
        let store = crate::RouterRedbStore::open_without_wal(&path)?;
        let (inbox, _) = store.load_delivery_state(1_760_000_001)?;
        assert_eq!(
            inbox.pull_after(&entry.target_delivery_id, 0, 2),
            vec![entry.clone()],
            "redb recovery must preserve the original route and sealed envelope together"
        );
    }
    let wal = root.path().join("wal");
    {
        let store = RouterWalStore::open(&wal)?;
        store.record_submission(
            &crate::tests::request_replay_fixture("reach-reopen"),
            9_999_999_999,
            Some(&entry),
        )?;
    }
    let store = RouterWalStore::open(&wal)?;
    let submissions = store.submissions(1_760_000_001);
    assert_eq!(submissions.len(), 1, "the bounded fixture must recover exactly one submission");
    let recovered = submissions.first().ok_or("submission missing")?;
    assert_eq!(
        recovered.entry.as_ref(),
        Some(&entry),
        "WAL recovery must preserve route signature, envelope and nullable cost exactly"
    );
    Ok(())
}
#[test]
fn cr_wal_rejects_mismatched_reach_before_append_and_recovery() -> TestResult {
    let mut entry = entry()?;
    entry.envelope.encrypted_payload.push('x');
    let payload = RouterWalPayload::Submission {
        replay_key: crate::tests::request_replay_fixture("reach-mismatch"),
        replay_expires_at: 9_999_999_999,
        entry: Some(Box::new(entry.clone())),
        accepted_at: Some(1_760_000_000),
        local_delivery: None,
    };
    assert!(
        StoredRouterWalPayload::try_from(&payload).is_err(),
        "a mismatched route must be rejected before creating an unrecoverable WAL record"
    );
    let original = entry.reach.take().ok_or("metadata")?;
    let RouterWalPayload::Submission { replay_key, replay_expires_at, accepted_at, .. } = payload;
    let stored = StoredRouterWalPayload::SubmissionAccepted {
        replay_key,
        replay_expires_at,
        accepted_at: accepted_at.ok_or("acceptance time")?,
        entry: Some(Box::new(StoredRouterWalInboxEntry::try_from(&entry)?)),
    };
    assert!(
        decode_reach_payload(&ramflux_protocol::canonical_json_bytes(&original)?, stored).is_err(),
        "recovery must refuse a copied proof attached to different sealed bytes"
    );
    Ok(())
}
