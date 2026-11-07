// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared store-mode contract for namespace fencing and published ACK bounds.
#![allow(clippy::expect_used, reason = "negative contract assertions")]
use super::*;
use crate::router_store::{
    incarnation::test_store,
    publication::tests::{entry, fixture},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
pub(crate) fn reject_stale(store: &crate::RouterRedbStore, target: &str, old: &str) -> Result {
    let router = store.load_router()?.ok_or("router")?;
    let status = router.session_push_status(target);
    assert_ne!(status.incarnation_id.as_deref(), Some(old));
    let before = router.resume(target, 0, 10);
    // A reused issued sequence is terminally bound to the new E, even if its old row disappeared.
    let raw =
        serde_json::json!({"target_delivery_id":target,"incarnation_id":old,"inbox_seqs":[1]});
    if status.inbox_seq > 0 {
        let request = serde_json::from_value(raw)?;
        let error = router.session_ack_batch(store, &request).expect_err("stale wire ACK");
        assert!(matches!(error.reason, SessionPushReason::IncarnationMismatch));
        assert_eq!(error.incarnation_id, status.incarnation_id);
        assert_eq!(router.resume(target, 0, 10), before);
    }
    Ok(())
}
#[test]
fn incarnation_bound_batch_all_store_modes() -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("session-ack-{mode}"));
        let store = test_store(&root, mode, u64::MAX)?;
        for seq in 1..=65 {
            store.record_submission_increment(
                &format!("row-{seq}"),
                i64::MAX,
                Some(&entry(seq)),
            )?;
        }
        let router = store.load_router()?.ok_or("router")?;
        let id = store.inbox_status("target")?.0.ok_or("E")?;
        let bad = SessionAckBatchRequest {
            target_delivery_id: "target".into(),
            incarnation_id: "00000000000000000000000000000000".into(),
            inbox_seqs: (1..=64).collect(),
        };
        assert!(matches!(
            router.session_ack_batch(&store, &bad).expect_err("mismatch").reason,
            SessionPushReason::IncarnationMismatch
        ));
        assert_eq!(router.resume("target", 0, 100).len(), 65);
        let future = SessionAckBatchRequest { inbox_seqs: vec![66], ..bad.clone() };
        assert!(matches!(
            router.session_ack_batch(&store, &future).expect_err("E before future seq").reason,
            SessionPushReason::IncarnationMismatch
        ));
        let oversized = SessionAckBatchRequest {
            target_delivery_id: "target".into(),
            incarnation_id: id.clone(),
            inbox_seqs: (1..=65).collect(),
        };
        assert!(matches!(
            router.session_ack_batch(&store, &oversized).expect_err("65 issued members").reason,
            SessionPushReason::InvalidSeq
        ));
        assert_eq!(router.resume("target", 0, 100).len(), 65);
        let good = SessionAckBatchRequest { incarnation_id: id.clone(), ..bad };
        let response = router.session_ack_batch(&store, &good)?;
        assert_eq!(response.incarnation_id, id);
        assert_eq!(response.results.len(), 64);
        assert!(response.results.iter().all(|r| r.outcome == SessionAckOutcome::Acked));
        let again = router.session_ack_batch(&store, &good)?;
        assert!(again.results.iter().all(|r| r.outcome == SessionAckOutcome::AlreadySettled));
        drop(router);
        drop(store);
        let store = test_store(&root, mode, u64::MAX)?;
        let router = store.load_router()?.ok_or("reopen")?;
        assert_eq!(store.inbox_status("target")?, (Some(id), 65));
        assert_eq!(
            router.resume("target", 0, 10).iter().map(|e| e.inbox_seq).collect::<Vec<_>>(),
            vec![65]
        );
        drop(router);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn forward_outcome_decoder_rejects_bad_combinations() {
    for (outcome, delivered) in [
        ("queued", true),
        ("overflowed", true),
        ("no_session", false),
        ("full", false),
        ("unsupported", false),
        ("expired", false),
        ("invalid", false),
    ] {
        assert!(
            serde_json::from_value::<SessionPushForwardResponse>(
                serde_json::json!({"delivered":delivered,"outcome":outcome})
            )
            .is_ok()
        );
        assert!(
            serde_json::from_value::<SessionPushForwardResponse>(
                serde_json::json!({"delivered":!delivered,"outcome":outcome})
            )
            .is_err()
        );
    }
    for outcome in ["", "unknown"] {
        assert!(
            serde_json::from_value::<SessionPushForwardResponse>(
                serde_json::json!({"delivered":false,"outcome":outcome})
            )
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<SessionPushForwardResponse>(serde_json::json!({"delivered":true}))
            .is_ok()
    );
}
