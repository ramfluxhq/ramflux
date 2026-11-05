// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T18 ACK/NACK legs (introduced P8; sweep/checkpoint/recovery completed P9).
#![allow(clippy::expect_used, reason = "regression assertions")]
use super::*;
use crate::router_store::incarnation::{decode_cursor, test_store};
use crate::router_store::publication::{
    capture,
    tests::{entry, fixture},
    view_tests::submit,
};
use redb::ReadableTable;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn persisted(store: &crate::RouterRedbStore) -> CursorAckState {
    let tx = store.migration_db().begin_read().expect("read");
    let table = tx.open_table(crate::ROUTER_CURSOR_STATE_TABLE).expect("cursor table");
    decode_cursor(table.get("target").expect("row").expect("cursor").value()).expect("decode")
}
fn ack(seq: u64) -> ramflux_protocol::Ack {
    ramflux_protocol::Ack {
        schema: "ramflux.ack.v1".into(),
        version: 1,
        domain: "ramflux.ack.v1".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: entry(seq).envelope.signed,
        ack_id: format!("ack-{seq}"),
        envelope_id: format!("entry-{seq}"),
        receiver_device_id: "receiver".into(),
        received_at: 1_760_000_010,
        cursor_after: None,
    }
}
fn nack() -> ramflux_protocol::Nack {
    ramflux_protocol::Nack {
        schema: "ramflux.nack.v1".into(),
        version: 1,
        domain: "ramflux.nack.v1".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: entry(3).envelope.signed,
        nack_id: "nack-3".into(),
        envelope_id: "entry-3".into(),
        receiver_device_id: "receiver".into(),
        received_at: 1_760_000_010,
        reason: ramflux_protocol::NackReason::Expired,
        retry_after: None,
        proof_hash: None,
        new_home_node_hint: None,
    }
}
fn run_receiver(nack_leg: bool) -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("settled-{mode}-{nack_leg}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let id = store.initialize_inbox("target")?;
        let router = crate::RouterCore::new();
        router.prepare_publication_target(&store, "target")?;
        let core = store.publication_core()?;
        capture(|| submit(&router, &store, 1, true))?.published_blocking()?;
        let held = core.reserve("target", &id, &[])?;
        assert_eq!(held.sequence(), 2);
        let later = capture(|| submit(&router, &store, 3, true))?;
        assert_eq!(core.view("target", &id).0, 1);
        let mut first_ack = ack(1);
        first_ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(1));
        let cursor = router.apply_ack_for_target("target", &first_ack)?;
        assert_eq!(core.settled_view("target", &id), (1, 0), "tentative ACK does not publish R");
        assert_eq!(
            router.inbox_snapshot().cursor_state("target").expect("cursor").settled_inbox_seq,
            0,
            "snapshot must not export tentative R"
        );
        store.record_ack_increment(&cursor, &first_ack.envelope_id)?;
        assert_eq!(persisted(&store).settled_inbox_seq, 1, "ACK must stop before held guard");
        assert_eq!(core.settled_view("target", &id), (1, 1));
        if nack_leg {
            let mut nack = nack();
            nack.ext.ext.insert("inbox_seq".into(), serde_json::json!(3));
            for _ in 0..ROUTER_NACK_RETRY_LIMIT {
                let cursor = router.apply_nack_for_target("target", &nack)?;
                assert_eq!(cursor.settled_inbox_seq, 1, "NACK memory candidate stops at guard");
                store.record_nack_increment(&cursor)?;
                assert_eq!(
                    persisted(&store).settled_inbox_seq,
                    1,
                    "NACK must stop before held guard"
                );
            }
        } else {
            let mut later_ack = ack(3);
            later_ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(3));
            let mut cursor = router.apply_ack_for_target("target", &later_ack)?;
            assert_eq!(cursor.settled_inbox_seq, 1, "empty pending does not settle the guard");
            // Public raw-cursor writers must revalidate too; a caller's issued
            // maximum is never deletion authority for WAL recovery.
            cursor.settled_inbox_seq = cursor.issued_inbox_seq;
            store.record_ack_increment(&cursor, &later_ack.envelope_id)?;
            assert_eq!(persisted(&store).settled_inbox_seq, 1, "writer rejects raw issued floor");
        }
        let write = held.hand_off().expect("hand off");
        let middle = entry(2);
        store.record_submission_increment(
            "middle",
            middle.envelope.created_at + 3600,
            Some(&middle),
        )?;
        write.accepted_durable();
        later.published_blocking()?;
        assert_eq!(
            core.settled_view("target", &id),
            (3, 1),
            "R publishes only a committed checkpoint"
        );
        drop(held);
        drop(core);
        drop(router);
        drop(store);
        for _ in 0..2 {
            let store = test_store(&root, mode, 1024 * 1024)?;
            let reopened = store.load_router()?.expect("router");
            assert_eq!(store.inbox_status("target")?.0.as_deref(), Some(id.as_str()));
            assert!(
                reopened.resume("target", 0, 10).iter().any(|row| row.inbox_seq == 2),
                "guard-era checkpoint must not delete later accepted WAL row"
            );
            if nack_leg {
                assert!(
                    reopened
                        .inbox_snapshot()
                        .dead_letter_index
                        .get("target")
                        .is_some_and(|rows| rows.contains_key(&3)),
                    "startup rebuilds the sorted dead-letter index from durable cursor metadata"
                );
            }
            drop(reopened);
            drop(store);
        }
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn settled_prefix_bounded_by_publication() -> Result {
    run_receiver(false)?;
    run_receiver(true)
}

#[test]
fn ordered_indexes_restore_and_release() -> Result {
    let mut inbox = OpaqueDeviceInbox::new();
    for seq in [1_000_000_000_000_000, 7, 3] {
        inbox.restore_pending_entry_until(entry(seq), Some(i64::MAX));
    }
    assert_eq!(
        inbox.pull_after("target", 3, 2).iter().map(|e| e.inbox_seq).collect::<Vec<_>>(),
        [7, 1_000_000_000_000_000]
    );
    inbox.dead_letter("target", 7, DeadLetterReason::AckWindowOverflow);
    inbox.dead_letter("target", 3, DeadLetterReason::AckWindowOverflow);
    assert_eq!(inbox.dead_letter_index["target"].keys().copied().collect::<Vec<_>>(), [3, 7]);
    let json = serde_json::to_value(&inbox)?;
    assert!(json["pending"]["target"].is_array(), "legacy snapshot schema");
    let restored: OpaqueDeviceInbox = serde_json::from_value(json)?;
    let mut merged = OpaqueDeviceInbox::new();
    merged.merge_from(&restored);
    assert_eq!(serde_json::to_value(&inbox)?, serde_json::to_value(&merged)?);
    assert_eq!(inbox.dead_letter_index, merged.dead_letter_index);
    // Sorted metadata is released on the same events as its bounded source.
    merged.expire_entries(i64::MAX);
    assert!(merged.dead_letter_index.is_empty());
    assert!(merged.pending.is_empty());
    assert!(merged.retain_until.is_empty());
    assert!(merged.expiry.due.is_empty());
    inbox.remove_target("target");
    assert!(inbox.dead_letter_index.is_empty());
    Ok(())
}

#[test]
fn ordered_indexes_do_not_retain_retired_payloads() -> Result {
    let mut inbox = OpaqueDeviceInbox::new();
    for seq in 1..=u64::try_from(ROUTER_DEAD_LETTER_LIMIT * 2)? {
        let row = inbox.append(entry(seq).envelope);
        inbox.dead_letter("target", row.inbox_seq, DeadLetterReason::AckWindowOverflow);
        assert!(inbox.pending.is_empty(), "retirement releases pending index");
        assert!(inbox.retain_until.is_empty(), "retirement releases deadline index");
        assert!(inbox.dead_letter_index["target"].len() <= ROUTER_DEAD_LETTER_LIMIT);
    }
    assert_eq!(inbox.dead_letter_index["target"].len(), ROUTER_DEAD_LETTER_LIMIT);
    assert_eq!(
        inbox.dead_letter_index["target"].first_key_value().map(|(&seq, _)| seq),
        Some(u64::try_from(ROUTER_DEAD_LETTER_LIMIT)? + 1)
    );
    let mut restored: OpaqueDeviceInbox = serde_json::from_slice(&serde_json::to_vec(&inbox)?)?;
    restored.bound_retained_receipts();
    assert_eq!(restored.dead_letter_index, inbox.dead_letter_index);
    restored.remove_target("target");
    assert!(restored.dead_letter_index.is_empty());
    Ok(())
}
