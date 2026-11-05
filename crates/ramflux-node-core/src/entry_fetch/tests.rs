// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T4: a vanished/expired oversized legacy row never produces `TooLarge`.
use super::*;
use crate::router_store::{
    incarnation::test_store,
    publication::tests::{entry, fixture},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn fetch_all_terminal_races() -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("entry-fetch-{mode}"));
        let store = test_store(&root, mode, 2 * 1024 * 1024)?;
        let now = i64::try_from(crate::now_unix_seconds())?;
        let deadline = now + 3600;
        for seq in 1..=2 {
            let mut row = entry(seq);
            row.envelope.created_at = now;
            if seq == 2 {
                row.envelope.encrypted_payload = "x".repeat(crate::ENTRY_FRAME_BYTE_CAP);
            }
            // Deliberate legacy fixture: persistence accepts rows predating admission bounds.
            store.record_submission_increment(&format!("legacy-{seq}"), deadline, Some(&row))?;
        }
        let router = store.load_router()?.ok_or("router")?;
        let id = store.inbox_status("target")?.0;
        match router.fetch_entry("target", 1, now)? {
            InboxEntryResponse::Entry { incarnation_id, record } => {
                assert_eq!(incarnation_id, id);
                assert_eq!(record.entry.inbox_seq, 1);
                assert_eq!(record.retain_until, deadline);
                assert!(
                    serde_json::to_vec(&InboxEntryResponse::Entry { incarnation_id, record })?
                        .len()
                        <= crate::ENTRY_FRAME_BYTE_CAP
                );
            }
            other => return Err(format!("expected entry: {other:?}").into()),
        }
        assert!(
            matches!(router.fetch_entry("target",2,now)?,InboxEntryResponse::EntryTooLarge {retain_until,..} if retain_until==deadline)
        );
        assert!(matches!(
            router.fetch_entry("target", 2, deadline)?,
            InboxEntryResponse::EntryGone {
                reason: EntryGoneReason::Expired,
                observed_issued_inbox_seq: 2,
                ..
            }
        ));
        assert_eq!(router.resume("target", 0, 10).len(), 2, "point expiry does not delete");
        assert_eq!(router.fetch_entry("target", 0, now).err(), Some(EntryFetchError::InvalidSeq));
        assert_eq!(router.fetch_entry("target", 3, now).err(), Some(EntryFetchError::InvalidSeq));
        assert_eq!(router.fetch_entry("unknown", 1, now).err(), Some(EntryFetchError::InvalidSeq));
        assert_eq!(store.inbox_status("unknown")?, (None, 0));
        store.sweep_delivery_retention(deadline + 1, false)?;
        assert_eq!(router.sweep_delivery_retention(deadline + 1), 2);
        let gone = router.fetch_entry("target", 2, deadline + 1)?;
        assert!(matches!(gone, InboxEntryResponse::EntryGone { observed_issued_inbox_seq: 2, .. }));
        assert!(
            serde_json::to_value(gone)?.get("retain_until").is_none(),
            "gone invents no deadline/intent"
        );
        drop(router);
        drop(store);
        let store = test_store(&root, mode, 2 * 1024 * 1024)?;
        let router = store.load_router()?.ok_or("reopened router")?;
        assert!(matches!(
            router.fetch_entry("target", 2, now)?,
            InboxEntryResponse::EntryGone { observed_issued_inbox_seq: 2, .. }
        ));
        assert_eq!(store.inbox_status("target")?.1, 2);
        drop(router);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
