// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete signer totals and isolated upgrade admission across large task accounts.
use super::*;
use crate::{AccountDbKey, AccountIndex};
fn database(label: &str) -> Result<(std::path::PathBuf, AccountDb), StorageError> {
    let root = std::env::temp_dir().join(format!("task-usage-{label}-{}", std::process::id()));
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "principal")?;
    let db = AccountDb::open(&index, "a", &AccountDbKey::derive("a", b"secret"))?;
    Ok((root, db))
}
#[test]
fn signer_usage_totals_are_complete_beyond_maintenance_pages_and_ignore_other_signers()
-> Result<(), StorageError> {
    let (root, db) = database("totals")?;
    db.write_transaction(|| {
        for index in 0..2100 {
            db.persist_actor_state(&format!("task/lifecycle/{index:04}"), &serde_json::json!({"source":"requester","conversation_id":if index<1000 {"a"} else {"b"},"task_id":index.to_string(),"usage":{"agent":{"bytes":4096,"events":1,"decisions":0,"decision_bytes":0}}}))?;
        }
        Ok::<_,StorageError>(())
    })?;
    assert_eq!(db.task_signer_usage("agent", None, "")?, Some([2100 * 4096, 2100, 0, 0]));
    assert_eq!(db.task_signer_usage("requester", None, "")?, Some([0, 0, 0, 0]));
    assert_eq!(
        db.task_signer_usage("agent", Some("a"), "task/lifecycle/0000")?,
        Some([999 * 4096, 999, 0, 0])
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn legacy_accounting_is_pending_only_for_its_actual_event_signers() -> Result<(), StorageError> {
    let (root, db) = database("upgrade")?;
    db.persist_actor_state(
        "task/history/old",
        &serde_json::json!({"events":[{"carrier":{"principal_id":"agent"}}]}),
    )?;
    db.persist_actor_state(
        "task/lifecycle/old",
        &serde_json::json!({"source":"requester","conversation_id":"thread"}),
    )?;
    assert_eq!(db.task_signer_usage("agent", None, "")?, None);
    assert_eq!(db.task_signer_usage("requester", None, "")?, Some([0, 0, 0, 0]));
    assert_eq!(db.task_signer_usage("agent", None, "task/lifecycle/old")?, Some([0, 0, 0, 0]));
    db.persist_actor_state("task/lifecycle/old",&serde_json::json!({"source":"requester","conversation_id":"thread","usage":{"agent":{"bytes":700,"events":1,"decisions":0,"decision_bytes":0}}}))?;
    assert_eq!(db.task_signer_usage("agent", None, "")?, Some([700, 1, 0, 0]));
    assert_eq!(db.task_signer_usage("requester", None, "")?, Some([0, 0, 0, 0]));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
