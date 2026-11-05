// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_storage::{AccountDb, AccountIndex, BackupOpenMode};

#[test]
fn candidate_input_checks_authenticated_counts_before_private_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "rf-worker-input-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let index = AccountIndex::open(&root)?;
    index.create_account("account", "principal")?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "account", &key)?;
    db.persist_actor_state("surface/state/input", &serde_json::json!({"revision":1}))?;
    for mode in [BackupOpenMode::PreNormalization, BackupOpenMode::Normalized] {
        let path = root.join(format!("input-{mode:?}.db"));
        let snapshot = db.write_backup_snapshot(&path)?;
        let input = open_checked_input(&path, &snapshot.key, &snapshot.counts, mode)
            .map_err(|e| format!("input failed: {e:?}"))?;
        assert_eq!(input.original_input().counts.surfaces, 1);
        let mut wrong = snapshot.counts.clone();
        wrong.surfaces += 1;
        let Err(error) = open_checked_input(&path, &snapshot.key, &wrong, mode) else {
            return Err("authenticated count mismatch accepted".into());
        };
        assert_eq!(error.code, BackupFailureCode::Tampered);
        input.put_state("surface/state/private", &serde_json::json!({"revision":2}))?;
        assert_eq!(input.counts()?.surfaces, 2);
        assert_eq!(input.original_input().counts, snapshot.counts);
    }
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
