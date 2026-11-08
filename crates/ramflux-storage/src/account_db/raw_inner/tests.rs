// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{RawInnerCopyKind, RawInnerCopyWrite, RawInnerQuotaScope, writer};
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, StorageError, tests::test_db};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn unsupported_quota_is_atomic_and_preserves_existing_rows() -> TestResult {
    let (_root, db) = test_db("unsupported-quota-atomic")?;
    let existing = vec![0x31; super::writer::MAX_INNER_BYTES];
    for index in 0..16 {
        let copy_id = format!("copy-existing-{index}");
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: "owner-existing",
                verified_source_anchor: "verified-root",
                copy_id: &copy_id,
                kind: RawInnerCopyKind::OuterInner,
                bytes: &existing,
                bounded_metadata: b"{}",
            })
        })?;
    }

    // 16 valid outer copies leave 576 bytes in the source budget. The nested
    // copy is charged at its actual size and crosses that boundary by one byte.
    let nested = vec![0x72; 577];
    let failed = db.write_transaction(|| {
        db.persist_actor_state("test/ratchet", &serde_json::json!({"counter":9}))?;
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "owner-existing",
            verified_source_anchor: "verified-root",
            copy_id: "copy-nested",
            kind: RawInnerCopyKind::NestedGroup,
            bytes: &nested,
            bounded_metadata: b"{}",
        })
    });
    assert!(matches!(
        failed,
        Err(StorageError::UnsupportedRawQuotaExceeded {
            source_anchor,
            scope: RawInnerQuotaScope::Source,
        }) if source_anchor == "verified-root"
    ));
    assert_eq!(
        db.raw_inner_copy("copy-existing-0")?.ok_or(StorageError::AuthorizationRejected)?.bytes,
        existing
    );
    assert!(db.raw_inner_copy("copy-nested")?.is_none());
    assert!(db.load_actor_state::<serde_json::Value>("test/ratchet")?.is_none());
    let usage = db.unsupported_raw_quota(Some("verified-root"))?;
    assert_eq!(usage.owners, 1);
    assert_eq!(usage.raw_bytes, (16 * super::writer::MAX_INNER_BYTES) as u64);
    Ok(())
}

#[test]
fn raw_copy_write_requires_transaction_and_charges_duplicate_copies() -> TestResult {
    let (_root, db) = test_db("raw-copy-transaction")?;
    let bytes = b"exact inner";
    assert!(matches!(
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "owner",
            verified_source_anchor: "root",
            copy_id: "outside-transaction",
            kind: RawInnerCopyKind::OuterInner,
            bytes,
            bounded_metadata: b"{}",
        }),
        Err(StorageError::AuthorizationRejected)
    ));
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "owner",
            verified_source_anchor: "root",
            copy_id: "copy-a",
            kind: RawInnerCopyKind::OuterInner,
            bytes,
            bounded_metadata: b"{}",
        })?;
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "owner",
            verified_source_anchor: "root",
            copy_id: "copy-b",
            kind: RawInnerCopyKind::NestedGroup,
            bytes,
            bounded_metadata: b"{}",
        })?;
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "owner",
            verified_source_anchor: "root",
            copy_id: "copy-c",
            kind: RawInnerCopyKind::HistoryContainer,
            bytes: b"serialized history container",
            bounded_metadata: b"{}",
        })
    })?;
    let usage = db.unsupported_raw_quota(Some("root"))?;
    assert_eq!(usage.owners, 1);
    assert_eq!(usage.raw_bytes, (bytes.len() * 2 + b"serialized history container".len()) as u64);
    Ok(())
}

#[test]
fn raw_copy_limits_accept_inclusive_boundaries_and_reject_overages() -> TestResult {
    let (_root, db) = test_db("raw-copy-inclusive-limits")?;
    let max_id = "i".repeat(256);
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: &max_id,
            verified_source_anchor: &max_id,
            copy_id: &max_id,
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"i",
            bounded_metadata: &vec![b'm'; 4096],
        })
    })?;
    let max_inner = vec![b'b'; writer::MAX_INNER_BYTES];
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "inner-boundary-owner",
            verified_source_anchor: "inner-boundary-source",
            copy_id: "inner-boundary-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: &max_inner,
            bounded_metadata: b"{}",
        })
    })?;
    let max_history = vec![b'h'; writer::MAX_HISTORY_CONTAINER_BYTES];
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "history-boundary-owner",
            verified_source_anchor: "history-boundary-source",
            copy_id: "history-boundary-copy",
            kind: RawInnerCopyKind::HistoryContainer,
            bytes: &max_history,
            bounded_metadata: b"{}",
        })
    })?;

    let over_inner = vec![b'b'; writer::MAX_INNER_BYTES + 1];
    let over_history = vec![b'h'; writer::MAX_HISTORY_CONTAINER_BYTES + 1];
    for (owner, source, copy, bytes, metadata) in [
        ("empty-owner", "empty-source", "empty-copy", &[][..], &b"{}"[..]),
        (
            "inner-over-owner",
            "inner-over-source",
            "inner-over-copy",
            over_inner.as_slice(),
            &b"{}"[..],
        ),
        (
            "history-over-owner",
            "history-over-source",
            "history-over-copy",
            over_history.as_slice(),
            &b"{}"[..],
        ),
        (
            "metadata-over-owner",
            "metadata-over-source",
            "metadata-over-copy",
            &b"x"[..],
            &vec![b'm'; 4097][..],
        ),
    ] {
        assert!(matches!(
            db.write_transaction(|| {
                db.put_unsupported_raw_copy(RawInnerCopyWrite {
                    owner_id: owner,
                    verified_source_anchor: source,
                    copy_id: copy,
                    kind: if copy.starts_with("history-") {
                        RawInnerCopyKind::HistoryContainer
                    } else {
                        RawInnerCopyKind::OuterInner
                    },
                    bytes,
                    bounded_metadata: metadata,
                })
            }),
            Err(StorageError::AuthorizationRejected)
        ));
    }
    for (owner, source, copy) in [
        ("o".repeat(257), "source".to_owned(), "copy".to_owned()),
        ("owner".to_owned(), "s".repeat(257), "copy".to_owned()),
        ("owner".to_owned(), "source".to_owned(), "c".repeat(257)),
        ("owner\u{7f}".to_owned(), "source".to_owned(), "copy".to_owned()),
    ] {
        assert!(matches!(
            db.write_transaction(|| {
                db.put_unsupported_raw_copy(RawInnerCopyWrite {
                    owner_id: &owner,
                    verified_source_anchor: &source,
                    copy_id: &copy,
                    kind: RawInnerCopyKind::OuterInner,
                    bytes: b"x",
                    bounded_metadata: b"{}",
                })
            }),
            Err(StorageError::AuthorizationRejected)
        ));
    }
    Ok(())
}

#[test]
fn raw_copy_rejects_owner_source_conflicts_and_invalid_bind_targets() -> TestResult {
    let (_root, db) = test_db("raw-copy-conflicts")?;
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "owner",
            verified_source_anchor: "source-a",
            copy_id: "copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"first",
            bounded_metadata: b"{}",
        })
    })?;
    assert!(matches!(
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: "owner",
                verified_source_anchor: "source-b",
                copy_id: "another-copy",
                kind: RawInnerCopyKind::OuterInner,
                bytes: b"other",
                bounded_metadata: b"{}",
            })
        }),
        Err(StorageError::AuthorizationRejected)
    ));
    assert!(matches!(
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: "owner",
                verified_source_anchor: "source-a",
                copy_id: "copy",
                kind: RawInnerCopyKind::OuterInner,
                bytes: b"conflicting bytes",
                bounded_metadata: b"{}",
            })
        }),
        Err(StorageError::AuthorizationRejected)
    ));
    assert!(matches!(
        db.write_transaction(|| db.bind_raw_inner_copy("unknown-copy", "target")),
        Err(StorageError::AuthorizationRejected)
    ));

    db.connection.execute(
        "INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at)
         VALUES('thread','deleted-target','sender',x'',x'7b7d',0,0,1)",
        [],
    )?;
    db.delete_direct_message("thread", "deleted-target", "sender", "tombstone")?;
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "unbound-owner",
            verified_source_anchor: "source",
            copy_id: "bind-deleted-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"raw",
            bounded_metadata: b"{}",
        })
    })?;
    assert!(matches!(
        db.write_transaction(|| db.bind_raw_inner_copy("bind-deleted-copy", "deleted-target")),
        Err(StorageError::AuthorizationRejected)
    ));
    Ok(())
}

#[test]
fn unsupported_owner_limit_is_per_account_and_source() -> TestResult {
    let (_root, db) = test_db("unsupported-owner-limit")?;
    for index in 0..64 {
        let owner = format!("owner-{index}");
        let source = format!("root-{}", index / 16);
        let copy = format!("copy-{index}");
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: &owner,
                verified_source_anchor: &source,
                copy_id: &copy,
                kind: RawInnerCopyKind::OuterInner,
                bytes: b"x",
                bounded_metadata: b"{}",
            })
        })?;
    }
    let failed = db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "owner-over-limit",
            verified_source_anchor: "root-0",
            copy_id: "copy-over-limit",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"x",
            bounded_metadata: b"{}",
        })
    });
    assert!(matches!(
        failed,
        Err(StorageError::UnsupportedRawQuotaExceeded {
            source_anchor,
            scope: RawInnerQuotaScope::Account,
        }) if source_anchor == "root-0"
    ));
    assert!(db.raw_inner_copy("copy-over-limit")?.is_none());
    assert_eq!(db.unsupported_raw_quota(None)?.owners, 64);
    Ok(())
}

#[test]
fn fault_after_copy_and_linkage_rolls_back_all_writes() -> TestResult {
    let (_root, db) = test_db("raw-inner-post-write-fault")?;
    writer::fail_after_last_write_once();
    let failed = db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "fault-owner",
            verified_source_anchor: "root",
            copy_id: "copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"raw",
            bounded_metadata: b"{}",
        })
    });
    assert!(matches!(failed, Err(StorageError::AuthorizationRejected)));
    assert!(db.raw_inner_copy("copy")?.is_none());
    assert_eq!(db.unsupported_raw_quota(None)?.owners, 0);
    let footprints = db.connection.query_row(
        "SELECT count(*) FROM message_footprint WHERE kind='raw_inner'",
        [],
        |row| row.get::<_, u64>(0),
    )?;
    assert_eq!(footprints, 0);
    Ok(())
}

#[test]
fn known_content_evidence_is_private_and_erased_with_its_message() -> TestResult {
    let (_root, db) = test_db("known-content-evidence")?;
    db.store_message_content("thread", "known-message", b"exact inner")?;
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "known-message",
            verified_source_anchor: "verified-root",
            copy_id: "known-raw-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"unknown extension bytes",
            bounded_metadata: b"{}",
        })
    })?;
    db.write_transaction(|| {
        db.put_known_content_evidence(
            "known-message",
            "thread",
            b"exact inner",
            b"verified provenance",
            b"selected report opening",
        )
    })?;
    let evidence =
        db.known_content_evidence("known-message")?.ok_or(StorageError::AuthorizationRejected)?;
    assert_eq!(evidence.provenance, b"verified provenance");
    assert_eq!(evidence.report_opening, b"selected report opening");
    assert_eq!(
        db.message_content("known-message")?.ok_or(StorageError::AuthorizationRejected)?,
        b"exact inner"
    );
    db.connection.execute(
        "INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at)
         VALUES('thread','known-message','sender',x'',x'7b7d',0,0,1)",
        [],
    )?;
    db.delete_direct_message("thread", "known-message", "sender", "tombstone")?;
    assert!(db.known_content_evidence("known-message")?.is_none());
    assert!(db.message_content("known-message")?.is_none());
    assert!(db.raw_inner_copy("known-raw-copy")?.is_none());
    assert_eq!(db.unsupported_raw_quota(None)?.owners, 0);
    let late_write = db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "known-message",
            verified_source_anchor: "verified-root",
            copy_id: "late-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"must not resurrect",
            bounded_metadata: b"{}",
        })
    });
    assert!(matches!(late_write, Err(StorageError::AuthorizationRejected)));
    assert!(matches!(
        db.write_transaction(|| {
            db.put_known_content_evidence(
                "known-message",
                "thread",
                b"exact inner",
                b"late provenance",
                b"late opening",
            )
        }),
        Err(StorageError::AuthorizationRejected)
    ));
    Ok(())
}

#[test]
fn raw_copy_binding_moves_the_locator_to_the_authenticated_replay_target() -> TestResult {
    let (_root, db) = test_db("raw-inner-replay-binding")?;
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "copy:authenticated-envelope",
            verified_source_anchor: "verified-root",
            copy_id: "envelope-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"exact unknown inner",
            bounded_metadata: b"{}",
        })?;
        db.bind_raw_inner_copy("envelope-copy", "message-target")
    })?;
    assert_eq!(
        db.connection.query_row(
            "SELECT copy_id FROM message_copy_binding WHERE message_id='message-target'",
            [],
            |row| row.get::<_, String>(0),
        )?,
        "raw:envelope-copy"
    );
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM message_footprint WHERE message_id='copy:authenticated-envelope' AND kind='raw_inner'",
            [],
            |row| row.get::<_, u64>(0),
        )?,
        0
    );
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM message_footprint WHERE message_id='message-target' AND kind='raw_inner' AND locator='envelope-copy'",
            [],
            |row| row.get::<_, u64>(0),
        )?,
        1
    );
    db.connection.execute(
        "INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at)
         VALUES('thread','message-target','sender',x'',x'7b7d',0,0,1)",
        [],
    )?;
    db.delete_direct_message("thread", "message-target", "sender", "tombstone")?;
    assert!(db.raw_inner_copy("envelope-copy")?.is_none());
    assert_eq!(db.unsupported_raw_quota(None)?.owners, 0);
    Ok(())
}

#[test]
fn erased_bound_raw_copy_cannot_be_rewritten() -> TestResult {
    let (_root, db) = test_db("raw-copy-sticky-erasure")?;
    db.connection.execute(
        "INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at)
         VALUES('thread','message-target','sender',x'',x'7b7d',0,0,1)",
        [],
    )?;
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "copy:authenticated-envelope",
            verified_source_anchor: "verified-root",
            copy_id: "same-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"exact raw bytes",
            bounded_metadata: b"{}",
        })?;
        db.bind_raw_inner_copy("same-copy", "message-target")
    })?;
    db.delete_direct_message("thread", "message-target", "sender", "tombstone")?;
    let rewrite = db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "copy:authenticated-envelope",
            verified_source_anchor: "verified-root",
            copy_id: "same-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"exact raw bytes",
            bounded_metadata: b"{}",
        })
    });
    assert!(matches!(rewrite, Err(StorageError::AuthorizationRejected)));
    let different_owner = db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "different-owner",
            verified_source_anchor: "verified-root",
            copy_id: "same-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"exact raw bytes",
            bounded_metadata: b"{}",
        })
    });
    assert!(matches!(different_owner, Err(StorageError::AuthorizationRejected)));
    let different_copy = db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "copy:authenticated-envelope",
            verified_source_anchor: "verified-root",
            copy_id: "different-copy",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"exact raw bytes",
            bounded_metadata: b"{}",
        })
    });
    assert!(matches!(different_copy, Err(StorageError::AuthorizationRejected)));
    assert!(db.raw_inner_copy("same-copy")?.is_none());
    assert!(db.raw_inner_copy("different-copy")?.is_none());
    assert_eq!(db.unsupported_raw_quota(None)?.owners, 0);
    for table in ["raw_inner_copy", "raw_inner_owner", "raw_inner_evidence"] {
        assert_eq!(
            db.connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get::<_, u64>(0))?,
            0,
            "unexpected persisted rows in {table}"
        );
    }
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM message_copy_binding WHERE copy_id='raw:same-copy'",
            [],
            |row| row.get::<_, u64>(0),
        )?,
        0
    );
    Ok(())
}

#[test]
fn unsupported_source_owner_limit_is_enforced_without_eviction() -> TestResult {
    let (_root, db) = test_db("unsupported-source-owner-limit")?;
    for index in 0..16 {
        let owner = format!("source-owner-{index}");
        let copy = format!("source-copy-{index}");
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: &owner,
                verified_source_anchor: "one-source",
                copy_id: &copy,
                kind: RawInnerCopyKind::OuterInner,
                bytes: b"x",
                bounded_metadata: b"{}",
            })
        })?;
    }
    let failed = db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "source-owner-over-limit",
            verified_source_anchor: "one-source",
            copy_id: "source-copy-over-limit",
            kind: RawInnerCopyKind::OuterInner,
            bytes: b"x",
            bounded_metadata: b"{}",
        })
    });
    assert!(matches!(
        failed,
        Err(StorageError::UnsupportedRawQuotaExceeded {
            source_anchor,
            scope: RawInnerQuotaScope::Source,
        }) if source_anchor == "one-source"
    ));
    assert!(db.raw_inner_copy("source-copy-0")?.is_some());
    assert!(db.raw_inner_copy("source-copy-over-limit")?.is_none());
    assert_eq!(db.unsupported_raw_quota(Some("one-source"))?.owners, 16);
    Ok(())
}

#[test]
fn raw_copies_survive_backup_restore_and_full_merge_with_footprints() -> TestResult {
    let root = crate::tests::temp_root("raw-inner-backup-merge");
    let source_index = AccountIndex::open(root.join("source"))?;
    let target_index = AccountIndex::open(root.join("target"))?;
    source_index.create_account("acct", "root")?;
    target_index.create_account("acct", "root")?;
    let source = AccountDb::open(&source_index, "acct", &AccountDbKey::generate()?)?;
    let target = AccountDb::open(&target_index, "acct", &AccountDbKey::generate()?)?;
    source.write_transaction(|| {
        source.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "message",
            verified_source_anchor: "verified-root",
            copy_id: "copy",
            kind: RawInnerCopyKind::NestedGroup,
            bytes: b"verified nested bytes",
            bounded_metadata: b"{}",
        })
    })?;

    let source_path = root.join("source.db");
    let source_snapshot = source.write_backup_snapshot(&source_path)?;
    let archived = BackupDatabase::open(&source_path, &source_snapshot.key)?;
    assert_eq!(
        archived.db.query_row(
            "SELECT raw_bytes FROM raw_inner_copy WHERE copy_id='copy'",
            [],
            |row| row.get::<_, Vec<u8>>(0)
        )?,
        b"verified nested bytes"
    );
    let restored_path = root.join("restored.db");
    let restored_key = AccountDbKey::generate()?;
    archived.copy_to(&restored_path, &restored_key)?;
    let restored = BackupDatabase::open(&restored_path, &restored_key)?;
    assert_eq!(
        restored.db.query_row(
            "SELECT raw_bytes FROM raw_inner_copy WHERE copy_id='copy'",
            [],
            |row| row.get::<_, Vec<u8>>(0)
        )?,
        b"verified nested bytes"
    );

    let target_path = root.join("target.db");
    let target_snapshot = target.write_backup_snapshot(&target_path)?;
    let mut merged = BackupDatabase::open(&target_path, &target_snapshot.key)?;
    merged.merge_backup(&source_path, &source_snapshot.key, || Ok(()))?;
    assert_eq!(
        merged.db.query_row(
            "SELECT raw_bytes FROM raw_inner_copy WHERE copy_id='copy'",
            [],
            |row| row.get::<_, Vec<u8>>(0)
        )?,
        b"verified nested bytes"
    );
    assert_eq!(
        merged.db.query_row("SELECT count(*) FROM message_footprint WHERE message_id='message' AND kind='raw_inner' AND locator='copy'", [], |row| row.get::<_, u64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn full_merge_does_not_restore_a_raw_copy_for_a_deleted_owner() -> TestResult {
    let root = crate::tests::temp_root("raw-inner-deleted-merge");
    let source_index = AccountIndex::open(root.join("source"))?;
    let target_index = AccountIndex::open(root.join("target"))?;
    source_index.create_account("acct", "root")?;
    target_index.create_account("acct", "root")?;
    let source = AccountDb::open(&source_index, "acct", &AccountDbKey::generate()?)?;
    let target = AccountDb::open(&target_index, "acct", &AccountDbKey::generate()?)?;
    source.write_transaction(|| {
        source.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "deleted-message",
            verified_source_anchor: "verified-root",
            copy_id: "deleted-copy",
            kind: RawInnerCopyKind::NestedGroup,
            bytes: b"stale archive raw bytes",
            bounded_metadata: b"{}",
        })
    })?;
    target.connection.execute(
        "INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at)
         VALUES('thread','deleted-message','sender',x'',x'7b7d',0,0,1)",
        [],
    )?;
    target.delete_direct_message("thread", "deleted-message", "sender", "tombstone")?;

    let source_path = root.join("source.db");
    let source_snapshot = source.write_backup_snapshot(&source_path)?;
    let target_path = root.join("target.db");
    let target_snapshot = target.write_backup_snapshot(&target_path)?;
    let mut merged = BackupDatabase::open(&target_path, &target_snapshot.key)?;
    merged.merge_backup(&source_path, &source_snapshot.key, || Ok(()))?;
    assert_eq!(
        merged
            .db
            .query_row("SELECT count(*) FROM raw_inner_copy", [], |row| row.get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        merged
            .db
            .query_row("SELECT count(*) FROM raw_inner_owner", [], |row| row.get::<_, u64>(0))?,
        0
    );
    Ok(())
}
