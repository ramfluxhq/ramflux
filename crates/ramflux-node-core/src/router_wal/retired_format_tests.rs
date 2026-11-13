// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real WAL refusals must precede identity reservation, repair and all startup commits.
use super::*;
use crate::tests::persisted_image::image;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn stored(
    key: &str,
    expires: i64,
    kind: u8,
) -> std::result::Result<StoredRouterWalPayload, Box<dyn std::error::Error>> {
    let entry = super::tests::router_wal_inbox_entry("format-row", "format-target");
    let body = if kind == 0 {
        StoredRouterWalPayload::SubmissionAccepted {
            replay_key: key.into(),
            replay_expires_at: expires,
            accepted_at: 1_760_000_001,
            entry: Some(Box::new(StoredRouterWalInboxEntry::try_from(&entry)?)),
        }
    } else {
        StoredRouterWalPayload::SubmissionClassified {
            replay_key: key.into(),
            replay_expires_at: expires,
            accepted_at: 1_760_000_001,
            entry: Some(Box::new(StoredRouterWalInboxEntry::try_from(&entry)?)),
            local_delivery: RouterWalLocalDelivery {
                sender_root_commitment: "root".into(),
                envelope_id: "format-row".into(),
                target_delivery_id: "format-target".into(),
            },
        }
    };
    Ok(if kind == 2 {
        StoredRouterWalPayload::Incarnated {
            incarnation_id: "a".repeat(32),
            payload: Box::new(body),
        }
    } else {
        body
    })
}

fn segment(root: &Path, values: &[StoredRouterWalPayload]) -> Result {
    fs::create_dir_all(root)?;
    let mut file = File::create(router_wal_segment_path(root, 0))?;
    file.write_all(ROUTER_WAL_MAGIC)?;
    for value in values {
        write_router_wal_record_to_file(&file, &postcard::to_allocvec(value)?)?;
    }
    file.sync_all()?;
    Ok(())
}

#[test]
fn retired_wal_keys_refuse_real_reopen_even_when_expired_and_mixed_with_current() -> Result {
    let root = ramflux_crypto::create_identity_root("format-owner", [9; 32]);
    let source =
        ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "format-device")?;
    let old = format!(
        "envelope/v2/{}/{}",
        source.storage_key(),
        ramflux_protocol::encode_base64url("format-row")
    );
    let current = crate::tests::request_replay_fixture("current-row");
    for key in [old.as_str(), "unqualified", "legacy/replay/aWQ"] {
        for expires in [0, i64::MAX] {
            for kind in 0..3 {
                let directory = tempfile::TempDir::new()?;
                let path = directory.path().join("db");
                let wal = directory.path().join("wal");
                drop(crate::RouterRedbStore::open_without_wal(&path)?);
                segment(&wal, &[stored(&current, i64::MAX, 0)?, stored(key, expires, kind)?])?;
                let before = image(directory.path())?;
                assert!(
                    matches!(
                        RouterWalStore::open(&wal),
                        Err(NodeCoreError::UnsupportedPersistedFormat("router replay identity"))
                    ),
                    "standalone WAL must refuse raw retired key before repair"
                );
                assert_eq!(
                    image(directory.path())?,
                    before,
                    "standalone refusal changed WAL or redb bytes"
                );
                assert!(
                    matches!(
                        crate::RouterRedbStore::open_with_wal(&path, &wal),
                        Err(NodeCoreError::UnsupportedPersistedFormat("router replay identity"))
                    ),
                    "associated startup must refuse raw retired key before schema/association writes"
                );
                assert_eq!(
                    image(directory.path())?,
                    before,
                    "associated refusal changed a logical table, journal, incarnation or WAL"
                );
                assert!(
                    crate::RouterRedbStore::rotate_inbox_incarnations_at(&path, Some(&wal), None)
                        .is_err(),
                    "maintenance must refuse before its prelude writes"
                );
                assert_eq!(
                    image(directory.path())?,
                    before,
                    "maintenance refusal changed authority or WAL"
                );
            }
        }
    }
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("absent-db");
    let wal = directory.path().join("wal");
    segment(&wal, &[stored(&old, 0, 0)?])?;
    let before = image(directory.path())?;
    assert!(
        matches!(
            crate::RouterRedbStore::open_with_wal(&path, &wal),
            Err(NodeCoreError::UnsupportedPersistedFormat(_))
        ),
        "retired WAL must refuse before creating a fresh database"
    );
    assert!(!path.try_exists()?, "refused WAL startup must not publish an empty database");
    assert_eq!(image(directory.path())?, before, "fresh startup refusal changed the WAL directory");
    Ok(())
}

#[test]
fn current_accepted_classified_and_incarnated_wal_records_reopen_unchanged() -> Result {
    for kind in 0..3 {
        let directory = tempfile::TempDir::new()?;
        let key = crate::tests::request_replay_fixture("current-row");
        segment(directory.path(), &[stored(&key, i64::MAX, kind)?])?;
        let before = image(directory.path())?;
        let wal = RouterWalStore::open_with_shards_config(directory.path(), 1, false)?;
        let rows = wal.submissions(0);
        assert_eq!(rows.len(), 1, "current postcard variant must retain its submission");
        assert_eq!(
            rows.first().ok_or("submission missing")?.replay_key,
            key,
            "reopen must not transform current replay identities"
        );
        drop(wal);
        // Recovery may create an empty shard, but the supplied segment must remain byte-exact.
        let after = image(directory.path())?;
        for (path, digest) in before {
            assert_eq!(after.get(&path), Some(&digest), "current WAL record bytes changed");
        }
    }
    Ok(())
}

#[tokio::test]
async fn retired_append_refuses_before_reserving_sender_identity() -> Result {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("db");
        let db = Arc::new(redb::Database::create(&path)?);
        crate::RouterRedbStore::initialize_open_schema(&db)?;
        let wal =
            RouterWalStore::open_associated(&directory.path().join("wal"), Arc::clone(&db), &path)?;
        let entry = super::tests::router_wal_inbox_entry("row", "unreserved-target");
        let before = crate::tests::persisted_image::database_image(&db)?;
        let before_wal = image(&directory.path().join("wal"))?;
        for key in ["envelope/v2/source/id", "unqualified", "legacy/replay/aWQ"] {
            assert!(
                matches!(
                    wal.record_submission(key, i64::MAX, Some(&entry)),
                    Err(NodeCoreError::UnsupportedPersistedFormat(_))
                ),
                "synchronous append admitted retired key"
            );
            assert!(
                matches!(
                    wal.record_submission_async(key, i64::MAX, Some(&entry)).await,
                    Err(NodeCoreError::UnsupportedPersistedFormat(_))
                ),
                "asynchronous append admitted retired key"
            );
        }
        assert_eq!(
            crate::tests::persisted_image::database_image(&db)?,
            before,
            "a refused append reserved sender identity or changed WAL bytes"
        );
        assert_eq!(
            image(&directory.path().join("wal"))?,
            before_wal,
            "refused append changed WAL bytes"
        );
        Ok(())
    })
    .await?
}

#[test]
fn pending_rotation_root_refuses_expired_retired_keys_before_quarantine_with_other_wal_modes()
-> Result {
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("router.redb");
    let pending_root = directory.path().join("pending-wal");
    let other_root = directory.path().join("other-wal");
    drop(crate::RouterRedbStore::open_without_wal(&path)?);
    let owner = ramflux_crypto::create_identity_root("pending-owner", [7; 32]);
    let source =
        ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&owner, "device")?;
    let retired = format!(
        "envelope/v2/{}/{}",
        source.storage_key(),
        ramflux_protocol::encode_base64url("expired")
    );
    segment(
        &pending_root,
        &[
            stored(&crate::tests::request_replay_fixture("current"), i64::MAX, 0)?,
            stored(&retired, 0, 0)?,
        ],
    )?;
    segment(&other_root, &[stored(&crate::tests::request_replay_fixture("other"), i64::MAX, 0)?])?;
    let damaged = router_wal_segment_path(&pending_root, 1);
    fs::write(&damaged, b"damaged segment awaiting quarantine")?;
    let quarantine = pending_root.join("quarantine");
    let destination = quarantine.join("pending-segment");
    let db = redb::Database::open(&path)?;
    let txn = db.begin_write()?;
    txn.open_table(crate::ROUTER_SNAPSHOT_TABLE)?.insert("session_push_rotation_pending_v1", serde_json::to_vec(&serde_json::json!({"version":1,"wal_root":pending_root,"quarantine":{"source":damaged,"destination":destination}}))?.as_slice())?;
    txn.commit()?;
    drop(db);
    let before = image(directory.path())?;
    for root in [None, Some(other_root.as_path())] {
        let opened = match root {
            None => crate::RouterRedbStore::open_without_wal(&path),
            Some(root) => crate::RouterRedbStore::open_with_wal(&path, root),
        };
        assert!(
            matches!(
                opened,
                Err(NodeCoreError::UnsupportedPersistedFormat("router replay identity"))
            ),
            "pending WAL must be checked when startup WAL is disabled or points elsewhere"
        );
        assert_eq!(
            image(directory.path())?,
            before,
            "pending-root startup refusal changed a table, journal or WAL file"
        );
        assert!(
            matches!(
                crate::RouterRedbStore::rotate_inbox_incarnations_at(&path, root, None),
                Err(NodeCoreError::UnsupportedPersistedFormat("router replay identity"))
            ),
            "offline rotation must check its pending root before initialization or quarantine"
        );
        assert_eq!(
            image(directory.path())?,
            before,
            "pending-root rotation refusal changed a table, journal or WAL file"
        );
        assert!(
            damaged.is_file() && !destination.try_exists()? && !quarantine.try_exists()?,
            "format refusal must precede quarantine directory creation and movement"
        );
    }
    Ok(())
}
