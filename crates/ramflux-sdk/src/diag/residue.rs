// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unlocked-account residue diagnostic. The report lists locations and counts.

use super::files::{self, ScanRoot};
use crate::RamfluxClient;
use crate::SdkError;
use ramflux_storage::{
    AccountDb, ResidueScan, ResidueScanStatus, ResidueTable, ResidueTableStatus,
};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zeroize::Zeroize;

/// One directory the caller wants scanned in addition to the account object,
/// outbox, spool, and segment directories.
pub struct ResidueDirectory {
    pub path: PathBuf,
    /// `account` for this account's files, or `shared` for a daemon-wide spool.
    pub scope: &'static str,
}

/// Inputs for one residue diagnostic. The marker buffer is wiped before return.
pub struct ResidueDiagnostic<'a> {
    pub account_id: &'a str,
    pub marker: &'a mut [u8],
    pub data_root: &'a Path,
    pub directories: &'a [ResidueDirectory],
    pub deadline: Instant,
}

/// Scans the unlocked account database and the named directories.
///
/// The account must already be unlocked. A locked account returns
/// [`SdkError::AccountDbNotUnlocked`] before the marker is validated.
///
/// # Errors
/// Returns a typed lock error, a storage error, or a local-bus error when a
/// path, deadline, or read bound fails. The error text does not include the marker.
#[must_use = "discarding the residue report hides plaintext hits"]
pub fn diagnose_plaintext_residue(
    client: &RamfluxClient,
    diagnostic: &mut ResidueDiagnostic<'_>,
) -> Result<Value, SdkError> {
    let db = client.account_db()?;
    if db.local_account_id != diagnostic.account_id {
        return Err(SdkError::LocalBus("residue scan account is not the unlocked account".into()));
    }
    let wipe = Wipe(diagnostic.marker);
    let scan = db.scan_plaintext_residue(wipe.0, diagnostic.deadline)?;
    let owned = account_directories(db)?;
    let mut roots = Vec::with_capacity(owned.len().saturating_add(diagnostic.directories.len()));
    for path in &owned {
        roots.push(ScanRoot { path, scope: "account" });
    }
    for directory in diagnostic.directories {
        roots.push(ScanRoot { path: &directory.path, scope: directory.scope });
    }
    let needles = NeedleWipe(ramflux_storage::residue_needles(wipe.0)?);
    let files = files::scan_roots(diagnostic.data_root, &roots, &needles.0, diagnostic.deadline)?;
    drop(needles);
    Ok(report_json(&db.local_account_id, &scan, &files))
}

struct Wipe<'a>(&'a mut [u8]);

impl Drop for Wipe<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct NeedleWipe(Vec<Vec<u8>>);

impl Drop for NeedleWipe {
    fn drop(&mut self) {
        for needle in &mut self.0 {
            needle.zeroize();
        }
    }
}

fn account_directories(db: &AccountDb) -> Result<Vec<PathBuf>, SdkError> {
    let account_dir = db
        .path
        .parent()
        .ok_or_else(|| SdkError::LocalBus("residue scan account path has no directory".into()))?;
    Ok(vec![
        account_dir.join("objects"),
        account_dir.join("outbox"),
        account_dir.join("spool"),
        db.path.with_extension("segments"),
    ])
}

fn report_json(account: &str, scan: &ResidueScan, files: &files::FileScan) -> Value {
    let tables = scan.tables.iter().map(table_json).collect::<Vec<_>>();
    let file_rows = files.records.iter().map(file_json).collect::<Vec<_>>();
    serde_json::json!({
        "account": account,
        "status": publish_status(scan, files),
        "hits": scan.hits.saturating_add(files.hits),
        "truncated": scan.truncated || files.truncated,
        "tables": tables,
        "files": file_rows,
    })
}

fn publish_status(scan: &ResidueScan, files: &files::FileScan) -> &'static str {
    let mut status = scan.status;
    if files.truncated {
        status = status.merge(ResidueScanStatus::Truncated);
    }
    if files.hits > 0 {
        status = status.merge(ResidueScanStatus::Residue);
    }
    status.as_str()
}

fn table_json(table: &ResidueTable) -> Value {
    let ResidueTableStatus::Scanned = table.status else {
        return serde_json::json!({
            "name": table.name,
            "status": ResidueTableStatus::Unscannable.as_str(),
        });
    };
    let Some(hits) = table.hits else {
        return serde_json::json!({
            "name": table.name,
            "status": ResidueTableStatus::Unscannable.as_str(),
        });
    };
    let locations = table.locations.iter().map(|hit| {
        let mut location = Map::new();
        if let Some(rowid) = hit.rowid {
            location.insert("rowid".to_owned(), Value::from(rowid));
        }
        location.insert("column".to_owned(), Value::String(hit.column.clone()));
        Value::Object(location)
    });
    serde_json::json!({
        "name": table.name,
        "status": ResidueTableStatus::Scanned.as_str(),
        "hits": hits,
        "truncated": table.truncated,
        "locations": locations.collect::<Vec<_>>(),
    })
}

fn file_json(record: &files::FileRecord) -> Value {
    let locations = record
        .locations
        .iter()
        .map(|offset| serde_json::json!({ "offset": offset }))
        .collect::<Vec<_>>();
    serde_json::json!({
        "path": record.path,
        "present": record.present,
        "scope": record.scope,
        "hits": record.hits,
        "truncated": record.truncated,
        "locations": locations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_storage::{
        AccountDb, AccountDbKey, AccountIndex, DirectMessageWrite, MessageMetadata, ResidueScan,
        ResidueScanStatus, ResidueTable, ResidueTableStatus,
    };
    use std::time::Duration;

    const MARKER: &[u8] = b"b11canarymarker";

    fn unlocked(root: &Path) -> (AccountIndex, AccountDb) {
        let index = AccountIndex::open(root).expect("test: index");
        index.create_account("acct", "principal").expect("test: account");
        let db = AccountDb::open(&index, "acct", &AccountDbKey::from_bytes([9; 32]))
            .expect("test: database");
        db.enable_runtime().expect("test: runtime");
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "thread",
            message_id: "message-1",
            sender_id: "sender",
            encrypted_body: b"ciphertext",
            metadata: &MessageMetadata::default(),
            created_at: 1,
        })
        .expect("test: projection");
        db.store_message_content("thread", "message-1", MARKER).expect("test: content");
        (index, db)
    }

    #[test]
    fn locked_account_residue_scan_is_typed() {
        let client = RamfluxClient::new();
        let mut marker = b"b11canarymarker".to_vec();
        let error = {
            let mut diagnostic = ResidueDiagnostic {
                account_id: "acct",
                marker: &mut marker,
                data_root: Path::new("/tmp"),
                directories: &[],
                deadline: Instant::now() + Duration::from_secs(5),
            };
            diagnose_plaintext_residue(&client, &mut diagnostic).expect_err("test: locked account")
        };
        assert!(
            matches!(error, SdkError::AccountDbNotUnlocked),
            "locked scan must stay typed, got {error}"
        );
        assert_eq!(marker, b"b11canarymarker", "a locked refusal does not consume the marker");
    }

    #[test]
    fn file_and_table_marker_is_located_without_content() {
        let root = tempfile::tempdir().expect("test: temp");
        let (index, db) = unlocked(root.path());
        let object = root.path().join("accounts/acct/objects/blob.bin");
        std::fs::write(&object, b"xxxxb11canarymarker").expect("test: object");
        let shared = root.path().join("shared-spool");
        std::fs::create_dir_all(&shared).expect("test: shared dir");
        std::fs::write(shared.join("download.bin"), b"yyb11canarymarker").expect("test: spool");
        let mut client = RamfluxClient::new();
        client.account_index = Some(index);
        client.active_account_db = Some(db);
        let mut marker = MARKER.to_vec();
        let directories = [ResidueDirectory { path: shared.clone(), scope: "shared" }];
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                "blob.bin",
                root.path().join("accounts/acct/objects/escape"),
            )
            .expect("test: symlink");
            let mut probe = MARKER.to_vec();
            let mut diagnostic = ResidueDiagnostic {
                account_id: "acct",
                marker: &mut probe,
                data_root: root.path(),
                directories: &directories,
                deadline: Instant::now() + Duration::from_secs(5),
            };
            let refused = diagnose_plaintext_residue(&client, &mut diagnostic);
            assert!(refused.is_err(), "a symlink must fail the scan closed");
            assert!(
                !format!("{refused:?}").contains("b11canarymarker"),
                "the refusal must not echo the marker"
            );
            std::fs::remove_file(root.path().join("accounts/acct/objects/escape"))
                .expect("test: unlink");
        }
        let report = {
            let mut diagnostic = ResidueDiagnostic {
                account_id: "acct",
                marker: &mut marker,
                data_root: root.path(),
                directories: &directories,
                deadline: Instant::now() + Duration::from_secs(5),
            };
            diagnose_plaintext_residue(&client, &mut diagnostic).expect("test: scan")
        };
        assert_eq!(marker, vec![0; MARKER.len()], "the marker buffer is wiped");
        let rendered = report.to_string();
        assert!(!rendered.contains("b11canarymarker"), "the report must not contain the marker");
        assert_ne!(report["status"], "clean", "a located marker is not a clean scan");
        let tables = report["tables"].as_array().expect("test: tables");
        assert!(
            tables.iter().any(|table| {
                table["name"] == "runtime_message_content"
                    && table["locations"].as_array().is_some_and(|locations| {
                        locations.iter().any(|hit| hit["column"] == "body")
                    })
            }),
            "plaintext body is located"
        );
        let files = report["files"].as_array().expect("test: files");
        assert!(
            files.iter().any(|file| {
                file["path"] == "accounts/acct/objects/blob.bin"
                    && file["locations"]
                        .as_array()
                        .is_some_and(|locations| locations.iter().any(|hit| hit["offset"] == 4))
            }),
            "object store hit keeps the file offset"
        );
        assert!(
            files
                .iter()
                .any(|file| file["path"] == "accounts/acct/outbox" && file["present"] == false),
            "a missing outbox directory is listed"
        );
        assert!(
            files.iter().any(|file| {
                file["scope"] == "shared"
                    && file["path"] == "shared-spool/download.bin"
                    && file["hits"].as_u64().is_some_and(|hits| hits > 0)
            }),
            "the shared spool hit is labeled"
        );
        let huge = root.path().join("accounts/acct/objects/huge.bin");
        let created = std::fs::File::create(&huge).expect("test: huge");
        created.set_len(16 * 1024 * 1024 + 1).expect("test: length");
        drop(created);
        marker = MARKER.to_vec();
        let mut oversized_diagnostic = ResidueDiagnostic {
            account_id: "acct",
            marker: &mut marker,
            data_root: root.path(),
            directories: &[],
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let oversized = diagnose_plaintext_residue(&client, &mut oversized_diagnostic);
        assert!(oversized.is_err(), "a file over 16 MiB must not look like a clean scan");
    }

    #[test]
    fn unscannable_table_json_omits_the_hit_count() {
        let scan = ResidueScan {
            tables: vec![ResidueTable {
                name: "residue_probe".into(),
                status: ResidueTableStatus::Unscannable,
                hits: None,
                truncated: false,
                locations: Vec::new(),
            }],
            hits: 0,
            status: ResidueScanStatus::Unscannable,
            truncated: false,
        };
        let files = super::files::FileScan { records: Vec::new(), hits: 3, truncated: true };
        let report = super::report_json("acct", &scan, &files);
        assert_eq!(report["status"], "unscannable");
        let table = report["tables"][0].to_string();
        assert!(table.contains("\"status\":\"unscannable\""));
        assert!(!table.contains("hits"), "an unscannable table must not report a hit count");
    }
}
