// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only logical snapshots of node redb stores and the router WAL.
//! The live service keeps the writable database. redb rows are read from a
//! byte copy. WAL segments are read in place and never repaired or truncated.

use redb::{MultimapTableHandle, ReadableDatabase, ReadableTable, TableDefinition, TableHandle};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::NodeCoreError;

const COPY_CAP: u64 = 32 * 1024 * 1024;
const RECORD_CAP: u32 = 8 * 1024 * 1024;
const RECORD_COUNT_CAP: usize = 100_000;
const FILE_CAP: usize = 4_000;
/// Same header as `router_wal`. A mismatch is an error, not a skipped file.
const WAL_MAGIC: &[u8] = b"ramflux-router-wal-v1\n";
const SHARD_PREFIX: &str = "router-wal-shard-";

/// Logical rows of every normal table in `path`, plus the multimap table names.
///
/// Tables are taken from the store. Each one is decoded with its real key and
/// value types. A type this reader cannot open is an error, never a row.
///
/// # Errors
/// Returns an error when the file is missing, larger than 32 MiB, the copy
/// cannot be opened, or any table cannot be decoded.
pub fn logical_redb_rows(path: &Path) -> Result<BTreeMap<String, Vec<String>>, NodeCoreError> {
    let bytes = read_bounded(path)?;
    let copy = TempCopy::create();
    std::fs::write(&copy.path, &bytes)
        .map_err(|error| NodeCoreError::Redb(format!("write {}: {error}", copy.path.display())))?;
    let database = redb::ReadOnlyDatabase::open(&copy.path)
        .map_err(|error| NodeCoreError::Redb(format!("open {}: {error}", path.display())))?;
    let transaction =
        database.begin_read().map_err(|error| NodeCoreError::Redb(error.to_string()))?;
    let mut tables = BTreeMap::new();
    let mut names = Vec::new();
    for handle in
        transaction.list_tables().map_err(|error| NodeCoreError::Redb(error.to_string()))?
    {
        names.push(handle.name().to_owned());
    }
    names.sort();
    for name in names {
        if name.is_empty() {
            return Err(NodeCoreError::Redb(format!("empty table name in {}", path.display())));
        }
        tables.insert(name.clone(), table_rows(&transaction, &name)?);
    }
    let mut multimaps = Vec::new();
    for handle in transaction
        .list_multimap_tables()
        .map_err(|error| NodeCoreError::Redb(error.to_string()))?
    {
        multimaps.push(handle.name().to_owned());
    }
    multimaps.sort();
    tables.insert("__multimap_tables__".to_owned(), multimaps);
    drop(transaction);
    drop(database);
    Ok(tables)
}

/// CRC-valid router WAL payloads and the regular segment files that held them.
#[derive(Debug)]
#[must_use]
pub struct LogicalWal {
    /// Sorted blake3 digests of CRC-valid payloads.
    pub records: Vec<String>,
    /// Regular `router-wal-*.wal` files, including shard segments.
    pub files: Vec<PathBuf>,
}

/// Digests of committed router WAL records under `root`, including shard segments.
/// A missing directory is an error. Incomplete tails are not records.
///
/// # Errors
/// Returns an error when the directory or a segment cannot be read, or a segment
/// does not start with the WAL header.
pub fn logical_wal_records(root: &Path) -> Result<LogicalWal, NodeCoreError> {
    if !root.is_dir() {
        return Err(NodeCoreError::Redb(format!(
            "router wal directory missing: {}",
            root.display()
        )));
    }
    let mut files = Vec::new();
    collect_wal_files(root, &mut files)?;
    let mut records = Vec::new();
    for path in &files {
        records.extend(segment_digests(path)?);
        if records.len() > RECORD_COUNT_CAP {
            return Err(NodeCoreError::Redb(
                "router wal snapshot exceeded 100000 records".to_owned(),
            ));
        }
    }
    records.sort();
    Ok(LogicalWal { records, files })
}

enum ReadRows {
    Rows(Vec<String>),
    /// The table exists with a different key/value type. `detail` names that type.
    Mismatch(String),
    Failed(String),
}

fn table_rows(
    transaction: &redb::ReadTransaction,
    name: &str,
) -> Result<Vec<String>, NodeCoreError> {
    let mut mismatch = String::new();
    for read in [
        read_str_bytes,
        read_byte_bytes,
        read_str_text,
        read_str_counter,
        read_str_flag,
        read_u64_bytes,
        read_str_pair_flag,
        read_deadline_flag,
        read_signed_deadline_flag,
        read_signed_deadline_counter,
        read_owner_expiry,
    ] {
        match read(transaction, name) {
            ReadRows::Rows(rows) => return Ok(rows),
            ReadRows::Mismatch(detail) => mismatch = detail,
            ReadRows::Failed(error) => {
                return Err(NodeCoreError::Redb(format!("{name}: {error}")));
            }
        }
    }
    Err(NodeCoreError::Redb(format!("undecodable table {name}: {mismatch}")))
}

fn read_str_bytes(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<&str, &[u8], _>(transaction, name, |key, value| format!("{key}\t{}", hex(value)))
}

fn read_byte_bytes(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<&[u8], &[u8], _>(transaction, name, |key, value| {
        format!("{}\t{}", hex(key), hex(value))
    })
}

fn read_str_text(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<&str, &str, _>(transaction, name, |key, value| format!("{key}\t{value}"))
}

fn read_str_counter(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<&str, u64, _>(transaction, name, |key, value| format!("{key}\t{value}"))
}

fn read_str_flag(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<&str, u8, _>(transaction, name, |key, value| format!("{key}\t{value}"))
}

fn read_u64_bytes(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<u64, &[u8], _>(transaction, name, |key, value| format!("{key}\t{}", hex(value)))
}

fn read_str_pair_flag(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<(&str, &str), u8, _>(transaction, name, |key, value| {
        format!("{}\t{}\t{value}", key.0, key.1)
    })
}

fn read_deadline_flag(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<(u64, &str), u8, _>(transaction, name, |key, value| {
        format!("{}\t{}\t{value}", key.0, key.1)
    })
}

fn read_signed_deadline_flag(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<(i64, &str), u8, _>(transaction, name, |key, value| {
        format!("{}\t{}\t{value}", key.0, key.1)
    })
}

fn read_signed_deadline_counter(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<(i64, &str), u64, _>(transaction, name, |key, value| {
        format!("{}\t{}\t{value}", key.0, key.1)
    })
}

fn read_owner_expiry(transaction: &redb::ReadTransaction, name: &str) -> ReadRows {
    read_table::<(&str, u64, i64, &str), u8, _>(transaction, name, |key, value| {
        format!("{}\t{}\t{}\t{}\t{value}", key.0, key.1, key.2, key.3)
    })
}

fn read_table<K, V, F>(
    transaction: &redb::ReadTransaction,
    name: &str,
    mut format_row: F,
) -> ReadRows
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
    F: FnMut(K::SelfType<'_>, V::SelfType<'_>) -> String,
{
    let table = match transaction.open_table(TableDefinition::<K, V>::new(name)) {
        Ok(table) => table,
        Err(redb::TableError::TableTypeMismatch { table, key, value }) => {
            return ReadRows::Mismatch(format!(
                "{table} is Table<{}, {}>",
                key.name(),
                value.name()
            ));
        }
        Err(error) => return ReadRows::Failed(error.to_string()),
    };
    let mut rows = Vec::new();
    let entries = match table.iter() {
        Ok(entries) => entries,
        Err(error) => return ReadRows::Failed(error.to_string()),
    };
    for entry in entries {
        let (key, value) = match entry {
            Ok(pair) => pair,
            Err(error) => return ReadRows::Failed(error.to_string()),
        };
        rows.push(format_row(key.value(), value.value()));
        if rows.len() > RECORD_COUNT_CAP {
            return ReadRows::Failed(format!("{name} exceeded {RECORD_COUNT_CAP} rows"));
        }
    }
    rows.sort();
    ReadRows::Rows(rows)
}

fn collect_wal_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), NodeCoreError> {
    let entries = std::fs::read_dir(dir)
        .map_err(|error| NodeCoreError::Redb(format!("read {}: {error}", dir.display())))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| NodeCoreError::Redb(format!("read {}: {error}", dir.display())))?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_str().unwrap_or("");
        let kind = entry.file_type().map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        if kind.is_dir() && name.starts_with(SHARD_PREFIX) {
            collect_wal_files(&path, files)?;
            continue;
        }
        let wal_extension =
            Path::new(name).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("wal"));
        if kind.is_file() && name.starts_with("router-wal-") && wal_extension {
            if files.len() >= FILE_CAP {
                return Err(NodeCoreError::Redb(
                    "router wal snapshot exceeded 4000 files".to_owned(),
                ));
            }
            files.push(path);
        }
    }
    Ok(())
}

fn segment_digests(path: &Path) -> Result<Vec<String>, NodeCoreError> {
    let mut file = File::open(path)
        .map_err(|error| NodeCoreError::Redb(format!("open {}: {error}", path.display())))?;
    let mut magic = vec![0_u8; WAL_MAGIC.len()];
    file.read_exact(&mut magic)
        .map_err(|error| NodeCoreError::Redb(format!("header {}: {error}", path.display())))?;
    if magic != WAL_MAGIC {
        return Err(NodeCoreError::Redb(format!("wal header mismatch: {}", path.display())));
    }
    let mut digests = Vec::new();
    loop {
        let mut header = [0_u8; 8];
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                return Err(NodeCoreError::Redb(format!("record {}: {error}", path.display())));
            }
        }
        let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let expected = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if len > RECORD_CAP {
            break;
        }
        let Ok(len_usize) = usize::try_from(len) else {
            break;
        };
        let mut payload = vec![0_u8; len_usize];
        match file.read_exact(&mut payload) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                return Err(NodeCoreError::Redb(format!("payload {}: {error}", path.display())));
            }
        }
        if crc32fast::hash(&payload) != expected {
            break;
        }
        let digest = ramflux_crypto::blake3_256("ramflux.node.wal-record.v1", &payload);
        digests.push(hex(&digest));
    }
    Ok(digests)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, NodeCoreError> {
    let meta = std::fs::metadata(path)
        .map_err(|error| NodeCoreError::Redb(format!("stat {}: {error}", path.display())))?;
    if !meta.file_type().is_file() {
        return Err(NodeCoreError::Redb(format!("not a regular store file: {}", path.display())));
    }
    if meta.len() > COPY_CAP {
        return Err(NodeCoreError::Redb(format!("store exceeds 32 MiB: {}", path.display())));
    }
    std::fs::read(path)
        .map_err(|error| NodeCoreError::Redb(format!("read {}: {error}", path.display())))
}

fn hex_digit(nibble: u8) -> char {
    char::from(*b"0123456789abcdef".get(usize::from(nibble)).unwrap_or(&b'0'))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

struct TempCopy {
    path: PathBuf,
}

impl TempCopy {
    fn create() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rf-redb-copy-{}-{n}", std::process::id()));
        Self { path }
    }
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{logical_redb_rows, logical_wal_records};

    #[test]
    fn redb_snapshot_reads_rows_and_rejects_a_non_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let error = logical_redb_rows(dir.path()).expect_err("a directory is not a store file");
        assert!(
            error.to_string().contains("not a regular"),
            "test: a directory must not be read as a redb file: {error}"
        );
        let path = dir.path().join("sample.redb");
        let database = redb::Database::create(&path).expect("create");
        let definition = redb::TableDefinition::<&str, &[u8]>::new("federation_outbound_spool_v1");
        let write = database.begin_write().expect("write");
        {
            let mut table = write.open_table(definition).expect("table");
            table.insert("spool-1", b"payload".as_slice()).expect("insert");
        }
        write.commit().expect("commit");
        drop(database);
        let rows = logical_redb_rows(&path).expect("rows");
        let spool = rows.get("federation_outbound_spool_v1").expect("spool table");
        assert_eq!(spool.len(), 1, "test: the spool table keeps its one row");
        assert!(
            spool[0].starts_with("spool-1\t"),
            "test: the spool key is the logical row identity: {}",
            spool[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn redb_snapshot_rejects_a_unix_socket() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("alice.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("socket");
        let error = logical_redb_rows(&path).expect_err("a socket is not a store file");
        assert!(
            error.to_string().contains("not a regular"),
            "test: a unix socket must not be read as a redb file: {error}"
        );
    }

    #[test]
    fn wal_snapshot_hashes_a_valid_record_and_requires_the_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = logical_wal_records(&dir.path().join("missing")).expect_err("missing wal");
        assert!(
            missing.to_string().contains("missing"),
            "test: a missing router wal directory is an error: {missing}"
        );
        let payload = b"typing-must-not-persist";
        let mut bytes = b"ramflux-router-wal-v1\n".to_vec();
        let len = u32::try_from(payload.len()).expect("len");
        bytes.extend(len.to_le_bytes());
        bytes.extend(crc32fast::hash(payload).to_le_bytes());
        bytes.extend(payload);
        bytes.extend([0_u8, 1]);
        let segment = dir.path().join("router-wal-1.wal");
        std::fs::write(&segment, &bytes).expect("segment");
        let wal = logical_wal_records(dir.path()).expect("wal");
        assert_eq!(wal.files, vec![segment], "test: the regular segment is selected");
        let digest = super::hex(&ramflux_crypto::blake3_256("ramflux.node.wal-record.v1", payload));
        assert_eq!(wal.records, vec![digest], "test: the incomplete tail is not a record");
    }

    fn assert_one_row(
        rows: &std::collections::BTreeMap<String, Vec<String>>,
        table: &str,
        expected: &str,
        message: &str,
    ) {
        assert_eq!(
            rows.get(table).map(Vec::as_slice),
            Some([expected.to_owned()].as_slice()),
            "test: {message}"
        );
    }

    fn seed_typed_tables(write: &redb::WriteTransaction) {
        write
            .open_table(redb::TableDefinition::<&str, &str>::new("custody_node_heads_v1"))
            .expect("heads")
            .insert("root-a", "head-a")
            .expect("head");
        write
            .open_table(redb::TableDefinition::<&str, u64>::new(
                "federation_outbound_dead_letter_counts_v1",
            ))
            .expect("counts")
            .insert("peer", 7_u64)
            .expect("count");
        write
            .open_table(redb::TableDefinition::<&str, u8>::new("router_mailbox_key_format_v1"))
            .expect("flags")
            .insert("version", 1_u8)
            .expect("flag");
        write
            .open_table(redb::TableDefinition::<u64, &[u8]>::new("router_identity_admission_v1"))
            .expect("journal")
            .insert(3_u64, b"row".as_slice())
            .expect("journal row");
        write
            .open_table(redb::TableDefinition::<(&str, &str), u8>::new(
                "notification_origin_receipt_scopes_v1",
            ))
            .expect("scopes")
            .insert(("res", "scope"), 1_u8)
            .expect("scope");
        write
            .open_table(redb::TableDefinition::<(u64, &str), u8>::new(
                "notification_origin_shared_due_v1",
            ))
            .expect("due")
            .insert((9_u64, "scope"), 1_u8)
            .expect("due row");
        write
            .open_table(redb::TableDefinition::<(i64, &str), u8>::new("gateway_replay_expiry_v3"))
            .expect("expiry")
            .insert((4_i64, "id"), 1_u8)
            .expect("expiry row");
        write
            .open_table(redb::TableDefinition::<(i64, &str), u64>::new(
                "gateway_replay_root_expiry_v3",
            ))
            .expect("root expiry")
            .insert((4_i64, "root"), 11_u64)
            .expect("root expiry row");
        write
            .open_table(redb::TableDefinition::<(&str, u64, i64, &str), u8>::new(
                "gateway_replay_owner_expiry_v3",
            ))
            .expect("owner")
            .insert(("own", 2_u64, 4_i64, "id"), 1_u8)
            .expect("owner row");
        write
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("username_checkpoint_image"))
            .expect("image")
            .insert(b"img".as_slice(), b"raw".as_slice())
            .expect("image row");
    }

    #[test]
    fn redb_snapshot_reads_text_counters_and_boot_key_types() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("types.redb");
        let database = redb::Database::create(&path).expect("create");
        let write = database.begin_write().expect("write");
        seed_typed_tables(&write);
        write.commit().expect("commit");
        drop(database);
        let rows = logical_redb_rows(&path).expect("rows");
        assert_one_row(&rows, "custody_node_heads_v1", "root-a\thead-a", "text value");
        assert_one_row(
            &rows,
            "federation_outbound_dead_letter_counts_v1",
            "peer\t7",
            "counter value",
        );
        assert_one_row(&rows, "router_mailbox_key_format_v1", "version\t1", "format flag");
        assert_one_row(
            &rows,
            "router_identity_admission_v1",
            &format!("3\t{}", super::hex(b"row")),
            "numeric key",
        );
        assert_one_row(&rows, "notification_origin_receipt_scopes_v1", "res\tscope\t1", "pair key");
        assert_one_row(&rows, "notification_origin_shared_due_v1", "9\tscope\t1", "deadline key");
        assert_one_row(&rows, "gateway_replay_expiry_v3", "4\tid\t1", "signed deadline flag");
        assert_one_row(
            &rows,
            "gateway_replay_root_expiry_v3",
            "4\troot\t11",
            "signed deadline counter",
        );
        assert_one_row(&rows, "gateway_replay_owner_expiry_v3", "own\t2\t4\tid\t1", "owner expiry");
        assert_one_row(
            &rows,
            "username_checkpoint_image",
            &format!("{}\t{}", super::hex(b"img"), super::hex(b"raw")),
            "byte key and value",
        );
    }

    #[test]
    fn redb_snapshot_errors_when_a_table_cannot_be_decoded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("unknown.redb");
        let database = redb::Database::create(&path).expect("create");
        let write = database.begin_write().expect("write");
        {
            write
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                    "federation_outbound_spool_v1",
                ))
                .expect("spool")
                .insert("spool-1", b"payload".as_slice())
                .expect("spool row");
            write
                .open_table(redb::TableDefinition::<&str, (u64, u64)>::new("notify_route_fence_v2"))
                .expect("fence")
                .insert("root", (1_u64, 2_u64))
                .expect("fence row");
        }
        write.commit().expect("commit");
        drop(database);
        let error = logical_redb_rows(&path).expect_err("an unknown value type is not a snapshot");
        let text = error.to_string();
        assert!(text.contains("undecodable"), "test: an unknown table type is an error: {text}");
        assert!(
            !text.contains("unreadable:"),
            "test: a decode failure is not comparable data: {text}"
        );
    }

    #[test]
    fn redb_snapshot_reads_every_table_a_service_creates_on_open() {
        let dir = tempfile::tempdir().expect("temp dir");
        let router = dir.path().join("ramflux-router.redb");
        let federation = dir.path().join("ramflux-federation.redb");
        let gateway = dir.path().join("ramflux-gateway.redb");
        let retention = dir.path().join("ramflux-retention.redb");
        drop(crate::RouterRedbStore::open(&router).expect("router"));
        drop(crate::FederationRedbStore::open(&federation).expect("federation"));
        drop(crate::gateway_state::GatewayRedbStore::open(&gateway).expect("gateway"));
        drop(crate::retention::RetentionRedbStore::open(&retention).expect("retention"));
        for path in [&router, &federation, &gateway, &retention] {
            let tables = logical_redb_rows(path).expect("service tables");
            assert!(
                tables.keys().any(|name| name != "__multimap_tables__"),
                "test: {} lists its tables",
                path.display()
            );
            for (name, rows) in &tables {
                assert!(
                    rows.iter().all(|row| !row.starts_with("unreadable:")),
                    "test: {name} in {} is decoded: {rows:?}",
                    path.display()
                );
            }
        }
        let router_rows = logical_redb_rows(&router).expect("router rows");
        assert_eq!(
            router_rows.get("router_mailbox_key_format_v1").map(Vec::as_slice),
            Some(["version\t1".to_owned()].as_slice()),
            "test: the router format flag is a real row"
        );
        let gateway_rows = logical_redb_rows(&gateway).expect("gateway rows");
        assert!(
            gateway_rows.contains_key("gateway_replay_expiry_v3"),
            "test: the gateway expiry table is enumerated"
        );
        assert!(
            gateway_rows.contains_key("gateway_replay_owner_expiry_v3"),
            "test: the gateway owner-expiry table is enumerated"
        );
    }
}
