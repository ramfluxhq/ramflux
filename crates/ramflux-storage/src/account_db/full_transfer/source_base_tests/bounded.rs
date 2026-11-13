// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Large fixed-family input reaches a bounded streaming sink without retaining its output.
use super::*;
#[derive(Default)]
struct Probe {
    bytes: u64,
    calls: u64,
    largest: usize,
}
impl std::io::Write for Probe {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > CHUNK_BYTES as usize {
            return Err(std::io::Error::other("test: source passed an unbounded write slice"));
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("test: byte count overflow"))?;
        self.calls += 1;
        self.largest = self.largest.max(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn primary_transfer_full_large_stream_is_bounded() -> TestResult {
    const RECORDS: u64 = 16_384;
    let (root, db) = crate::account_db::full_transfer::test_support::owned_source_test_db(
        "full-bounded-record-stream",
    )?;
    db.connection.call(|raw| {
        let tx = raw.transaction()?;
        {
            let mut insert =
                tx.prepare("INSERT INTO object_identity_replacement(commitment) VALUES(?1)")?;
            for index in 0..RECORDS {
                let mut key = [0_u8; 32];
                key.get_mut(..8)
                    .ok_or(rusqlite::Error::InvalidQuery)?
                    .copy_from_slice(&index.to_be_bytes());
                insert.execute([ramflux_protocol::encode_base64url(key)])?;
            }
        }
        tx.commit()
    })?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let path = root.path().join("bounded-source-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let id = &manifest.manifest.snapshot_id;
    stage.adopt_source_cut(0, id, &path, snapshot)?;
    let (probe, encoded) = stage.encode_fixed_base_source(id, Probe::default())?;
    let family = encoded
        .schema
        .families
        .iter()
        .find(|family| family.id == "sql/object_identity_replacement")
        .ok_or("test: encoded fixed family absent")?;
    assert_eq!(
        family.portable_records.0, RECORDS,
        "test: bounded encoder silently truncated the source"
    );
    assert_eq!(
        probe.bytes, encoded.total_bytes,
        "test: streamed bytes disagreed with signed totals"
    );
    assert!(encoded.chunk_count > 16, "test: large input did not cross enough encrypted slots");
    assert!(probe.calls > RECORDS, "test: source buffered the whole record family before output");
    assert!(probe.largest <= CHUNK_BYTES as usize, "test: output write exceeded one bounded slot");
    Ok(())
}
