// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed pairing table DDL. Installed on every account open; no schema-version collision.

use rusqlite::{Connection, OptionalExtension};

pub(crate) const TABLES: [&str; 10] = [
    "pairing_floor",
    "pairing_live",
    "pairing_head",
    "pairing_terminal",
    "pairing_adoption",
    "pairing_full_tail",
    "pairing_source_cleanup",
    "pairing_full_tail_apply",
    "pairing_full_tail_dependency",
    "pairing_full_completion",
];

pub(crate) const LIVE_CAP: i64 = 3;
pub(crate) const TERMINAL_CAP: i64 = 128;
pub(crate) const LIVE_ROW_MAX: usize = 65_536;
pub(crate) const DESCRIPTOR_MAX: usize = 16_000;
pub(crate) const TERMINAL_ROW_MAX: usize = 1_024;
pub(crate) const FLOOR_ROW_MAX: usize = 1_024;
pub(crate) const ADOPTION_ROW_MAX: usize = 2_048;
pub(crate) const HEAD_ROW_MAX: usize = 5 * 1024 * 1024;
pub(crate) const TERMINAL_TTL_SECONDS: i64 = 24 * 60 * 60;
pub(crate) const ID_MAX: usize = 128;

const PHASES: &str = "'invited','commitments','revealed','sas_pending','mutually_confirmed','proposal_pending','prepared','submitted','acknowledged','locally_installed','completed','cancelled','expired','rejected'";

pub(crate) const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS pairing_floor (
 account_id TEXT NOT NULL CHECK(typeof(account_id)='text' AND length(account_id) BETWEEN 1 AND 128),
 account_anchor TEXT NOT NULL CHECK(typeof(account_anchor)='text' AND length(account_anchor)=43),
 issued_seq INTEGER NOT NULL CHECK(typeof(issued_seq)='integer' AND issued_seq>=0 AND issued_seq<=9007199254740991),
 next_generation INTEGER NOT NULL CHECK(typeof(next_generation)='integer' AND next_generation>=0 AND next_generation<=9007199254740991),
 PRIMARY KEY(account_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS pairing_live (
 account_id TEXT NOT NULL CHECK(typeof(account_id)='text' AND length(account_id) BETWEEN 1 AND 128),
 operation_id TEXT NOT NULL CHECK(typeof(operation_id)='text' AND length(operation_id)=43),
 invitation_id TEXT NOT NULL CHECK(typeof(invitation_id)='text' AND length(invitation_id)=43),
 issuer_seq INTEGER NOT NULL CHECK(typeof(issuer_seq)='integer' AND issuer_seq>=1 AND issuer_seq<=9007199254740991),
 local_seq INTEGER NOT NULL CHECK(typeof(local_seq)='integer' AND local_seq>=1 AND local_seq<=9007199254740991),
 generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation>=1 AND generation<=9007199254740991),
 role TEXT NOT NULL CHECK(role IN ('initiator','responder')),
 descriptor BLOB NOT NULL CHECK(typeof(descriptor)='blob' AND length(descriptor)>0 AND length(descriptor)<=16000),
 phase TEXT NOT NULL CHECK(phase IN ('invited','commitments','revealed','sas_pending','mutually_confirmed','proposal_pending','prepared','submitted','acknowledged','locally_installed','completed','cancelled','expired','rejected')),
 context BLOB CHECK(context IS NULL OR (typeof(context)='blob' AND length(context)>0 AND length(context)<=57344)),
 transcript_hash TEXT CHECK(transcript_hash IS NULL OR (typeof(transcript_hash)='text' AND length(transcript_hash)=43)),
 proposal_hash TEXT CHECK(proposal_hash IS NULL OR (typeof(proposal_hash)='text' AND length(proposal_hash)=43)),
 transfer_ciphertext_hash TEXT CHECK(transfer_ciphertext_hash IS NULL OR (typeof(transfer_ciphertext_hash)='text' AND length(transfer_ciphertext_hash)=43)),
 candidate_id TEXT CHECK(candidate_id IS NULL OR (typeof(candidate_id)='text' AND length(candidate_id)=43)),
 branch_reservation TEXT CHECK(branch_reservation IS NULL OR (typeof(branch_reservation)='text' AND length(branch_reservation) BETWEEN 1 AND 128)),
 branch_vault_ref TEXT CHECK(branch_vault_ref IS NULL OR (typeof(branch_vault_ref)='text' AND length(branch_vault_ref) BETWEEN 1 AND 128)),
 primary_vault_ref TEXT CHECK(primary_vault_ref IS NULL OR (typeof(primary_vault_ref)='text' AND length(primary_vault_ref) BETWEEN 1 AND 128)),
 base_record_hash TEXT NOT NULL CHECK(typeof(base_record_hash)='text' AND length(base_record_hash)=43),
 base_epoch INTEGER NOT NULL CHECK(typeof(base_epoch)='integer' AND base_epoch>=0 AND base_epoch<=9007199254740991),
 expires_at INTEGER NOT NULL CHECK(typeof(expires_at)='integer' AND expires_at>=0 AND expires_at<=9007199254740991),
 result BLOB CHECK(result IS NULL OR (typeof(result)='blob' AND length(result)>0 AND length(result)<=1024)),
 PRIMARY KEY(account_id, operation_id),
 UNIQUE(account_id, local_seq),
 UNIQUE(account_id, invitation_id),
 CHECK((context IS NULL)=(transcript_hash IS NULL)),
 CHECK(phase NOT IN ('invited','commitments') OR context IS NULL),
 CHECK(phase IN ('invited','commitments') OR context IS NOT NULL)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS pairing_live_phase ON pairing_live(account_id, phase, expires_at);
CREATE TABLE IF NOT EXISTS pairing_head (
 account_id TEXT NOT NULL CHECK(typeof(account_id)='text' AND length(account_id) BETWEEN 1 AND 128),
 operation_id TEXT NOT NULL CHECK(typeof(operation_id)='text' AND length(operation_id)=43),
 invitation_id TEXT CHECK(invitation_id IS NULL OR (typeof(invitation_id)='text' AND length(invitation_id)=43)),
 generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation>=1 AND generation<=9007199254740991),
 kind TEXT NOT NULL CHECK(kind IN ('enroll','transfer','revoke','head_update')),
 base_record_hash TEXT NOT NULL CHECK(typeof(base_record_hash)='text' AND length(base_record_hash)=43),
 base_epoch INTEGER NOT NULL CHECK(typeof(base_epoch)='integer' AND base_epoch>=0 AND base_epoch<=9007199254740991),
 publisher_ref BLOB NOT NULL CHECK(typeof(publisher_ref)='blob' AND length(publisher_ref)>0 AND length(publisher_ref)<=4096),
 candidate BLOB NOT NULL CHECK(typeof(candidate)='blob' AND length(candidate)>0 AND length(candidate)<=5242880),
 candidate_hash TEXT NOT NULL CHECK(typeof(candidate_hash)='text' AND length(candidate_hash)=43),
 state TEXT NOT NULL CHECK(state IN ('prepared','submitted','acknowledged')),
 ack BLOB CHECK(ack IS NULL OR (typeof(ack)='blob' AND length(ack)>0 AND length(ack)<=1024)),
 recipient_ref BLOB CHECK(recipient_ref IS NULL OR (typeof(recipient_ref)='blob' AND length(recipient_ref)>0 AND length(recipient_ref)<=4096)),
 revoked_ref BLOB CHECK(revoked_ref IS NULL OR (typeof(revoked_ref)='blob' AND length(revoked_ref)>0 AND length(revoked_ref)<=4096)),
 created_at INTEGER NOT NULL CHECK(typeof(created_at)='integer' AND created_at>=0 AND created_at<=9007199254740991),
 PRIMARY KEY(account_id),
 UNIQUE(account_id, operation_id),
 CHECK((kind IN ('enroll','transfer') AND recipient_ref IS NOT NULL AND revoked_ref IS NULL AND invitation_id IS NOT NULL)
    OR (kind='revoke' AND recipient_ref IS NULL AND revoked_ref IS NOT NULL AND invitation_id IS NULL)
    OR (kind='head_update' AND recipient_ref IS NULL AND revoked_ref IS NULL AND invitation_id IS NULL)),
 CHECK((state='acknowledged' AND ack IS NOT NULL) OR (state<>'acknowledged' AND ack IS NULL))
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS pairing_terminal (
 account_id TEXT NOT NULL CHECK(typeof(account_id)='text' AND length(account_id) BETWEEN 1 AND 128),
 operation_id TEXT NOT NULL CHECK(typeof(operation_id)='text' AND length(operation_id)=43),
 invitation_id TEXT NOT NULL CHECK(typeof(invitation_id)='text' AND length(invitation_id)=43),
 issuer_seq INTEGER NOT NULL CHECK(typeof(issuer_seq)='integer' AND issuer_seq>=1 AND issuer_seq<=9007199254740991),
 local_seq INTEGER NOT NULL CHECK(typeof(local_seq)='integer' AND local_seq>=1 AND local_seq<=9007199254740991),
 generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation>=1 AND generation<=9007199254740991),
 outcome TEXT NOT NULL CHECK(outcome IN ('completed','cancelled','expired','rejected')),
 record_hash TEXT CHECK(record_hash IS NULL OR (typeof(record_hash)='text' AND length(record_hash)=43)),
 finished_at INTEGER NOT NULL CHECK(typeof(finished_at)='integer' AND finished_at>=0 AND finished_at<=9007199254740991),
 cleanup TEXT NOT NULL CHECK(cleanup IN ('none','pending','done')),
 PRIMARY KEY(account_id, operation_id),
 UNIQUE(account_id, invitation_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS pairing_terminal_finished ON pairing_terminal(account_id, finished_at, operation_id);
CREATE TABLE IF NOT EXISTS pairing_adoption (
 account_id TEXT NOT NULL CHECK(typeof(account_id)='text' AND length(account_id) BETWEEN 1 AND 128),
 operation_id TEXT NOT NULL CHECK(typeof(operation_id)='text' AND length(operation_id)=43),
 record_hash TEXT NOT NULL CHECK(typeof(record_hash)='text' AND length(record_hash)=43),
 local_ref BLOB NOT NULL CHECK(typeof(local_ref)='blob' AND length(local_ref)>0 AND length(local_ref)<=4096),
 local_role TEXT NOT NULL CHECK(local_role IN ('primary','secondary')),
 branch_vault_ref TEXT NOT NULL CHECK(typeof(branch_vault_ref)='text' AND length(branch_vault_ref) BETWEEN 1 AND 128),
 data_vault_ref TEXT NOT NULL CHECK(typeof(data_vault_ref)='text' AND length(data_vault_ref) BETWEEN 1 AND 128),
 primary_vault_ref TEXT CHECK(primary_vault_ref IS NULL OR (typeof(primary_vault_ref)='text' AND length(primary_vault_ref) BETWEEN 1 AND 128)),
 full_generation_nonce TEXT CHECK(full_generation_nonce IS NULL OR (typeof(full_generation_nonce)='text' AND length(full_generation_nonce)=43)),
 full_initial_union_root TEXT CHECK(full_initial_union_root IS NULL OR (typeof(full_initial_union_root)='text' AND length(full_initial_union_root)=43)),
 CHECK((full_generation_nonce IS NULL)=(full_initial_union_root IS NULL)),
 CHECK((local_role='primary' AND primary_vault_ref IS NOT NULL) OR (local_role='secondary' AND primary_vault_ref IS NULL)),
 PRIMARY KEY(account_id)
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS pairing_live_cap BEFORE INSERT ON pairing_live BEGIN
 SELECT CASE WHEN (SELECT count(*) FROM pairing_live WHERE account_id=NEW.account_id AND operation_id<>NEW.operation_id)>=3
  THEN RAISE(ABORT,'pairing.live.cap') END;
END;
CREATE TRIGGER IF NOT EXISTS pairing_terminal_cap BEFORE INSERT ON pairing_terminal BEGIN
 SELECT CASE WHEN (SELECT count(*) FROM pairing_terminal WHERE account_id=NEW.account_id AND operation_id<>NEW.operation_id)>=128
  THEN RAISE(ABORT,'pairing.terminal.cap') END;
END;
CREATE TRIGGER IF NOT EXISTS pairing_floor_monotonic BEFORE UPDATE ON pairing_floor BEGIN
 SELECT CASE WHEN NEW.issued_seq<OLD.issued_seq OR NEW.next_generation<OLD.next_generation
  THEN RAISE(ABORT,'pairing.floor.monotonic') END;
END;
";

/// Creates pairing tables, indexes and caps. Idempotent.
///
/// # Errors
/// Returns SQLite errors.
pub(crate) fn install(db: &Connection) -> rusqlite::Result<()> {
    let existing: Option<String> = db
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='pairing_head'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if existing.is_some_and(|sql| !sql.contains("'head_update'")) {
        let transaction = db.unchecked_transaction()?;
        db.execute_batch("ALTER TABLE pairing_head RENAME TO pairing_head_before_head_update;")?;
        db.execute_batch(SCHEMA)?;
        db.execute_batch("INSERT INTO pairing_head SELECT * FROM pairing_head_before_head_update; DROP TABLE pairing_head_before_head_update;")?;
        transaction.commit()?;
    } else {
        db.execute_batch(SCHEMA)?;
    }
    install_full_adoption_columns(db)?;
    db.execute_batch(super::tail::SCHEMA)?;
    let _ = PHASES;
    Ok(())
}

fn install_full_adoption_columns(db: &Connection) -> rusqlite::Result<()> {
    let columns: (bool,bool) = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('pairing_adoption') WHERE name='full_generation_nonce'),EXISTS(SELECT 1 FROM pragma_table_info('pairing_adoption') WHERE name='full_initial_union_root')",
        [], |row|Ok((row.get(0)?,row.get(1)?)),
    )?;
    if columns == (true, true) {
        return Ok(());
    }
    let tx = db.unchecked_transaction()?;
    if !columns.0 {
        tx.execute_batch("ALTER TABLE pairing_adoption ADD COLUMN full_generation_nonce TEXT CHECK(full_generation_nonce IS NULL OR (typeof(full_generation_nonce)='text' AND length(full_generation_nonce)=43));")?;
    }
    if !columns.1 {
        tx.execute_batch("ALTER TABLE pairing_adoption ADD COLUMN full_initial_union_root TEXT CHECK((full_initial_union_root IS NULL OR (typeof(full_initial_union_root)='text' AND length(full_initial_union_root)=43)) AND ((full_generation_nonce IS NULL)=(full_initial_union_root IS NULL)));")?;
    }
    tx.commit()
}
