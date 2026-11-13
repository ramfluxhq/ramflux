// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Derived tables live in the keyed account database; nothing installs them at ordinary startup.
use super::{SearchError, SearchResult};
use rusqlite::Connection;
use std::fmt::Write as _;

pub(super) fn exists(db: &Connection) -> rusqlite::Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='local_search_state')",[],|row|row.get(0))
}

pub(super) fn prepare(db: &Connection) -> SearchResult<()> {
    prerequisites(db)?;
    Ok(())
}
pub(super) fn initialize(db: &Connection, epoch: i64) -> SearchResult<()> {
    if db.is_autocommit() {
        return Err(SearchError::IndexUnavailable);
    }
    if exists(db)? {
        let version: (i64, i64) = db.query_row(
            "SELECT format,normalizer FROM local_search_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if version != (1, 1) {
            super::lifecycle::strip(db)?;
            db.execute_batch("DROP TABLE IF EXISTS local_search_compaction_pending;")?;
        }
    }
    db.execute_batch(SCHEMA)?;
    db.execute("INSERT INTO local_search_state(singleton,format,normalizer,epoch) VALUES(1,1,1,?1) ON CONFLICT(singleton) DO NOTHING",[epoch])?;
    db.execute(
        "INSERT INTO local_search_fts(local_search_fts,rank) VALUES('secure-delete',1)",
        [],
    )?;
    let secure: i64 =
        db.query_row("SELECT v FROM local_search_fts_config WHERE k='secure-delete'", [], |row| {
            row.get(0)
        })?;
    if secure != 1 {
        return Err(SearchError::IndexUnavailable);
    }
    install_sources(db)?;
    db.execute(
        "INSERT INTO local_search_fts(local_search_fts,rank) VALUES('integrity-check',1)",
        [],
    )?;
    Ok(())
}

fn prerequisites(db: &Connection) -> SearchResult<()> {
    if !db.is_autocommit() {
        return Err(SearchError::IndexUnavailable);
    }
    let cipher: String = db
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(|_| SearchError::IndexUnavailable)?;
    if cipher.is_empty() {
        return Err(SearchError::IndexUnavailable);
    }
    let version: String = db.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let mut parts = version.split('.');
    let major =
        parts.next().and_then(|v| v.parse::<u32>().ok()).ok_or(SearchError::IndexUnavailable)?;
    let minor =
        parts.next().and_then(|v| v.parse::<u32>().ok()).ok_or(SearchError::IndexUnavailable)?;
    let memory:bool=db.query_row("SELECT sqlite_compileoption_used('TEMP_STORE=2') OR sqlite_compileoption_used('TEMP_STORE=3')",[],|row|row.get(0))?;
    if major < 3 || major == 3 && minor < 42 || !memory {
        return Err(SearchError::IndexUnavailable);
    }
    db.execute_batch("PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;")?;
    let secure: i64 = db.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    let temporary: i64 = db.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    verify_dbstat(db)?;
    let pages:u64=db.query_row("SELECT COALESCE(sum(pgsize),0) FROM main.dbstat WHERE name IN ('sqlite_schema','sqlite_master')",[],|row|row.get(0)).map_err(|_|SearchError::IndexUnavailable)?;
    if secure != 1 || temporary != 2 || pages == 0 {
        return Err(SearchError::IndexUnavailable);
    }
    Ok(())
}

pub(super) fn verify_dbstat(db: &Connection) -> SearchResult<()> {
    let shadow:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name='dbstat') OR EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE name='dbstat')",[],|r|r.get(0))?;
    let compiled: bool =
        db.query_row("SELECT sqlite_compileoption_used('ENABLE_DBSTAT_VTAB')", [], |r| r.get(0))?;
    if shadow || !compiled {
        return Err(SearchError::IndexUnavailable);
    }
    Ok(())
}

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS local_search_state(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), format INTEGER NOT NULL,normalizer INTEGER NOT NULL,
 epoch INTEGER NOT NULL,revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(revision)='integer' AND revision>0),
 canonical_revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(canonical_revision)='integer' AND canonical_revision>0),
 coverage TEXT NOT NULL DEFAULT 'building', document_count INTEGER NOT NULL DEFAULT 0 CHECK(document_count BETWEEN 0 AND 1000000),
 rebuild_required INTEGER NOT NULL DEFAULT 1, checkpoint_kind INTEGER NOT NULL DEFAULT 0,checkpoint TEXT NOT NULL DEFAULT '',
 truncated INTEGER NOT NULL DEFAULT 0,quota_limited INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS local_search_doc(
 doc_id INTEGER PRIMARY KEY AUTOINCREMENT,kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 2),
 source_ref TEXT NOT NULL,source_key TEXT NOT NULL,conversation_id TEXT NOT NULL,message_id TEXT,
 source_revision TEXT NOT NULL,timestamp INTEGER NOT NULL,source_hash BLOB NOT NULL CHECK(length(source_hash)=32),
 UNIQUE(kind,source_ref));
CREATE INDEX IF NOT EXISTS local_search_doc_conversation ON local_search_doc(conversation_id,doc_id);
CREATE INDEX IF NOT EXISTS local_search_doc_message ON local_search_doc(message_id,doc_id);
CREATE INDEX IF NOT EXISTS local_search_doc_source ON local_search_doc(source_key,kind,doc_id);
CREATE TABLE IF NOT EXISTS local_search_terms(doc_id INTEGER PRIMARY KEY,tokens TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS local_search_fts USING fts5(tokens,content='local_search_terms',content_rowid='doc_id',tokenize='ascii',detail=none,columnsize=0);
CREATE TABLE IF NOT EXISTS local_search_dependency(source_table TEXT NOT NULL,source_key TEXT NOT NULL,doc_id INTEGER NOT NULL,PRIMARY KEY(source_table,source_key,doc_id));
CREATE INDEX IF NOT EXISTS local_search_dependency_doc ON local_search_dependency(doc_id);
CREATE TABLE IF NOT EXISTS local_search_dirty(kind INTEGER NOT NULL CHECK(kind IN(0,1)),source_key TEXT NOT NULL,PRIMARY KEY(kind,source_key));
CREATE TRIGGER IF NOT EXISTS local_search_terms_insert AFTER INSERT ON local_search_terms BEGIN
 INSERT INTO local_search_fts(rowid,tokens) VALUES(NEW.doc_id,NEW.tokens); END;
CREATE TRIGGER IF NOT EXISTS local_search_terms_delete BEFORE DELETE ON local_search_terms BEGIN
 INSERT INTO local_search_fts(local_search_fts,rowid,tokens) VALUES('delete',OLD.doc_id,OLD.tokens); END;
CREATE TRIGGER IF NOT EXISTS local_search_terms_no_update BEFORE UPDATE ON local_search_terms BEGIN
 SELECT RAISE(ABORT,'search terms require replacement'); END;
CREATE TRIGGER IF NOT EXISTS local_search_doc_insert AFTER INSERT ON local_search_doc BEGIN
 UPDATE local_search_state SET document_count=document_count+1,revision=revision+1;
 INSERT INTO message_footprint SELECT NEW.message_id,'local_search_doc',CAST(NEW.doc_id AS TEXT) WHERE NEW.message_id IS NOT NULL ON CONFLICT DO NOTHING; END;
CREATE TRIGGER IF NOT EXISTS local_search_doc_delete BEFORE DELETE ON local_search_doc BEGIN
 INSERT INTO runtime_privacy_maintenance VALUES(1,1) ON CONFLICT(singleton) DO UPDATE SET erasure_pending=1;
 DELETE FROM local_search_terms WHERE doc_id=OLD.doc_id;
 DELETE FROM local_search_dependency WHERE doc_id=OLD.doc_id;
 DELETE FROM message_footprint WHERE kind='local_search_doc' AND locator=CAST(OLD.doc_id AS TEXT);
 UPDATE local_search_state SET document_count=document_count-1,revision=revision+1; END;
";

fn install_sources(db: &Connection) -> rusqlite::Result<()> {
    for (table, key, parent) in [
        ("runtime_message_content", "message_id", Some(1)),
        ("direct_message_projection", "message_id", Some(1)),
        ("runtime_actor_state", "state_kind", None),
        ("conversation_list_state", "conversation_id", Some(0)),
        ("conversation_projection", "conversation_id", Some(0)),
        ("conversation_disappearing_policy", "conversation_id", Some(0)),
        ("object_retention_reference", "reference_hash", None),
        ("group_projection", "group_id", None),
        ("shared_group_member_projection", "group_id", None),
        ("object_index", "object_id", None),
        ("object_message_reference", "message_id", Some(1)),
        ("object_retention_payload", "commitment", None),
        ("object_erasure_fence", "commitment", None),
    ] {
        if !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [table],
            |row| row.get::<_, bool>(0),
        )? {
            continue;
        }
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            let current = if operation == "DELETE" { "OLD" } else { "NEW" };
            let keys = if operation == "UPDATE" {
                format!("OLD.{key},NEW.{key}")
            } else {
                format!("{current}.{key}")
            };
            let selected = format!(
                "SELECT doc_id FROM local_search_dependency WHERE source_table='{table}' AND source_key IN({keys})"
            );
            let mut body = format!(
                "UPDATE local_search_state SET revision=revision+1,canonical_revision=canonical_revision+1,coverage=CASE WHEN coverage='building' THEN coverage ELSE 'lagging' END; INSERT INTO local_search_dirty SELECT DISTINCT CASE WHEN kind=0 THEN 0 ELSE 1 END,source_key FROM local_search_doc WHERE doc_id IN({selected}) LIMIT 4097 ON CONFLICT DO NOTHING; DELETE FROM local_search_doc WHERE doc_id IN({selected});"
            );
            if let Some(kind) = parent {
                let column = if kind == 0 { "conversation_id" } else { "message_id" };
                write!(body, "DELETE FROM local_search_doc WHERE {column} IN({keys});")
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                write!(body, "INSERT INTO local_search_dirty SELECT {kind},{current}.{key} WHERE length(CAST({current}.{key} AS BLOB))<=256 AND (SELECT count(*) FROM local_search_dirty)<4096 ON CONFLICT DO NOTHING;").map_err(|_|rusqlite::Error::InvalidQuery)?;
                write!(body, "UPDATE local_search_state SET rebuild_required=1,checkpoint_kind=0,checkpoint='',coverage='building',truncated=1 WHERE length(CAST({current}.{key} AS BLOB))>256;").map_err(|_|rusqlite::Error::InvalidQuery)?;
                if operation == "UPDATE" {
                    write!(body, "INSERT INTO local_search_dirty SELECT {kind},OLD.{key} WHERE length(CAST(OLD.{key} AS BLOB))<=256 AND (SELECT count(*) FROM local_search_dirty)<4096 ON CONFLICT DO NOTHING;").map_err(|_|rusqlite::Error::InvalidQuery)?;
                }
            }
            if matches!(table, "group_projection" | "shared_group_member_projection") {
                body.push_str("UPDATE local_search_state SET rebuild_required=1,checkpoint_kind=0,checkpoint='',coverage='building';");
            }
            if table == "runtime_actor_state" {
                write!(body, "INSERT INTO local_search_dirty SELECT 0,substr({current}.state_kind,24) WHERE {current}.state_kind GLOB 'directory/conversation/*' AND length(CAST(substr({current}.state_kind,24) AS BLOB))<=256 AND (SELECT count(*) FROM local_search_dirty)<4096 ON CONFLICT DO NOTHING;").map_err(|_|rusqlite::Error::InvalidQuery)?;
                body.push_str(
                    "UPDATE local_search_state SET rebuild_required=1,checkpoint_kind=0,checkpoint='',coverage='building';",
                );
            }
            body.push_str("UPDATE local_search_state SET rebuild_required=1,checkpoint_kind=0,checkpoint='',coverage='building' WHERE (SELECT count(*) FROM local_search_dirty)>=4096; DELETE FROM local_search_dirty WHERE (SELECT count(*) FROM local_search_dirty)>=4096;");
            let guard = if table == "runtime_actor_state" {
                format!(
                    " WHEN {current}.state_kind GLOB 'directory/*' OR {current}.state_kind GLOB 'routed/generated-identity/*' OR {current}.state_kind GLOB 'routed/group-projection/*' OR {current}.state_kind GLOB 'routed/edit-revision/*' OR {current}.state_kind GLOB 'shared-group/*' OR {current}.state_kind GLOB 'group/*' OR {current}.state_kind GLOB 'attachment/*' OR {current}.state_kind GLOB 'identity/*' OR {current}.state_kind GLOB 'profile/*' OR EXISTS(SELECT 1 FROM local_search_dependency WHERE source_table='runtime_actor_state' AND source_key IN({keys}))"
                )
            } else {
                String::new()
            };
            db.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS local_search_source_{table}_{operation} AFTER {operation} ON {table}{guard} BEGIN {body} END;"))?;
        }
    }
    Ok(())
}
