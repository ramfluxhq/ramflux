// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Staging and reconciliation of erased-input authority around a merge, plus sweep S3.
//!
//! Dormant helpers: nothing calls them until the merge wiring and the producers land. A tuple
//! source for a live message is (A) an `erased-input:` binding or (B) a footprinted copy row of a
//! Source kind that holds a complete envelope at a fixed path whose payload is bound to that
//! message. Staging is read-only on the incoming snapshot.
#![allow(dead_code)]
use crate::StorageError;
use rusqlite::{Connection, params};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use super::erased_input::ErasedTuple;

const LABEL: &[u8] = b"ramflux/deleted-envelope/v1";
const MAX_CLOCK_SKEW: i64 = 120;
const MAX_ENVELOPE_TTL: i64 = 604_800;
const SLACK: i64 = 300;
/// Expired rows and bindings removed by each account open (sweep S3).
const OPEN_SWEEP: i64 = 1024;
/// SQL for the signed expiry: the whole final colon-delimited field of an `erased-input:` copy id.
pub(crate) const BINDING_EXPIRY_SQL: &str =
    "CAST(substr(copy_id,length(rtrim(copy_id,replace(copy_id,':','')))+1) AS INTEGER)";

/// Which database a staging pass reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Side {
    Local,
    Incoming,
}

impl Side {
    fn schema(self) -> &'static str {
        match self {
            Self::Local => "main",
            Self::Incoming => "incoming",
        }
    }
}

/// One footprint kind that can hold a message's inbound envelope.
pub(crate) struct SourceKind {
    pub kind: &'static str,
    pub table: &'static str,
    /// Locator expression over the table alias `t`.
    pub locator: &'static str,
    pub column: &'static str,
}

/// Every footprint kind classified Source. A kind that appears in neither this list nor
/// `NON_SOURCE_KINDS` is unclassified, which the inventory guard rejects.
pub(crate) const SOURCE_KINDS: [SourceKind; 11] = [
    SourceKind {
        kind: "actor",
        table: "runtime_actor_state",
        locator: "t.state_kind",
        column: "state_json",
    },
    SourceKind {
        kind: "archived_actor",
        table: "backup_archived_actor_state",
        locator: "CAST(t.rowid AS TEXT)",
        column: "state_json",
    },
    SourceKind {
        kind: "event",
        table: "local_event_log",
        locator: "t.event_id",
        column: "event_body",
    },
    SourceKind {
        kind: "archived_event",
        table: "backup_archived_local_event",
        locator: "CAST(t.rowid AS TEXT)",
        column: "event_body",
    },
    SourceKind {
        kind: "unrouted",
        table: "runtime_unrouted",
        locator: "t.envelope_id",
        column: "entry_json",
    },
    SourceKind {
        kind: "retry",
        table: "runtime_inbox_retry",
        locator: "t.envelope_key",
        column: "entry_json",
    },
    SourceKind {
        kind: "dead_letter",
        table: "runtime_inbox_dead_letter",
        locator: "t.envelope_key",
        column: "entry_json",
    },
    SourceKind {
        kind: "journal",
        table: "runtime_journal",
        locator: "CAST(t.seq AS TEXT)",
        column: "body_json",
    },
    SourceKind {
        kind: "group_pending_undecrypted",
        table: "group_pending_undecrypted",
        locator: "CAST(t.rowid AS TEXT)",
        column: "envelope_json",
    },
    SourceKind {
        kind: "contact_message_request",
        table: "contact_message_request",
        locator: "CAST(t.rowid AS TEXT)",
        column: "message_json",
    },
    SourceKind {
        kind: "receive_work",
        table: "gateway_receive_work",
        locator: "json_array(t.target_delivery_id,t.incarnation_id,hex(t.inbox_seq))",
        column: "entry_json",
    },
];

/// Footprint kinds that cannot hold an inbound envelope: aliases, pointers, projections,
/// outbound or ack ids, digests and scratch.
pub(crate) const NON_SOURCE_KINDS: &[&str] = &[
    "replay_actor",
    "watermark",
    "outbox",
    "revocation_selector",
    "raw_envelope_log:envelope_id",
    "outbox_queue:envelope_id",
    "ack_state:envelope_id",
    "nack_state:envelope_id",
    "cursor_checkpoint:last_envelope_id",
    "device_inbox_cursor:last_envelope_id",
    "event_causal_dependency:event_id",
    "event_causal_dependency:depends_on_event_id",
    "projection_checkpoint:last_event_id",
    "runtime_message_content",
    "message_projection",
    "receipt_projection",
    "rejected_inbox_projection",
    "conversation_unread_marker",
    "group_message_tombstone_projection",
    "root_group_sender_key_counter_seen",
    "group_sender_key_counter_seen",
    "conversation_read_state",
    "conversation_delivery_state",
];

/// Tables named by a `footprint_%` trigger that can never hold an erased-input Source tuple.
/// A Source tuple is the six authenticated fields (principal, device, signing key, payload hash,
/// `created_at`, `ttl`) read from a stored inbound envelope, so a table qualifies only if it has
/// no envelope column and no production writer that stores one. Each entry names its writer or
/// its absence; Source tables are in `SOURCE_KINDS`.
pub(crate) const NON_SOURCE_TABLES: &[&str] = &[
    // Envelope-id or cursor pointers: ids and counters only, no envelope body, and no
    // production writer exists (`schema.rs` creates them; only `tests.rs` lists them).
    "ack_state",
    "nack_state",
    "cursor_checkpoint",
    "device_inbox_cursor",
    "event_causal_dependency",
    // Writers `event_store.rs:176`, `group_pending.rs:294` and `receive/stage.rs:170`: projection
    // name, version, a last event id and a checkpoint hash; no envelope and no tuple fields.
    "projection_checkpoint",
    // Legacy transport stores with no production writer: `raw_envelope_log` keeps
    // `source_device_id`, `payload_hash` and the sealed `encrypted_payload` blob (not a JSON
    // envelope, and no principal, signing key or timestamps, so no tuple can be formed);
    // `outbox_queue.encrypted_envelope` is outbound; `message_projection` keeps `body_cipher`
    // and ids.
    "raw_envelope_log",
    "outbox_queue",
    "message_projection",
    // Projections of already-opened messages: writer `conversation_projection.rs` (read,
    // delivery, unread) stores conversation/message ids and times only.
    "conversation_read_state",
    "conversation_delivery_state",
    "conversation_unread_marker",
    // Writer `receipt_projection`: `conversation_projection.rs:93` stores ids and receipt type;
    // `rejected_inbox_projection`: `friend.rs:214` stores ids and a reason code.
    "receipt_projection",
    "rejected_inbox_projection",
    // Writer `groups.rs:600`: tombstone ids, scope and epoch only.
    "group_message_tombstone_projection",
    // Replay counters keyed by group, epoch, sender and counter (`group_pending.rs:171`):
    // no payload hash, device or signing key.
    "group_sender_key_counter_seen",
    "root_group_sender_key_counter_seen",
    // The projection itself: writers `messages.rs:77,107` and `deleted_messages.rs:297,456` store
    // the sender principal, `encrypted_body` and typed `MessageMetadata`, whose optional
    // franking report carries the message header, ciphertext and a device-id hash. None of
    // them is a transport envelope: the six tuple fields never sit at the fixed envelope paths
    // (`$`, `$.envelope`, `$.entry.envelope`) that capture reads, so no tuple can be formed.
    "direct_message_projection",
    // Writers `journal/mod.rs:198` and `surface.rs:30`: the locally rendered message body.
    "runtime_message_content",
    // The footprint bindings themselves: copy ids and message ids only.
    "message_copy_binding",
    // Transient stages written and consumed by one trigger statement (`message_footprint/
    // schema.rs` `staged_actor_copy` and `journal_copy`): they carry ids and bindings, or the
    // journal body whose durable home is `runtime_journal` (a Source). Always empty at rest.
    "message_footprint_actor_stage",
    "message_footprint_journal_stage",
];

/// Why the classification guard refused. It is crate-internal on purpose: a new public
/// `StorageError` variant would break every downstream exhaustive match.
#[derive(Debug)]
pub(crate) enum ClassificationError {
    /// The unclassified tables and kinds, named exactly.
    Unclassified(String),
    Sqlite(rusqlite::Error),
}

impl From<rusqlite::Error> for ClassificationError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// Rejects any table named by a `footprint_%` trigger, and any `message_footprint.kind`, that is
/// classified neither as a Source nor as a Non-source, so a new store cannot silently escape the
/// erased-input capture.
///
/// # Errors
/// Returns `Unclassified` naming every unclassified table and kind, or SQLite errors.
pub(crate) fn classification_guard(db: &Connection) -> Result<(), ClassificationError> {
    let mut tables: BTreeSet<String> = BTreeSet::new();
    let mut triggers = db.prepare(
        "SELECT DISTINCT tbl_name FROM main.sqlite_master \
         WHERE type='trigger' AND name LIKE 'footprint\\_%' ESCAPE '\\'",
    )?;
    for table in triggers.query_map([], |r| r.get::<_, String>(0))? {
        let table = table?;
        let known = SOURCE_KINDS.iter().any(|s| s.table == table)
            || NON_SOURCE_TABLES.contains(&table.as_str());
        if !known {
            tables.insert(table);
        }
    }
    let mut kinds: BTreeSet<String> = BTreeSet::new();
    if has_table(db, "main", "message_footprint")? {
        let mut found = db.prepare("SELECT DISTINCT kind FROM main.message_footprint")?;
        for kind in found.query_map([], |r| r.get::<_, String>(0))? {
            let kind = kind?;
            let known = SOURCE_KINDS.iter().any(|s| s.kind == kind)
                || NON_SOURCE_KINDS.contains(&kind.as_str());
            if !known {
                kinds.insert(kind);
            }
        }
    }
    if tables.is_empty() && kinds.is_empty() {
        return Ok(());
    }
    let list = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
    Err(ClassificationError::Unclassified(format!(
        "tables [{}]; kinds [{}]",
        list(&tables),
        list(&kinds)
    )))
}

struct Candidate {
    message: String,
    selector: String,
    bundle: String,
    expires_at: i64,
    eligible: bool,
}

fn has_table(db: &Connection, schema: &str, table: &str) -> rusqlite::Result<bool> {
    db.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?1)"
        ),
        params![table],
        |row| row.get(0),
    )
}

fn lifetime(created_at: i64, ttl: i64, now: i64) -> i64 {
    created_at.min(now.saturating_add(MAX_CLOCK_SKEW)) + ttl.clamp(0, MAX_ENVELOPE_TTL) + SLACK
}

/// Parses `erased-input:{bundle}:{selector}:{expires_at}`; both ids are 32-byte base64url.
fn parse_binding(copy_id: &str) -> Result<(String, String, i64), StorageError> {
    let bad = StorageError::Integrity("malformed erased-input binding");
    let mut parts = copy_id.split(':');
    let (Some("erased-input"), Some(bundle), Some(selector), Some(expires), None) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad);
    };
    for id in [bundle, selector] {
        let decoded = ramflux_protocol::decode_base64url(id)
            .map_err(|_| StorageError::Integrity("malformed erased-input binding"))?;
        if decoded.len() != 32 || ramflux_protocol::encode_base64url(decoded) != id {
            return Err(bad);
        }
    }
    let expires_at = expires
        .parse::<i64>()
        .map_err(|_| StorageError::Integrity("malformed erased-input binding"))?;
    Ok((bundle.to_owned(), selector.to_owned(), expires_at))
}

/// Live message -> payload hashes bound to it (`P_X(M)`).
fn payload_sets(
    db: &Connection,
    schema: &str,
    only: Option<&BTreeSet<&str>>,
) -> rusqlite::Result<BTreeMap<String, BTreeSet<String>>> {
    let scope = in_list("b", only);
    let mut query = db.prepare(&format!(
        "SELECT b.message_id,substr(b.copy_id,9) FROM {schema}.message_copy_binding b \
         JOIN {schema}.direct_message_projection m ON m.message_id=b.message_id AND m.deleted=0 \
         WHERE b.copy_id GLOB 'payload:*'{scope}"
    ))?;
    let mut sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (message, payload) = row?;
        sets.entry(message).or_default().insert(payload);
    }
    Ok(sets)
}

/// ` AND alias.message_id IN (...)` for a scoped read, or nothing. Ids are quoted, never bound
/// as SQL text.
fn in_list(alias: &str, only: Option<&BTreeSet<&str>>) -> String {
    only.map_or_else(String::new, |set| {
        let list = set
            .iter()
            .map(|id| format!("'{}'", id.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        format!(" AND {alias}.message_id IN ({list})")
    })
}

fn current_bundle_mac(
    db: &Connection,
    tuple: &ErasedTuple<'_>,
) -> Result<(String, String), StorageError> {
    let value = tuple.canonical()?;
    super::super::mac_subkeys::bundle_macs(db, LABEL, &value)?
        .into_iter()
        .next()
        .ok_or(StorageError::AuthorizationRejected)
}

/// The authenticated tuple of a stored value's fixed-path envelope: payload, MAC inputs and the
/// lifetime-clamped expiry. Nothing for an unparsable, incomplete or already-expired value.
struct Tuple {
    principal: String,
    device: String,
    signing_key_id: String,
    payload_hash: String,
    expires_at: i64,
}

fn tuple_of(body: &[u8], now: i64) -> Option<Tuple> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let envelope = super::super::message_footprint::fixed_path_envelope(&value)?;
    let text =
        |name: &str| envelope.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
    let expires_at =
        lifetime(envelope.get("created_at")?.as_i64()?, envelope.get("ttl")?.as_i64()?, now);
    (expires_at > now).then(|| Tuple {
        principal: text("source_principal_id"),
        device: text("source_device_id"),
        signing_key_id: text("signing_key_id"),
        payload_hash: text("payload_hash"),
        expires_at,
    })
}

/// Writes binding (i) for an admitted work item: one `erased-input:` binding per retained MAC
/// bundle, bound to the message, so the tuple survives until its deletion is captured.
///
/// # Errors
/// Returns storage or MAC errors.
pub(crate) fn write_work_bindings(
    db: &Connection,
    message: &str,
    entry_json: &[u8],
    now: i64,
) -> Result<(), StorageError> {
    let Some(tuple) = tuple_of(entry_json, now) else { return Ok(()) };
    let canonical = ErasedTuple {
        principal: &tuple.principal,
        device: &tuple.device,
        signing_key_id: &tuple.signing_key_id,
        payload_hash: &tuple.payload_hash,
    }
    .canonical()?;
    for (bundle, selector) in super::super::mac_subkeys::bundle_macs(db, LABEL, &canonical)? {
        import_binding(db, &bundle, &selector, tuple.expires_at, message)?;
    }
    Ok(())
}

/// Records every live work envelope as a tombstone before a backup strip deletes the work rows.
/// Selectors use this database's retained MAC bundles; merge then unions the table as today.
///
/// # Errors
/// Returns storage or MAC errors.
pub(crate) fn carry_work_tombstones(db: &Connection, now: i64) -> Result<(), StorageError> {
    if !has_table(db, "main", "gateway_receive_work")?
        || !has_table(db, "main", "receive_erased_input")?
    {
        return Ok(());
    }
    let mut query = db.prepare("SELECT CAST(entry_json AS BLOB) FROM gateway_receive_work")?;
    let bodies = query
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(query);
    for body in bodies {
        let Some(tuple) = tuple_of(&body, now) else {
            continue;
        };
        let canonical = ErasedTuple {
            principal: &tuple.principal,
            device: &tuple.device,
            signing_key_id: &tuple.signing_key_id,
            payload_hash: &tuple.payload_hash,
        }
        .canonical()?;
        for (bundle, selector) in super::super::mac_subkeys::bundle_macs(db, LABEL, &canonical)? {
            db.execute(
                "INSERT INTO receive_erased_input VALUES(?1,?2,?3) \
                 ON CONFLICT(selector) DO UPDATE SET expires_at=max(expires_at,excluded.expires_at)",
                params![selector, bundle, tuple.expires_at],
            )?;
        }
    }
    Ok(())
}

/// Reads a six-field envelope out of one stored value, or nothing.
fn candidate_tuple(
    db: &Connection,
    body: &[u8],
    now: i64,
) -> Result<Option<(String, String, String, i64)>, StorageError> {
    let Some(t) = tuple_of(body, now) else { return Ok(None) };
    let tuple = ErasedTuple {
        principal: &t.principal,
        device: &t.device,
        signing_key_id: &t.signing_key_id,
        payload_hash: &t.payload_hash,
    };
    let (bundle, selector) = current_bundle_mac(db, &tuple)?;
    Ok(Some((t.payload_hash.clone(), selector, bundle, t.expires_at)))
}

fn collect(
    db: &Connection,
    side: Side,
    now: i64,
    only: Option<&BTreeSet<&str>>,
) -> Result<Vec<Candidate>, StorageError> {
    let schema = side.schema();
    let payloads = payload_sets(db, schema, only)?;
    let binding_scope = in_list("b", only);
    let footprint_scope = in_list("f", only);
    let mut found: Vec<Candidate> = Vec::new();
    // (A) pre-deletion bindings of live messages.
    let mut query = db.prepare(&format!(
        "SELECT b.copy_id,b.message_id FROM {schema}.message_copy_binding b \
         JOIN {schema}.direct_message_projection m ON m.message_id=b.message_id AND m.deleted=0 \
         WHERE b.copy_id GLOB 'erased-input:*'{binding_scope}"
    ))?;
    let bindings = query
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (copy_id, message) in bindings {
        let (bundle, selector, expires_at) = parse_binding(&copy_id)?;
        if expires_at > now {
            found.push(Candidate {
                message,
                selector,
                bundle,
                expires_at,
                eligible: side == Side::Incoming,
            });
        }
    }
    drop(query);
    let footprinted = has_table(db, schema, "message_footprint")?;
    for source in &SOURCE_KINDS {
        if !has_table(db, schema, source.table)? {
            continue;
        }
        let sql = if footprinted {
            // (B) footprinted copy rows, plus rule (C): unfootprinted legacy replay rows of an
            // incoming snapshot written before those rows were registered.
            let legacy = if side == Side::Incoming
                && matches!(source.kind, "actor" | "archived_actor")
            {
                format!(
                    " UNION ALL SELECT NULL,CAST(t.{col} AS BLOB) FROM {schema}.{table} t \
                     WHERE t.state_kind GLOB 'legacy/replay/*' AND NOT EXISTS(SELECT 1 FROM {schema}.message_footprint f \
                     WHERE f.kind='{kind}' AND f.locator={locator})",
                    col = source.column,
                    table = source.table,
                    kind = source.kind,
                    locator = source.locator
                )
            } else {
                String::new()
            };
            format!(
                "SELECT f.message_id,CAST(t.{col} AS BLOB) FROM {schema}.message_footprint f \
                 JOIN {schema}.{table} t ON {locator}=f.locator \
                 JOIN {schema}.direct_message_projection m ON m.message_id=f.message_id AND m.deleted=0 \
                 WHERE f.kind='{kind}'{footprint_scope}{legacy}",
                col = source.column,
                table = source.table,
                locator = source.locator,
                kind = source.kind
            )
        } else {
            // An old snapshot without footprints: ownership comes from payload bindings alone.
            format!(
                "SELECT NULL,CAST(t.{col} AS BLOB) FROM {schema}.{table} t",
                col = source.column,
                table = source.table
            )
        };
        let mut rows = db.prepare(&sql)?;
        let rows = rows
            .query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Vec<u8>>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (owner, body) in rows {
            let Some((payload, selector, bundle, expires_at)) = candidate_tuple(db, &body, now)?
            else {
                continue;
            };
            let owners: Vec<String> = match owner {
                Some(message) => vec![message],
                None => payloads
                    .iter()
                    .filter(|(_, set)| set.contains(&payload))
                    .map(|(message, _)| message.clone())
                    .collect(),
            };
            for message in owners {
                // The payload must be one this message owns; a copy naming another is ignored.
                if payloads.get(&message).is_some_and(|set| set.contains(&payload)) {
                    found.push(Candidate {
                        message,
                        selector: selector.clone(),
                        bundle: bundle.clone(),
                        expires_at,
                        eligible: false,
                    });
                }
            }
        }
    }
    Ok(found)
}

fn ensure_staging(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS backup_erased_capture(
            selector TEXT NOT NULL,bundle_id TEXT NOT NULL,expires_at INTEGER NOT NULL,
            PRIMARY KEY(selector,bundle_id));
         CREATE TEMP TABLE IF NOT EXISTS backup_erased_capture_message(
            selector TEXT NOT NULL,bundle_id TEXT NOT NULL,message_id TEXT NOT NULL,
            binding_eligible INTEGER NOT NULL,PRIMARY KEY(selector,bundle_id,message_id));",
    )
}

/// Stages every tuple source of every live message on one side. Local goes first and clears the
/// staging tables. Read-only on `incoming`; writes only the transaction-local staging tables.
///
/// # Errors
/// Refuses a malformed binding with `Integrity`; returns SQLite or MAC errors.
pub(crate) fn stage_merge_capture(
    db: &Connection,
    side: Side,
    now: i64,
) -> Result<(), StorageError> {
    ensure_staging(db)?;
    if side == Side::Local {
        db.execute_batch("DELETE FROM temp.backup_erased_capture; DELETE FROM temp.backup_erased_capture_message;")?;
    }
    for c in collect(db, side, now, None)? {
        db.execute(
            "INSERT INTO temp.backup_erased_capture VALUES(?1,?2,?3) \
             ON CONFLICT(selector,bundle_id) DO UPDATE SET expires_at=max(expires_at,excluded.expires_at)",
            params![c.selector, c.bundle, c.expires_at],
        )?;
        db.execute(
            "INSERT INTO temp.backup_erased_capture_message VALUES(?1,?2,?3,?4) \
             ON CONFLICT(selector,bundle_id,message_id) DO UPDATE SET \
             binding_eligible=binding_eligible OR excluded.binding_eligible",
            params![c.selector, c.bundle, c.message, i64::from(c.eligible)],
        )?;
    }
    Ok(())
}

/// Resolves staged associations against the final projection state: any linked message deleted
/// records one tombstone; otherwise each eligible live message gets the incoming binding; else
/// the association is discarded. An unknown bundle refuses the whole merge.
///
/// # Errors
/// Returns `Integrity` for an unknown bundle, or SQLite errors.
pub(crate) fn reconcile_merge_capture(db: &Connection, now: i64) -> Result<(), StorageError> {
    ensure_staging(db)?;
    let unknown: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.backup_erased_capture c \
         WHERE c.bundle_id NOT IN (SELECT bundle_id FROM main.account_mac_bundle))",
        [],
        |r| r.get(0),
    )?;
    if unknown {
        return Err(StorageError::Integrity("erased-input bundle unknown to the merged set"));
    }
    let mut query = db.prepare(
        "SELECT c.selector,c.bundle_id,c.expires_at,\
         EXISTS(SELECT 1 FROM temp.backup_erased_capture_message l \
                JOIN main.direct_message_projection p ON p.message_id=l.message_id AND p.deleted=1 \
                WHERE l.selector=c.selector AND l.bundle_id=c.bundle_id) \
         FROM temp.backup_erased_capture c",
    )?;
    let associations = query
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, bool>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(query);
    for (selector, bundle, expires_at, deleted) in associations {
        if expires_at <= now {
            continue;
        }
        if deleted {
            db.execute(
                "INSERT INTO main.receive_erased_input VALUES(?1,?2,?3) \
                 ON CONFLICT(selector) DO UPDATE SET expires_at=max(expires_at,excluded.expires_at)",
                params![selector, bundle, expires_at],
            )?;
            continue;
        }
        let mut live = db.prepare(
            "SELECT l.message_id FROM temp.backup_erased_capture_message l \
             JOIN main.direct_message_projection p ON p.message_id=l.message_id AND p.deleted=0 \
             WHERE l.selector=?1 AND l.bundle_id=?2 AND l.binding_eligible=1",
        )?;
        let messages = live
            .query_map(params![selector, bundle], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(live);
        for message in messages {
            import_binding(db, &bundle, &selector, expires_at, &message)?;
        }
    }
    db.execute_batch(
        "DELETE FROM temp.backup_erased_capture; DELETE FROM temp.backup_erased_capture_message;",
    )?;
    // S1: reconcile is a tombstone write, so it also reclaims a bounded batch of expired rows.
    db.execute(super::erased_input::S1_SWEEP_SQL, params![now, super::erased_input::SWEEP])?;
    Ok(())
}

/// One binding per (bundle, selector, message), keeping the maximum expiry.
fn import_binding(
    db: &Connection,
    bundle: &str,
    selector: &str,
    expires_at: i64,
    message: &str,
) -> rusqlite::Result<()> {
    let prefix = format!("erased-input:{bundle}:{selector}:");
    let newest: Option<i64> = db.query_row(
        "SELECT max(CAST(substr(copy_id,length(?1)+1) AS INTEGER)) FROM main.message_copy_binding \
         WHERE message_id=?2 AND substr(copy_id,1,length(?1))=?1",
        params![prefix, message],
        |r| r.get(0),
    )?;
    // Always collapse the prefix to exactly one variant at the combined maximum.
    let expires_at = newest.map_or(expires_at, |existing| existing.max(expires_at));
    db.execute(
        "DELETE FROM main.message_copy_binding WHERE message_id=?2 AND substr(copy_id,1,length(?1))=?1",
        params![prefix, message],
    )?;
    db.execute(
        "INSERT INTO main.message_copy_binding VALUES(?1,?2)",
        params![format!("{prefix}{expires_at}"), message],
    )?;
    Ok(())
}

/// Converts the tuple sources of the named messages (on `main`) into tombstones, before the
/// deletion that would drop their bindings. A binding keeps its own selector and bundle; a copy
/// row yields one tombstone per retained bundle.
///
/// # Errors
/// Returns storage or MAC errors, or `Integrity` for a malformed binding.
pub(crate) fn capture_for(
    db: &Connection,
    messages: &[&str],
    now: i64,
) -> Result<(), StorageError> {
    let wanted: BTreeSet<&str> = messages.iter().copied().collect();
    let mut staged: Vec<(String, String, i64)> = Vec::new();
    for c in collect_for_deleted_targets(db, &wanted, now)? {
        staged.push((c.selector, c.bundle, c.expires_at));
    }
    let any = !staged.is_empty();
    for (selector, bundle, expires_at) in staged {
        db.execute(
            "INSERT INTO main.receive_erased_input VALUES(?1,?2,?3) \
             ON CONFLICT(selector) DO UPDATE SET expires_at=max(expires_at,excluded.expires_at)",
            params![selector, bundle, expires_at],
        )?;
    }
    if any {
        // S1: the live capture is a tombstone write, so it also reclaims expired rows.
        db.execute(super::erased_input::S1_SWEEP_SQL, params![now, super::erased_input::SWEEP])?;
    }
    Ok(())
}

/// `capture_for` runs before the deletion, while the targets are still live on `main`.
fn collect_for_deleted_targets(
    db: &Connection,
    wanted: &BTreeSet<&str>,
    now: i64,
) -> Result<Vec<Candidate>, StorageError> {
    Ok(collect(db, Side::Local, now, Some(wanted))?
        .into_iter()
        .filter(|c| wanted.contains(c.message.as_str()))
        .collect())
}

/// Sweep S3: each account open removes up to 1,024 expired rows and 1,024 expired bindings.
///
/// # Errors
/// Returns SQLite errors.
pub(crate) fn sweep_open(db: &Connection, now: i64) -> rusqlite::Result<()> {
    if !has_table(db, "main", "receive_erased_input")? {
        return Ok(());
    }
    db.execute(
        "DELETE FROM receive_erased_input WHERE selector IN \
         (SELECT selector FROM receive_erased_input WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)",
        params![now, OPEN_SWEEP],
    )?;
    db.execute(
        &format!(
            "DELETE FROM message_copy_binding WHERE rowid IN (SELECT rowid FROM message_copy_binding \
             WHERE copy_id GLOB 'erased-input:*' AND {BINDING_EXPIRY_SQL}<=?1 LIMIT ?2)"
        ),
        params![now, OPEN_SWEEP],
    )?;
    Ok(())
}

impl crate::AccountDb {
    /// Converts a live message's tuple sources into tombstones before its deletion drops them.
    pub(in crate::account_db) fn capture_erased_inputs(
        &self,
        message: &str,
    ) -> Result<(), StorageError> {
        let message = message.to_owned();
        let now = crate::unix_now();
        self.connection.call(move |raw| Ok(capture_for(raw, &[message.as_str()], now)))?
    }
}
