// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! W0-backed hold admission and oldest-first typed eviction. The caller stages W0 first.
use super::ReceiveTransaction;
use super::settle::{ReceiveSettle, ReceiveSettleKind, ReceiveSettleResult};
use crate::{ProjectionStore, StorageError};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

const HOLD_LIMIT: usize = 256;
const HOLD_BYTES: usize = 16 * 1024 * 1024;
const SOURCE_LIMIT: usize = 64;
const SOURCE_BYTES: usize = 4 * 1024 * 1024;
const UNROUTED_LIMIT: usize = 64;
const CONTACT_LIMIT: usize = 64;

/// Existing local hold class. These labels are stored in the existing inbox-policy row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveHoldClass {
    Unrouted,
    Contact,
    Policy,
}

impl ReceiveHoldClass {
    const fn label(self) -> &'static str {
        match self {
            Self::Unrouted => "unrouted",
            Self::Contact => "contact",
            Self::Policy => "policy",
        }
    }

    const fn limit(self) -> usize {
        match self {
            Self::Unrouted => UNROUTED_LIMIT,
            Self::Contact => CONTACT_LIMIT,
            Self::Policy => 128,
        }
    }
}

/// Optional compact journal effect that must join the held receipt transaction.
#[derive(Clone, Copy, Debug)]
pub struct ReceiveHoldJournal<'a> {
    pub source_key: &'a str,
    pub topic: &'a str,
    pub body: &'a Value,
    pub subject: Option<&'a str>,
}

/// Admission for an already-staged W0 entry. `unrouted_id` uses the existing quarantine table;
/// `contact_root` is used only by contact backpressure's one-per-root cap.
#[derive(Clone, Copy, Debug)]
pub struct ReceiveHold<'a> {
    pub sequence: u64,
    pub admission_key: &'a str,
    pub class: ReceiveHoldClass,
    pub contact_root: Option<&'a str>,
    pub unrouted_id: Option<&'a str>,
    pub journal: Option<ReceiveHoldJournal<'a>>,
    pub at: i64,
}

/// A full class/source pool pauses admission without changing its staged W0 input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveHoldResult {
    Held { evicted: Vec<u64> },
    Paused,
}

#[derive(Clone, Debug)]
struct HeldRow {
    incarnation: String,
    sequence: u64,
    admission_key: String,
    byte_len: usize,
    first_seen: i64,
    source: String,
    trusted: bool,
    class: ReceiveHoldClass,
    subject: String,
}

impl ReceiveTransaction<'_> {
    /// Joins the held receipt, existing quarantine row and unique journal effect after W0.
    /// Quota evictions settle through P06 WS; this method never directly deletes ledger work.
    ///
    /// # Errors
    /// Returns stale-authority, malformed-work, journal, SQL or settlement errors. A quota
    /// refusal returns `Paused` and leaves W0 untouched.
    pub fn admit_hold(&self, input: ReceiveHold<'_>) -> Result<ReceiveHoldResult, StorageError> {
        self.require_writer()?;
        self.refuse_retired()?;
        if input.sequence == 0 || input.admission_key.is_empty() {
            return Err(StorageError::Integrity("receive hold identity missing"));
        }
        if input.class == ReceiveHoldClass::Contact && input.contact_root.is_none_or(str::is_empty)
        {
            return Err(StorageError::Integrity("contact hold root missing"));
        }
        let candidate = self.load_candidate(&input)?;
        let mut rows = self.load_holds()?;
        let already_held = rows
            .iter()
            .any(|row| row.incarnation == candidate.incarnation && row.sequence == input.sequence);
        if !already_held {
            rows.push(candidate.clone());
        }
        let cursor = self.cursor_value()?;
        let Some(evictions) = plan_evictions(&mut rows, &candidate, cursor) else {
            return Ok(ReceiveHoldResult::Paused);
        };

        // This is the final typed transition for the new admission. If it is C+1, WS delegates
        // to ordered W2; any later error rolls that nested savepoint back with the outer commit.
        if self.settle(ReceiveSettle { sequence: input.sequence, kind: ReceiveSettleKind::Held })?
            != ReceiveSettleResult::Held
        {
            return Err(StorageError::Integrity("hold admission coverage paused"));
        }
        let mut evicted = Vec::with_capacity(evictions.len());
        for row in evictions {
            match self.settle_retained_for(
                &row.incarnation,
                ReceiveSettle { sequence: row.sequence, kind: ReceiveSettleKind::Terminal },
            )? {
                ReceiveSettleResult::Settled => {}
                ReceiveSettleResult::Held | ReceiveSettleResult::Paused => {
                    return Err(StorageError::Integrity("held eviction did not settle"));
                }
            }
            self.db.insert_journal(
                &format!(
                    "receive-hold-terminal:{}:{}:{}",
                    self.target, self.incarnation, row.sequence
                ),
                "inbox.receive_failure",
                &serde_json::json!({
                    "target_delivery_id": self.target,
                    "incarnation_id": row.incarnation,
                    "inbox_seq": row.sequence,
                    "reason": "held_evicted",
                }),
                input.at,
                None,
            )?;
            self.db.connection.execute(
                "DELETE FROM runtime_unrouted WHERE envelope_id=?1",
                params![row.admission_key],
            )?;
            self.db.connection.execute(
                "DELETE FROM runtime_inbox_policy WHERE envelope_key=?1
                   AND NOT EXISTS(SELECT 1 FROM runtime_inbox_retry WHERE envelope_key=?1)
                   AND NOT EXISTS(SELECT 1 FROM runtime_inbox_dead_letter WHERE envelope_key=?1)
                   AND NOT EXISTS(SELECT 1 FROM gateway_receive_work WHERE admission_key=?1)",
                params![row.admission_key],
            )?;
            evicted.push(row.sequence);
        }

        if let Some(id) = input.unrouted_id {
            let bytes = self.work_bytes(input.sequence)?;
            self.db.insert_unrouted_row(id, input.sequence, &bytes, input.at, false)?;
        }
        self.ensure_hold_policy(&candidate, input.at)?;
        if let Some(journal) = input.journal {
            self.db.insert_journal(
                journal.source_key,
                journal.topic,
                journal.body,
                input.at,
                journal.subject,
            )?;
        }
        before_commit()?;
        Ok(ReceiveHoldResult::Held { evicted })
    }

    fn cursor_value(&self) -> Result<u64, StorageError> {
        self.db
            .projection_checkpoint(&format!("gateway_receive_cursor:{}", self.target))?
            .map_or(Ok(0), |value| {
                value.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected)
            })
    }

    fn load_candidate(&self, input: &ReceiveHold<'_>) -> Result<HeldRow, StorageError> {
        let (byte_len, first_seen, key): (i64, i64, String) = self
            .db
            .connection
            .query_row(
                "SELECT w.byte_len,r.first_seen,w.admission_key
             FROM gateway_receive_work w JOIN gateway_receive_receipt r
               USING(target_delivery_id,incarnation_id,inbox_seq)
             WHERE w.target_delivery_id=?1 AND w.incarnation_id=?2 AND w.inbox_seq=?3",
                params![self.target, self.incarnation, input.sequence.to_be_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(StorageError::Integrity("hold requires staged work"))?;
        if key != input.admission_key {
            return Err(StorageError::Integrity("hold admission key differs from W0"));
        }
        let policy: Option<(String, i64)> = self
            .db
            .connection
            .query_row(
                "SELECT source,trusted FROM runtime_inbox_policy WHERE envelope_key=?1",
                params![input.admission_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let source = policy
            .as_ref()
            .map_or_else(|| "unverified".to_owned(), |(source, _)| source_bucket(source));
        let trusted = policy.is_some_and(|(_, trusted)| trusted != 0);
        Ok(HeldRow {
            incarnation: self.incarnation.to_owned(),
            sequence: input.sequence,
            admission_key: key,
            byte_len: usize::try_from(byte_len)
                .map_err(|_| StorageError::Integrity("receive work byte length"))?,
            first_seen,
            source,
            trusted,
            class: input.class,
            subject: input.contact_root.unwrap_or_default().to_owned(),
        })
    }

    fn load_holds(&self) -> Result<Vec<HeldRow>, StorageError> {
        let retired_blob: Vec<u8> = self.db.connection.query_row(
            "SELECT retired_incarnations FROM gateway_receive_epoch WHERE target_delivery_id=?1",
            params![self.target],
            |row| row.get(0),
        )?;
        let retired: Vec<String> = if retired_blob.is_empty() {
            Vec::new()
        } else {
            serde_json::from_slice(&retired_blob)
                .map_err(|_| StorageError::Integrity("retired incarnation encoding"))?
        };
        let mut query = self.db.connection.prepare(
            "SELECT w.incarnation_id,w.inbox_seq,w.admission_key,w.byte_len,r.first_seen,
                    coalesce(p.source,'unverified'),coalesce(p.trusted,0),
                    CASE
                      WHEN u.envelope_id IS NOT NULL THEN 'unrouted'
                      WHEN p.failure_class='receive_hold_contact' THEN 'contact'
                      WHEN (p.failure_class NOT IN ('none','receive_hold_unrouted','receive_hold_contact')
                            OR retry.envelope_key IS NOT NULL) THEN 'policy'
                      ELSE 'unrouted'
                    END,
                    coalesce(p.subject,'')
             FROM gateway_receive_work w
             JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq)
             LEFT JOIN runtime_inbox_policy p ON p.envelope_key=w.admission_key
             LEFT JOIN runtime_unrouted u ON u.envelope_id=w.admission_key
             LEFT JOIN runtime_inbox_retry retry ON retry.envelope_key=w.admission_key
              WHERE w.target_delivery_id=?1
                AND r.disposition IN ('held','quarantined')",
        )?;
        let records = query
            .query_map(params![self.target], |row| {
                let class: String = row.get(7)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    class,
                    row.get::<_, String>(8)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        records
            .into_iter()
            .map(
                |(
                    incarnation,
                    seq,
                    admission_key,
                    byte_len,
                    first_seen,
                    source,
                    trusted,
                    class,
                    subject,
                )| {
                    if incarnation != self.incarnation
                        && !retired.iter().any(|value| value == &incarnation)
                    {
                        return Err(StorageError::Integrity(
                            "hold row incarnation is not retained",
                        ));
                    }
                    Ok(HeldRow {
                        incarnation,
                        sequence: decode_sequence(seq)?,
                        admission_key,
                        byte_len: usize::try_from(byte_len)
                            .map_err(|_| StorageError::Integrity("receive work byte length"))?,
                        first_seen,
                        source: source_bucket(&source),
                        trusted: trusted != 0,
                        class: match class.as_str() {
                            "contact" => ReceiveHoldClass::Contact,
                            "policy" => ReceiveHoldClass::Policy,
                            _ => ReceiveHoldClass::Unrouted,
                        },
                        subject,
                    })
                },
            )
            .collect()
    }

    fn work_bytes(&self, sequence: u64) -> Result<Vec<u8>, StorageError> {
        Ok(self.db.connection.query_row(
            "SELECT entry_json FROM gateway_receive_work
             WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
            params![self.target, self.incarnation, sequence.to_be_bytes().as_slice()],
            |row| row.get(0),
        )?)
    }

    fn ensure_hold_policy(&self, row: &HeldRow, at: i64) -> Result<(), StorageError> {
        let exists: bool = self.db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_inbox_policy WHERE envelope_key=?1)",
            params![row.admission_key],
            |record| record.get(0),
        )?;
        if !exists {
            let source = row.source.clone();
            self.db.connection.execute(
                "INSERT INTO runtime_inbox_policy VALUES(?1,?2,?3,?4,?5,0,?6,?7,0,0)",
                params![
                    row.admission_key,
                    source,
                    row.trusted,
                    at,
                    at.saturating_add(7 * 24 * 60 * 60),
                    format!("receive_hold_{}", row.class.label()),
                    row.subject,
                ],
            )?;
        } else if matches!(row.class, ReceiveHoldClass::Contact | ReceiveHoldClass::Policy) {
            let failure_class = format!("receive_hold_{}", row.class.label());
            self.db.connection.execute(
                "UPDATE runtime_inbox_policy SET failure_class=?2,subject=?3
                 WHERE envelope_key=?1 AND failure_class='none'
                   AND NOT EXISTS(SELECT 1 FROM runtime_inbox_retry WHERE envelope_key=?1)",
                params![row.admission_key, failure_class, row.subject],
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Scope {
    Aggregate,
    Source,
    Class,
    ContactRoot,
    UntrustedPolicy,
}

fn violations<'a>(
    rows: &'a [HeldRow],
    candidate: &'a HeldRow,
) -> Option<(Scope, String, ReceiveHoldClass, String)> {
    let count = rows.len();
    let bytes = rows.iter().fold(0usize, |sum, row| sum.saturating_add(row.byte_len));
    if count > HOLD_LIMIT || bytes > HOLD_BYTES {
        return Some((Scope::Aggregate, String::new(), candidate.class, String::new()));
    }
    let source_rows = rows.iter().filter(|row| row.source == candidate.source);
    let (source_count, source_bytes) = source_rows.fold((0usize, 0usize), |(n, b), row| {
        (n.saturating_add(1), b.saturating_add(row.byte_len))
    });
    if source_count > SOURCE_LIMIT || source_bytes > SOURCE_BYTES {
        return Some((Scope::Source, candidate.source.clone(), candidate.class, String::new()));
    }
    if candidate.class == ReceiveHoldClass::Policy {
        let policy_source_count = rows
            .iter()
            .filter(|row| row.class == ReceiveHoldClass::Policy && row.source == candidate.source)
            .count();
        let source_limit = if candidate.trusted {
            8
        } else if candidate.source == "unverified" {
            16
        } else {
            2
        };
        if policy_source_count > source_limit {
            return Some((Scope::Source, candidate.source.clone(), candidate.class, String::new()));
        }
        let untrusted_policy_count =
            rows.iter().filter(|row| row.class == ReceiveHoldClass::Policy && !row.trusted).count();
        if !candidate.trusted && untrusted_policy_count > 16 {
            return Some((Scope::UntrustedPolicy, String::new(), candidate.class, String::new()));
        }
    }
    let class_rows = rows.iter().filter(|row| row.class == candidate.class);
    let (class_count, _class_bytes) = class_rows.fold((0usize, 0usize), |(n, b), row| {
        (n.saturating_add(1), b.saturating_add(row.byte_len))
    });
    if class_count > candidate.class.limit() {
        return Some((Scope::Class, String::new(), candidate.class, String::new()));
    }
    if candidate.class == ReceiveHoldClass::Contact {
        let root_count = rows
            .iter()
            .filter(|row| {
                row.class == ReceiveHoldClass::Contact && row.subject == candidate.subject
            })
            .count();
        if root_count > 1 {
            return Some((
                Scope::ContactRoot,
                String::new(),
                candidate.class,
                candidate.subject.clone(),
            ));
        }
    }
    None
}

fn plan_evictions(
    rows: &mut Vec<HeldRow>,
    candidate: &HeldRow,
    cursor: u64,
) -> Option<Vec<HeldRow>> {
    let mut evictions = Vec::new();
    while let Some((scope, source, class, subject)) = violations(rows, candidate) {
        let next = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                row.incarnation != candidate.incarnation || row.sequence != candidate.sequence
            })
            .filter(|(_, row)| row.incarnation != candidate.incarnation || row.sequence <= cursor)
            .filter(|(_, row)| match scope {
                Scope::Aggregate => true,
                Scope::Source => row.source == source,
                Scope::Class => row.class == class,
                Scope::ContactRoot => {
                    row.class == ReceiveHoldClass::Contact && row.subject == subject
                }
                Scope::UntrustedPolicy => row.class == ReceiveHoldClass::Policy && !row.trusted,
            })
            .min_by_key(|(_, row)| (row.first_seen, row.sequence, row.admission_key.clone()))
            .map(|(index, _)| index);
        let index = next?;
        evictions.push(rows.remove(index));
    }
    Some(evictions)
}

fn source_bucket(source: &str) -> String {
    if source == "unverified" || source.starts_with("unverified/") {
        "unverified".to_owned()
    } else {
        source.to_owned()
    }
}

fn decode_sequence(bytes: Vec<u8>) -> Result<u64, StorageError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| StorageError::Integrity("receive sequence encoding"))?,
    ))
}

fn before_commit() -> Result<(), StorageError> {
    if current_fault() == Fault::BeforeCommit {
        return Err(StorageError::Integrity("receive hold before-commit"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    BeforeCommit,
}

fn current_fault() -> Fault {
    #[cfg(test)]
    {
        FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        Fault::None
    }
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
}

#[cfg(test)]
pub(crate) fn run<T>(write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|slot| slot.set(Fault::None));
        }
    }
    FAULT.with(|slot| slot.set(Fault::BeforeCommit));
    let _reset = Reset;
    write()
}
