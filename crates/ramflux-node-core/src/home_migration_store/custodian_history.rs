// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Capture transition-time human evidence with agent home records; never substitute current state.
use super::{
    NodeCoreError, RecordEvidence, Refusal, auth_error, bytes, decode, read, refusal, storage,
    write,
};
use crate::{CustodyPublication, RouterRedbStore, custody_authority::CustodyAccountState};
use ramflux_protocol::{
    contact_reach::HistoricalCustodian,
    custody::{CustodyAuthority, CustodyKind, Publication, object_hash},
    home_migration::HomeRecord,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::BTreeSet;

const HISTORY: TableDefinition<&str, &[u8]> = TableDefinition::new("home_custodian_history_v1");
const CUSTODY: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_accounts_v3");
const LIMIT: usize = 1024 * 1024;
fn key(root: &str, hash: &str) -> Result<String, NodeCoreError> {
    serde_json::to_string(&(root, hash)).map_err(storage)
}
fn at(evidence: &RecordEvidence) -> u64 {
    match &evidence.record {
        HomeRecord::Genesis { genesis } => genesis.body.registered_at,
        HomeRecord::Committed { authorization, .. } => authorization.body.issued_at,
    }
}
pub(super) fn capture(
    tx: &redb::WriteTransaction,
    publication: &CustodyPublication,
    now: u64,
) -> Result<Option<Publication>, NodeCoreError> {
    let record = &publication.record;
    let certificate = &record.body.master_certificate.body;
    if certificate.custody_kind != CustodyKind::ExternalHuman {
        return Ok(None);
    }
    let human: CustodyAccountState =
        read(tx, CUSTODY, &certificate.primary_device_ref.account_anchor)?
            .ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
    let verified = ramflux_crypto::custody::verify_record(
        &human.publication.record,
        now,
        human.publication.compacted_ids.as_deref(),
        None,
    )
    .map_err(auth_error)?;
    human.pins.require_current(&verified).map_err(auth_error)?;
    let human = Publication {
        record: human.publication.record,
        compacted_ids: human.publication.compacted_ids,
    };
    ramflux_crypto::custody::verify_publication(
        &CustodyAuthority {
            publication: Publication {
                record: record.clone(),
                compacted_ids: publication.compacted_ids.clone(),
            },
            custodian_publication: Some(human.clone()),
        },
        now,
    )
    .map_err(auth_error)?;
    Ok(Some(human))
}
pub(super) fn remember(
    tx: &redb::WriteTransaction,
    evidence: &RecordEvidence,
) -> Result<(), NodeCoreError> {
    let publication = &evidence.authority;
    if publication.record.body.master_certificate.body.custody_kind != CustodyKind::ExternalHuman {
        return Ok(());
    }
    let hash = object_hash(&publication.record).map_err(storage)?;
    let root = &publication.record.body.account_anchor;
    let key = key(root, &hash)?;
    if let Some(old) = read::<HistoricalCustodian>(tx, HISTORY, &key)? {
        if old.authority.publication != *publication {
            return Err(refusal(Refusal::EvidenceRequired));
        }
        ramflux_crypto::custody::verify_publication(&old.authority, at(evidence))
            .map_err(auth_error)?;
        return Ok(());
    }
    let p = CustodyPublication {
        record: publication.record.clone(),
        compacted_ids: publication.compacted_ids.clone(),
    };
    let human = capture(tx, &p, at(evidence))?.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
    let reference = HistoricalCustodian {
        record_hash: hash,
        authority: CustodyAuthority {
            publication: publication.clone(),
            custodian_publication: Some(human),
        },
    };
    save_reference(tx, root, &key, &reference)
}
fn save_reference(
    tx: &redb::WriteTransaction,
    root: &str,
    key: &str,
    reference: &HistoricalCustodian,
) -> Result<(), NodeCoreError> {
    let prefix = format!("[{},", serde_json::to_string(root).map_err(storage)?);
    let table = tx.open_table(HISTORY).map_err(storage)?;
    let mut count = 0_usize;
    let mut total = bytes(reference)?.len();
    for row in table.range(prefix.as_str()..).map_err(storage)?.take(65) {
        let (k, v) = row.map_err(storage)?;
        if !k.value().starts_with(&prefix) {
            break;
        }
        count += 1;
        total =
            total.checked_add(v.value().len()).ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
    }
    if count >= 64 || total > LIMIT {
        return Err(refusal(Refusal::EvidenceRequired));
    }
    drop(table);
    write(tx, HISTORY, key, reference)
}
impl RouterRedbStore {
    /// Export exact independently captured human references for a bounded historical home proof.
    /// The caller transfers these originals alongside the records; no current-human fallback exists.
    /// # Errors
    /// Refuses missing historical evidence, changed agent publications and aggregate proof overflow.
    pub fn home_custodian_history(
        &self,
        records: &[RecordEvidence],
    ) -> Result<Vec<HistoricalCustodian>, NodeCoreError> {
        if records.len() > 64 {
            return Err(refusal(Refusal::EvidenceRequired));
        }
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let mut refs = Vec::new();
        let mut seen = BTreeSet::new();
        for evidence in records {
            let publication = &evidence.authority;
            if publication.record.body.master_certificate.body.custody_kind
                != CustodyKind::ExternalHuman
            {
                continue;
            }
            let hash = object_hash(&publication.record).map_err(storage)?;
            if !seen.insert(hash.clone()) {
                continue;
            }
            let key = key(&publication.record.body.account_anchor, &hash)?;
            let table = tx.open_table(HISTORY).map_err(storage)?;
            let raw = table
                .get(key.as_str())
                .map_err(storage)?
                .ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
            let reference: HistoricalCustodian = decode(raw.value())?;
            if reference.record_hash != hash || reference.authority.publication != *publication {
                return Err(refusal(Refusal::EvidenceRequired));
            }
            ramflux_crypto::custody::verify_publication(&reference.authority, at(evidence))
                .map_err(auth_error)?;
            refs.push(reference);
        }
        if bytes(&(records, &refs))?.len() > LIMIT {
            return Err(refusal(Refusal::EvidenceRequired));
        }
        Ok(refs)
    }
}
