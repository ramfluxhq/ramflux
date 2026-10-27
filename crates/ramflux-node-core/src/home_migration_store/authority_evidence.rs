// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retain A's own verified attestation authority across a concurrent primary replacement.
use super::{
    Authorization, NodeCoreError, ReadableTable, Refusal, Signed, VerifiedRecord, auth_error,
    crypto, decode, maintenance, read, refusal, storage, write,
};
use ramflux_protocol::custody::{Publication, object_hash};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
const AUTHORITIES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("migration_authority_evidence_v1");
const EXPIRY: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_authority_expiry_v1");
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    publication: Publication,
    retain_until: u64,
}
pub(super) fn remember(
    tx: &redb::WriteTransaction,
    publication: &crate::CustodyPublication,
    now: u64,
) -> Result<(), NodeCoreError> {
    let hash = object_hash(&publication.record).map_err(storage)?;
    // Owner-attested preflight expires in 60s, offer/seal in at most 600s,
    // authorization's hard bound in at most 1800s. One hour covers that chain,
    // including the admitted-peer skew, without importing any peer retention value.
    let until = now.checked_add(3600).ok_or_else(|| refusal(Refusal::CommitExpired))?;
    let until = if let Some(old) = read::<Evidence>(tx, AUTHORITIES, &hash)? {
        tx.open_table(EXPIRY)
            .map_err(storage)?
            .remove(maintenance::expiry_key(old.retain_until, &hash).as_str())
            .map_err(storage)?;
        until.max(old.retain_until)
    } else {
        until
    };
    let evidence = Evidence {
        publication: Publication {
            record: publication.record.clone(),
            compacted_ids: publication.compacted_ids.clone(),
        },
        retain_until: until,
    };
    write(tx, AUTHORITIES, &hash, &evidence)?;
    write(tx, EXPIRY, &maintenance::expiry_key(until, &hash), &hash)
}
pub(super) fn verify(
    tx: &redb::WriteTransaction,
    authorization: &Signed<Authorization>,
    current: &VerifiedRecord,
) -> Result<(), NodeCoreError> {
    let a = &authorization.body;
    if object_hash(current.envelope()).map_err(storage)? == a.authority_record_hash {
        return crypto::verify_authorization(authorization, current, a.issued_at)
            .map_err(auth_error);
    }
    let evidence: Evidence = read(tx, AUTHORITIES, &a.authority_record_hash)?
        .ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
    let p = &evidence.publication;
    let at = a
        .issued_at
        .max(p.record.body.issued_at)
        .max(p.record.body.master_certificate.body.issued_at);
    let authority =
        ramflux_crypto::custody::verify_record(&p.record, at, p.compacted_ids.as_deref(), None)
            .map_err(auth_error)?;
    crypto::verify_authorization(authorization, &authority, a.issued_at).map_err(auth_error)
}
pub(super) fn cleanup(tx: &redb::WriteTransaction, now: u64) -> Result<(), NodeCoreError> {
    let upper = format!("{now:020}/");
    let expired = tx
        .open_table(EXPIRY)
        .map_err(storage)?
        .range(..upper.as_str())
        .map_err(storage)?
        .take(128)
        .map(|row| {
            let (k, v) = row.map_err(storage)?;
            Ok((k.value().to_owned(), decode::<String>(v.value())?))
        })
        .collect::<Result<Vec<_>, NodeCoreError>>()?;
    for (index, hash) in expired {
        tx.open_table(EXPIRY).map_err(storage)?.remove(index.as_str()).map_err(storage)?;
        tx.open_table(AUTHORITIES).map_err(storage)?.remove(hash.as_str()).map_err(storage)?;
    }
    Ok(())
}
