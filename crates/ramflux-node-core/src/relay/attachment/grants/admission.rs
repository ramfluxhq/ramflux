// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Reference binding and indexed per-owner metadata admission in the grant transaction.
use super::{
    AttachmentAuthority, AttachmentLedgerError, AttachmentRegistrationReceipt, CONFIG, GRANTS,
    REFERENCES, ReadableTable, ReadableTableMetadata, RegisteredAttachmentGrant,
    ScopedGrantRegistry, TableDefinition, VerifiedScopedGrant, decode, invalid, store,
};
pub(super) const OWNER_COUNTS: TableDefinition<&str, u64> =
    TableDefinition::new("native_attachment_grant_owner_counts_v1");
pub(super) const GRANT_OWNERS: TableDefinition<&[u8], &str> =
    TableDefinition::new("native_attachment_grant_owners_v1");
pub(super) const SCHEMA: TableDefinition<&str, u64> =
    TableDefinition::new("native_attachment_grant_owner_schema_v1");
pub const SCOPED_GRANTS_PER_OWNER_MAX: u64 = 1024;
fn signed_grant(
    row: &RegisteredAttachmentGrant,
    authority: &AttachmentAuthority,
    now: u64,
) -> Result<VerifiedScopedGrant, AttachmentLedgerError> {
    let bytes = ramflux_protocol::decode_base64url(&row.capability).map_err(invalid)?;
    let (grant, _) = AttachmentRegistrationReceipt::decode_capability(
        &bytes,
        &authority.source,
        authority.generation,
        &authority.signing_public_key,
        now.min(row.expires_at.saturating_sub(1)),
    )
    .map_err(invalid)?;
    Ok(grant)
}
pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), AttachmentLedgerError> {
    let _ = tx.open_table(OWNER_COUNTS).map_err(store)?;
    let _ = tx.open_table(GRANT_OWNERS).map_err(store)?;
    let mut schema = tx.open_table(SCHEMA).map_err(store)?;
    if schema.get("counted").map_err(store)?.is_some() {
        return Ok(());
    }
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let rows = tx.open_table(GRANTS).map_err(store)?;
        let start = cursor.as_deref().map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let page = rows
            .range::<&[u8]>((start, std::ops::Bound::Unbounded))
            .map_err(store)?
            .take(64)
            .map(|e| {
                let (k, v) = e.map_err(store)?;
                if v.value().len() > 32 * 1024 {
                    return Err(AttachmentLedgerError::State);
                }
                Ok((k.value().to_vec(), decode::<RegisteredAttachmentGrant>(v.value())?))
            })
            .collect::<Result<Vec<_>, AttachmentLedgerError>>()?;
        drop(rows);
        if page.is_empty() {
            break;
        }
        let authority: AttachmentAuthority = {
            let config = tx.open_table(CONFIG).map_err(store)?;
            let value = config.get("source").map_err(store)?.ok_or(AttachmentLedgerError::State)?;
            decode(value.value())?
        };
        for (id, row) in page {
            let grant = signed_grant(&row, &authority, row.expires_at.saturating_sub(1))?;
            record(tx, &id, &grant.grant().owner.account_anchor)?;
            cursor = Some(id);
        }
    }
    schema.insert("counted", 1).map_err(store)?;
    Ok(())
}
pub(super) fn check_owner(
    tx: &redb::WriteTransaction,
    owner: &str,
) -> Result<(), AttachmentLedgerError> {
    let table = tx.open_table(OWNER_COUNTS).map_err(store)?;
    let count = table.get(owner).map_err(store)?.map_or(0, |v| v.value());
    if count >= SCOPED_GRANTS_PER_OWNER_MAX {
        return Err(AttachmentLedgerError::Capacity);
    }
    Ok(())
}
pub(super) fn record(
    tx: &redb::WriteTransaction,
    id: &[u8],
    owner: &str,
) -> Result<(), AttachmentLedgerError> {
    let mut counts = tx.open_table(OWNER_COUNTS).map_err(store)?;
    let count = counts
        .get(owner)
        .map_err(store)?
        .map_or(0, |v| v.value())
        .checked_add(1)
        .ok_or(AttachmentLedgerError::State)?;
    counts.insert(owner, count).map_err(store)?;
    tx.open_table(GRANT_OWNERS).map_err(store)?.insert(id, owner).map_err(store)?;
    Ok(())
}
pub(super) fn release(tx: &redb::WriteTransaction, id: &[u8]) -> Result<(), AttachmentLedgerError> {
    let owner = tx
        .open_table(GRANT_OWNERS)
        .map_err(store)?
        .remove(id)
        .map_err(store)?
        .ok_or(AttachmentLedgerError::State)?
        .value()
        .to_owned();
    let mut counts = tx.open_table(OWNER_COUNTS).map_err(store)?;
    let count = counts
        .get(owner.as_str())
        .map_err(store)?
        .ok_or(AttachmentLedgerError::State)?
        .value()
        .checked_sub(1)
        .ok_or(AttachmentLedgerError::State)?;
    if count == 0 {
        counts.remove(owner.as_str()).map_err(store)?;
    } else {
        counts.insert(owner.as_str(), count).map_err(store)?;
    }
    Ok(())
}
impl ScopedGrantRegistry {
    pub(super) fn check_reference(
        &self,
        tx: &redb::WriteTransaction,
        grant: &VerifiedScopedGrant,
        upload: &[u8; 32],
        now: u64,
    ) -> Result<(), AttachmentLedgerError> {
        let g = grant.grant();
        let refs = tx.open_table(REFERENCES).map_err(store)?;
        let first = refs
            .range(g.reference_id.as_slice()..)
            .map_err(store)?
            .next()
            .transpose()
            .map_err(store)?;
        #[cfg(test)]
        if first.is_some() {
            REFERENCE_VISITS.with(|n| n.set(n.get() + 1));
        }
        if let Some((key, _)) = first
            && key.value().starts_with(&g.reference_id)
        {
            let id = key.value().get(32..64).ok_or(AttachmentLedgerError::State)?;
            let rows = tx.open_table(GRANTS).map_err(store)?;
            let value = rows.get(id).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
            #[cfg(test)]
            REFERENCE_VISITS.with(|n| n.set(n.get() + 1));
            if value.value().len() > 32 * 1024 {
                return Err(AttachmentLedgerError::State);
            }
            let old: RegisteredAttachmentGrant = decode(value.value())?;
            let previous = signed_grant(&old, &self.authority, now)?;
            if previous.grant().owner != g.owner
                || old.upload_id != *upload
                || old.object_id != g.object_id
            {
                return Err(AttachmentLedgerError::Conflict);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
std::thread_local! { pub(super) static REFERENCE_VISITS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)}; }
