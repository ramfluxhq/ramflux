// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Account-qualified native reference associations and immutable retirement delivery work.
use super::AccountDb;
use crate::StorageError;
use ramflux_protocol::large_attachment::{
    AttachmentRetirement, ScopedAttachmentGrant, VerifiedAttachmentRetirement, VerifiedScopedGrant,
};
use rusqlite::{OptionalExtension, params};
const MAX_GRANTS: u64 = 4096;
const MAX_REFERENCE_GRANTS: u64 = 64;
#[derive(Debug, Clone)]
pub struct NativeGrantAssociation {
    pub grant: VerifiedScopedGrant,
    pub source_authority: String,
    pub authority_generation: u64,
}
#[derive(Debug, Clone)]
pub struct PendingAttachmentRetirement {
    pub signed: VerifiedAttachmentRetirement,
}
fn invalid<T>(_: T) -> StorageError {
    StorageError::AuthorizationRejected
}
fn id(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}
impl AccountDb {
    pub(super) fn install_attachment_retirement_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS runtime_attachment_reference(
          reference_id BLOB PRIMARY KEY CHECK(length(reference_id)=32), message_id TEXT NOT NULL, reference_hash TEXT NOT NULL,
          sealed INTEGER NOT NULL DEFAULT 0 CHECK(sealed IN(0,1)), grants INTEGER NOT NULL DEFAULT 0 CHECK(grants BETWEEN 0 AND 64));
          CREATE TABLE IF NOT EXISTS runtime_attachment_grant(
          grant_id BLOB PRIMARY KEY CHECK(length(grant_id)=32), reference_id BLOB NOT NULL REFERENCES runtime_attachment_reference(reference_id),
          signed_grant BLOB NOT NULL CHECK(length(signed_grant)<=4096), source TEXT NOT NULL, generation INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS runtime_attachment_grant_reference ON runtime_attachment_grant(reference_id,grant_id);
          CREATE TABLE IF NOT EXISTS runtime_attachment_retirement(
          operation BLOB PRIMARY KEY CHECK(length(operation)=32), grant_id BLOB NOT NULL UNIQUE REFERENCES runtime_attachment_grant(grant_id),
          body BLOB NOT NULL CHECK(length(body)<=512), signature BLOB NOT NULL CHECK(length(signature)=64), signer BLOB NOT NULL CHECK(length(signer)=32),
          pending INTEGER NOT NULL CHECK(pending IN(0,1)));
          CREATE INDEX IF NOT EXISTS runtime_attachment_retirement_pending ON runtime_attachment_retirement(pending,operation);
          CREATE TABLE IF NOT EXISTS runtime_attachment_budget(singleton INTEGER PRIMARY KEY CHECK(singleton=1),grants INTEGER NOT NULL CHECK(grants BETWEEN 0 AND 4096));
          INSERT OR IGNORE INTO runtime_attachment_budget VALUES(1,0);
          CREATE TABLE IF NOT EXISTS runtime_attachment_expiry(grant_id BLOB PRIMARY KEY,expires INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS runtime_attachment_expiry_due ON runtime_attachment_expiry(expires,grant_id);")?;
        self.connection.call(|db| Ok(recount_archive(db).and_then(|()| backfill_expiry(db))))??;
        Ok(())
    }
    /// Bind only after authenticating and persisting the exact message reference.
    /// The account DB namespace plus message id and reference hash qualify this association.
    /// # Errors
    /// Refuses owner/payload/reference substitution, sealed references and bounded capacity.
    pub fn bind_native_grant(
        &self,
        message_id: &str,
        reference_hash: &str,
        association: &NativeGrantAssociation,
    ) -> Result<(), StorageError> {
        let g = association.grant.grant();
        if g.owner.account_anchor != self.principal_commitment
            || message_id.is_empty()
            || message_id.len() > 256
            || reference_hash.len() > 256
            || association.source_authority.is_empty()
            || association.source_authority.len() > 256
            || association.authority_generation == 0
            || association.authority_generation > i64::MAX as u64
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let signed = association.grant.signed_bytes().map_err(invalid)?;
        self.write_transaction(|| {
            let veto:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM object_segment_reference_veto WHERE reference_id=?1)",params![g.reference_id.as_slice()],|r|r.get(0))?;
            if veto { return Err(StorageError::ObjectErased); }
            let matched: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM object_message_reference m JOIN object_retention_reference r USING(reference_hash) JOIN object_retention_payload p USING(commitment) WHERE m.message_id=?1 AND m.reference_hash=?2 AND p.wire_id IN(?3,?4) AND p.manifest_hash IN(?5,?6))", params![message_id,reference_hash,id(&g.object_id),ramflux_protocol::encode_base64url(g.object_id),id(&g.manifest_hash),ramflux_protocol::encode_base64url(g.manifest_hash)], |r|r.get(0))?;
            if !matched { return Err(StorageError::AuthorizationRejected); }
            self.connection.execute("INSERT INTO runtime_attachment_reference(reference_id,message_id,reference_hash) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",params![g.reference_id.as_slice(),message_id,reference_hash])?;
            let (message, reference, sealed, count):(String,String,bool,u64) = self.connection.query_row("SELECT message_id,reference_hash,sealed,grants FROM runtime_attachment_reference WHERE reference_id=?1",params![g.reference_id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            if message!=message_id || reference!=reference_hash { return Err(StorageError::AuthorizationRejected); }
            let old: Option<(Vec<u8>,String,u64)> = self.connection.query_row("SELECT signed_grant,source,generation FROM runtime_attachment_grant WHERE grant_id=?1",params![g.grant_id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some(old) = old { return if old == (signed.clone(),association.source_authority.clone(),association.authority_generation) && !sealed { Ok(()) } else { Err(StorageError::AuthorizationRejected) }; }
            let total:u64=self.connection.query_row("SELECT grants FROM runtime_attachment_budget WHERE singleton=1",[],|r|r.get(0))?;
            if sealed || count>=MAX_REFERENCE_GRANTS || total>=MAX_GRANTS { return Err(StorageError::AuthorizationRejected); }
            self.connection.execute("INSERT INTO runtime_attachment_grant VALUES(?1,?2,?3,?4,?5)",params![g.grant_id.as_slice(),g.reference_id.as_slice(),signed,association.source_authority,association.authority_generation])?;
            self.connection.execute("UPDATE runtime_attachment_reference SET grants=grants+1 WHERE reference_id=?1",params![g.reference_id.as_slice()])?;
            self.connection.execute("UPDATE runtime_attachment_budget SET grants=grants+1 WHERE singleton=1",[])?;
            self.connection.execute("INSERT INTO runtime_attachment_expiry VALUES(?1,?2)",params![g.grant_id.as_slice(),g.expires_at])?;
            Ok(())
        })
    }
    /// # Errors
    /// Returns storage errors; a missing reference has no durable retirement intent.
    pub fn native_reference_retirement_started(
        &self,
        reference: &[u8; 32],
    ) -> Result<bool, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT sealed FROM runtime_attachment_reference WHERE reference_id=?1",
                params![reference.as_slice()],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false))
    }
    /// Bounded fanout snapshot; sealing below revalidates the complete snapshot atomically.
    /// # Errors
    /// Refuses unavailable, malformed or oversized persisted state.
    pub fn native_reference_grants(
        &self,
        reference: &[u8; 32],
    ) -> Result<Vec<NativeGrantAssociation>, StorageError> {
        let mut query=self.connection.prepare("SELECT signed_grant,source,generation FROM runtime_attachment_grant WHERE reference_id=?1 ORDER BY grant_id LIMIT 65")?;
        let rows = query
            .query_map(params![reference.as_slice()], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?, r.get::<_, u64>(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() > 64 {
            return Err(StorageError::AuthorizationRejected);
        }
        rows.into_iter()
            .map(|(bytes, source_authority, authority_generation)| {
                Ok(NativeGrantAssociation {
                    grant: ScopedAttachmentGrant::decode_signed(&bytes).map_err(invalid)?,
                    source_authority,
                    authority_generation,
                })
            })
            .collect()
    }
    /// Persist every per-grant operation and seal against concurrent registration in one FULL transaction.
    /// # Errors
    /// Refuses missing/extra/substituted fanout entries or changed immutable operations.
    pub fn enqueue_native_reference_retirement(
        &self,
        reference: &[u8; 32],
        requests: &[VerifiedAttachmentRetirement],
    ) -> Result<(), StorageError> {
        if requests.is_empty() || requests.len() > 64 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            let grants=self.native_reference_grants(reference)?;
            if grants.len()!=requests.len() { return Err(StorageError::AuthorizationRejected); }
            let mut seen=std::collections::BTreeSet::new();
            for signed in requests {
                let r=signed.request();
                let a=grants.iter().find(|g| g.grant.grant().grant_id==r.grant_id).ok_or(StorageError::AuthorizationRejected)?;
                let g=a.grant.grant();
                if !seen.insert(r.grant_id) || r.reference_id!=*reference || r.grant_hash!=g.hash().map_err(invalid)? || r.grant_epoch!=g.epoch || r.source_authority!=a.source_authority || r.authority_generation!=a.authority_generation { return Err(StorageError::AuthorizationRejected); }
                let body=r.canonical_bytes().map_err(invalid)?;
                let old:Option<Vec<u8>>=self.connection.query_row("SELECT body FROM runtime_attachment_retirement WHERE operation=?1",params![r.operation_id.as_slice()],|r|r.get(0)).optional()?;
                if old.as_ref().is_some_and(|old| *old!=body) { return Err(StorageError::AuthorizationRejected); }
                self.connection.execute("INSERT INTO runtime_attachment_retirement VALUES(?1,?2,?3,?4,?5,1) ON CONFLICT(operation) DO NOTHING",params![r.operation_id.as_slice(),r.grant_id.as_slice(),body,signed.signature().as_slice(),signed.signer().as_slice()])?;
            }
            self.connection.execute("UPDATE runtime_attachment_reference SET sealed=1 WHERE reference_id=?1",params![reference.as_slice()])?;
            Ok(())
        })
    }
    /// Keyset page of durable work; failures and Pending responses leave it queued.
    /// # Errors
    /// Refuses unbounded pages or corrupt signature evidence.
    pub fn pending_attachment_retirements(
        &self,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<PendingAttachmentRetirement>, StorageError> {
        if limit == 0 || limit > 64 {
            return Err(StorageError::AuthorizationRejected);
        }
        let cursor = after.map_or(&[][..], |v| v.as_slice());
        let mut query=self.connection.prepare("SELECT body,signature,signer FROM runtime_attachment_retirement WHERE pending=1 AND operation>?1 ORDER BY operation LIMIT ?2")?;
        let rows = query
            .query_map(params![cursor, limit as u64], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(body, sig, key)| {
                Ok(PendingAttachmentRetirement {
                    signed: AttachmentRetirement::verify(
                        &body,
                        &sig.try_into().map_err(invalid)?,
                        &key.try_into().map_err(invalid)?,
                    )
                    .map_err(invalid)?,
                })
            })
            .collect()
    }
    /// Call only after a Retired response from the authenticated named source/generation.
    /// A transport timeout or `RevocationPending` must never call this method.
    /// # Errors
    /// Refuses mismatched request identity or a missing durable operation.
    pub fn acknowledge_attachment_retirement(
        &self,
        request: &AttachmentRetirement,
    ) -> Result<(), StorageError> {
        let body = request.canonical_bytes().map_err(invalid)?;
        self.write_transaction(|| {
            let changed = self.connection.execute(
                "UPDATE runtime_attachment_retirement SET pending=0 WHERE operation=?1 AND body=?2",
                params![request.operation_id.as_slice(), body],
            )?;
            if changed != 1 {
                return Err(StorageError::AuthorizationRejected);
            }
            Ok(())
        })
    }
}
#[cfg(test)]
mod tests;

/// Target rows are authoritative. Incoming grants/work/counters are never unioned.
pub(super) fn recount_archive(db: &rusqlite::Connection) -> Result<(), StorageError> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='runtime_attachment_grant')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(());
    }
    db.execute_batch("UPDATE runtime_attachment_reference SET grants=(SELECT count(*) FROM runtime_attachment_grant g WHERE g.reference_id=runtime_attachment_reference.reference_id); UPDATE runtime_attachment_budget SET grants=(SELECT count(*) FROM runtime_attachment_grant) WHERE singleton=1;")?;
    Ok(())
}
impl AccountDb {
    /// Bounded reclamation. An expired signed grant needs no server retirement ACK.
    /// # Errors
    /// Refuses invalid bounds and corrupt durable work.
    pub fn gc_attachment_retirements(&self, now: u64, limit: usize) -> Result<usize, StorageError> {
        if limit == 0 || limit > 64 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            let mut q=self.connection.prepare("SELECT grant_id FROM runtime_attachment_retirement WHERE pending=0 ORDER BY operation LIMIT ?1")?;
            let mut ids=q.query_map(params![limit],|r|r.get::<_,Vec<u8>>(0))?.collect::<Result<Vec<_>,_>>()?;
            drop(q);
            let mut q=self.connection.prepare("SELECT grant_id FROM runtime_attachment_expiry WHERE expires<=?1 ORDER BY expires,grant_id LIMIT ?2")?;
            ids.extend(q.query_map(params![now,limit-ids.len()],|r|r.get::<_,Vec<u8>>(0))?.collect::<Result<Vec<_>,_>>()?);
            let mut count=0;
            for id in ids {
                let reference:Option<Vec<u8>>=self.connection.query_row("SELECT reference_id FROM runtime_attachment_grant WHERE grant_id=?1",params![id],|r|r.get(0)).optional()?;
                self.connection.execute("DELETE FROM runtime_attachment_retirement WHERE grant_id=?1",params![id])?;
                self.connection.execute("DELETE FROM runtime_attachment_expiry WHERE grant_id=?1",params![id])?;
                if let Some(reference)=reference {
                    self.connection.execute("DELETE FROM runtime_attachment_grant WHERE grant_id=?1",params![id])?;
                    self.connection.execute("UPDATE runtime_attachment_reference SET grants=grants-1 WHERE reference_id=?1",params![reference])?;
                    self.connection.execute("UPDATE runtime_attachment_budget SET grants=grants-1 WHERE singleton=1",[])?;
                    count+=1;
                }
            }
            Ok(count)
        })
    }
    /// Persist replacement current-device signature without changing immutable intent.
    /// # Errors
    /// Refuses changed body or missing work.
    pub fn refresh_attachment_retirement_signature(
        &self,
        signed: &VerifiedAttachmentRetirement,
    ) -> Result<(), StorageError> {
        let r = signed.request();
        let body = r.canonical_bytes().map_err(invalid)?;
        self.write_transaction(|| {
            if self.connection.execute("UPDATE runtime_attachment_retirement SET signature=?3,signer=?4 WHERE operation=?1 AND body=?2 AND pending=1",params![r.operation_id.as_slice(),body,signed.signature().as_slice(),signed.signer().as_slice()])?!=1 { return Err(StorageError::AuthorizationRejected); } Ok(())
        })
    }
}

fn backfill_expiry(db: &rusqlite::Connection) -> Result<(), StorageError> {
    let mut after = Vec::new();
    loop {
        let mut q=db.prepare("SELECT g.grant_id,g.signed_grant FROM runtime_attachment_grant g WHERE g.grant_id>?1 AND NOT EXISTS(SELECT 1 FROM runtime_attachment_expiry e WHERE e.grant_id=g.grant_id) ORDER BY g.grant_id LIMIT 64")?;
        let rows = q
            .query_map(params![after], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.is_empty() {
            break;
        }
        for (id, bytes) in rows {
            after.clone_from(&id);
            let grant = ScopedAttachmentGrant::decode_signed(&bytes).map_err(invalid)?;
            db.execute(
                "INSERT INTO runtime_attachment_expiry VALUES(?1,?2)",
                params![id, grant.grant().expires_at],
            )?;
        }
    }
    Ok(())
}
