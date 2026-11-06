// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Durable scoped registration; operation admission and retirement are separate owners.
mod admission;
use super::{
    AttachmentLedger, AttachmentLedgerError, AttachmentOwner, AttachmentReservation,
    AttachmentReservationState, RECORDS, ReadableDatabase, ReadableTable, deadline, decode, encode,
    key, store,
};
use crate::{
    GatewayIssuerCertificate, ObjectRelayCapability, RelayInvocationV3, RelayTrustSnapshotCache,
    verify_relay_invocation_v3, verify_relay_token_v3_with_trust_snapshot,
};
pub use admission::SCOPED_GRANTS_PER_OWNER_MAX;
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::large_attachment::{
    AttachmentRegistrationReceipt, VerifiedContentManifest, VerifiedScopedGrant,
};
use redb::{ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
const GRANTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_scoped_grants_v1");
const EXPIRY: TableDefinition<&[u8], ()> =
    TableDefinition::new("native_attachment_scoped_expiry_v1");
const CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("native_attachment_authority_v1");
const REFERENCES: TableDefinition<&[u8], ()> =
    TableDefinition::new("native_attachment_scoped_references_v1");
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentAuthority {
    pub source: String,
    pub generation: u64,
    pub signing_public_key: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopedGrantState {
    Active,
    Retiring,
    Retired,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredAttachmentGrant {
    pub state: ScopedGrantState,
    pub capability: String,
    pub upload_id: [u8; 32],
    pub object_id: [u8; 32],
    pub reference_id: [u8; 32],
    pub expires_at: u64,
}
pub struct ScopedGrantRegistry {
    ledger: AttachmentLedger,
    authority: AttachmentAuthority,
}
/// Existing gateway-attested owner-session verification, with a pinned cache.
/// This is not native operation `PoP` admission or a substitute for the replay ledger.
pub struct ScopedRegistrationAuth<'a> {
    pub invocation: RelayInvocationV3<'a>,
    pub certificate: &'a GatewayIssuerCertificate,
    pub pinned_trust: &'a RelayTrustSnapshotCache,
}
pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), AttachmentLedgerError> {
    let _ = tx.open_table(GRANTS).map_err(store)?;
    let _ = tx.open_table(EXPIRY).map_err(store)?;
    let _ = tx.open_table(CONFIG).map_err(store)?;
    let _ = tx.open_table(REFERENCES).map_err(store)?;
    admission::install(tx)?;
    Ok(())
}
fn invalid(_: impl std::fmt::Display) -> AttachmentLedgerError {
    AttachmentLedgerError::Conflict
}
fn hex(bytes: &[u8]) -> String {
    super::backend::hex(bytes)
}
impl AttachmentLedger {
    /// Opens the one persisted authority configuration; changes require external fencing.
    /// # Errors
    /// Refuses invalid or conflicting authority/generation/key configuration.
    pub fn scoped_grants(
        &self,
        authority: AttachmentAuthority,
    ) -> Result<ScopedGrantRegistry, AttachmentLedgerError> {
        if authority.source.is_empty()
            || authority.source.len() > 256
            || authority.generation == 0
            || ed25519_dalek::VerifyingKey::from_bytes(&authority.signing_public_key).is_err()
        {
            return Err(AttachmentLedgerError::Invalid);
        }
        let tx = self.db.begin_write().map_err(store)?;
        {
            let mut config = tx.open_table(CONFIG).map_err(store)?;
            if let Some(value) = config.get("source").map_err(store)? {
                let old: AttachmentAuthority = decode(value.value())?;
                if old != authority {
                    return Err(AttachmentLedgerError::Conflict);
                }
            }
            config.insert("source", encode(&authority)?.as_slice()).map_err(store)?;
        }
        tx.commit().map_err(store)?;
        Ok(ScopedGrantRegistry { ledger: self.clone(), authority })
    }
}
impl ScopedGrantRegistry {
    fn authenticate(
        &self,
        grant: &VerifiedScopedGrant,
        native: &VerifiedContentManifest,
        auth: &ScopedRegistrationAuth<'_>,
    ) -> Result<(), AttachmentLedgerError> {
        let ctx = &auth.invocation;
        let owner = &native.manifest().owner;
        let t = ctx.token;
        if ctx.capability != ObjectRelayCapability::Put
            || ctx.expected_audience_node_id != self.authority.source
            || ctx.expected_body_hash != hex(&grant.grant().hash().map_err(invalid)?)
            || ctx.issuer_public_key != auth.certificate.attestation_public_key
            || t.issuer_node_id != owner.home_node_id
            || t.owner_principal_id != owner.account_anchor
            || t.owner_home_node_id != owner.home_node_id
            || t.owner_signing_key_id != owner.device_id
            || t.owner_device_epoch != owner.device_epoch
            || t.requester_device_epoch != owner.device_epoch
            || t.owner_public_key != ramflux_protocol::encode_base64url(owner.signing_public_key)
            || t.object_id != hex(&native.manifest().object_id)
            || t.manifest_hash != hex(&native.manifest().hash().map_err(invalid)?)
        {
            return Err(AttachmentLedgerError::Conflict);
        }
        let snapshot = auth.pinned_trust.current(&t.issuer_node_id, ctx.now).map_err(invalid)?;
        verify_relay_token_v3_with_trust_snapshot(
            t,
            auth.certificate,
            snapshot,
            ctx.capability,
            ctx.expected_audience_node_id,
            ctx.now,
        )
        .map_err(invalid)?;
        verify_relay_invocation_v3(ctx).map_err(invalid)
    }
    /// Registers one immutable owner-signed grant against the committed native payload.
    /// Duplicate registration cannot slide expiry or revive a non-Active grant.
    /// # Errors
    /// Refuses unauthenticated/current-owner mismatch, substitution, expiry and capacity.
    pub fn register(
        &self,
        upload_id: &[u8; 32],
        native: &VerifiedContentManifest,
        grant: &VerifiedScopedGrant,
        auth: &ScopedRegistrationAuth<'_>,
        signer: &SigningKey,
    ) -> Result<RegisteredAttachmentGrant, AttachmentLedgerError> {
        self.authenticate(grant, native, auth)?;
        let now = auth.invocation.now;
        let g = grant.grant();
        let m = native.manifest();
        if signer.verifying_key().to_bytes() != self.authority.signing_public_key
            || g.owner != m.owner
            || g.object_id != m.object_id
            || g.manifest_hash != m.hash().map_err(invalid)?
            || g.epoch != 1
            || now.saturating_add(5) < g.issued_at
            || now >= g.expires_at
        {
            return Err(AttachmentLedgerError::Conflict);
        }
        let owner = AttachmentOwner::from_authenticated_session(&m.owner.account_anchor)?;
        let tx = self.ledger.db.begin_write().map_err(store)?;
        clock(&tx, now)?;
        let payload: AttachmentReservation = {
            let records = tx.open_table(RECORDS).map_err(store)?;
            let value = records
                .get(key(&owner, upload_id).as_slice())
                .map_err(store)?
                .ok_or(AttachmentLedgerError::Conflict)?;
            decode(value.value())?
        };
        let expiry = payload.expires_at.ok_or(AttachmentLedgerError::State)?;
        if payload.state != AttachmentReservationState::Committed
            || payload.object_id != g.object_id
            || payload.manifest_hash != Some(g.manifest_hash)
            || now >= expiry
        {
            return Err(AttachmentLedgerError::Expired);
        }
        self.check_reference(&tx, grant, upload_id, now)?;
        let mut rows = tx.open_table(GRANTS).map_err(store)?;
        if let Some(value) = rows.get(g.grant_id.as_slice()).map_err(store)? {
            if value.value().len() > 32 * 1024 {
                return Err(AttachmentLedgerError::State);
            }
            let old: RegisteredAttachmentGrant = decode(value.value())?;
            if old.state != ScopedGrantState::Active {
                return Err(AttachmentLedgerError::State);
            }
            let bytes = ramflux_protocol::decode_base64url(&old.capability).map_err(invalid)?;
            let (old_grant, _) = AttachmentRegistrationReceipt::decode_capability(
                &bytes,
                &self.authority.source,
                self.authority.generation,
                &self.authority.signing_public_key,
                now,
            )
            .map_err(invalid)?;
            if old.upload_id != *upload_id || old_grant.grant() != g {
                return Err(AttachmentLedgerError::Conflict);
            }
            return Ok(old);
        }
        if rows.len().map_err(store)? >= 16_384 {
            return Err(AttachmentLedgerError::Capacity);
        }
        admission::check_owner(&tx, &g.owner.account_anchor)?;
        let receipt = AttachmentRegistrationReceipt {
            grant_hash: g.hash().map_err(invalid)?,
            grant_epoch: g.epoch,
            source_authority: self.authority.source.clone(),
            authority_generation: self.authority.generation,
            expires_at: g.expires_at.min(expiry),
        };
        let signature = signer.sign(&receipt.signing_bytes().map_err(invalid)?).to_bytes();
        let capability = receipt
            .capability(grant, &signature, &self.authority.signing_public_key)
            .map_err(invalid)?;
        let row = RegisteredAttachmentGrant {
            state: ScopedGrantState::Active,
            capability: ramflux_protocol::encode_base64url(&capability),
            upload_id: *upload_id,
            object_id: g.object_id,
            reference_id: g.reference_id,
            expires_at: receipt.expires_at,
        };
        admission::record(&tx, &g.grant_id, &g.owner.account_anchor)?;
        rows.insert(g.grant_id.as_slice(), encode(&row)?.as_slice()).map_err(store)?;
        let until = g.expires_at.checked_add(305).ok_or(AttachmentLedgerError::Invalid)?;
        tx.open_table(EXPIRY)
            .map_err(store)?
            .insert(deadline(until, &g.grant_id).as_slice(), ())
            .map_err(store)?;
        let mut reference = g.reference_id.to_vec();
        reference.extend(g.grant_id);
        tx.open_table(REFERENCES)
            .map_err(store)?
            .insert(reference.as_slice(), ())
            .map_err(store)?;
        drop(rows);
        tx.commit().map_err(store)?;
        Ok(row)
    }
    /// Private worker lookup; a stored receipt is never operation-admission authority.
    /// # Errors
    /// Refuses unavailable or corrupt durable state.
    pub fn lookup(
        &self,
        id: &[u8; 32],
    ) -> Result<Option<RegisteredAttachmentGrant>, AttachmentLedgerError> {
        let tx = self.ledger.db.begin_read().map_err(store)?;
        let table = tx.open_table(GRANTS).map_err(store)?;
        table
            .get(id.as_slice())
            .map_err(store)?
            .map(|v| {
                if v.value().len() > 32 * 1024 {
                    return Err(AttachmentLedgerError::State);
                }
                decode(v.value())
            })
            .transpose()
    }
    /// Expires registration evidence only after all grant/token authority has expired.
    /// # Errors
    /// Refuses unbounded work and corrupt storage.
    pub fn gc_expired(&self, now: u64, limit: usize) -> Result<usize, AttachmentLedgerError> {
        if limit == 0 || limit > 64 {
            return Err(AttachmentLedgerError::Invalid);
        }
        let tx = self.ledger.db.begin_write().map_err(store)?;
        clock(&tx, now)?;
        let mut index = tx.open_table(EXPIRY).map_err(store)?;
        let mut upper = now.to_be_bytes().to_vec();
        upper.extend([255; 32]);
        let keys = index
            .range(..=upper.as_slice())
            .map_err(store)?
            .take(limit)
            .map(|e| e.map(|(k, _)| k.value().to_vec()).map_err(store))
            .collect::<Result<Vec<_>, _>>()?;
        let mut rows = tx.open_table(GRANTS).map_err(store)?;
        let mut refs = tx.open_table(REFERENCES).map_err(store)?;
        for k in &keys {
            let id = k.get(8..).ok_or(AttachmentLedgerError::State)?;
            let row: RegisteredAttachmentGrant = {
                let v = rows.get(id).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
                decode(v.value())?
            };
            let mut reference = row.reference_id.to_vec();
            reference.extend(id);
            refs.remove(reference.as_slice()).map_err(store)?;
            admission::release(&tx, id)?;
            rows.remove(id).map_err(store)?;
            index.remove(k.as_slice()).map_err(store)?;
        }
        let count = keys.len();
        drop(refs);
        drop(rows);
        drop(index);
        tx.commit().map_err(store)?;
        Ok(count)
    }
}
#[cfg(test)]
mod tests;

fn clock(tx: &redb::WriteTransaction, now: u64) -> Result<(), AttachmentLedgerError> {
    let mut table = tx.open_table(CONFIG).map_err(store)?;
    let before = table.get("clock_fence").map_err(store)?.map(|v| v.value().to_vec());
    let before = before
        .map(|v| v.try_into().map(u64::from_be_bytes).map_err(|_| AttachmentLedgerError::State))
        .transpose()?
        .unwrap_or(0);
    if now.saturating_add(5) < before {
        return Err(AttachmentLedgerError::State);
    }
    table.insert("clock_fence", now.max(before).to_be_bytes().as_slice()).map_err(store)?;
    Ok(())
}
