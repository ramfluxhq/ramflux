// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant account-owned retirement outbox; delivery uses authenticated source transport.
use crate::{
    SdkError,
    custody::{BornAccount, PrimaryVault},
};
use ramflux_protocol::large_attachment::{AttachmentRegistrationReceipt, AttachmentRetirement};
use ramflux_storage::{
    AccountDb, AccountIndex, NativeGrantAssociation, PendingAttachmentRetirement, StorageError,
};
fn refused<T>(_: T) -> SdkError {
    StorageError::AuthorizationRejected.into()
}
/// Source identity/key must come from the client's pinned authoritative source trust.
pub struct RetirementSource<'a> {
    pub authority: &'a str,
    pub generation: u64,
    pub signing_public_key: &'a [u8; 32],
}
/// A response received over the authenticated, request-bound source transport.
/// Pending and transport failures retain every durable delivery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetirementDeliveryStatus {
    RevocationPending,
    Retired,
}
pub struct AttachmentRetirementOutbox<'a> {
    db: &'a AccountDb,
    account: &'a BornAccount,
}
impl<'a> AttachmentRetirementOutbox<'a> {
    /// # Errors
    /// Refuses mismatched account/database authority or an unbound database path.
    pub fn new(
        db: &'a AccountDb,
        index: &AccountIndex,
        account: &'a BornAccount,
    ) -> Result<Self, SdkError> {
        let indexed = index.account(account.local_account_id())?;
        if indexed.principal_commitment != account.record().body.account_anchor
            || db.local_account_id != account.local_account_id()
            || db.path.canonicalize()?
                != index.root().join(indexed.db_relative_path).canonicalize()?
        {
            return Err(refused("account binding"));
        }
        Ok(Self { db, account })
    }
    /// Persist the authenticated message/reference association before publication.
    /// # Errors
    /// Refuses receipt/source/owner substitution, missing local ownership or sealed references.
    pub fn bind_registered(
        &self,
        message: &str,
        reference_hash: &str,
        capability: &[u8],
        source: &RetirementSource<'_>,
        now: u64,
    ) -> Result<(), SdkError> {
        let (grant, receipt) = AttachmentRegistrationReceipt::decode_capability(
            capability,
            source.authority,
            source.generation,
            source.signing_public_key,
            now,
        )
        .map_err(refused)?;
        if grant.grant().owner.account_anchor != self.account.record().body.account_anchor {
            return Err(refused("grant owner"));
        }
        self.db.bind_native_grant(
            message,
            reference_hash,
            &NativeGrantAssociation {
                grant,
                source_authority: receipt.source_authority,
                authority_generation: receipt.authority_generation,
            },
        )?;
        Ok(())
    }
    /// Atomically seal a reference and queue its complete bounded per-grant fanout.
    /// Signing/vault work happens outside the writer transaction. A concurrent bind
    /// changes the snapshot and causes refusal rather than omitting a recipient.
    /// # Errors
    /// Refuses stale owner keys, changed fanout, malformed records and storage failure.
    pub fn begin(
        &self,
        reference: &[u8; 32],
        vault: &dyn PrimaryVault,
        now: u64,
    ) -> Result<(), SdkError> {
        if self.db.native_reference_retirement_started(reference)? {
            return Ok(());
        }
        let grants = self.db.native_reference_grants(reference)?;
        let mut requests = Vec::with_capacity(grants.len());
        for association in grants {
            let g = association.grant.grant();
            let (actor, credentials) = self.account.credentials(vault, &g.owner.device_id, now)?;
            let key = &credentials.signing.signing_key;
            if actor.account_anchor != g.owner.account_anchor
                || actor.device_epoch != g.owner.device_epoch
                || key.verifying_key().to_bytes() != g.owner.signing_public_key
            {
                return Err(refused("owner key"));
            }
            let request = AttachmentRetirement {
                reference_id: *reference,
                grant_id: g.grant_id,
                grant_hash: g.hash().map_err(refused)?,
                grant_epoch: g.epoch,
                source_authority: association.source_authority,
                authority_generation: association.authority_generation,
                operation_id: ramflux_crypto::random_32()?,
                issued_at: now,
            };
            let signature: [u8; 64] = ramflux_protocol::decode_base64url(
                &ramflux_crypto::sign_canonical_bytes_with_device_branch(
                    &request.signing_bytes().map_err(refused)?,
                    &credentials.signing,
                ),
            )
            .map_err(refused)?
            .try_into()
            .map_err(refused)?;
            requests.push(
                AttachmentRetirement::verify(
                    &request.canonical_bytes().map_err(refused)?,
                    &signature,
                    &g.owner.signing_public_key,
                )
                .map_err(refused)?,
            );
        }
        self.db.enqueue_native_reference_retirement(reference, &requests)?;
        Ok(())
    }
    /// # Errors
    /// Refuses unbounded pages or corrupt durable operations. No timer clears work.
    pub fn pending(
        &self,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<PendingAttachmentRetirement>, SdkError> {
        Ok(self.db.pending_attachment_retirements(after, limit)?)
    }
    /// Apply only a request-bound response from the authenticated source, after transport verification.
    /// # Errors
    /// Refuses source/generation substitution or a response for different immutable work.
    pub fn apply_authenticated_response(
        &self,
        request: &AttachmentRetirement,
        source: &RetirementSource<'_>,
        status: RetirementDeliveryStatus,
    ) -> Result<(), SdkError> {
        if request.source_authority != source.authority
            || request.authority_generation != source.generation
        {
            return Err(refused("source binding"));
        }
        if status == RetirementDeliveryStatus::Retired {
            self.db.acknowledge_attachment_retirement(request)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
