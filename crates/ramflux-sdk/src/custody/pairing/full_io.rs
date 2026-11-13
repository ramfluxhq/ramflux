// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private local data I/O. Requests are not bus JSON and confer no signing/publication right.
use super::transport::wire;
use crate::{SdkError, custody};
use ramflux_crypto::custody::pairing::{FullResumeTrust, PairingRole};
use ramflux_protocol::custody::pairing::full_transfer::{
    CHUNK_BYTES, Family, Manifest, SourceManifest, chunk_digest,
};
use ramflux_storage::{
    AccountDb, AccountIndex, FullStageIoCancel, FullTransferStage, full_transfer_catalog,
};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

mod application;
mod rebind;
mod reverse;
mod source_delta;
pub use application::FullApplicationDraft;
pub use source_delta::FullDeltaManifestDraft;
mod port;
pub use port::{FullLocalIoLoan, FullLocalIoPort, FullLocalIoService};

#[derive(Clone)]
struct FullLocalIoScope {
    root: PathBuf,
    account: String,
    anchor: String,
    operation: String,
    generation: u64,
    role: PairingRole,
    digest: [u8; 32],
    transfer_id: String,
    base_manifest_hash: String,
    destination_key: String,
    source_key: String,
    lease_expires_at: u64,
    cancelled: FullStageIoCancel,
    unlocked: Arc<ramflux_storage::FullLocalUnlockGuard>,
    runtime: Arc<super::coordinator::FullRuntimeCancel>,
}
impl FullLocalIoScope {
    fn new(
        participant: &super::LocalPairingParticipant,
        db: &AccountDb,
        operation: (String, u64),
        trust: &FullResumeTrust,
        cancelled: FullStageIoCancel,
        runtime: Arc<super::coordinator::FullRuntimeCancel>,
    ) -> Result<Self, SdkError> {
        let record = trust.local_stage_record()?;
        Ok(Self {
            root: std::fs::canonicalize(&participant.root)?,
            account: participant.account_id.clone(),
            anchor: record.grant.source_ref.account_anchor.clone(),
            operation: operation.0,
            generation: operation.1,
            role: record.role,
            digest: record.stage_digest()?,
            base_manifest_hash: record.base_manifest_hash,
            transfer_id: record.transfer_id,
            lease_expires_at: trust.lease_expires_at().min(record.grant.expires_at),
            destination_key: record.grant.branch_keys.destination,
            source_key: record.grant.branch_keys.source,
            cancelled,
            runtime,
            unlocked: Arc::new(db.full_local_unlock_guard()?),
        })
    }
    fn require_db(&self, db: &AccountDb) -> Result<ramflux_storage::LiveRow, SdkError> {
        self.live()?;
        if db.local_account_id != self.account {
            return Err(wrong());
        }
        let index = AccountIndex::open(&self.root)?;
        let selected = index.account(&self.account)?;
        if selected.account_state == "removed"
            || selected.principal_commitment != self.anchor
            || std::fs::canonicalize(&db.path)?
                != std::fs::canonicalize(self.root.join(selected.db_relative_path))?
        {
            return Err(wrong());
        }
        let row = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == self.operation)
            .ok_or_else(wrong)?;
        let reference = row.full_stage_reference()?.ok_or_else(wrong)?;
        if row.generation != self.generation
            || row.role != self.role.as_str()
            || reference.stage_id != self.transfer_id
            || reference.record_digest != ramflux_protocol::encode_base64url(self.digest)
            || reference.lease_expires_at.0 != self.lease_expires_at
            || matches!(row.phase.as_str(), "completed" | "cancelled" | "expired" | "rejected")
        {
            return Err(wrong());
        }
        Ok(row)
    }
    fn request(&self, action: FullLocalAction) -> FullLocalIoRequest {
        FullLocalIoRequest { scope: self.clone(), action }
    }
    fn live(&self) -> Result<(), SdkError> {
        self.runtime.require_live()?;
        if custody::network_now()? >= self.lease_expires_at {
            return Err(SdkError::PairingCode("LeaseExpired"));
        }
        self.unlocked.require_unlocked()?;
        if self.cancelled.is_cancelled() { Err(SdkError::PairingCode("Retired")) } else { Ok(()) }
    }
}
/// No Debug/serde/clone: chunk plaintext cannot escape through generic status/events.
struct FullLocalIoRequest {
    scope: FullLocalIoScope,
    action: FullLocalAction,
}
enum FullLocalAction {
    Rebind(rebind::Action),
    ReceiverReplay { copy: Box<ramflux_storage::FullReceiverBaseCopy>, hash: String },
    Reverse(reverse::Action),
    VerifyDuplex(Option<Box<ramflux_storage::FullReceiverBaseCopy>>),
    PreparedDuplex,
    RetainedReverseReceipt,
    Semantic(application::Action),
    SourceDelta(source_delta::Action),
    ProjectReceiverDelta { copy: Box<ramflux_storage::FullReceiverBaseCopy>, hash: String },
    ObservePrepublication(Box<ramflux_crypto::custody::VerifiedRecord>),
    ReadSourceChunk { hash: String, index: u64 },
    PrepareEmptyReverse,
    RetainReverseManifest { manifest: Box<SourceManifest> },
    RetainManifest { manifest: Box<SourceManifest> },
    RetainChunk { hash: String, index: u64, digest: [u8; 32], bytes: Zeroizing<Vec<u8>> },
    VerifyForwardRoot { hash: String },
    PinReceiverBase { hash: String },
    ProjectReceiverBase { copy: Box<ramflux_storage::FullReceiverBaseCopy> },
}
struct FullLocalIoReply(FullLocalResult);
enum FullLocalResult {
    Rebind(rebind::Applied),
    ReceiverReplay(Box<ramflux_storage::FullReceiverReplayWork>),
    Reverse(reverse::Applied),
    Duplex(ramflux_storage::FullDuplexReceipt, Option<Box<ramflux_storage::FullReceiverBaseCopy>>),
    ReverseReceipt(Box<ramflux_protocol::custody::pairing::full_transfer::DataPacket>),
    Semantic(application::Applied),
    SourceDelta(source_delta::Applied),
    NativeObserved { current_hash: String, bound_hash: String },
    SourceChunk(Zeroizing<Vec<u8>>),
    UnsignedReverse(Box<Manifest>),
    ReverseManifestRetained,
    DurablePrefix(Option<u64>),
    ForwardRootChecked,
    ReceiverPinned(Box<ramflux_storage::FullPinnedReceiverBase>),
    ReceiverProjected(Box<ramflux_storage::FullReceiverBaseCopy>),
}
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
impl FullLocalIoRequest {
    /// The owner chooses its actual current account; no DB key or stage key leaves this call.
    /// Semantic receipts require their durable typed application; no result is approval.
    fn apply(self, db: &AccountDb) -> Result<FullLocalIoReply, SdkError> {
        let _local = self.scope.runtime.local_work()?;
        let row = self.scope.require_db(db)?;
        if matches!(
            &self.action,
            FullLocalAction::PrepareEmptyReverse
                | FullLocalAction::Reverse(
                    reverse::Action::PrepareSource
                        | reverse::Action::AcceptSource(_)
                        | reverse::Action::RetainChunk { .. }
                        | reverse::Action::Prefix(_)
                        | reverse::Action::Validate(_)
                        | reverse::Action::AcceptInput(_)
                        | reverse::Action::Merge(_)
                )
                | FullLocalAction::Rebind(_)
                | FullLocalAction::ReceiverReplay { .. }
                | FullLocalAction::SourceDelta(_)
                | FullLocalAction::ProjectReceiverDelta { .. }
                | FullLocalAction::Semantic(
                    application::Action::RetainReplay(_)
                        | application::Action::Prepare(_)
                        | application::Action::Record { .. }
                        | application::Action::PrepareReverse
                        | application::Action::RecordReverse { .. }
                )
        ) && (row.phase != "mutually_confirmed"
            || row.candidate_id.is_some()
            || row.proposal_hash.is_some())
        {
            return Err(wrong());
        }
        if matches!(
            &self.action,
            FullLocalAction::PreparedDuplex | FullLocalAction::RetainedReverseReceipt
        ) {
            let head = db.pairing_head()?.ok_or_else(wrong)?;
            if row.phase != "prepared"
                || head.state != "prepared"
                || head.kind != "transfer"
                || head.operation_id != self.scope.operation
                || head.generation != self.scope.generation
                || row.proposal_hash.as_deref() != Some(head.candidate_hash.as_str())
            {
                return Err(wrong());
            }
        }
        let mut stage = db.open_full_transfer_stage(
            &self.scope.operation,
            self.scope.role,
            custody::network_now()?,
        )?;
        stage.bind_local_io_cancellation(&self.scope.cancelled)?;
        if stage.resume_record()?.stage_digest()? != self.scope.digest {
            return Err(wrong());
        }
        let result = apply_action(self.action, &self.scope, stage)?;
        self.scope.require_db(db)?;
        Ok(FullLocalIoReply(result))
    }
}

fn verified_duplex(
    scope: &FullLocalIoScope,
    stage: &FullTransferStage<'_>,
    copy: Option<Box<ramflux_storage::FullReceiverBaseCopy>>,
) -> Result<FullLocalResult, SdkError> {
    if (scope.role == PairingRole::Responder) != copy.is_some() {
        return Err(wrong());
    }
    if let Some(copy) = &copy {
        copy.require_materialized_generation(stage)?;
    }
    Ok(FullLocalResult::Duplex(stage.verified_duplex(custody::network_now()?)?, copy))
}

fn apply_action(
    action: FullLocalAction,
    scope: &FullLocalIoScope,
    mut stage: FullTransferStage<'_>,
) -> Result<FullLocalResult, SdkError> {
    Ok(match action {
        FullLocalAction::ReceiverReplay { copy, hash } => {
            if scope.role != PairingRole::Responder {
                return Err(wrong());
            }
            FullLocalResult::ReceiverReplay(Box::new(stage.into_receiver_replay_through(
                *copy,
                &hash,
                custody::network_now()?,
            )?))
        }
        FullLocalAction::Rebind(action) => {
            FullLocalResult::Rebind(rebind::apply(action, scope, &mut stage)?)
        }
        FullLocalAction::Reverse(action) => {
            FullLocalResult::Reverse(reverse::apply(action, scope, stage)?)
        }
        FullLocalAction::RetainedReverseReceipt => FullLocalResult::ReverseReceipt(Box::new(
            stage.retained_reverse_data_verified(custody::network_now()?)?,
        )),
        FullLocalAction::PreparedDuplex => {
            FullLocalResult::Duplex(stage.verified_duplex(custody::network_now()?)?, None)
        }
        FullLocalAction::VerifyDuplex(copy) => verified_duplex(scope, &stage, copy)?,
        FullLocalAction::SourceDelta(action) => {
            FullLocalResult::SourceDelta(source_delta::apply(action, scope, stage)?)
        }
        FullLocalAction::ProjectReceiverDelta { mut copy, hash } => {
            if scope.role != PairingRole::Responder {
                return Err(wrong());
            }
            copy.project_delta(&stage, &hash)?;
            FullLocalResult::ReceiverProjected(copy)
        }
        FullLocalAction::Semantic(action) => {
            FullLocalResult::Semantic(application::apply(action, scope, &mut stage)?)
        }
        FullLocalAction::ObservePrepublication(current) => {
            observe_prepublication(&mut stage, &current)?
        }
        FullLocalAction::PrepareEmptyReverse => {
            if scope.role != PairingRole::Responder {
                return Err(wrong());
            }
            FullLocalResult::UnsignedReverse(Box::new(stage.prepare_empty_reverse_manifest()?))
        }
        FullLocalAction::RetainReverseManifest { manifest } => {
            let catalog = full_transfer_catalog()
                .iter()
                .map(ramflux_storage::FamilyRule::manifest_family)
                .collect::<Result<Vec<_>, _>>()?;
            stage.retain_reverse_manifest(&manifest, &catalog)?;
            FullLocalResult::ReverseManifestRetained
        }
        FullLocalAction::ReadSourceChunk { hash, index } => {
            if scope.role != PairingRole::Initiator {
                return Err(wrong());
            }
            FullLocalResult::SourceChunk(stage.read_source_wire_chunk(&hash, index)?)
        }
        FullLocalAction::RetainManifest { manifest } => {
            if scope.role != PairingRole::Responder {
                return Err(wrong());
            }
            retain_forward_manifest(&mut stage, &manifest)?
        }
        FullLocalAction::RetainChunk { hash, index, digest, bytes } => {
            if scope.role != PairingRole::Responder
                || bytes.len() > CHUNK_BYTES as usize
                || chunk_digest(index, &bytes).map_err(|error| wire(&error))? != digest
            {
                return Err(wrong());
            }
            stage.retain_forward_chunk(&hash, index, &bytes)?;
            FullLocalResult::DurablePrefix(stage.revalidate_forward_prefix(&hash)?)
        }
        FullLocalAction::PinReceiverBase { hash } => {
            if scope.role != PairingRole::Responder {
                return Err(wrong());
            }
            FullLocalResult::ReceiverPinned(Box::new(stage.pin_receiver_base(&hash)?))
        }
        FullLocalAction::ProjectReceiverBase { mut copy } => {
            if scope.role != PairingRole::Responder {
                return Err(wrong());
            }
            copy.project(&stage)?;
            FullLocalResult::ReceiverProjected(copy)
        }
        FullLocalAction::VerifyForwardRoot { hash } => {
            if scope.role != PairingRole::Responder {
                return Err(wrong());
            }
            stage.verify_forward_root(&hash)?;
            FullLocalResult::ForwardRootChecked
        }
    })
}

fn observe_prepublication(
    stage: &mut FullTransferStage<'_>,
    current: &ramflux_crypto::custody::VerifiedRecord,
) -> Result<FullLocalResult, SdkError> {
    // Retain rollback/revocation/fork observations before testing the current role.
    stage.observe_full_native_head(current)?;
    ramflux_crypto::custody::pairing::verify_full_prepublication_authority(
        &stage.resume_record()?.grant,
        current,
        custody::network_now()?,
    )?;
    Ok(FullLocalResult::NativeObserved {
        current_hash: ramflux_protocol::custody::object_hash(current.envelope())?,
        bound_hash: stage.full_prepublication_record_hash()?,
    })
}

fn retain_forward_manifest(
    stage: &mut ramflux_storage::FullTransferStage<'_>,
    manifest: &SourceManifest,
) -> Result<FullLocalResult, SdkError> {
    if manifest.manifest.census_hash
        != ramflux_protocol::encode_base64url(ramflux_storage::full_census_hash(
            full_transfer_catalog(),
        )?)
    {
        return Err(SdkError::PairingCode("SchemaMismatch"));
    }
    let catalog: Vec<Family> = full_transfer_catalog()
        .iter()
        .map(ramflux_storage::FamilyRule::manifest_family)
        .collect::<Result<_, _>>()?;
    let hash = ramflux_protocol::encode_base64url(
        ramflux_protocol::custody::pairing::full_transfer::manifest_hash(manifest)
            .map_err(|error| wire(&error))?,
    );
    stage.retain_forward_manifest(manifest, &catalog)?;
    Ok(FullLocalResult::DurablePrefix(stage.revalidate_forward_prefix(&hash)?))
}

/// Data-only local stage access bound to one actual ceremony, account and generation.
/// It retains no database connection, database key, stage key, token or signer. Each
/// operation takes a short loan of the ordinary owner's actual unlocked database.
/// It does not check native freshness or grant permission to transmit, issue `DataVerified`,
/// install, publish, or use a tail. Those endpoint gates must precede network data actions.
pub struct FullTransferLocalIo {
    scope: FullLocalIoScope,
}
impl FullTransferLocalIo {
    pub(super) fn new(
        participant: &super::LocalPairingParticipant,
        db: &AccountDb,
        operation: (String, u64),
        trust: &FullResumeTrust,
        cancelled: FullStageIoCancel,
        runtime: Arc<super::coordinator::FullRuntimeCancel>,
    ) -> Result<Self, SdkError> {
        Ok(Self {
            scope: FullLocalIoScope::new(participant, db, operation, trust, cancelled, runtime)?,
        })
    }

    /// Prepare the new recipient's reverse draft from its OWN pinned local data cut.
    /// The opaque draft authorizes only this exact empty reverse manifest, never a
    /// candidate/publication signature. Persist the signed object before any send.
    /// # Errors
    /// Refuses another role/mode, effective restrictive state or changed local scope.
    pub fn prepare_empty_reverse(
        &self,
        db: &AccountDb,
    ) -> Result<FullReverseManifestDraft, SdkError> {
        let FullLocalIoReply(FullLocalResult::UnsignedReverse(manifest)) =
            self.scope.request(FullLocalAction::PrepareEmptyReverse).apply(db)?
        else {
            return Err(wrong());
        };
        Ok(FullReverseManifestDraft { manifest, scope: self.scope.clone() })
    }
    /// Retain the one exact B-signed reverse object; this grants no applied/DV marker.
    /// # Errors
    /// Refuses wrong local scope, peer key/catalog, references, recuts or cancellation.
    pub fn retain_reverse_manifest(
        &self,
        db: &AccountDb,
        manifest: &SourceManifest,
    ) -> Result<(), SdkError> {
        let FullLocalIoReply(FullLocalResult::ReverseManifestRetained) = self
            .scope
            .request(FullLocalAction::RetainReverseManifest {
                manifest: Box::new(manifest.clone()),
            })
            .apply(db)?
        else {
            return Err(wrong());
        };
        Ok(())
    }
    /// Read an exact locally signed source chunk. Drop the DB loan before relay waits.
    /// # Errors
    /// Refuses foreign/locked/changed local owners, unsigned spools and cancellation.
    pub fn read_source_chunk(
        &self,
        db: &AccountDb,
        hash: &str,
        index: u64,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        let FullLocalIoReply(FullLocalResult::SourceChunk(bytes)) = self
            .scope
            .request(FullLocalAction::ReadSourceChunk { hash: hash.into(), index })
            .apply(db)?
        else {
            return Err(wrong());
        };
        Ok(bytes)
    }
    /// Retain a source-signed manifest under the actual receiver ledger's chain rules.
    /// # Errors
    /// Refuses wrong local role/scope, signature/catalog/chain mismatch or cancellation.
    pub fn retain_manifest(
        &self,
        db: &AccountDb,
        manifest: &SourceManifest,
    ) -> Result<Option<u64>, SdkError> {
        let FullLocalIoReply(FullLocalResult::DurablePrefix(prefix)) = self
            .scope
            .request(FullLocalAction::RetainManifest { manifest: Box::new(manifest.clone()) })
            .apply(db)?
        else {
            return Err(wrong());
        };
        Ok(prefix)
    }
    /// Persist/fsync one bounded chunk before returning its revalidated durable prefix.
    /// This is a disk receipt only, never semantic verification or cut-retirement authority.
    /// # Errors
    /// Refuses wrong scope/order/digest, changed local ownership or failed durable I/O.
    pub fn retain_chunk(
        &self,
        db: &AccountDb,
        hash: &str,
        index: u64,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Option<u64>, SdkError> {
        let digest = chunk_digest(index, &bytes).map_err(|error| wire(&error))?;
        let FullLocalIoReply(FullLocalResult::DurablePrefix(prefix)) = self
            .scope
            .request(FullLocalAction::RetainChunk { hash: hash.into(), index, digest, bytes })
            .apply(db)?
        else {
            return Err(wrong());
        };
        Ok(prefix)
    }
    /// Check complete retained disk bytes against the manifest root. This never marks the
    /// logical input applied/verified, signs `DataVerified`, or admits a successor manifest.
    /// # Errors
    /// Refuses incomplete/corrupt bytes, foreign ownership or cancellation.
    pub fn verify_forward_root(&self, db: &AccountDb, hash: &str) -> Result<(), SdkError> {
        let FullLocalIoReply(FullLocalResult::ForwardRootChecked) = self
            .scope
            .request(FullLocalAction::VerifyForwardRoot { hash: hash.into() })
            .apply(db)?
        else {
            return Err(wrong());
        };
        Ok(())
    }
}

/// Opaque local proof of the actual new B's empty restrictive cut. No Debug/serde/clone.
/// Only the original branch signer can turn this exact object into reverse metadata;
/// it grants neither primary signing nor permission to publish or install.
pub struct FullReverseManifestDraft {
    manifest: Box<Manifest>,
    scope: FullLocalIoScope,
}
impl FullReverseManifestDraft {
    pub(crate) fn sign_with(
        &self,
        participant: &super::LocalPairingParticipant,
        sign: impl FnOnce(&Manifest, &str) -> Result<String, SdkError>,
    ) -> Result<SourceManifest, SdkError> {
        let _local = self.scope.runtime.local_work()?;
        self.scope.live()?;
        if self.scope.role != PairingRole::Responder
            || participant.account_id != self.scope.account
            || std::fs::canonicalize(&participant.root)? != self.scope.root
        {
            return Err(wrong());
        }
        let signature = sign(&self.manifest, &self.scope.destination_key)?;
        ramflux_crypto::verify_canonical_signature(
            &self.manifest.signing_bytes().map_err(|error| wire(&error))?,
            &signature,
            &self.scope.destination_key,
        )?;
        self.scope.live()?;
        Ok(SourceManifest { manifest: (*self.manifest).clone(), source_signature: signature })
    }
}
