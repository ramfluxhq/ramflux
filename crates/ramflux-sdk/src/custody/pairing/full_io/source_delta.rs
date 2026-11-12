// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact source successor signing after root-owned, off-loan immutable-cut encoding.
use super::{FullLocalIoScope, SdkError, wrong};
use crate::custody::pairing::LocalPairingParticipant;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::{Manifest, SourceManifest};
use ramflux_storage::{FullSourceDeltaDraft, FullSourceSuccessorWork, FullTransferStage};

pub(super) enum Action {
    Prepare,
    Retain { draft: Box<FullDeltaManifestDraft>, manifest: Box<SourceManifest> },
}
pub(super) enum Applied {
    Work(Box<FullSourceSuccessorWork>),
    Retained,
}
/// Non-forgeable source-only request over the exact locally encoded successor.
pub struct FullDeltaManifestDraft {
    proof: FullSourceDeltaDraft,
    scope: FullLocalIoScope,
}
impl FullDeltaManifestDraft {
    pub(super) fn new(
        proof: FullSourceDeltaDraft,
        scope: &FullLocalIoScope,
    ) -> Result<Self, SdkError> {
        scope.live()?;
        if scope.role != PairingRole::Initiator
            || proof.stage_digest() != scope.digest
            || proof.expected_branch_key() != scope.source_key
            || proof.manifest().transfer_id != scope.transfer_id
            || proof.manifest().account_anchor != scope.anchor
        {
            return Err(wrong());
        }
        Ok(Self { proof, scope: scope.clone() })
    }
    pub(crate) fn sign_with(
        &self,
        participant: &LocalPairingParticipant,
        sign: impl FnOnce(&Manifest, &str) -> Result<String, SdkError>,
    ) -> Result<SourceManifest, SdkError> {
        let _local = self.scope.runtime.local_work()?;
        self.scope.live()?;
        if participant.account_id != self.scope.account
            || std::fs::canonicalize(&participant.root)? != self.scope.root
            || crate::custody::network_now()? >= self.proof.expires_at()
        {
            return Err(wrong());
        }
        let signature = sign(self.proof.manifest(), self.proof.expected_branch_key())?;
        self.scope.live()?;
        Ok(self.proof.signed_manifest(signature)?)
    }
}
pub(super) fn apply(
    action: Action,
    scope: &FullLocalIoScope,
    mut stage: FullTransferStage<'_>,
) -> Result<Applied, SdkError> {
    if scope.role != PairingRole::Initiator {
        return Err(wrong());
    }
    let now = crate::custody::network_now()?;
    match action {
        Action::Prepare => Ok(Applied::Work(Box::new(stage.into_source_successor_work(now)?))),
        Action::Retain { draft, manifest } => {
            draft.scope.live()?;
            if draft.scope.root != scope.root
                || draft.scope.operation != scope.operation
                || draft.scope.generation != scope.generation
                || draft.scope.digest != scope.digest
            {
                return Err(wrong());
            }
            stage.retain_source_delta(&draft.proof, &manifest, now)?;
            Ok(Applied::Retained)
        }
    }
}
