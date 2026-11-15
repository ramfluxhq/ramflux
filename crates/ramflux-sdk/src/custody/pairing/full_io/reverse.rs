// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original reverse cut/bytes/input-validation/actual-merge requests; no approval or native authority.
use super::{FullLocalIoScope, FullTransferStage, PairingRole, SdkError, Zeroizing, wrong};
use ramflux_protocol::custody::pairing::full_transfer::Manifest;
use ramflux_storage::{
    FullReverseSourceDraft, FullReverseSourceWork, FullReverseValidationWork,
    FullValidatedReverseInput,
};
pub(super) enum Action {
    Current,
    PrepareSource,
    AcceptSource(Box<FullReverseSourceDraft>),
    ReadSource { hash: String, index: u64 },
    RetainChunk { hash: String, index: u64, bytes: Zeroizing<Vec<u8>> },
    Prefix(String),
    Validate(String),
    AcceptInput(Box<FullValidatedReverseInput>),
    Merge(String),
}
pub(super) enum Applied {
    Current(Box<Option<ramflux_protocol::custody::pairing::full_transfer::SourceManifest>>),
    Source(Box<FullReverseSourceWork>),
    Draft(Box<Manifest>),
    Bytes(Zeroizing<Vec<u8>>),
    Prefix(Option<u64>),
    Validation(Box<FullReverseValidationWork>),
    InputAccepted,
    Merged(bool),
}
pub(super) fn apply(
    action: Action,
    scope: &FullLocalIoScope,
    stage: FullTransferStage<'_>,
) -> Result<Applied, SdkError> {
    let expected = match &action {
        Action::Current
        | Action::PrepareSource
        | Action::AcceptSource(_)
        | Action::ReadSource { .. } => PairingRole::Responder,
        _ => PairingRole::Initiator,
    };
    if scope.role != expected {
        return Err(wrong());
    }
    Ok(match action {
        Action::Current => Applied::Current(Box::new(stage.retained_reverse_manifest()?)),
        Action::PrepareSource => Applied::Source(Box::new(stage.into_reverse_source_work()?)),
        Action::AcceptSource(draft) => {
            Applied::Draft(Box::new(stage.accept_reverse_source_draft(&draft)?))
        }
        Action::ReadSource { hash, index } => {
            Applied::Bytes(stage.read_reverse_source_wire_chunk(&hash, index)?)
        }
        Action::RetainChunk { hash, index, bytes } => {
            stage.retain_reverse_chunk(&hash, index, &bytes)?;
            Applied::Prefix(stage.revalidate_reverse_prefix(&hash)?)
        }
        Action::Prefix(hash) => Applied::Prefix(stage.revalidate_reverse_prefix(&hash)?),
        Action::Validate(hash) => {
            Applied::Validation(Box::new(stage.into_reverse_validation_work(&hash)?))
        }
        Action::AcceptInput(input) => {
            stage.accept_validated_reverse_input(&input)?;
            Applied::InputAccepted
        }
        Action::Merge(hash) => Applied::Merged(stage.apply_restrictive_reverse_batch(&hash, 32)?),
    })
}
mod port;
