// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source native observation carries public bytes only across the frontend handback.
use crate::{SdkError, custody};
use ramflux_protocol::custody::{CustodyAuthority, Publication};
use std::path::PathBuf;

/// Own native evidence for one live actor's exact source candidate. No public constructor,
/// key, provider, writer, stage or restored approval is carried by this value.
pub struct FullSourceCandidateObservation {
    pub(in crate::custody::pairing) root: PathBuf,
    pub(in crate::custody::pairing) account: String,
    pub(in crate::custody::pairing) scope: (String, u64, [u8; 32]),
    pub(in crate::custody::pairing) candidate: Publication,
    pub(in crate::custody::pairing) authority: CustodyAuthority,
}
impl super::LocalPairingParticipant {
    pub(in crate::custody::pairing) fn validate_candidate_for_affirmation(
        &self,
        observation: &FullSourceCandidateObservation,
        context: &ramflux_protocol::custody::pairing::context_v3::TranscriptV3,
    ) -> Result<(), SdkError> {
        self.require_source_observation(observation, &observation.scope)?;
        let now = custody::network_now()?;
        let current = ramflux_crypto::custody::verify_publication(&observation.authority, now)?;
        if observation.candidate.compacted_ids != observation.authority.publication.compacted_ids
            || observation.candidate.record.body.previous_record_hash.as_deref()
                != Some(ramflux_protocol::custody::object_hash(current.envelope())?.as_str())
            || current.envelope().body.master_certificate.body.primary_device_ref
                != context.initiator.device_ref
        {
            return Err(super::wrong());
        }
        let proposed = ramflux_crypto::custody::verify_publication(
            &CustodyAuthority {
                publication: observation.candidate.clone(),
                custodian_publication: observation.authority.custodian_publication.clone(),
            },
            now,
        )?;
        super::preservation::require_destination(
            context,
            &proposed,
            &context.responder.device_ref,
            now,
        )?;
        ramflux_crypto::custody::verify_cooperative_preservation(
            &current,
            &proposed,
            &context.responder.device_ref,
            context.initiator.common.recipient_mode == "new",
        )?;
        Ok(())
    }
    pub(in crate::custody::pairing) fn require_source_observation(
        &self,
        observation: &FullSourceCandidateObservation,
        scope: &(String, u64, [u8; 32]),
    ) -> Result<(), SdkError> {
        if observation.root != self.root
            || observation.account != self.account_id
            || observation.scope != *scope
        {
            return Err(super::wrong());
        }
        let now = custody::network_now()?;
        ramflux_crypto::custody::verify_publication(&observation.authority, now)?;
        if matches!(
            custody::accept_publication(&self.root, &self.account_id, &observation.authority, now)?,
            ramflux_crypto::custody::PinOutcome::Fenced(_)
        ) {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        Ok(())
    }
}
