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
