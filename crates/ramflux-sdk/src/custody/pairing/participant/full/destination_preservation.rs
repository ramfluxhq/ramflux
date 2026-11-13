// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! B retains source approval under its own short actual-writer service, never from a peer flag.
use super::{LocalPairingParticipant, wrong};
use crate::SdkError;
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{DeviceSet, Envelope, object_hash, pairing::full_transfer::PreservationFull},
};
pub(in crate::custody::pairing) struct FullDestinationReady {
    pub(in crate::custody::pairing) operation: String,
    pub(in crate::custody::pairing) generation: u64,
    pub(in crate::custody::pairing) th: [u8; 32],
    pub(in crate::custody::pairing) previous: Envelope<DeviceSet>,
    pub(in crate::custody::pairing) candidate: Envelope<DeviceSet>,
    pub(in crate::custody::pairing) preservation: Envelope<PreservationFull>,
}
impl LocalPairingParticipant {
    pub(in crate::custody::pairing) fn retain_destination_preservation_in(
        &self,
        db: &ramflux_storage::AccountDb,
        ready: &FullDestinationReady,
    ) -> Result<(), SdkError> {
        self.full_selected_db(db, Some(&ready.previous.body.account_anchor))?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == ready.operation)
            .ok_or_else(wrong)?;
        let head = db.pairing_head()?.ok_or_else(wrong)?;
        if live.role != "responder"
            || live.generation != ready.generation
            || live.phase != "prepared"
            || head.operation_id != ready.operation
            || head.state != "prepared"
            || head.generation != ready.generation
            || head.candidate_hash != object_hash(&ready.candidate)?
        {
            return Err(wrong());
        }
        let candidate: ramflux_protocol::custody::Publication =
            ramflux_protocol::parse_i_json(&head.candidate)?;
        if canonical_json_bytes(&candidate.record)? != canonical_json_bytes(&ready.candidate)? {
            return Err(wrong());
        }
        let stage = db.open_full_transfer_stage(
            &ready.operation,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            crate::custody::network_now()?,
        )?;
        if stage.resume_record()?.th != ready.th {
            return Err(wrong());
        }
        stage.retain_destination_full_preservation(
            &ready.previous,
            &ready.candidate,
            &ready.preservation,
            crate::custody::network_now()?,
        )?;
        Ok(())
    }
}
