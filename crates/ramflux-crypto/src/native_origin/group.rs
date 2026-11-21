// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original group membership and exact per-message opening.
use super::{Author, EvidenceError, Kind, RetainedOrigin, g};
use prost::Message as _;

impl RetainedOrigin {
    pub(super) fn verify_group_binding(
        &self,
        identity: &g::EventIdentity,
        decoded: &g::Inner,
        author: &Author,
    ) -> Result<(), EvidenceError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let group_id = identity.group_id.as_ref().ok_or(bad)?;
        if self.routing.group_id.as_ref() != Some(group_id)
            || self.routing.kind != Kind::GroupMessage
            || decoded.kind != 1
        {
            return Err(bad);
        }
        let wrapper = g::Message::decode(decoded.body.as_slice()).map_err(|_| bad)?;
        let sealed = wrapper.sealed_group.as_ref().ok_or(bad)?;
        if &sealed.group_id != group_id
            || identity.group_epoch != Some(sealed.key_epoch)
            || sealed.author != identity.author
            || !sealed.native_authority_proof.is_empty()
        {
            return Err(bad);
        }
        let snapshot = self.evidence.group_membership.as_ref().ok_or(bad)?;
        let snapshot =
            ramflux_protocol::group_state::GroupStateSnapshot::from_wire_bytes(&snapshot.canonical)
                .map_err(|_| bad)?;
        let verified = crate::verify_group_state_snapshot(snapshot).map_err(|_| bad)?;
        let state = verified.snapshot();
        if state.group_id != *group_id
            || state.epoch != sealed.key_epoch
            || state.genesis.conversation_id != identity.conversation_id
            || ramflux_protocol::decode_base64url(&state.state_hash).map_err(|_| bad)?
                != sealed.group_state_hash
            || verified.view().effective_role(&author.root, author.device.device_id()).is_none()
        {
            return Err(bad);
        }
        Ok(())
    }

    pub(super) fn verify_group_opening(&self, decoded: &g::Inner) -> Result<(), EvidenceError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let wrapper = g::Message::decode(decoded.body.as_slice()).map_err(|_| bad)?;
        let sealed = wrapper.sealed_group.as_ref().ok_or(bad)?;
        let mut working = zeroize::Zeroizing::new(self.evidence.group_opening.clone());
        crate::verify_group_message_opening(&mut working, &self.evidence.group_plaintext, sealed)
            .map_err(|_| bad)?;
        Ok(())
    }
}
