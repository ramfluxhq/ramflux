// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original group authority and per-message opening, independent of the forwarding route.
use super::*;

impl RetainedOrigin {
    pub(super) fn verify_group_binding(
        &self,
        identity: &g::EventIdentity,
        decoded: &g::Inner,
        author: &crate::client::generated_history::Author,
    ) -> Result<(), SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let group_id = identity.group_id.as_ref().ok_or(bad)?;
        if self.routing.group_id.as_ref() != Some(group_id)
            || self.routing.kind != crate::client::routed::Kind::GroupMessage
            || decoded.kind != 1
        {
            return Err(bad.into());
        }
        let wrapper = g::Message::decode(decoded.body.as_slice()).map_err(|_| bad)?;
        let sealed = wrapper.sealed_group.as_ref().ok_or(bad)?;
        if &sealed.group_id != group_id
            || identity.group_epoch != Some(sealed.key_epoch)
            || sealed.author != identity.author
            || !sealed.native_authority_proof.is_empty()
        {
            return Err(bad.into());
        }
        let snapshot = self.evidence.group_membership.as_ref().ok_or(bad)?;
        let snapshot =
            ramflux_protocol::group_state::GroupStateSnapshot::from_wire_bytes(&snapshot.canonical)
                .map_err(|_| bad)?;
        let verified = ramflux_crypto::verify_group_state_snapshot(snapshot).map_err(|_| bad)?;
        let state = verified.snapshot();
        if state.group_id != *group_id
            || state.epoch != sealed.key_epoch
            || state.genesis.conversation_id != identity.conversation_id
            || ramflux_protocol::decode_base64url(&state.state_hash).map_err(|_| bad)?
                != sealed.group_state_hash
            || verified.view().effective_role(&author.root, author.device.device_id()).is_none()
        {
            return Err(bad.into());
        }
        Ok(())
    }

    pub(super) fn verify_group_opening(&self, decoded: &g::Inner) -> Result<(), SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let wrapper = g::Message::decode(decoded.body.as_slice()).map_err(|_| bad)?;
        let sealed = wrapper.sealed_group.as_ref().ok_or(bad)?;
        let mut working = zeroize::Zeroizing::new(self.evidence.group_opening.clone());
        ramflux_crypto::verify_group_message_opening(
            &mut working,
            &self.evidence.group_plaintext,
            sealed,
        )
        .map_err(|_| bad)?;
        Ok(())
    }
}

impl RamfluxClient {
    pub(crate) fn capture_group_retained_origin(
        &self,
        opened: &Opened,
        entry: &crate::GatewayInboxEntry,
        exact_inner: &[u8],
        decrypted: &ramflux_crypto::DmDecryptionOutput,
        sealed: &g::GroupSealedContent,
    ) -> Result<Option<RetainedOrigin>, SdkError> {
        let Some(mut origin) = self.capture_origin_material(opened, entry)? else {
            return Ok(None);
        };
        let state = self
            .account_db()?
            .shared_group_state_at_epoch(&sealed.group_id, sealed.key_epoch)?
            .ok_or(EvidenceError::OriginEvidenceMissing)?;
        origin.evidence.group_membership = Some(g::NativeGroupSnapshot {
            canonical: ramflux_protocol::canonical_json_bytes(state.snapshot())?,
        });
        origin.evidence.group_plaintext.clone_from(&decrypted.plaintext);
        origin.evidence.group_opening.extend_from_slice(&decrypted.opening_key);
        origin.evidence.group_opening.extend_from_slice(&decrypted.commitment_key);
        let identity = g::Inner::decode(exact_inner)
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?
            .identity
            .ok_or(EvidenceError::OriginCommitmentMismatch)?;
        origin.verify(&identity, exact_inner)?;
        Ok(Some(origin))
    }
}

impl Drop for RetainedOrigin {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.evidence.report_opening.zeroize();
        self.evidence.group_opening.zeroize();
        self.evidence.group_plaintext.zeroize();
        self.reported_inner.zeroize();
    }
}
