// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original group authority and per-message opening, independent of the forwarding route.
use super::*;

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
