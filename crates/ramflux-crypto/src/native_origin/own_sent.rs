// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-root attestations preserve their enclosing proof; they never become peer origin.
use super::{EvidenceError, RetainedOrigin, g};
use prost::Message as _;
use zeroize::Zeroize as _;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnSentAttestation {
    pub exact_outer_inner: Vec<u8>,
    pub origin: RetainedOrigin,
}
impl Drop for OwnSentAttestation {
    fn drop(&mut self) {
        self.exact_outer_inner.zeroize();
        self.origin.reported_inner.zeroize();
        self.origin.evidence.report_opening.zeroize();
        self.origin.evidence.group_plaintext.zeroize();
        self.origin.evidence.group_opening.zeroize();
    }
}

impl OwnSentAttestation {
    /// Decode the enclosing own-copy; call verify before trusting its claims.
    /// # Errors
    /// Refuses an invalid inner, control or payload variant.
    pub fn enclosing_copy(&self) -> Result<g::OwnMessageCopy, EvidenceError> {
        let inner = g::Inner::decode(self.exact_outer_inner.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        let control = g::Control::decode(inner.body.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        match control.payload {
            Some(g::control::Payload::OwnMessageCopy(copy)) => Ok(copy),
            _ => Err(EvidenceError::OriginCommitmentMismatch),
        }
    }

    /// Verify own-root transport attestation independently of nested peer-origin proofs.
    /// # Errors
    /// Refuses changed enclosing/nested bytes, foreign roots and invalid native identity.
    pub fn verify(
        &self,
        exact_nested: &[u8],
        own_root: &str,
    ) -> Result<g::OwnSentMessage, EvidenceError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let scanned = g::validation::scan_inner(&self.exact_outer_inner).map_err(|_| bad)?;
        let outer = g::Inner::decode(self.exact_outer_inner.as_slice()).map_err(|_| bad)?;
        let identity = outer.identity.as_ref().ok_or(bad)?;
        if scanned.kind != 8
            || identity.group_id.is_some()
            || identity.device_sequence & (1 << 63) == 0
        {
            return Err(bad);
        }
        // This verifies C against the enclosing own-copy, never against the nested Message.
        let verified = self.origin.verify(identity, &self.exact_outer_inner)?;
        if verified.author.root != own_root
            || verified.outer.delivery_mode.as_deref() != Some("durable")
            || verified.outer.delivery_class != ramflux_protocol::DeliveryClass::Message
        {
            return Err(bad);
        }
        let control = g::Control::decode(scanned.body).map_err(|_| bad)?;
        let Some(g::control::Payload::OwnMessageCopy(copy)) = control.payload else {
            return Err(bad);
        };
        if control.operation != 15
            || copy.source.as_ref() != identity.author.as_ref()
            || copy.target.as_ref().is_none_or(|target| target.account_anchor != own_root)
        {
            return Err(bad);
        }
        let Some(g::own_message_copy::Payload::Sent(sent)) = copy.payload else {
            return Err(bad);
        };
        if sent.exact_inner != exact_nested
            || sent
                .context
                .as_ref()
                .is_none_or(|context| context.conversation_id != identity.conversation_id)
        {
            return Err(bad);
        }
        let nested = g::Inner::decode(exact_nested).map_err(|_| bad)?;
        g::validation::scan_inner(exact_nested).map_err(|_| bad)?;
        let original = nested.identity.as_ref().ok_or(bad)?;
        g::identity::verify(original).map_err(|_| bad)?;
        if original.conversation_id != identity.conversation_id
            || original.device_sequence & (1 << 63) != 0
            || original.author.as_ref().is_none_or(|author| author.account_anchor != own_root)
            || ramflux_protocol::encode_base64url(&original.id) != sent.message_id
            || !matches!(nested.kind, 1 | 3 | 4 | 5)
        {
            return Err(bad);
        }
        Ok(sent)
    }
}
