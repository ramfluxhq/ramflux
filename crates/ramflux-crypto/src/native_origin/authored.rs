// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-authored plaintext is same-account history, never first-hand peer origin evidence.
use super::{EvidenceError, g};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

/// Exact local plaintext captured before recipient-specific sealing.
/// The enclosing authenticated own-account transfer/attestation is a separate requirement.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnAuthoredCapture {
    pub target: Vec<u8>,
    pub current: Vec<u8>,
    pub original: g::EventIdentity,
    pub sent: g::OwnSentMessage,
}
impl Drop for OwnAuthoredCapture {
    fn drop(&mut self) {
        self.target.zeroize();
        self.current.zeroize();
        self.sent.exact_inner.zeroize();
    }
}
impl OwnAuthoredCapture {
    /// Move the original transport-independent message into an own-copy payload.
    #[must_use]
    pub fn into_sent(mut self) -> g::OwnSentMessage {
        std::mem::take(&mut self.sent)
    }

    /// Check direct Message/Edit identity and content bindings under an independently
    /// authenticated same-account history carrier. This returns data, not signer authority.
    /// # Errors
    /// Refuses a foreign root, changed target/current/original identity, group wrapper,
    /// unsupported payload or mismatched context. Never use it to prove peer origin.
    pub fn check_direct(&self, own_root: &str) -> Result<g::EventIdentity, EvidenceError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let scanned = g::validation::scan_inner(&self.sent.exact_inner).map_err(|_| bad)?;
        if scanned.outcome != g::validation::ScanOutcome::Supported
            || !matches!(scanned.kind, 1 | 3)
        {
            return Err(bad);
        }
        let inner = g::Inner::decode(self.sent.exact_inner.as_slice()).map_err(|_| bad)?;
        let identity = inner.identity.as_ref().ok_or(bad)?;
        g::identity::verify(identity).map_err(|_| bad)?;
        g::identity::verify(&self.original).map_err(|_| bad)?;
        let context = self.sent.context.as_ref().ok_or(bad)?;
        if self.current != identity.id
            || self.target != self.original.id
            || self.original.group_id.is_some()
            || self.original.group_epoch.is_some()
            || identity.group_id.is_some()
            || identity.group_epoch.is_some()
            || context.group.is_some()
            || identity.device_sequence & (1 << 63) != 0
            || self.original.device_sequence & (1 << 63) != 0
            || identity.author.as_ref().is_none_or(|author| author.account_anchor != own_root)
            || self.original.author.as_ref().is_none_or(|author| author.account_anchor != own_root)
            || self.original.conversation_id != identity.conversation_id
            || context.conversation_id != identity.conversation_id
            || self.sent.message_id != ramflux_protocol::encode_base64url(&identity.id)
            || self.sent.ciphertext_digest.is_some()
        {
            return Err(bad);
        }
        match inner.kind {
            1 => {
                let message = g::Message::decode(inner.body.as_slice()).map_err(|_| bad)?;
                if message.sealed_group.is_some() || identity != &self.original {
                    return Err(bad);
                }
                g::validation::validate_message(&message).map_err(|_| bad)?;
            }
            3 => {
                let edit = g::Edit::decode(inner.body.as_slice()).map_err(|_| bad)?;
                let target = edit.target.as_ref().ok_or(bad)?;
                if target.id != self.target
                    || target.conversation_id != identity.conversation_id
                    || target.author_anchor != own_root
                    || edit
                        .replacement
                        .as_ref()
                        .is_some_and(|message| message.sealed_group.is_some())
                {
                    return Err(bad);
                }
                g::validation::validate_content(&g::Content {
                    value: Some(g::content::Value::Edit(edit)),
                })
                .map_err(|_| bad)?;
            }
            _ => return Err(bad),
        }
        Ok(identity.clone())
    }
}

#[cfg(test)]
mod tests;
