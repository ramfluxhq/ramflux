// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Coupled direct-message versions. No current permission or local cursor is imported.
use super::{EvidenceError, Kind, OriginalHeader, OwnAuthoredCapture, RetainedOrigin, g};
use prost::Message as _;

/// These evidence classes are deliberately distinct. Authored data requires an
/// independently authenticated same-account carrier; it is never peer-origin proof.
#[derive(Clone, Copy)]
pub enum DirectEvidence<'a> {
    Received { origin: &'a RetainedOrigin, original: Option<&'a OriginalHeader> },
    Authored(&'a OwnAuthoredCapture),
}

/// Original order and current revision admitted together, never independent maxima.
pub struct DirectVersion {
    original: g::EventIdentity,
    current: g::EventIdentity,
    revision: u64,
}
impl DirectVersion {
    #[must_use]
    pub const fn original(&self) -> &g::EventIdentity {
        &self.original
    }
    #[must_use]
    pub const fn current(&self) -> &g::EventIdentity {
        &self.current
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Verify exact supported Message/Edit bytes in the derived own/peer namespace.
    /// The result authenticates historical data only, not delivery, membership or pins.
    /// # Errors
    /// Refuses foreign roots/scopes, unsupported/group/control bodies, missing or
    /// changed native evidence, cross-author edits and mixed original/current versions.
    pub fn verify(
        exact_inner: &[u8],
        own_root: &str,
        peer_root: &str,
        evidence: DirectEvidence<'_>,
    ) -> Result<Self, EvidenceError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let conversation = g::dm_scope::derive(own_root, peer_root).map_err(|_| bad)?;
        let scanned = g::validation::scan_inner(exact_inner).map_err(|_| bad)?;
        if scanned.outcome != g::validation::ScanOutcome::Supported
            || !matches!(scanned.kind, 1 | 3)
        {
            return Err(bad);
        }
        let inner = g::Inner::decode(exact_inner).map_err(|_| bad)?;
        let current = inner.identity.ok_or(bad)?;
        check_scope(&current, &conversation, own_root, peer_root)?;
        let original = match evidence {
            DirectEvidence::Received { origin, original } => {
                let verified = origin.verify(&current, exact_inner)?;
                if verified.outer.delivery_mode.as_deref() != Some("durable")
                    || verified.outer.delivery_class != ramflux_protocol::DeliveryClass::Message
                    || origin.routing.kind != Kind::Direct
                    || origin.routing.group_id.is_some()
                    || origin.routing.group_message_id.is_some()
                    || origin.routing.message_id != ramflux_protocol::encode_base64url(&current.id)
                {
                    return Err(bad);
                }
                match (inner.kind, original) {
                    (1, None) => current.clone(),
                    (3, Some(header)) => header.verify_header()?.identity().clone(),
                    _ => return Err(bad),
                }
            }
            DirectEvidence::Authored(capture) => {
                if capture.sent.exact_inner != exact_inner
                    || capture.check_direct(own_root)? != current
                {
                    return Err(bad);
                }
                capture.original.clone()
            }
        };
        check_scope(&original, &conversation, own_root, peer_root)?;
        if original.author.as_ref().map(|a| &a.account_anchor)
            != current.author.as_ref().map(|a| &a.account_anchor)
        {
            return Err(bad);
        }
        let content =
            g::registry::decode_body(inner.kind, &inner.body, inner.layer).map_err(|_| bad)?;
        let revision = match content.value {
            Some(g::content::Value::Message(message))
                if message.sealed_group.is_none() && original == current =>
            {
                0
            }
            Some(g::content::Value::Edit(edit)) => {
                let target = edit.target.as_ref().ok_or(bad)?;
                if target.id != original.id
                    || target.conversation_id != conversation
                    || original
                        .author
                        .as_ref()
                        .is_none_or(|a| a.account_anchor != target.author_anchor)
                    || edit.replacement.as_ref().is_none_or(|m| m.sealed_group.is_some())
                    || current.id == original.id
                {
                    return Err(bad);
                }
                edit.revision
            }
            _ => return Err(bad),
        };
        Ok(Self { original, current, revision })
    }
}

fn check_scope(
    identity: &g::EventIdentity,
    conversation: &str,
    own: &str,
    peer: &str,
) -> Result<(), EvidenceError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    g::identity::verify(identity).map_err(|_| bad)?;
    g::identity::order_key(identity).map_err(|_| bad)?;
    if identity.conversation_id != conversation
        || identity.group_id.is_some()
        || identity.group_epoch.is_some()
        || identity.device_sequence & (1 << 63) != 0
        || identity
            .author
            .as_ref()
            .is_none_or(|a| a.account_anchor != own && a.account_anchor != peer)
    {
        return Err(bad);
    }
    Ok(())
}
