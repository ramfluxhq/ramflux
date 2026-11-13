// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact own-authored plaintext captured before recipient-specific sealing.
use super::{OwnSentInput, RamfluxClient, SdkError, g, invalid};
use prost::Message as _;
use serde::{Deserialize, Serialize};

pub(crate) mod delivery;

pub(super) const CAPTURE: &str = "own-history/capture/";

#[derive(Deserialize, Serialize)]
pub(super) struct Captured {
    pub target: Vec<u8>,
    pub current: Vec<u8>,
    pub original: g::EventIdentity,
    pub sent: g::OwnSentMessage,
}

impl RamfluxClient {
    /// Joins the send writer; plaintext capture, ratchet and outbox roll back together.
    pub(crate) fn capture_own_authored_revision(
        &self,
        input: OwnSentInput<'_>,
    ) -> Result<(), SdkError> {
        if !crate::client::target_selection::schema_v1_selected() {
            return Ok(());
        }
        let Ok(scanned) = g::validation::scan_inner(input.body) else { return Ok(()) };
        if !matches!(scanned.kind, 1 | 3) {
            return Ok(());
        }
        let inner = g::Inner::decode(input.body).map_err(|_| invalid("authored Inner missing"))?;
        let identity = inner.identity.ok_or_else(|| invalid("authored identity missing"))?;
        g::identity::verify(&identity).map_err(|_| invalid("authored identity invalid"))?;
        let local = self.owned_device_identity()?;
        let author = identity.author.as_ref().ok_or_else(|| invalid("authored source missing"))?;
        if author.account_anchor != local.root_commitment()
            || identity.device_sequence & (1 << 63) != 0
            || author.device_id != local.device_id()
            || author.device_epoch
                != self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch
            || identity.conversation_id != input.conversation
            || identity.group_id.as_deref() != input.group
        {
            return Err(invalid("authored capture source or context mismatch"));
        }
        let target = if scanned.kind == 3 {
            g::Edit::decode(scanned.body)
                .map_err(|_| invalid("authored Edit missing"))?
                .target
                .ok_or_else(|| invalid("authored Edit target missing"))?
                .id
        } else {
            let message = g::Message::decode(scanned.body)
                .map_err(|_| invalid("authored Message missing"))?;
            // Group wrappers are never a plaintext capture. The caller captures I before group seal.
            if message.sealed_group.is_some() {
                return Ok(());
            }
            identity.id.clone()
        };
        let mut packet = self.own_sent_packet(input)?;
        packet.message_id = ramflux_protocol::encode_base64url(&identity.id);
        packet.ciphertext_hash = None;
        let sent = packet.to_generated()?;
        self.validate_own_context_namespace(&packet.context)?;
        packet.validate_route(input.envelope, input.conversation, input.group)?;
        let owner = ramflux_protocol::encode_base64url(&target);
        let db = self.account_db()?;
        let key = format!("{CAPTURE}{owner}");
        let old = db.load_actor_state::<Captured>(&key)?;
        let original =
            self.authored_original_identity(scanned.kind, &identity, &target, old.as_ref())?;
        let captured = Captured { target, current: identity.id, original, sent };
        if db.message_is_deleted(&owner)? {
            return Ok(());
        }
        if let Some(old) = old {
            if old.current == captured.current {
                if old.sent.exact_inner != captured.sent.exact_inner {
                    return Err(invalid("authored event changed its exact plaintext"));
                }
                return Ok(());
            }
            let old_inner = g::Inner::decode(old.sent.exact_inner.as_slice())
                .map_err(|_| invalid("stored authored Inner invalid"))?;
            if scanned.kind == 1 {
                return Ok(());
            }
            if old_inner.kind == 3 {
                let previous = g::Edit::decode(old_inner.body.as_slice())
                    .map_err(|_| invalid("stored authored Edit invalid"))?;
                let incoming =
                    g::Edit::decode(scanned.body).map_err(|_| invalid("authored Edit invalid"))?;
                if (incoming.revision, &captured.current) <= (previous.revision, &old.current) {
                    return Ok(());
                }
            }
        }
        // Known captures follow ordinary history retention, including the same per-copy bound.
        let encoded = zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(&captured)?);
        if encoded.len() > 4 * 1024 * 1024 {
            return Err(invalid("own history capture exceeds history-container limit"));
        }
        self.retire_authored_history_for_owner(&owner)?;
        db.persist_message_actor_state(&owner, &key, &captured)?;
        Ok(())
    }

    fn authored_original_identity(
        &self,
        kind: u32,
        identity: &g::EventIdentity,
        target: &[u8],
        old: Option<&Captured>,
    ) -> Result<g::EventIdentity, SdkError> {
        let original = if kind == 1 {
            identity.clone()
        } else if let Some(old) = old {
            old.original.clone()
        } else {
            self.account_db()?
                .load_actor_state::<g::EventIdentity>(&format!(
                    "routed/generated-identity/{}",
                    ramflux_protocol::encode_base64url(target)
                ))?
                .ok_or_else(|| invalid("authored Edit original identity unavailable"))?
        };
        let root = self.own_account_anchor()?;
        if original.id != target
            || original.conversation_id != identity.conversation_id
            || original.author.as_ref().is_none_or(|author| author.account_anchor != root)
        {
            return Err(invalid("authored Edit original identity mismatch"));
        }
        Ok(original)
    }

    pub(crate) fn capture_own_authored_direct(
        &self,
        message: &crate::GatewayDirectMessage,
        exact: &[u8],
    ) -> Result<(), SdkError> {
        // Native controls and legacy plaintext are not message captures.
        if !g::validation::scan_inner(exact).is_ok_and(|scanned| matches!(scanned.kind, 1 | 3)) {
            return Ok(());
        }
        let peer = self.own_sent_peer(message)?;
        let recipients = self.own_original_recipient(message)?;
        self.capture_own_authored_revision(OwnSentInput {
            envelope: &message.envelope_id,
            conversation: &message.conversation_id,
            message: &message.message_id,
            sender: &message.sender_id,
            original_recipients: &recipients,
            group: None,
            peer: Some(&peer),
            body: exact,
            ciphertext: &[],
            at: message.created_at,
        })
    }
    pub(crate) fn capture_own_authored_group(
        &self,
        group: &str,
        sender: &str,
        exact: &[u8],
    ) -> Result<(), SdkError> {
        let Ok(scanned) = g::validation::scan_inner(exact) else { return Ok(()) };
        if !matches!(scanned.kind, 1 | 3) {
            return Ok(());
        }
        let inner = g::Inner::decode(exact).map_err(|_| invalid("authored group Inner invalid"))?;
        let identity = inner.identity.ok_or_else(|| invalid("authored group identity missing"))?;
        let event = ramflux_protocol::encode_base64url(&identity.id);
        let envelope =
            self.own_group_copy_envelope(group, &identity.conversation_id, &event, None)?;
        let recipients = self.group_state(group)?.members.into_iter().collect::<Vec<_>>();
        self.capture_own_authored_revision(OwnSentInput {
            envelope: &envelope,
            conversation: &identity.conversation_id,
            message: &event,
            sender,
            original_recipients: &recipients,
            group: Some(group),
            peer: None,
            body: exact,
            ciphertext: &[],
            at: crate::time::now_unix_timestamp(),
        })
    }
}
