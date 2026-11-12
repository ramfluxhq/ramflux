// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit peer-control sends; builders never submit or accept a guardian invitation.
use super::{authority, content};
use crate::client::recovery::{SdkGuardianAcceptMessage, SdkGuardianInviteMessage};
use crate::client::routed::{Route, SealPair};
use crate::prelude::*;
use prost::Message as _;
use ramflux_protocol::message as g;
use zeroize::Zeroize as _;

impl RamfluxClient {
    fn native_control_target(
        &self,
        message: &GatewayDirectMessage,
        principal: &str,
        require_contact: bool,
    ) -> Result<String, SdkError> {
        if !crate::client::target_selection::schema_v1_selected() {
            return Err(content("generated durable profile is not selected"));
        }
        let root = message.recipient_principal_commitment.as_deref()
            .ok_or_else(|| authority("peer control requires an explicit recipient root"))?;
        if require_contact { self.require_accepted_contact(root)?; }
        let device = message.recipient_device_id.as_deref()
            .ok_or_else(|| authority("peer control recipient device absent"))?;
        let remote = self.device_identity_for_root(root, device)?;
        let (pinned_principal, _) = self.pinned_peer(&remote)?;
        if (pinned_principal != principal && root != principal) || root == self.own_account_anchor()? {
            return Err(authority("peer control recipient differs from its native role"));
        }
        Ok(root.to_owned())
    }

    async fn submit_generated_peer_control(
        &self,
        engine: &mut impl GatewaySessionAccess,
        mut message: GatewayDirectMessage,
        exact: &[u8],
    ) -> Result<GatewayInboxEntry, SdkError> {
        let mut inner = g::Inner::decode(exact).map_err(|_| content("generated control malformed"))?;
        inner.body.zeroize();
        let identity = inner.identity.ok_or_else(|| content("control identity absent"))?;
        if message.conversation_id != identity.conversation_id {
            return Err(content("peer control conversation differs from its exact Inner"));
        }
        let local = self.owned_device_identity()?;
        self.current_custody_authority(local.root_commitment(), crate::custody::network_now()?)?
            .ok_or(SdkError::NetworkingPending)?;
        message.message_id = ramflux_protocol::encode_base64url(&identity.id);
        let (mut session, header, bundle) = self.send_pair_session(engine, &message).await?;
        let recipient = Self::qualified_recipient(&message)?;
        let envelope = self.account_db()?.write_transaction(|| {
            self.bind_outgoing_delivery(&local, &message, &crate::client::routed::Kind::Control)?;
            let sealed = self.seal_routed_with_route_in(
                &message, exact, Route::control(),
                SealPair { local: &engine.config().device_id, remote: &recipient,
                    session: &mut session, header, bundle },
                Some((g::outer::CANDIDATE_ENVELOPE_SCHEMA, 2)),
            )?;
            crate::dm::gateway_generated_envelope_from_sealed(engine.config(), &mut message, sealed)
        })?;
        engine.submit_envelope(envelope).await
    }

    /// Sends an already signed guardian invite through the native peer-control carrier.
    /// # Errors
    /// Refuses a mismatched recipient, missing native authority, or a failed gateway submission.
    pub async fn send_guardian_invite_via_gateway(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: GatewayDirectMessage,
        invite: &SdkGuardianInviteMessage,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let root = self.native_control_target(&message, &invite.guardian_principal_id, true)?;
        let exact = self.generated_guardian_invite_inner(invite, &root)?;
        let accepted = self.submit_generated_peer_control(engine, message, &exact).await?;
        self.retire_generated_peer_control(&format!("guardian-invite/{}", invite.invite_id))?;
        Ok(accepted)
    }

    /// Sends the signed response produced by an explicit local guardian acceptance.
    /// # Errors
    /// Refuses a mismatched owner, missing native authority, or a failed gateway submission.
    pub async fn send_guardian_accept_via_gateway(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: GatewayDirectMessage,
        accept: &SdkGuardianAcceptMessage,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let root = self.native_control_target(&message, &accept.owner_principal_id, true)?;
        let exact = self.generated_guardian_accept_inner(accept, &root)?;
        let accepted = self.submit_generated_peer_control(engine, message, &exact).await?;
        self.retire_generated_peer_control(&format!("guardian-accept/{}", accept.invite_id))?;
        Ok(accepted)
    }

    /// Sends an object-owner revocation through the native peer-control carrier.
    /// # Errors
    /// Refuses a mismatched recipient, malformed revocation, or a failed gateway submission.
    pub async fn send_object_revoke_via_gateway(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: GatewayDirectMessage,
        revoke: g::ObjectRevokeAccess,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let root = self.native_control_target(&message, &revoke.recipient_principal_id, false)?;
        let operation = format!("object-revoke/{}/{}/{}", revoke.object_id, revoke.recipient_principal_id, revoke.link_id);
        let exact = self.generated_object_revoke_inner(revoke, &root)?;
        let accepted = self.submit_generated_peer_control(engine, message, &exact).await?;
        self.retire_generated_peer_control(&operation)?;
        Ok(accepted)
    }
}
