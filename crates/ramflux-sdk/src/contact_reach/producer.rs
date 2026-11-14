// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Seal the exact generated Inner and freeze its existing public source proof before signing W.
use super::{inner::bind_inner, refused};
use crate::{GatewayDirectMessage, GatewaySessionConfig, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::{
    contact_reach::{self as wire, GroupRoute, Reason, Submission, Traffic},
    custody, message as g,
};

/// Local producer intent. This is not a wire field or an authority grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReachSendIntent {
    Ordinary,
    /// Only a verified signed group snapshot can use the invitation placement.
    GroupInvitation,
}

fn invalid() -> SdkError {
    refused(Reason::ReachRouteInvalid)
}

fn traffic(inner: &g::Inner, own: bool, intent: ReachSendIntent) -> Result<Traffic, SdkError> {
    let identity = inner.identity.as_ref().ok_or_else(invalid)?;
    if intent == ReachSendIntent::GroupInvitation {
        return if !own && identity.group_id.is_some() && inner.kind == 8 {
            Ok(Traffic::GroupInvite)
        } else {
            Err(invalid())
        };
    }
    if own {
        return Ok(if inner.kind == 12 { Traffic::SelfSync } else { Traffic::OwnCopy });
    }
    if identity.group_id.is_some() {
        return Ok(Traffic::Group);
    }
    if inner.kind == 6 {
        return match g::Receipt::decode(inner.body.as_slice()).map_err(|_| invalid())?.state {
            1 => Ok(Traffic::ReceiptDelivered),
            2 => Ok(Traffic::ReceiptRead),
            _ => Err(invalid()),
        };
    }
    Ok(Traffic::Dm)
}

impl RamfluxClient {
    /// Seal and sign one native durable submission using already verified recipient authority.
    /// The optional prekey is needed only when no usable recipient pair exists. This method
    /// performs no network operation. The caller must durably retain the returned complete
    /// submission in its retry record before awaiting Submit; retries reuse those exact bytes.
    /// # Errors
    /// Refuses inactive generated schema, missing current authority/prekeys, a changed identity,
    /// unadopted group head, invalid invitation, forbidden durable kind, or expired retention.
    pub fn prepare_reach_submission(
        &self,
        config: &GatewaySessionConfig,
        message: &GatewayDirectMessage,
        exact_inner: &[u8],
        prekey: Option<ramflux_crypto::PrekeyBundle>,
        intent: ReachSendIntent,
    ) -> Result<Submission, SdkError> {
        g::validation::scan_inner(exact_inner).map_err(|_| invalid())?;
        let inner = g::Inner::decode(exact_inner).map_err(|_| invalid())?;
        let identity = inner.identity.as_ref().ok_or_else(invalid)?;
        g::identity::verify(identity).map_err(|_| invalid())?;
        if !message.encrypted_body.is_empty()
            || message.message_id != ramflux_protocol::encode_base64url(&identity.id)
        {
            return Err(invalid());
        }
        let (recipient, _) =
            ramflux_protocol::parse_qualified_device_id(&message.target_delivery_id)?
                .ok_or_else(invalid)?;
        let traffic = traffic(&inner, recipient == self.own_account_anchor()?, intent)?;
        let transport = match (inner.kind, identity.group_id.as_deref()) {
            (8, Some(group)) => crate::client::routed::Route::group_control(group),
            (8 | 11 | 12, None) => crate::client::routed::Route::control(),
            (6, _) => crate::client::routed::Route::receipt(),
            (_, Some(group)) => crate::client::routed::Route::group_message(group),
            _ => crate::client::routed::Route::direct(),
        };
        self.account_db()?.write_transaction(|| {
            let now = crate::custody::network_now()?;
            let root = self.own_account_anchor()?;
            let proof =
                self.current_custody_evidence(&root, now)?.ok_or(SdkError::NetworkingPending)?;
            let authority = ramflux_crypto::custody::verify_publication(&proof, now)?;
            let group = self.reach_outgoing_group(&inner, exact_inner, intent)?;
            let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            let mut route = wire::Route {
                version: 1,
                source: custody::DeviceRef {
                    account_anchor: root,
                    device_id: branch.device_id.clone(),
                    device_epoch: branch.device_epoch,
                },
                recipient_root: recipient.clone(),
                conversation_id: identity.conversation_id.clone(),
                traffic,
                group: (traffic == Traffic::Group).then_some(group).flatten(),
                envelope_hash: String::new(),
                authority_head_hash: custody::object_hash(authority.envelope())?,
                issued_at: u64::try_from(message.created_at).map_err(|_| invalid())?,
                expires_at: u64::try_from(message.created_at)
                    .map_err(|_| invalid())?
                    .checked_add(u64::from(message.ttl))
                    .ok_or_else(invalid)?,
            };
            bind_inner(&route, &inner)?;
            let sealed = self.seal_generated_routed_prepared(
                config,
                message,
                exact_inner,
                transport,
                crate::client::routed::SendMaterial { manifest: None, bundle: prekey },
            )?;
            let mut message = message.clone();
            let mut envelope =
                crate::dm::gateway_generated_envelope_from_sealed(config, &mut message, sealed)?;
            let capability = if matches!(traffic, Traffic::OwnCopy | Traffic::SelfSync) {
                "sync"
            } else {
                "message"
            };
            attach_source(&mut envelope, &proof, &authority, &route.source, capability, now)?;
            route.envelope_hash = custody::framed_hash(wire::ENVELOPE_HASH_DOMAIN, &envelope)?;
            let submission = Submission {
                route: ramflux_crypto::contact_reach::sign_route(route, branch)?,
                envelope,
                cost: None,
            };
            ramflux_crypto::contact_reach::verify_current_source_submission(
                &submission,
                &authority,
                now,
            )?;
            Ok(submission)
        })
    }

    fn reach_outgoing_group(
        &self,
        inner: &g::Inner,
        exact: &[u8],
        intent: ReachSendIntent,
    ) -> Result<Option<GroupRoute>, SdkError> {
        let identity = inner.identity.as_ref().ok_or_else(invalid)?;
        let operation = if inner.kind == 8 {
            Some(g::Control::decode(inner.body.as_slice()).map_err(|_| invalid())?.operation)
        } else {
            None
        };
        let adopted = identity
            .group_id
            .as_ref()
            .map(|group| {
                self.require_reach_group_roster_unforked(group)?;
                self.account_db()?
                    .shared_group_state_at_epoch(group, identity.group_epoch.ok_or_else(invalid)?)?
                    .ok_or_else(|| {
                        SdkError::InboundPending("outgoing group head not adopted".into())
                    })
            })
            .transpose()?;
        wire::group_profile::check(identity, inner.kind, operation, adopted.is_some())
            .map_err(SdkError::ReachRefused)?;
        let candidate =
            if inner.kind == 8 { crate::client::shared_group::decode_packet(exact)? } else { None };
        if intent == ReachSendIntent::GroupInvitation
            && (operation != Some(4) || candidate.is_none())
        {
            return Err(invalid());
        }
        let Some(adopted) = adopted else { return Ok(None) };
        if candidate.is_none() {
            let (epoch, hash) = super::group_binding::referenced_head(inner)?;
            if epoch != adopted.view().epoch
                || hash.as_deref().is_some_and(|hash| hash != adopted.snapshot().state_hash)
            {
                return Err(invalid());
            }
        }
        if adopted.view().conversation_id != identity.conversation_id
            || candidate
                .as_ref()
                .is_some_and(|head| head.snapshot().state_hash != adopted.snapshot().state_hash)
        {
            return Err(invalid());
        }
        Ok(Some(GroupRoute {
            group_id: adopted.view().group_id.clone(),
            group_epoch: adopted.view().epoch,
            membership_hash: adopted.snapshot().state_hash.clone(),
        }))
    }
}

fn attach_source(
    envelope: &mut ramflux_protocol::Envelope,
    proof: &custody::CustodyAuthority,
    authority: &ramflux_crypto::custody::VerifiedRecord,
    source: &custody::DeviceRef,
    capability: &str,
    now: u64,
) -> Result<(), SdkError> {
    let certificate = authority.authorize(source, capability, now)?;
    envelope.ext.ext.insert("source_device_authority".into(), serde_json::json!({
        "custody_authority":proof,"root_public_key":null,"signed_device_set":null,
        "principal_id":authority.envelope().body.principal_id,"device_id":source.device_id,
        "device_epoch":source.device_epoch,"branch_public_key":certificate.branch_signing_public_key,
        "target_delivery_id":ramflux_protocol::qualified_device_id(&source.account_anchor,&source.device_id)?,"revoked":false,
    }));
    Ok(())
}

#[cfg(test)]
mod tests;
