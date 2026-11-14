// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable delivery proofs precede deduplication, authority preparation and inner effects.
use super::refused;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_protocol::{
    contact_reach::{self as wire, Reason, Submission, Traffic},
    custody,
};

impl RamfluxClient {
    pub(crate) fn require_reach_entry_metadata(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        if !wire::enabled() {
            return Ok(());
        }
        let reach = entry.reach.as_ref().ok_or_else(|| refused(Reason::ReachRouteInvalid))?;
        let route = &reach.route.body;
        route.validate()?;
        let own = self.owned_device_identity()?;
        let (root, device) =
            ramflux_protocol::parse_qualified_device_id(&entry.target_delivery_id)?
                .ok_or_else(|| refused(Reason::ReachRouteInvalid))?;
        if root != own.root_commitment()
            || device != own.device_id()
            || route.recipient_root != root
            || entry.envelope.target_delivery_id != entry.target_delivery_id
            || route.source.device_id != entry.envelope.source_device_id
            || route.envelope_hash
                != custody::framed_hash(wire::ENVELOPE_HASH_DOMAIN, &entry.envelope)?
            || route.traffic == Traffic::Typing
            || ramflux_protocol::canonical_json_bytes(&reach.route)?.len() > 4096
            || reach.cost.as_ref().is_some_and(|cost| {
                ramflux_protocol::canonical_json_bytes(cost).map_or(true, |v| v.len() > 2048)
            })
            || matches!(route.traffic, Traffic::OwnCopy | Traffic::SelfSync)
                && route.source.account_anchor != root
        {
            return Err(refused(Reason::ReachRouteInvalid));
        }
        Ok(())
    }
    pub(crate) fn require_reach_entry_authority(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        if !wire::enabled() {
            return Ok(());
        }
        self.require_reach_entry_metadata(entry)?;
        let reach = entry.reach.as_ref().ok_or_else(|| refused(Reason::ReachRouteInvalid))?;
        let now = crate::custody::network_now()?;
        let submission = Submission {
            route: reach.route.clone(),
            envelope: entry.envelope.clone(),
            cost: reach.cost.clone(),
        };
        ramflux_crypto::contact_reach::verify_original_source_submission(&submission, now)?;
        let authority = self
            .current_custody_authority(&reach.route.body.source.account_anchor, now)
            .map_err(|error| match error {
                error @ SdkError::Storage(_) => error,
                _ => SdkError::InboundPending("current reach source authority unavailable".into()),
            })?
            .ok_or_else(|| {
                SdkError::InboundPending("current reach source authority unavailable".into())
            })?;
        let root = &reach.route.body.source.account_anchor;
        self.require_fresh_custody_head(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            root,
            authority.envelope(),
        )?;
        let capability = if matches!(reach.route.body.traffic, Traffic::OwnCopy | Traffic::SelfSync)
        {
            "sync"
        } else {
            "message"
        };
        if authority.authorize(&reach.route.body.source, capability, now).is_err() {
            return Err(SdkError::FreshHeadRequired { root: root.clone() });
        }
        ramflux_crypto::contact_reach::verify_current_source_submission(
            &submission,
            &authority,
            now,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
