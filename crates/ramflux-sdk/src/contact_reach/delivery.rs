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
        let authority = self
            .current_custody_authority(&reach.route.body.source.account_anchor, now)?
            .ok_or_else(|| refused(Reason::CustodyRefused))?;
        ramflux_crypto::contact_reach::verify_submission(
            &Submission {
                route: reach.route.clone(),
                envelope: entry.envelope.clone(),
                cost: reach.cost.clone(),
            },
            &authority,
            now,
        )?;
        Ok(())
    }
}
