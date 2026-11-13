// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bind decrypted native identity and kind to the branch-signed public route before effects.
use super::refused;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError, client::routed::Opened};
use prost::Message as _;
use ramflux_protocol::{
    contact_reach::{self as wire, Reason, Route, Traffic},
    message as g,
};

fn bind_inner(route: &Route, inner: &g::Inner) -> Result<(), SdkError> {
    let identity = inner.identity.as_ref().ok_or_else(|| refused(Reason::ReachRouteInvalid))?;
    let author = identity.author.as_ref().ok_or_else(|| refused(Reason::ReachRouteInvalid))?;
    if author.account_anchor != route.source.account_anchor
        || author.device_id != route.source.device_id
        || author.device_epoch != route.source.device_epoch
        || identity.conversation_id != route.conversation_id
    {
        return Err(refused(Reason::ReachRouteInvalid));
    }
    let operation = if inner.kind == 8 {
        Some(
            g::Control::decode(inner.body.as_slice())
                .map_err(|_| refused(Reason::ReachRouteInvalid))?
                .operation,
        )
    } else {
        None
    };
    if operation == Some(11) {
        return Err(SdkError::GeneratedRefused {
            code: crate::error::GeneratedRefusalCode::Authority,
            reason: "A2I requires its separately verified durable grant owner".into(),
        });
    }
    let own = route.source.account_anchor == route.recipient_root;
    let valid = match route.traffic {
        Traffic::Dm => {
            !own && identity.group_id.is_none()
                && !matches!(inner.kind, 6 | 7 | 12)
                && operation != Some(15)
        }
        Traffic::Receipt => !own && identity.group_id.is_none() && inner.kind == 6,
        Traffic::Group => {
            !own && identity.group_id.is_some()
                && identity.group_epoch.is_some()
                && !matches!(inner.kind, 7 | 12)
                && operation != Some(15)
        }
        Traffic::GroupInvite => {
            !own && inner.kind == 8
                && operation == Some(4)
                && identity.group_id.is_some()
                && identity.group_epoch.is_some()
        }
        Traffic::OwnCopy => own && inner.kind == 8 && operation == Some(15),
        Traffic::SelfSync => own && inner.kind == 12,
        Traffic::Typing => false,
    };
    if !valid {
        return Err(refused(Reason::ReachRouteInvalid));
    }
    Ok(())
}
impl RamfluxClient {
    pub(crate) fn require_reach_decrypted_route(
        entry: &GatewayInboxEntry,
        opened: &Opened,
        body: &[u8],
    ) -> Result<(), SdkError> {
        if !wire::enabled() {
            return Ok(());
        }
        let route =
            &entry.reach.as_deref().ok_or_else(|| refused(Reason::ReachRouteInvalid))?.route.body;
        if route.traffic == Traffic::Group {
            // TODO(r4a): require the audited receiving-home group-route binding, with local parity.
            return Err(refused(Reason::ReachRouteInvalid));
        }
        if opened.remote_device.root_commitment() != route.source.account_anchor
            || opened.remote_device.device_id() != route.source.device_id
            || opened.routing.conversation_id != route.conversation_id
        {
            return Err(refused(Reason::ReachRouteInvalid));
        }
        g::validation::scan_inner(body).map_err(|_| refused(Reason::ReachRouteInvalid))?;
        let inner = g::Inner::decode(body).map_err(|_| refused(Reason::ReachRouteInvalid))?;
        bind_inner(route, &inner)
    }
}

#[cfg(test)]
mod tests;
