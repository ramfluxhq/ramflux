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

fn keyless_invitation(inner: &g::Inner) -> bool {
    let Ok(control) = g::Control::decode(inner.body.as_slice()) else { return false };
    if control.operation != 4 {
        return false;
    }
    let Some(g::control::Payload::GroupState(state)) = control.payload else { return false };
    matches!(
        state.body.and_then(|body| body.value),
        Some(g::group_control_body::Value::Snapshot(g::GroupControlBodySnapshot {
            snapshot: Some(_),
            distribution: None
        }))
    )
}

pub(super) fn bind_inner(route: &Route, inner: &g::Inner) -> Result<(), SdkError> {
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
    if identity.group_id.is_some() != identity.group_epoch.is_some()
        || matches!(operation, Some(4 | 5)) && identity.group_id.is_none()
    {
        return Err(refused(Reason::ReachRouteInvalid));
    }
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
        Traffic::ReceiptDelivered | Traffic::ReceiptRead => {
            let expected = if route.traffic == Traffic::ReceiptDelivered { 1 } else { 2 };
            !own && identity.group_id.is_none()
                && inner.kind == 6
                && g::Receipt::decode(inner.body.as_slice())
                    .is_ok_and(|receipt| receipt.state == expected)
        }
        Traffic::Group => {
            !own && identity.group_id.is_some()
                && identity.group_epoch.is_some()
                && !matches!(inner.kind, 7 | 12)
                && operation != Some(15)
        }
        Traffic::GroupInvite => {
            !own && inner.kind == 8
                && keyless_invitation(inner)
                && identity.group_id.is_some()
                && identity.group_epoch.is_some()
        }
        Traffic::OwnCopy => {
            own && identity.group_id.is_none() && inner.kind == 8 && operation == Some(15)
        }
        Traffic::SelfSync => own && identity.group_id.is_none() && inner.kind == 12,
        Traffic::Typing => false,
    };
    if !valid {
        return Err(refused(Reason::ReachRouteInvalid));
    }
    Ok(())
}
impl RamfluxClient {
    pub(crate) fn require_reach_decrypted_route(
        &self,
        entry: &GatewayInboxEntry,
        opened: &Opened,
        body: &[u8],
    ) -> Result<(), SdkError> {
        if !wire::enabled() {
            return Ok(());
        }
        let route =
            &entry.reach.as_deref().ok_or_else(|| refused(Reason::ReachRouteInvalid))?.route.body;
        if opened.remote_device.root_commitment() != route.source.account_anchor
            || opened.remote_device.device_id() != route.source.device_id
            || opened.routing.conversation_id != route.conversation_id
        {
            return Err(refused(Reason::ReachRouteInvalid));
        }
        g::validation::scan_inner(body).map_err(|_| refused(Reason::ReachRouteInvalid))?;
        let inner = g::Inner::decode(body).map_err(|_| refused(Reason::ReachRouteInvalid))?;
        bind_inner(route, &inner)?;
        if route.traffic == Traffic::Group {
            self.require_reach_group_binding(route, &inner, body)?;
        }
        if route.traffic == Traffic::GroupInvite {
            self.require_reach_group_invite_binding(route, &inner, body)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
