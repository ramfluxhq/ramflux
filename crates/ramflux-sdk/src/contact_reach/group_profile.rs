// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group profile facts come only from verified local state or a purely verified snapshot candidate.
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::{contact_reach as wire, message as g};
impl RamfluxClient {
    pub(crate) fn check_reach_group_profile(
        &self,
        identity: Option<&g::EventIdentity>,
        kind: u32,
        control_body: &[u8],
        exact_inner: &[u8],
    ) -> Result<(), SdkError> {
        if !wire::enabled() {
            return Ok(());
        }
        let operation = if kind == 8 {
            Some(
                g::Control::decode(control_body)
                    .map_err(|_| SdkError::ReachRefused(wire::Reason::ReachRouteInvalid))?
                    .operation,
            )
        } else {
            None
        };
        wire::group_profile::check(
            identity.ok_or(SdkError::ReachRefused(wire::Reason::ReachRouteInvalid))?,
            kind,
            operation,
            self.reach_signed_group_present(exact_inner)?,
        )
        .map_err(SdkError::ReachRefused)
    }
    pub(crate) fn reach_signed_group_present(&self, body: &[u8]) -> Result<bool, SdkError> {
        if !wire::enabled() {
            return Ok(false);
        }
        let Ok(inner) = g::Inner::decode(body) else { return Ok(false) };
        let Some(identity) = inner.identity else { return Ok(false) };
        let Some(group) = identity.group_id.as_deref() else { return Ok(false) };
        if inner.kind == 8
            && let Some(candidate) = crate::client::shared_group::decode_packet(body)?
        {
            return Ok(candidate.view().group_id == group);
        }
        Ok(self.account_db()?.shared_group_state(group)?.is_some())
    }
}
