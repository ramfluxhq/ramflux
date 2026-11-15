// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub fn send_a2i_control_event_via_gateway(
        &self,
        _engine: &mut impl GatewaySessionAccess,
        _event: &A2iControlEvent,
        _target_delivery_id: Option<String>,
    ) -> impl std::future::Future<Output = Result<GatewayInboxEntry, SdkError>> {
        std::future::ready(Self::refuse_a2i_binding_authority())
    }

    /// # Errors
    /// Returns an error when SDK-owned DM encryption, local projection persistence, envelope
    pub fn receive_a2i_control_events(
        &mut self,
        _engine: &mut impl GatewaySessionAccess,
        _limit: usize,
    ) -> impl std::future::Future<Output = Result<Vec<A2iControlEvent>, SdkError>> {
        std::future::ready(Self::refuse_a2i_binding_authority())
    }
}
