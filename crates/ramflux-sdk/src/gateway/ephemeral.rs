// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Narrow one-shot transient exchange. No engine, account, or durable submit authority.

use crate::{EphemeralSendOutcome, SdkError};
use std::future::Future;

/// The transport seam supplies only one ephemeral exchange; its owner is inaccessible here.
pub(crate) struct TransientExchange<F> {
    negotiated: bool,
    exchange: F,
}

impl<F, Fut> TransientExchange<F>
where
    F: FnOnce(ramflux_protocol::Envelope) -> Fut,
    Fut: Future<Output = Result<EphemeralSendOutcome, SdkError>>,
{
    pub(crate) fn new(negotiated: bool, exchange: F) -> Self {
        Self { negotiated, exchange }
    }

    pub(crate) async fn submit(
        self,
        envelope: ramflux_protocol::Envelope,
    ) -> Result<EphemeralSendOutcome, SdkError> {
        if let Err(reason) =
            ramflux_protocol::ephemeral::deadline(&envelope, crate::ephemeral::session::wall_ms())
        {
            return Ok(EphemeralSendOutcome::Invalid(reason));
        }
        if !self.negotiated {
            return Ok(EphemeralSendOutcome::Unsupported);
        }
        (self.exchange)(envelope).await
    }
}
