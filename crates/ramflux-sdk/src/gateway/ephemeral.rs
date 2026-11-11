// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transient submit on the existing generation-owned session exchange.

use super::frame_dispatch::ExpectedReply;
use crate::{
    EphemeralConsumer, EphemeralSendOutcome, GatewayClientFrame, GatewayServerFrame,
    GatewaySessionEngine, GatewaySubmitFrame, SdkError,
};

impl GatewaySessionEngine {
    /// Validate and submit once on this session, with no durable retry or ACK.
    ///
    /// # Errors
    /// Returns an error on transport loss, timeout, refusal, or a mismatching result.
    pub async fn submit_ephemeral(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> Result<EphemeralSendOutcome, SdkError> {
        if let Err(reason) =
            ramflux_protocol::ephemeral::deadline(&envelope, crate::ephemeral::session::wall_ms())
        {
            return Ok(EphemeralSendOutcome::Invalid(reason));
        }
        if !self.ephemeral_negotiated {
            return Ok(EphemeralSendOutcome::Unsupported);
        }
        let envelope_id = envelope.envelope_id.clone();
        let signed_request =
            self.signed_request("POST", "/gateway/session/submit", "already_authed", &envelope)?;
        self.write_frame(&GatewayClientFrame::Submit {
            submit: GatewaySubmitFrame { signed_request, envelope },
        })
        .await?;
        loop {
            let reply = self.read_raw_gateway_frame("ephemeral submit response").await?;
            if !self.dispatch_frame_for_request(
                &reply,
                Some(ExpectedReply::EphemeralSubmit),
                Some(&envelope_id),
            )? {
                continue;
            }
            if let GatewayServerFrame::Nack { reason } = reply {
                return Err(SdkError::GatewaySessionRejected(reason));
            }
            let bytes = serde_json::to_vec(&reply)
                .map_err(|error| SdkError::GatewaySessionRejected(error.to_string()))?;
            return crate::ephemeral::decode_ephemeral_result(&bytes, &envelope_id)
                .map_err(|error| SdkError::GatewaySessionRejected(error.to_string()));
        }
    }

    /// Take the account generation's single bounded transient ciphertext consumer.
    #[must_use]
    pub fn take_ephemeral_consumer(&mut self) -> Option<EphemeralConsumer> {
        self.ephemeral_inbox.consumer()
    }
}
