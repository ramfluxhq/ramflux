// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A generation-fenced client capability; it never owns or reads a gateway stream.

use super::{ConnectionHandle, SessionMetadata};
use crate::gateway::access::{GatewayCallFuture, GatewayPushAccess, GatewaySessionAccess};
use crate::prelude::*;
use tokio::time::Instant;

pub(crate) struct SessionClient {
    ephemeral_negotiated: bool,
    pub config: GatewaySessionConfig,
    session: GatewaySessionState,
    handle: ConnectionHandle,
    generation: u64,
    deadline: Instant,
}

impl SessionClient {
    pub(crate) fn new(
        handle: ConnectionHandle,
        metadata: SessionMetadata,
        deadline: Instant,
    ) -> Self {
        Self {
            ephemeral_negotiated: metadata.ephemeral_negotiated,
            config: metadata.config,
            session: metadata.session,
            generation: metadata.generation,
            handle,
            deadline,
        }
    }
    #[cfg(test)]
    pub(crate) async fn test_update_resume(
        &mut self,
        session: &str,
        token: &str,
    ) -> Result<(), SdkError> {
        let session = session.to_owned();
        let token = token.to_owned();
        self.config = self
            .handle
            .call_generation(
                move |engine| {
                    Box::pin(async move {
                        engine.config.previous_session_id = Some(session);
                        engine.config.resume_token = Some(token);
                        Ok(engine.config.clone())
                    })
                },
                self.deadline,
                self.generation,
            )
            .await?;
        Ok(())
    }
    /// Submits through the host and separates a certain gateway refusal (inner `Err`) from
    /// every uncertain failure (outer `Err`).
    pub(crate) fn submit_envelope_classified(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, Result<GatewayInboxEntry, crate::gateway::session_push::SubmitRefusal>>
    {
        Box::pin(self.handle.call_generation(
            move |engine| {
                Box::pin(async move { engine.submit_envelope_classified(envelope).await })
            },
            self.deadline,
            self.generation,
        ))
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

impl crate::gateway::access::ClassifiedSubmit for SessionClient {
    fn submit_classified(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, Result<GatewayInboxEntry, crate::gateway::session_push::SubmitRefusal>>
    {
        self.submit_envelope_classified(envelope)
    }
}

#[allow(private_interfaces)]
impl GatewaySessionAccess for SessionClient {
    fn config(&self) -> &GatewaySessionConfig {
        &self.config
    }
    fn session(&self) -> &GatewaySessionState {
        &self.session
    }
    fn ephemeral_negotiated(&self) -> bool {
        self.ephemeral_negotiated
    }
    fn heartbeat(&mut self) -> GatewayCallFuture<'_, ()> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.heartbeat().await }),
            self.deadline,
            self.generation,
        ))
    }
    fn submit_envelope(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, GatewayInboxEntry> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.submit_envelope(envelope).await }),
            self.deadline,
            self.generation,
        ))
    }
    fn submit_ephemeral(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, crate::ephemeral::EphemeralSendOutcome> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.submit_ephemeral(envelope).await }),
            self.deadline,
            self.generation,
        ))
    }
    fn take_ephemeral_consumer(
        &mut self,
    ) -> GatewayCallFuture<'_, Option<crate::ephemeral::EphemeralConsumer>> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { Ok(engine.take_ephemeral_consumer()) }),
            self.deadline,
            self.generation,
        ))
    }
    fn own_device_fanout(
        &mut self,
        principal_id: impl Into<String>,
        source_device_id: impl Into<String>,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, GatewayOwnDeviceFanoutResponse> {
        let principal_id = principal_id.into();
        let source_device_id = source_device_id.into();
        Box::pin(self.handle.call_generation(
            move |engine| {
                Box::pin(async move {
                    engine.own_device_fanout(principal_id, source_device_id, envelope).await
                })
            },
            self.deadline,
            self.generation,
        ))
    }
    fn ack(&mut self, ack: ramflux_protocol::Ack) -> GatewayCallFuture<'_, GatewayCursor> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.ack(ack).await }),
            self.deadline,
            self.generation,
        ))
    }
    fn cursor(&mut self) -> GatewayCallFuture<'_, Option<GatewayCursor>> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.cursor().await }),
            self.deadline,
            self.generation,
        ))
    }
    fn resume_after(
        &mut self,
        after_inbox_seq: u64,
        limit: usize,
    ) -> GatewayCallFuture<'_, Vec<GatewayInboxEntry>> {
        Box::pin(self.handle.call_generation(
            move |engine| {
                Box::pin(
                    async move { engine.resume_authoritative_after(after_inbox_seq, limit).await },
                )
            },
            self.deadline,
            self.generation,
        ))
    }
    fn register_identity(
        &mut self,
        request: SdkIdentityRegisterRequest,
    ) -> GatewayCallFuture<'_, SdkIdentityRegistrationResponse> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.register_identity(request).await }),
            self.deadline,
            self.generation,
        ))
    }
    fn publish_prekey_bundle<'a>(
        &'a mut self,
        device_id: &'a str,
        bundle: &'a ramflux_crypto::PrekeyBundle,
    ) -> GatewayCallFuture<'a, SdkPrekeyResponse> {
        let device_id = device_id.to_owned();
        let bundle = bundle.clone();
        Box::pin(self.handle.call_generation(
            move |engine| {
                Box::pin(async move { engine.publish_prekey_bundle(&device_id, &bundle).await })
            },
            self.deadline,
            self.generation,
        ))
    }
    fn fetch_principal_manifest<'a>(
        &'a mut self,
        principal: &'a str,
    ) -> GatewayCallFuture<'a, Option<SdkDeviceManifestResponse>> {
        let principal = principal.to_owned();
        Box::pin(self.handle.call_generation(
            move |engine| {
                Box::pin(async move { engine.fetch_principal_manifest(&principal).await })
            },
            self.deadline,
            self.generation,
        ))
    }
    fn fetch_prekey_bundle<'a>(
        &'a mut self,
        device_id: &'a str,
    ) -> GatewayCallFuture<'a, SdkPrekeyResponse> {
        let device_id = device_id.to_owned();
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.fetch_prekey_bundle(&device_id).await }),
            self.deadline,
            self.generation,
        ))
    }

    fn issue_relay_token_v3(
        &mut self,
        body: SdkRelayTokenV3IssueBody,
    ) -> GatewayCallFuture<'_, ramflux_protocol::RelayTokenV3> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.issue_relay_token_v3(body).await }),
            self.deadline,
            self.generation,
        ))
    }
    fn voice_lease(
        &mut self,
        body: ramflux_protocol::VoiceLeaseRequest,
    ) -> GatewayCallFuture<'_, ramflux_protocol::VoiceLeaseResponse> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.voice_lease(body).await }),
            self.deadline,
            self.generation,
        ))
    }
    fn set_push_route(
        &mut self,
        route: Option<GatewayPushRouteRegistration>,
    ) -> GatewayCallFuture<'_, Option<u64>> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.set_push_route(route).await }),
            self.deadline,
            self.generation,
        ))
    }
    fn register_push_route(&mut self) -> GatewayCallFuture<'_, Option<String>> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.register_push_route().await }),
            self.deadline,
            self.generation,
        ))
    }
    fn close<'a>(&'a mut self, reason: &'a str) -> GatewayCallFuture<'a, ()> {
        let reason = reason.to_owned();
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.close(&reason).await }),
            self.deadline,
            self.generation,
        ))
    }
}

impl GatewayPushAccess for SessionClient {
    fn resume_page(
        &mut self,
        after_inbox_seq: u64,
        limit: usize,
    ) -> GatewayCallFuture<'_, crate::gateway::push_resume::PageReply> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.resume_page(after_inbox_seq, limit).await }),
            self.deadline,
            self.generation,
        ))
    }
    fn fetch_entry(
        &mut self,
        seq: u64,
    ) -> GatewayCallFuture<'_, crate::gateway::push_point::PointReply> {
        Box::pin(self.handle.call_generation(
            move |engine| Box::pin(async move { engine.fetch_entry(seq).await }),
            self.deadline,
            self.generation,
        ))
    }
}
