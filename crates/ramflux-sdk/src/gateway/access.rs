// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session capabilities shared by direct SDK engines and daemon-managed clients.

use crate::prelude::*;
use std::{future::Future, pin::Pin};

/// One bounded session exchange, whose storage effects remain owned by its caller.
pub type GatewayCallFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SdkError>> + Send + 'a>>;

mod sealed {
    use super::{GatewayCallFuture, GatewayInboxEntry};
    use crate::gateway::session_push::SubmitRefusal;

    /// Submit that separates a certain gateway refusal (inner `Err`) from every uncertain failure
    /// (outer `Err`). Sealed: only the engine and the account's session client implement it.
    // The refusal type is crate-private; the trait is sealed and unreachable outside the crate.
    #[allow(private_interfaces)]
    pub trait ClassifiedSubmit: Send {
        /// # Errors
        /// Returns an error when the exchange fails after or while writing (uncertain).
        fn submit_classified(
            &mut self,
            envelope: ramflux_protocol::Envelope,
        ) -> GatewayCallFuture<'_, Result<GatewayInboxEntry, SubmitRefusal>>;
    }
}
pub(crate) use sealed::ClassifiedSubmit;

#[allow(private_interfaces)]
impl ClassifiedSubmit for GatewaySessionEngine {
    fn submit_classified(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, Result<GatewayInboxEntry, crate::gateway::session_push::SubmitRefusal>>
    {
        Box::pin(self.submit_envelope_classified(envelope))
    }
}

/// Gateway capabilities usable with a direct engine or an account's resident session host.
// The sealed `ClassifiedSubmit` supertrait is crate-private by design: every implementor is
// already classified, so callers that need it add no bound of their own.
#[allow(private_bounds)]
pub trait GatewaySessionAccess: Send + sealed::ClassifiedSubmit {
    /// Returns the caller's immutable connection coordinates and signing context.
    fn config(&self) -> &GatewaySessionConfig;
    /// Returns the authenticated session metadata captured for this caller's generation.
    fn session(&self) -> &GatewaySessionState;
    /// Returns the authenticated mailbox target.
    fn target_delivery_id(&self) -> &str {
        &self.config().target_delivery_id
    }
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn heartbeat(&mut self) -> GatewayCallFuture<'_, ()>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn submit_envelope(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, GatewayInboxEntry>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn own_device_fanout(
        &mut self,
        principal_id: impl Into<String>,
        source_device_id: impl Into<String>,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, GatewayOwnDeviceFanoutResponse>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn ack(&mut self, ack: ramflux_protocol::Ack) -> GatewayCallFuture<'_, GatewayCursor>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn cursor(&mut self) -> GatewayCallFuture<'_, Option<GatewayCursor>>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn resume_after(
        &mut self,
        after_inbox_seq: u64,
        limit: usize,
    ) -> GatewayCallFuture<'_, Vec<GatewayInboxEntry>>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn register_identity(
        &mut self,
        request: SdkIdentityRegisterRequest,
    ) -> GatewayCallFuture<'_, SdkIdentityRegistrationResponse>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn publish_prekey_bundle<'a>(
        &'a mut self,
        device_id: &'a str,
        bundle: &'a ramflux_crypto::PrekeyBundle,
    ) -> GatewayCallFuture<'a, SdkPrekeyResponse>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn fetch_principal_manifest<'a>(
        &'a mut self,
        principal: &'a str,
    ) -> GatewayCallFuture<'a, Option<SdkDeviceManifestResponse>>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn fetch_prekey_bundle<'a>(
        &'a mut self,
        device_id: &'a str,
    ) -> GatewayCallFuture<'a, SdkPrekeyResponse>;
    #[cfg(feature = "itest-local-mint")]
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn issue_relay_token(
        &mut self,
        body: GatewayRelayTokenIssueBody,
    ) -> GatewayCallFuture<'_, SdkRelayToken>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn issue_relay_token_v3(
        &mut self,
        body: SdkRelayTokenV3IssueBody,
    ) -> GatewayCallFuture<'_, ramflux_protocol::RelayTokenV3>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn voice_lease(
        &mut self,
        body: ramflux_protocol::VoiceLeaseRequest,
    ) -> GatewayCallFuture<'_, ramflux_protocol::VoiceLeaseResponse>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn set_push_route(
        &mut self,
        route: Option<GatewayPushRouteRegistration>,
    ) -> GatewayCallFuture<'_, Option<u64>>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn register_push_route(&mut self) -> GatewayCallFuture<'_, Option<String>>;
    /// # Errors
    /// Returns an error if the session exchange is refused, cancelled, or expires.
    fn close<'a>(&'a mut self, reason: &'a str) -> GatewayCallFuture<'a, ()>;
}

impl GatewaySessionAccess for GatewaySessionEngine {
    fn config(&self) -> &GatewaySessionConfig {
        &self.config
    }
    fn session(&self) -> &GatewaySessionState {
        self.session()
    }
    fn heartbeat(&mut self) -> GatewayCallFuture<'_, ()> {
        Box::pin(GatewaySessionEngine::heartbeat(self))
    }
    fn submit_envelope(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, GatewayInboxEntry> {
        Box::pin(GatewaySessionEngine::submit_envelope(self, envelope))
    }
    fn own_device_fanout(
        &mut self,
        principal_id: impl Into<String>,
        source_device_id: impl Into<String>,
        envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, GatewayOwnDeviceFanoutResponse> {
        let principal_id = principal_id.into();
        let source_device_id = source_device_id.into();
        Box::pin(GatewaySessionEngine::own_device_fanout(
            self,
            principal_id,
            source_device_id,
            envelope,
        ))
    }
    fn ack(&mut self, ack: ramflux_protocol::Ack) -> GatewayCallFuture<'_, GatewayCursor> {
        Box::pin(GatewaySessionEngine::ack(self, ack))
    }
    fn cursor(&mut self) -> GatewayCallFuture<'_, Option<GatewayCursor>> {
        Box::pin(GatewaySessionEngine::cursor(self))
    }
    fn resume_after(
        &mut self,
        after_inbox_seq: u64,
        limit: usize,
    ) -> GatewayCallFuture<'_, Vec<GatewayInboxEntry>> {
        Box::pin(GatewaySessionEngine::resume_after(self, after_inbox_seq, limit))
    }
    fn register_identity(
        &mut self,
        request: SdkIdentityRegisterRequest,
    ) -> GatewayCallFuture<'_, SdkIdentityRegistrationResponse> {
        Box::pin(GatewaySessionEngine::register_identity(self, request))
    }
    fn publish_prekey_bundle<'a>(
        &'a mut self,
        device_id: &'a str,
        bundle: &'a ramflux_crypto::PrekeyBundle,
    ) -> GatewayCallFuture<'a, SdkPrekeyResponse> {
        Box::pin(GatewaySessionEngine::publish_prekey_bundle(self, device_id, bundle))
    }
    fn fetch_principal_manifest<'a>(
        &'a mut self,
        principal: &'a str,
    ) -> GatewayCallFuture<'a, Option<SdkDeviceManifestResponse>> {
        Box::pin(GatewaySessionEngine::fetch_principal_manifest(self, principal))
    }
    fn fetch_prekey_bundle<'a>(
        &'a mut self,
        device_id: &'a str,
    ) -> GatewayCallFuture<'a, SdkPrekeyResponse> {
        Box::pin(GatewaySessionEngine::fetch_prekey_bundle(self, device_id))
    }
    #[cfg(feature = "itest-local-mint")]
    fn issue_relay_token(
        &mut self,
        body: GatewayRelayTokenIssueBody,
    ) -> GatewayCallFuture<'_, SdkRelayToken> {
        Box::pin(GatewaySessionEngine::issue_relay_token(self, body))
    }
    fn issue_relay_token_v3(
        &mut self,
        body: SdkRelayTokenV3IssueBody,
    ) -> GatewayCallFuture<'_, ramflux_protocol::RelayTokenV3> {
        Box::pin(GatewaySessionEngine::issue_relay_token_v3(self, body))
    }
    fn voice_lease(
        &mut self,
        body: ramflux_protocol::VoiceLeaseRequest,
    ) -> GatewayCallFuture<'_, ramflux_protocol::VoiceLeaseResponse> {
        Box::pin(GatewaySessionEngine::voice_lease(self, body))
    }
    fn set_push_route(
        &mut self,
        route: Option<GatewayPushRouteRegistration>,
    ) -> GatewayCallFuture<'_, Option<u64>> {
        Box::pin(GatewaySessionEngine::set_push_route(self, route))
    }
    fn register_push_route(&mut self) -> GatewayCallFuture<'_, Option<String>> {
        Box::pin(GatewaySessionEngine::register_push_route(self))
    }
    fn close<'a>(&'a mut self, reason: &'a str) -> GatewayCallFuture<'a, ()> {
        Box::pin(GatewaySessionEngine::close(self, reason))
    }
}

#[cfg(test)]
fn unused<'a, T: Send + 'a>(name: &'static str) -> GatewayCallFuture<'a, T> {
    Box::pin(async move { Err(SdkError::LocalBus(name.into())) })
}

/// Counts `resume_after` and `ack` so an Activated legacy path can prove it never touched the wire.
#[cfg(test)]
pub(crate) struct CountingGateway {
    config: GatewaySessionConfig,
    session: GatewaySessionState,
    pub resumes: u32,
    pub acks: u32,
}

#[cfg(test)]
impl CountingGateway {
    pub(crate) fn new(config: GatewaySessionConfig) -> Self {
        Self {
            config,
            session: GatewaySessionState {
                session_id: "counting".into(),
                gateway_id: "counting".into(),
                resume_token: "counting".into(),
                resume_window_seconds: 1,
                accepted_inbox_seq: 0,
            },
            resumes: 0,
            acks: 0,
        }
    }
}

#[cfg(test)]
impl ClassifiedSubmit for CountingGateway {
    fn submit_classified(
        &mut self,
        _envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, Result<GatewayInboxEntry, crate::gateway::session_push::SubmitRefusal>>
    {
        unused("submit_classified")
    }
}

#[cfg(test)]
impl GatewaySessionAccess for CountingGateway {
    fn config(&self) -> &GatewaySessionConfig {
        &self.config
    }
    fn session(&self) -> &GatewaySessionState {
        &self.session
    }
    fn heartbeat(&mut self) -> GatewayCallFuture<'_, ()> {
        unused("heartbeat")
    }
    fn submit_envelope(
        &mut self,
        _envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, GatewayInboxEntry> {
        unused("submit_envelope")
    }
    fn own_device_fanout(
        &mut self,
        _principal_id: impl Into<String>,
        _source_device_id: impl Into<String>,
        _envelope: ramflux_protocol::Envelope,
    ) -> GatewayCallFuture<'_, GatewayOwnDeviceFanoutResponse> {
        unused("own_device_fanout")
    }
    fn ack(&mut self, _ack: ramflux_protocol::Ack) -> GatewayCallFuture<'_, GatewayCursor> {
        self.acks += 1;
        let target = self.config.target_delivery_id.clone();
        Box::pin(async move {
            Ok(GatewayCursor {
                target_delivery_id: target,
                inbox_seq: 1,
                last_envelope_id: None,
                acked_envelope_ids: Vec::new(),
                nacked_envelope_ids: std::collections::BTreeMap::new(),
            })
        })
    }
    fn cursor(&mut self) -> GatewayCallFuture<'_, Option<GatewayCursor>> {
        unused("cursor")
    }
    fn resume_after(
        &mut self,
        _after_inbox_seq: u64,
        _limit: usize,
    ) -> GatewayCallFuture<'_, Vec<GatewayInboxEntry>> {
        self.resumes += 1;
        Box::pin(async move { Ok(Vec::new()) })
    }
    fn register_identity(
        &mut self,
        _request: SdkIdentityRegisterRequest,
    ) -> GatewayCallFuture<'_, SdkIdentityRegistrationResponse> {
        unused("register_identity")
    }
    fn publish_prekey_bundle<'a>(
        &'a mut self,
        _device_id: &'a str,
        _bundle: &'a ramflux_crypto::PrekeyBundle,
    ) -> GatewayCallFuture<'a, SdkPrekeyResponse> {
        unused("publish_prekey_bundle")
    }
    fn fetch_principal_manifest<'a>(
        &'a mut self,
        _principal: &'a str,
    ) -> GatewayCallFuture<'a, Option<SdkDeviceManifestResponse>> {
        unused("fetch_principal_manifest")
    }
    fn fetch_prekey_bundle<'a>(
        &'a mut self,
        _device_id: &'a str,
    ) -> GatewayCallFuture<'a, SdkPrekeyResponse> {
        unused("fetch_prekey_bundle")
    }
    #[cfg(feature = "itest-local-mint")]
    fn issue_relay_token(
        &mut self,
        _body: GatewayRelayTokenIssueBody,
    ) -> GatewayCallFuture<'_, SdkRelayToken> {
        unused("issue_relay_token")
    }
    fn issue_relay_token_v3(
        &mut self,
        _body: SdkRelayTokenV3IssueBody,
    ) -> GatewayCallFuture<'_, ramflux_protocol::RelayTokenV3> {
        unused("issue_relay_token_v3")
    }
    fn voice_lease(
        &mut self,
        _body: ramflux_protocol::VoiceLeaseRequest,
    ) -> GatewayCallFuture<'_, ramflux_protocol::VoiceLeaseResponse> {
        unused("voice_lease")
    }
    fn set_push_route(
        &mut self,
        _route: Option<GatewayPushRouteRegistration>,
    ) -> GatewayCallFuture<'_, Option<u64>> {
        unused("set_push_route")
    }
    fn register_push_route(&mut self) -> GatewayCallFuture<'_, Option<String>> {
        unused("register_push_route")
    }
    fn close<'a>(&'a mut self, _reason: &'a str) -> GatewayCallFuture<'a, ()> {
        unused("close")
    }
}
