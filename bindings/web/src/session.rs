// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client side of the `web_origin_bound` exchange as a state machine without I/O.
//!
//! The owner of the socket feeds it the negotiated subprotocol and every binary message, and
//! writes the frames it returns. Every check the contract requires before a signature is produced
//! lives in [`WebHandshake::on_message`]; a failed check returns an error and signs nothing.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ramflux_protocol::custody::{CustodyProofAction, DeviceRef, Envelope, signing_bytes};
use ramflux_protocol::{decode_base64url, domain, encode_base64url};
use serde_json::Value;

use crate::WebError;
use crate::wire::{
    BINDING_MODE_WEB_ORIGIN_BOUND, MAX_GATEWAY_FRAME_BYTES, TRANSPORT_KIND_WEBSOCKET,
    WEB_BINDING_WINDOW_SECS, WEB_CLOCK_SKEW_SECS, WEB_DOWNSTREAM_WINDOW_ENTRIES,
    WEB_ORIGIN_BINDING_SCHEMA, WEB_PRE_SESSION_FRAME_MAX_BYTES, WEB_PROOF_MAX_LIFETIME_SECS,
    WEB_SESSION_SUBPROTOCOL, WEB_UPSTREAM_WINDOW_ENTRIES, WebBranchChallenge, WebBranchProof,
    WebClientFrame, WebOpenFrame, WebOriginBindingV1, WebServerFrame, is_canonical_listener_url,
    is_serialized_origin,
};

/// Facts fixed when the browser was linked. None of them comes from the connection.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebLinkPins {
    /// The listener URL this build dials, in canonical form.
    pub listener_url: String,
    /// `self.origin` of the worker that owns the socket.
    pub origin: String,
    /// Node id pinned at link time.
    pub node_id: String,
    /// Node signing key pinned at link time, base64url.
    pub node_signing_public_key: String,
    /// This web device.
    pub device_ref: DeviceRef,
    /// Hash of the branch certificate issued at link time.
    pub certificate_hash: String,
    /// Current authority head known to this device.
    pub record_hash: String,
}

/// Produces the two values the handshake cannot derive itself.
pub trait SessionAuthority {
    /// Sign the canonical branch-proof transcript with the branch key of this device.
    ///
    /// # Errors
    /// Returns an error when the branch key is unavailable.
    fn sign_branch_proof(&self, transcript: &[u8]) -> Result<[u8; 64], WebError>;

    /// Build `Open` and the signed `Auth` body for an authenticated custody session.
    ///
    /// # Errors
    /// Returns an error when the request cannot be signed.
    fn open_and_auth(&self, custody_session: &Value, now: u64)
    -> Result<(WebOpenFrame, Value), WebError>;
}

impl SessionAuthorityKey for SigningKey {
    fn sign_transcript(&self, transcript: &[u8]) -> [u8; 64] {
        self.sign(transcript).to_bytes()
    }
}

/// Branch-key signing, separated so a vault-backed key can implement it.
pub trait SessionAuthorityKey {
    fn sign_transcript(&self, transcript: &[u8]) -> [u8; 64];
}

/// Where the exchange stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakePhase {
    Connecting,
    AwaitNodeIdentity,
    AwaitWebBinding,
    /// First-time device only: the challenge for its own prekey registration.
    AwaitRegisterChallenge,
    AwaitRegistered,
    AwaitChallenge,
    AwaitCustodySession,
    AwaitGatewaySession,
    Established,
    Failed,
}

/// What the socket owner does after a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeStep {
    /// Write these binary messages in order.
    Send(Vec<Vec<u8>>),
    /// The gateway session exists. `session` is the gateway `session_established` body.
    Established { session: Value },
}

/// The `web_origin_bound` client exchange.
#[derive(Debug)]
pub struct WebHandshake {
    pins: WebLinkPins,
    phase: HandshakePhase,
    context: Option<WebOriginBindingV1>,
    first_registration: Option<Value>,
    registered_delivery_id: Option<String>,
}

impl WebHandshake {
    /// # Errors
    /// Returns [`WebError::Binding`] when the pinned URL or origin is not canonical.
    pub fn new(pins: WebLinkPins) -> Result<Self, WebError> {
        if !is_canonical_listener_url(&pins.listener_url) {
            return Err(WebError::Binding("listener URL is not canonical"));
        }
        if !is_serialized_origin(&pins.origin) {
            return Err(WebError::Binding("origin is not a serialized https origin"));
        }
        Ok(Self {
            pins,
            phase: HandshakePhase::Connecting,
            context: None,
            first_registration: None,
            registered_delivery_id: None,
        })
    }

    /// A first-time device registers its own prekey bundle on the same connection, before
    /// `open_session`. This is the device's own registration, never an account action.
    #[must_use]
    pub fn with_first_registration(mut self, prekey_bundle: Value) -> Self {
        self.first_registration = Some(prekey_bundle);
        self
    }

    /// Delivery id returned by the node for a first registration on this connection.
    #[must_use]
    pub fn registered_delivery_id(&self) -> Option<&str> {
        self.registered_delivery_id.as_deref()
    }

    #[must_use]
    pub const fn phase(&self) -> HandshakePhase {
        self.phase
    }

    /// Largest inbound frame accepted in the current phase.
    #[must_use]
    pub const fn inbound_cap(&self) -> usize {
        match self.phase {
            HandshakePhase::Established => MAX_GATEWAY_FRAME_BYTES,
            _ => WEB_PRE_SESSION_FRAME_MAX_BYTES,
        }
    }

    /// Called on the socket `open` event with `ws.protocol` and `ws.extensions`.
    ///
    /// # Errors
    /// Returns [`WebError::Transport`] unless the subprotocol is exact and no extension was
    /// negotiated. The caller closes with 1000.
    pub fn on_open(&mut self, protocol: &str, extensions: &str) -> Result<Vec<u8>, WebError> {
        if self.phase != HandshakePhase::Connecting {
            return self.fail(WebError::Protocol("socket opened twice"));
        }
        if protocol != WEB_SESSION_SUBPROTOCOL {
            return self.fail(WebError::Transport("subprotocol was not negotiated"));
        }
        if !extensions.is_empty() {
            return self.fail(WebError::Transport("an extension was negotiated"));
        }
        self.phase = HandshakePhase::AwaitNodeIdentity;
        WebClientFrame::CustodyOpen { binding_mode: BINDING_MODE_WEB_ORIGIN_BOUND.to_owned() }
            .encode(WEB_PRE_SESSION_FRAME_MAX_BYTES)
    }

    /// Feed one binary message received before the gateway session exists.
    ///
    /// `proof_id` is 32 fresh random bytes; `now` is the local clock in Unix seconds.
    ///
    /// # Errors
    /// Any error is terminal: the caller closes the socket with 1000 and nothing was signed
    /// after the failing check.
    pub fn on_message(
        &mut self,
        bytes: &[u8],
        now: u64,
        proof_id: [u8; 32],
        authority: &dyn SessionAuthority,
    ) -> Result<HandshakeStep, WebError> {
        let frame = match WebServerFrame::decode(bytes, self.inbound_cap()) {
            Ok(frame) => frame,
            Err(error) => return self.fail(error),
        };
        let result = self.advance(frame, now, proof_id, authority);
        if result.is_err() {
            self.phase = HandshakePhase::Failed;
        }
        result
    }

    fn fail<T>(&mut self, error: WebError) -> Result<T, WebError> {
        self.phase = HandshakePhase::Failed;
        Err(error)
    }

    fn advance(
        &mut self,
        frame: WebServerFrame,
        now: u64,
        proof_id: [u8; 32],
        authority: &dyn SessionAuthority,
    ) -> Result<HandshakeStep, WebError> {
        match (self.phase, frame) {
            (_, WebServerFrame::Refused { .. } | WebServerFrame::Closed) => Err(WebError::Refused),
            (
                HandshakePhase::AwaitNodeIdentity,
                WebServerFrame::NodeIdentity { record, audience, binding_mode, .. },
            ) => {
                self.check_node_identity(&record, &audience, &binding_mode, now)?;
                self.phase = HandshakePhase::AwaitWebBinding;
                Ok(HandshakeStep::Send(Vec::new()))
            }
            (HandshakePhase::AwaitWebBinding, WebServerFrame::WebBinding { context }) => {
                self.check_context(&context, now)?;
                self.context = Some(context);
                let action = match self.first_registration.clone() {
                    Some(prekey_bundle) => {
                        self.phase = HandshakePhase::AwaitRegisterChallenge;
                        CustodyProofAction::Register { prekey_bundle }
                    }
                    None => {
                        self.phase = HandshakePhase::AwaitChallenge;
                        CustodyProofAction::OpenSession
                    }
                };
                self.send_challenge(action)
            }
            (HandshakePhase::AwaitRegisterChallenge, WebServerFrame::Challenge { challenge }) => {
                let Some(prekey_bundle) = self.first_registration.take() else {
                    return Err(WebError::Protocol("no registration is pending"));
                };
                let proof = self.prove(&challenge, now, proof_id, authority)?;
                self.phase = HandshakePhase::AwaitRegistered;
                let frame = WebClientFrame::Prove {
                    action: CustodyProofAction::Register { prekey_bundle },
                    proof: Box::new(proof),
                };
                Ok(HandshakeStep::Send(vec![frame.encode(WEB_PRE_SESSION_FRAME_MAX_BYTES)?]))
            }
            (
                HandshakePhase::AwaitRegistered,
                WebServerFrame::Registered { device_ref, target_delivery_id },
            ) => {
                if device_ref != self.pins.device_ref {
                    return Err(WebError::Binding("node registered another device"));
                }
                self.registered_delivery_id = Some(target_delivery_id);
                self.phase = HandshakePhase::AwaitChallenge;
                self.send_challenge(CustodyProofAction::OpenSession)
            }
            (HandshakePhase::AwaitChallenge, WebServerFrame::Challenge { challenge }) => {
                let proof = self.prove(&challenge, now, proof_id, authority)?;
                self.phase = HandshakePhase::AwaitCustodySession;
                let frame = WebClientFrame::Prove {
                    action: CustodyProofAction::OpenSession,
                    proof: Box::new(proof),
                };
                Ok(HandshakeStep::Send(vec![frame.encode(WEB_PRE_SESSION_FRAME_MAX_BYTES)?]))
            }
            (HandshakePhase::AwaitCustodySession, WebServerFrame::SessionEstablished { session }) => {
                let session_id = custody_session_id(&session, &self.pins)?;
                let (open, auth) = authority.open_and_auth(&session, now)?;
                check_open(&open, &self.pins)?;
                self.phase = HandshakePhase::AwaitGatewaySession;
                Ok(HandshakeStep::Send(vec![
                    WebClientFrame::GatewayHandoff { session_id }
                        .encode(WEB_PRE_SESSION_FRAME_MAX_BYTES)?,
                    WebClientFrame::Open { open }.encode(WEB_PRE_SESSION_FRAME_MAX_BYTES)?,
                    WebClientFrame::Auth { auth }.encode(WEB_PRE_SESSION_FRAME_MAX_BYTES)?,
                ]))
            }
            (HandshakePhase::AwaitGatewaySession, WebServerFrame::SessionEstablished { session }) => {
                self.phase = HandshakePhase::Established;
                self.context = None;
                Ok(HandshakeStep::Established { session })
            }
            _ => Err(WebError::Protocol("frame is not legal in this state")),
        }
    }

    fn send_challenge(&self, action: CustodyProofAction) -> Result<HandshakeStep, WebError> {
        let frame = WebClientFrame::Challenge { device_ref: self.pins.device_ref.clone(), action };
        Ok(HandshakeStep::Send(vec![frame.encode(WEB_PRE_SESSION_FRAME_MAX_BYTES)?]))
    }

    /// Contract check 3: the record verifies under the node key pinned at link time and
    /// advertises this listener for this origin.
    fn check_node_identity(
        &self,
        record: &Envelope<Value>,
        audience: &str,
        binding_mode: &str,
        now: u64,
    ) -> Result<(), WebError> {
        if binding_mode != BINDING_MODE_WEB_ORIGIN_BOUND {
            return Err(WebError::Binding("node answered with another binding mode"));
        }
        if audience != self.pins.node_id {
            return Err(WebError::Binding("audience is not the pinned node"));
        }
        let body = &record.body;
        if body.get("node_id").and_then(Value::as_str) != Some(self.pins.node_id.as_str())
            || body.get("node_signing_public_key").and_then(Value::as_str)
                != Some(self.pins.node_signing_public_key.as_str())
        {
            return Err(WebError::Binding("node record differs from the link-time pin"));
        }
        if body.get("issued_at").and_then(Value::as_u64).is_none_or(|issued| {
            issued > now.saturating_add(WEB_CLOCK_SKEW_SECS)
        }) {
            return Err(WebError::Binding("node record is from the future"));
        }
        verify_pinned_signature(
            &self.pins.node_signing_public_key,
            &signing_bytes(domain::CUSTODY_NODE_RECORD, body)?,
            &record.signature,
        )?;
        let advertises_mode = body
            .get("channel_binding_modes")
            .and_then(Value::as_array)
            .is_some_and(|modes| modes.iter().any(|m| m.as_str() == Some(BINDING_MODE_WEB_ORIGIN_BOUND)));
        if !advertises_mode {
            return Err(WebError::Binding("node record does not advertise web_origin_bound"));
        }
        let lists_listener = body.get("web_listeners").and_then(Value::as_array).is_some_and(|all| {
            all.iter().any(|listener| {
                listener.get("url").and_then(Value::as_str) == Some(self.pins.listener_url.as_str())
                    && listener.get("origins").and_then(Value::as_array).is_some_and(|origins| {
                        origins.iter().any(|o| o.as_str() == Some(self.pins.origin.as_str()))
                    })
            })
        });
        if !lists_listener {
            return Err(WebError::Binding("node record does not list this listener and origin"));
        }
        Ok(())
    }

    /// Contract checks 1, 2 and 4.
    fn check_context(&self, context: &WebOriginBindingV1, now: u64) -> Result<(), WebError> {
        if context.schema != WEB_ORIGIN_BINDING_SCHEMA || context.version != 1 {
            return Err(WebError::Binding("unsupported binding context"));
        }
        if context.origin != self.pins.origin {
            return Err(WebError::Binding("context origin is not this origin"));
        }
        if context.listener_url != self.pins.listener_url {
            return Err(WebError::Binding("context listener is not the dialed listener"));
        }
        if context.node_id != self.pins.node_id {
            return Err(WebError::Binding("context node is not the pinned node"));
        }
        if context.transport_kind != TRANSPORT_KIND_WEBSOCKET {
            return Err(WebError::Binding("context transport is not websocket"));
        }
        if context.expires_at.checked_sub(context.issued_at) != Some(WEB_BINDING_WINDOW_SECS) {
            return Err(WebError::Binding("context window is not 300 seconds"));
        }
        if now.abs_diff(context.issued_at) > WEB_CLOCK_SKEW_SECS {
            return Err(WebError::Clock);
        }
        if decode_base64url(&context.gateway_nonce).map(|nonce| nonce.len()) != Ok(32) {
            return Err(WebError::Binding("gateway nonce is not 32 bytes"));
        }
        Ok(())
    }

    /// Contract check 5, then the signature.
    fn prove(
        &self,
        challenge: &WebBranchChallenge,
        now: u64,
        proof_id: [u8; 32],
        authority: &dyn SessionAuthority,
    ) -> Result<Envelope<WebBranchProof>, WebError> {
        let Some(context) = self.context.as_ref() else {
            return Err(WebError::Protocol("challenge arrived before the binding context"));
        };
        if challenge.binding_mode != BINDING_MODE_WEB_ORIGIN_BOUND {
            return Err(WebError::Binding("challenge names another binding mode"));
        }
        if challenge.audience != context.node_id {
            return Err(WebError::Binding("challenge audience is not the context node"));
        }
        // The proof window is the server's, never the local clock's.
        let issued_at = challenge.issued_at.max(context.issued_at);
        let expires_at = challenge
            .expires_at
            .min(context.expires_at)
            .min(issued_at.saturating_add(WEB_PROOF_MAX_LIFETIME_SECS));
        if expires_at <= issued_at || now > expires_at.saturating_add(WEB_CLOCK_SKEW_SECS) {
            return Err(WebError::Binding("challenge or context already expired"));
        }
        let body = WebBranchProof {
            schema: domain::BRANCH_PROOF_V3.to_owned(),
            version: WebBranchProof::version(),
            device_ref: self.pins.device_ref.clone(),
            certificate_hash: self.pins.certificate_hash.clone(),
            record_hash: self.pins.record_hash.clone(),
            proof_id: encode_base64url(proof_id),
            challenge_nonce: challenge.challenge_nonce.clone(),
            action_hash: challenge.action_hash.clone(),
            audience: context.node_id.clone(),
            binding_mode: BINDING_MODE_WEB_ORIGIN_BOUND.to_owned(),
            transport_binding: context.transport_binding()?,
            issued_at,
            expires_at,
        };
        let transcript = signing_bytes(domain::BRANCH_PROOF_V3, &body)?;
        let signature = encode_base64url(authority.sign_branch_proof(&transcript)?);
        Ok(Envelope { body, signature })
    }
}

fn custody_session_id(session: &Value, pins: &WebLinkPins) -> Result<String, WebError> {
    if session.get("binding_mode").and_then(Value::as_str) != Some(BINDING_MODE_WEB_ORIGIN_BOUND) {
        return Err(WebError::Binding("custody session names another binding mode"));
    }
    let same_device = session
        .get("device_ref")
        .and_then(|value| serde_json::from_value::<DeviceRef>(value.clone()).ok())
        .is_some_and(|device| device == pins.device_ref);
    if !same_device {
        return Err(WebError::Binding("custody session is for another device"));
    }
    session
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or(WebError::Protocol("custody session has no id"))
}

/// The `Open` a browser may send: websocket, this device, no admission claims, clamped windows.
fn check_open(open: &WebOpenFrame, pins: &WebLinkPins) -> Result<(), WebError> {
    if open.transport_kind != TRANSPORT_KIND_WEBSOCKET {
        return Err(WebError::Protocol("Open.transport_kind must be websocket"));
    }
    if open.device_id != pins.device_ref.device_id {
        return Err(WebError::Protocol("Open.device_id is not the proven device"));
    }
    if open.pre_auth_now.is_some() || open.source_ip_hash.is_some() {
        return Err(WebError::Protocol("Open must not carry admission claims"));
    }
    if open.max_inflight_downstream > WEB_DOWNSTREAM_WINDOW_ENTRIES
        || open.max_inflight_upstream > WEB_UPSTREAM_WINDOW_ENTRIES
    {
        return Err(WebError::Protocol("Open windows exceed the web listener clamp"));
    }
    Ok(())
}

fn verify_pinned_signature(
    public_key: &str,
    message: &[u8],
    signature: &str,
) -> Result<(), WebError> {
    let refused = WebError::Binding("node record signature does not verify under the pin");
    let key: [u8; 32] =
        decode_base64url(public_key).ok().and_then(|k| k.try_into().ok()).ok_or(refused.clone())?;
    let signature: [u8; 64] =
        decode_base64url(signature).ok().and_then(|s| s.try_into().ok()).ok_or(refused.clone())?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| refused.clone())?;
    key.verify(message, &Signature::from_bytes(&signature)).map_err(|_| refused)
}

#[cfg(test)]
mod tests;
