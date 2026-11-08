// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ramflux_protocol::{Ack, Cursor, Envelope, Nack, ObjectChunkRequest, canonical_json_bytes};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::{
    AckFrame, AuthRequest, BackendKind, CursorFrame, DeliveryFrame, EnvelopeBatch, NackFrame,
    ObjectChunkStream, SubmitEnvelopeRequest, SubmitEnvelopeResult, TransportError,
    TransportFuture, TransportSession,
};

/// # Errors
/// Returns an error when the signed request or envelope cannot be canonicalized.
pub fn transport_submit_result(
    backend: BackendKind,
    request: &SubmitEnvelopeRequest,
) -> Result<SubmitEnvelopeResult, TransportError> {
    let signed_request_canonical = canonical_json_bytes(&request.signed_request)?;
    let envelope_canonical = canonical_json_bytes(&request.envelope)?;
    let envelope = decode_envelope(&envelope_canonical)?;
    Ok(SubmitEnvelopeResult { backend, signed_request_canonical, envelope_canonical, envelope })
}
#[derive(Clone, Debug)]
pub(crate) struct LoopbackBackend {
    kind: BackendKind,
    state: Arc<Mutex<LoopbackState>>,
}

#[derive(Debug, Default)]
struct LoopbackState {
    opened: bool,
    authed: bool,
    next_session: u64,
    deliveries: VecDeque<Envelope>,
    acks: Vec<Ack>,
    nacks: Vec<Nack>,
    cursors: Vec<Cursor>,
}

impl LoopbackBackend {
    pub(crate) fn new(kind: BackendKind) -> Self {
        Self { kind, state: Arc::new(Mutex::new(LoopbackState::default())) }
    }

    pub(crate) const fn kind(&self) -> BackendKind {
        self.kind
    }

    pub(crate) fn open(&self) -> TransportFuture<'_, TransportSession> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
            state.opened = true;
            state.next_session = state.next_session.saturating_add(1);
            Ok(TransportSession {
                backend: self.kind,
                session_id: format!("{}-session-{}", self.kind.as_str(), state.next_session),
            })
        })
    }

    pub(crate) fn accept(&self) -> TransportFuture<'_, TransportSession> {
        self.open()
    }

    pub(crate) fn auth(
        &self,
        session: TransportSession,
        _request: AuthRequest,
    ) -> TransportFuture<'_, TransportSession> {
        Box::pin(async move {
            self.ensure_backend(session.backend)?;
            let mut state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
            if !state.opened {
                return Err(TransportError::NotOpen);
            }
            state.authed = true;
            Ok(session)
        })
    }

    pub(crate) fn submit_envelope(
        &self,
        request: SubmitEnvelopeRequest,
    ) -> TransportFuture<'_, SubmitEnvelopeResult> {
        Box::pin(async move {
            self.ensure_authed()?;
            let result = transport_submit_result(self.kind, &request)?;
            let mut state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
            state.deliveries.push_back(result.envelope.clone());
            Ok(result)
        })
    }

    pub(crate) fn deliver(&self) -> TransportFuture<'_, DeliveryFrame> {
        Box::pin(async move {
            self.ensure_authed()?;
            let mut state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
            let envelope =
                state.deliveries.pop_front().ok_or(TransportError::EmptyDeliveryQueue)?;
            Ok(DeliveryFrame { backend: self.kind, envelope })
        })
    }

    pub(crate) fn pull_envelopes(&self, cursor: Cursor) -> TransportFuture<'_, EnvelopeBatch> {
        Box::pin(async move {
            self.ensure_authed()?;
            let mut state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
            let envelopes = state.deliveries.drain(..).collect();
            Ok(EnvelopeBatch { backend: self.kind, cursor, envelopes })
        })
    }

    pub(crate) fn ack(&self, ack: Ack) -> TransportFuture<'_, AckFrame> {
        Box::pin(async move {
            self.ensure_authed()?;
            let ack = decode_ack(&canonical_json_bytes(&ack)?)?;
            let mut state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
            state.acks.push(ack.clone());
            Ok(AckFrame { backend: self.kind, ack })
        })
    }

    pub(crate) fn nack(&self, nack: Nack) -> TransportFuture<'_, NackFrame> {
        Box::pin(async move {
            self.ensure_authed()?;
            let nack = decode_nack(&canonical_json_bytes(&nack)?)?;
            let mut state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
            state.nacks.push(nack.clone());
            Ok(NackFrame { backend: self.kind, nack })
        })
    }

    pub(crate) fn cursor(&self, cursor: Cursor) -> TransportFuture<'_, CursorFrame> {
        Box::pin(async move {
            self.ensure_authed()?;
            let cursor = decode_cursor(&canonical_json_bytes(&cursor)?)?;
            let mut state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
            state.cursors.push(cursor.clone());
            Ok(CursorFrame { backend: self.kind, cursor })
        })
    }

    pub(crate) fn request_object_chunks(
        &self,
        request: ObjectChunkRequest,
    ) -> TransportFuture<'_, ObjectChunkStream> {
        Box::pin(async move {
            self.ensure_authed()?;
            let request = decode_object_chunk_request(&canonical_json_bytes(&request)?)?;
            Ok(ObjectChunkStream {
                backend: self.kind,
                resume_token: request.resume_token.clone(),
                request,
                chunks: Vec::new(),
            })
        })
    }

    fn ensure_backend(&self, backend: BackendKind) -> Result<(), TransportError> {
        if backend == self.kind {
            Ok(())
        } else {
            Err(TransportError::BackendMismatch {
                expected: self.kind.as_str(),
                actual: backend.as_str(),
            })
        }
    }

    fn ensure_authed(&self) -> Result<(), TransportError> {
        let state = self.state.lock().map_err(|_err| TransportError::LockPoisoned)?;
        if !state.opened {
            return Err(TransportError::NotOpen);
        }
        if !state.authed {
            return Err(TransportError::NotAuthenticated);
        }
        Ok(())
    }
}

fn decode_envelope(bytes: &[u8]) -> Result<Envelope, TransportError> {
    Ok(ramflux_protocol::parse_i_json(bytes)?)
}

fn decode_ack(bytes: &[u8]) -> Result<Ack, TransportError> {
    Ok(ramflux_protocol::parse_i_json(bytes)?)
}

fn decode_nack(bytes: &[u8]) -> Result<Nack, TransportError> {
    Ok(ramflux_protocol::parse_i_json(bytes)?)
}

fn decode_cursor(bytes: &[u8]) -> Result<Cursor, TransportError> {
    Ok(serde_json::from_slice(bytes)?)
}

fn decode_object_chunk_request(bytes: &[u8]) -> Result<ObjectChunkRequest, TransportError> {
    Ok(serde_json::from_slice(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthRequest, BackendKind};
    use ramflux_protocol::{Ext, ProtocolError, SignatureAlg, SignedFields, SignedRequest};

    const IJSON_MAX: i64 = 9_007_199_254_740_991;
    const IJSON_OVERFLOW: i64 = 9_007_199_254_740_992;

    fn envelope(created_at: i64) -> Result<Envelope, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "schema": "ramflux.envelope.v1",
            "version": 1,
            "domain": "ramflux.envelope",
            "ext": {},
            "signing_key_id": "key",
            "signature_alg": "ed25519",
            "signature": "signature",
            "envelope_id": "envelope",
            "source_principal_id": "principal",
            "source_device_id": "device",
            "target_delivery_id": "delivery",
            "delivery_class": "opaque_event",
            "priority": "normal",
            "ttl": 60,
            "created_at": created_at,
            "encrypted_payload": "payload",
            "payload_hash": "hash"
        }))
    }

    fn signed_request() -> SignedRequest {
        SignedRequest {
            schema: "ramflux.signed_request.v1".to_owned(),
            version: 1,
            domain: "ramflux.signed_request".to_owned(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "key".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".to_owned(),
            },
            source_device_id: "device".to_owned(),
            request_id: "request".to_owned(),
            method: ramflux_protocol::HttpMethod::POST,
            path: "/submit".to_owned(),
            device_proof_hash: "proof".to_owned(),
            body_hash: "body".to_owned(),
            nonce: "nonce".to_owned(),
            created_at: 1,
            expires_at: 2,
        }
    }

    fn ack(received_at: i64) -> Result<Ack, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "schema": "ramflux.ack.v1",
            "version": 1,
            "domain": "ramflux.ack",
            "ext": {},
            "signing_key_id": "key",
            "signature_alg": "ed25519",
            "signature": "signature",
            "ack_id": "ack",
            "envelope_id": "envelope",
            "receiver_device_id": "device",
            "received_at": received_at
        }))
    }

    fn nack(received_at: i64) -> Result<Nack, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "schema": "ramflux.nack.v1",
            "version": 1,
            "domain": "ramflux.nack",
            "ext": {},
            "signing_key_id": "key",
            "signature_alg": "ed25519",
            "signature": "signature",
            "nack_id": "nack",
            "envelope_id": "envelope",
            "receiver_device_id": "device",
            "reason": "invalid_signature",
            "received_at": received_at
        }))
    }

    fn is_ijson_refusal<T>(result: &Result<T, TransportError>) -> bool {
        matches!(result, Err(TransportError::Protocol(ProtocolError::IJson(_))))
    }

    #[tokio::test]
    async fn loopback_signed_decodes_reject_unsafe_integer_without_queue_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let bad_envelope = envelope(IJSON_OVERFLOW)?;
        let bad_request = crate::SubmitEnvelopeRequest {
            signed_request: signed_request(),
            envelope: bad_envelope.clone(),
        };
        assert!(is_ijson_refusal(&transport_submit_result(BackendKind::GrpcH2, &bad_request)));

        let backend = LoopbackBackend::new(BackendKind::GrpcH2);
        let session = backend.open().await?;
        let session = backend
            .auth(
                session,
                AuthRequest {
                    device_id: "device".to_owned(),
                    signed_request_hash: "hash".to_owned(),
                },
            )
            .await?;
        assert!(is_ijson_refusal(&backend.submit_envelope(bad_request).await));
        assert!(is_ijson_refusal(&backend.ack(ack(IJSON_OVERFLOW)?).await));
        assert!(is_ijson_refusal(&backend.nack(nack(IJSON_OVERFLOW)?).await));
        {
            let state = backend.state.lock().map_err(|_| "loopback state lock poisoned")?;
            assert_eq!(state.deliveries.len(), 0);
            assert_eq!(state.acks.len(), 0);
            assert_eq!(state.nacks.len(), 0);
        }
        drop(session);
        Ok(())
    }

    #[tokio::test]
    async fn loopback_signed_decodes_accept_safe_integer_with_canonical_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let envelope = envelope(IJSON_MAX)?;
        let request = crate::SubmitEnvelopeRequest {
            signed_request: signed_request(),
            envelope: envelope.clone(),
        };
        let expected_envelope_bytes = canonical_json_bytes(&envelope)?;
        let result = transport_submit_result(BackendKind::GrpcH2, &request)?;
        assert_eq!(result.envelope, envelope);
        assert_eq!(result.envelope.created_at, IJSON_MAX);
        assert_eq!(result.envelope_canonical, expected_envelope_bytes);
        assert_eq!(canonical_json_bytes(&result.envelope)?, result.envelope_canonical);

        let backend = LoopbackBackend::new(BackendKind::GrpcH2);
        let session = backend.open().await?;
        let session = backend
            .auth(
                session,
                AuthRequest {
                    device_id: "device".to_owned(),
                    signed_request_hash: "hash".to_owned(),
                },
            )
            .await?;
        let submitted = backend.submit_envelope(request).await?;
        assert_eq!(submitted.envelope, envelope);
        assert_eq!(submitted.envelope.created_at, IJSON_MAX);
        assert_eq!(canonical_json_bytes(&submitted.envelope)?, submitted.envelope_canonical);

        let ack = ack(IJSON_MAX)?;
        let ack_bytes = canonical_json_bytes(&ack)?;
        let ack_frame = backend.ack(ack.clone()).await?;
        assert_eq!(ack_frame.ack, ack);
        assert_eq!(ack_frame.ack.received_at, IJSON_MAX);
        assert_eq!(canonical_json_bytes(&ack_frame.ack)?, ack_bytes);
        assert_eq!(ramflux_protocol::parse_i_json::<Ack>(&ack_bytes)?, ack_frame.ack);

        let nack = nack(IJSON_MAX)?;
        let nack_bytes = canonical_json_bytes(&nack)?;
        let nack_frame = backend.nack(nack.clone()).await?;
        assert_eq!(nack_frame.nack, nack);
        assert_eq!(nack_frame.nack.received_at, IJSON_MAX);
        assert_eq!(canonical_json_bytes(&nack_frame.nack)?, nack_bytes);
        assert_eq!(ramflux_protocol::parse_i_json::<Nack>(&nack_bytes)?, nack_frame.nack);
        drop(session);
        Ok(())
    }
}
