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
    Ok(serde_json::from_slice(bytes)?)
}

fn decode_ack(bytes: &[u8]) -> Result<Ack, TransportError> {
    Ok(serde_json::from_slice(bytes)?)
}

fn decode_nack(bytes: &[u8]) -> Result<Nack, TransportError> {
    Ok(serde_json::from_slice(bytes)?)
}

fn decode_cursor(bytes: &[u8]) -> Result<Cursor, TransportError> {
    Ok(serde_json::from_slice(bytes)?)
}

fn decode_object_chunk_request(bytes: &[u8]) -> Result<ObjectChunkRequest, TransportError> {
    Ok(serde_json::from_slice(bytes)?)
}
