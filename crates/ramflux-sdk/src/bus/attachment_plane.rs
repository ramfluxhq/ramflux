// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production attachment plane: every owner, registration, read and retirement call is one
//! frame on the account's authenticated gateway session. The gateway names the requester from
//! that session and forwards to the home relay over its mesh identity. The plane holds a
//! handle, never a session, so a worker thread opens a fresh capability per call and a
//! reconnect is picked up on the next call.

use std::time::Duration;

use ramflux_node_core::{AttachmentCall, AttachmentFrame, WireBytes};
use tokio::runtime::Handle;

use super::connection_manager::{ConnectionHandle, NetworkingState, SessionClient};
use crate::SdkError;
use crate::attachment_send::{
    CODE_AUTHORITY_UNAVAILABLE, OwnerCall, Plane, ReadCall, Refusal, RegisterCall, RetireCall,
};

const CALL_BUDGET: Duration = Duration::from_secs(60);

pub(crate) struct GatewayPlane {
    handle: ConnectionHandle,
    runtime: Handle,
}

impl GatewayPlane {
    /// Captures the current connection and the runtime that blocking workers will drive.
    pub(crate) fn new(handle: ConnectionHandle, runtime: Handle) -> Self {
        Self { handle, runtime }
    }

    fn session(&self) -> Result<SessionClient, SdkError> {
        let snapshot = self.handle.snapshot();
        if snapshot.state != NetworkingState::Live {
            return Err(self.handle.pending());
        }
        let metadata = self.handle.metadata().ok_or(SdkError::GatewaySessionNotEstablished)?;
        if metadata.generation != snapshot.generation {
            return Err(self.handle.pending());
        }
        Ok(SessionClient::new(
            self.handle.clone(),
            metadata,
            tokio::time::Instant::now() + CALL_BUDGET,
        ))
    }

    /// Runs one call and returns the reply body, or the stable code the relay answered with.
    fn call(&self, call: AttachmentCall) -> Result<Vec<u8>, Refusal> {
        let request_id = request_id()?;
        let mut session =
            self.session().map_err(|_| Refusal::new(CODE_AUTHORITY_UNAVAILABLE))?;
        let reply = self
            .runtime
            .block_on(session.attachment_call(AttachmentFrame { request_id, call }))
            .map_err(|_| Refusal::new(CODE_AUTHORITY_UNAVAILABLE))?;
        match reply.code {
            None => Ok(reply.body.0),
            Some(code) => Err(crate::attachment_send::refusal_for(&code)),
        }
    }

}

fn request_id() -> Result<String, Refusal> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Refusal::new(CODE_AUTHORITY_UNAVAILABLE))?;
    Ok(ramflux_protocol::encode_base64url(bytes))
}

impl Plane for GatewayPlane {
    fn authority(&self) -> Result<Vec<u8>, Refusal> {
        self.call(AttachmentCall::Authority)
    }

    fn owner(&self, call: &OwnerCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.call(AttachmentCall::Owner {
            operation: WireBytes(call.operation.to_vec()),
            body: WireBytes(call.body.to_vec()),
            proof: WireBytes(call.proof.to_vec()),
            signature: WireBytes(call.signature.to_vec()),
        })
    }

    fn register(&self, call: &RegisterCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.call(AttachmentCall::Register {
            upload_id: WireBytes(call.upload_id.to_vec()),
            manifest: WireBytes(call.manifest.to_vec()),
            grant: WireBytes(call.grant.to_vec()),
        })
    }

    fn read(&self, call: &ReadCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.call(AttachmentCall::Read {
            capability: WireBytes(call.capability.to_vec()),
            object_id: WireBytes(call.object_id.to_vec()),
            manifest_hash: WireBytes(call.manifest_hash.to_vec()),
            index: call.index,
            offset: call.offset,
            length: call.length,
        })
    }

    fn retire(&self, call: &RetireCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.call(AttachmentCall::Retire {
            retirement: WireBytes(call.retirement.to_vec()),
            signature: WireBytes(call.signature.to_vec()),
        })
    }
}
