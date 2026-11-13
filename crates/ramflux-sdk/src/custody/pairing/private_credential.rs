// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private credential framing and connection-owned correlation. Secret bytes have no JSON arm.
use super::{CredentialOutcome, SecretUtf8};
use crate::SdkError;
use ramflux_protocol::custody::pairing::{PairingWire, local_dto::CredentialRequest};
use std::{
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;
mod async_reader;
pub use async_reader::read_reply_after_discriminator;
mod calls;
pub use calls::{
    PrivateCredentialCall, PrivateCredentialCallKind, bind_call, cancel_call, parent_request_id,
    provider_for_account,
};
mod frontend;
pub use frontend::PairingBusClient;
mod channel;
pub use channel::{
    PrivateCredentialChannel, PrivateCredentialPrompt, PrivateCredentialScopeResolver,
};
const TAG: u8 = 0xC1;
const MAX_BODY: usize = 2064;
// Distinct connections must not accidentally have equal outstanding request IDs:
// the raw reply carries no account/connection discriminator beyond this generation.
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);
fn invalid() -> SdkError {
    SdkError::PairingField("credential_frame")
}
fn action(value: &str) -> Result<(), SdkError> {
    if matches!(value, "setup" | "unlock" | "phrase") { Ok(()) } else { Err(invalid()) }
}
fn identifier(id: &str) -> Result<(), SdkError> {
    if id.len() != 43 {
        return Err(invalid());
    }
    let raw = ramflux_protocol::decode_base64url(id).map_err(|_| invalid())?;
    if raw.len() != 32 || ramflux_protocol::encode_base64url(raw) != id {
        return Err(invalid());
    }
    Ok(())
}
/// One decoded raw reply. No Debug, serde, string conversion or generic event representation.
pub struct PrivateCredentialReply {
    generation: u64,
    action: String,
    outcome: CredentialOutcome,
}
/// Encode the one designated private frame, including its four-byte length prefix.
/// # Errors
/// Refuses another action, unequal setup confirmation or confirmation on unlock/phrase.
pub fn encode_reply(
    generation: u64,
    requested: &str,
    outcome: &CredentialOutcome,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    action(requested)?;
    if generation == 0 {
        return Err(invalid());
    }
    let (arm, pass, confirm): (u8, &[u8], &[u8]) = match outcome {
        CredentialOutcome::Refused => (0, &[], &[]),
        CredentialOutcome::Provided { passphrase, confirmation } => {
            let confirm = confirmation.as_ref().map_or(&[][..], SecretUtf8::as_bytes);
            if (requested == "setup" && passphrase.as_bytes() != confirm)
                || (requested != "setup" && !confirm.is_empty())
            {
                return Err(invalid());
            }
            (1, passphrase.as_bytes(), confirm)
        }
    };
    let total = 14 + pass.len() + confirm.len();
    let mut bytes = Zeroizing::new(Vec::with_capacity(total + 4));
    bytes.extend_from_slice(&u32::try_from(total).map_err(|_| invalid())?.to_be_bytes());
    bytes.push(TAG);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.push(arm);
    bytes.extend_from_slice(&u16::try_from(pass.len()).map_err(|_| invalid())?.to_be_bytes());
    bytes.extend_from_slice(pass);
    bytes.extend_from_slice(&u16::try_from(confirm.len()).map_err(|_| invalid())?.to_be_bytes());
    bytes.extend_from_slice(confirm);
    Ok(bytes)
}
/// Read a raw private frame, checking the tag and passphrase length before payload allocation.
/// The caller owns this connection's private outstanding slot; no JSON reader is involved.
/// # Errors
/// Refuses overlong/short/trailing fields, another discriminator, unknown arms or invalid UTF-8.
pub fn read_reply(
    reader: &mut impl Read,
    requested: &str,
) -> Result<PrivateCredentialReply, SdkError> {
    read_reply_checked(reader, requested, None)
}
fn read_reply_checked(
    reader: &mut impl Read,
    requested: &str,
    expected_generation: Option<u64>,
) -> Result<PrivateCredentialReply, SdkError> {
    action(requested)?;
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let total = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| invalid())?;
    if !(14..=MAX_BODY).contains(&total) {
        return Err(invalid());
    }
    let mut header = [0; 12];
    reader.read_exact(&mut header[..1])?;
    if header[0] != TAG {
        return Err(invalid());
    }
    reader.read_exact(&mut header[1..])?;
    let generation = u64::from_be_bytes(header[1..9].try_into().map_err(|_| invalid())?);
    if generation == 0 || expected_generation.is_some_and(|expected| expected != generation) {
        return Err(invalid());
    }
    let arm = header[9];
    let pass_len = usize::from(u16::from_be_bytes([header[10], header[11]]));
    if arm > 1 || pass_len > 1024 || total < 14 + pass_len || (arm == 0 && pass_len != 0) {
        return Err(invalid());
    }
    let mut pass = Zeroizing::new(vec![0; pass_len]);
    reader.read_exact(&mut pass)?;
    let mut length = [0; 2];
    reader.read_exact(&mut length)?;
    let confirm_len = usize::from(u16::from_be_bytes(length));
    if confirm_len > 1024
        || total != 14 + pass_len + confirm_len
        || (arm == 0 && confirm_len != 0)
        || (requested != "setup" && confirm_len != 0)
    {
        return Err(invalid());
    }
    let mut confirm = Zeroizing::new(vec![0; confirm_len]);
    reader.read_exact(&mut confirm)?;
    finish_reply(generation, requested, arm, pass, confirm)
}
fn finish_reply(
    generation: u64,
    requested: &str,
    arm: u8,
    pass: Zeroizing<Vec<u8>>,
    confirm: Zeroizing<Vec<u8>>,
) -> Result<PrivateCredentialReply, SdkError> {
    let outcome = if arm == 0 {
        CredentialOutcome::Refused
    } else {
        if requested == "setup" && *pass != *confirm {
            return Err(invalid());
        }
        CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_owned(pass)?,
            confirmation: if requested == "setup" {
                Some(SecretUtf8::from_owned(confirm)?)
            } else {
                None
            },
        }
    };
    Ok(PrivateCredentialReply { generation, action: requested.into(), outcome })
}
/// Public metadata bound by the daemon to the actual local call. It grants no approval.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateCredentialScope {
    request: CredentialRequest,
    operation: Option<String>,
    candidate: Option<String>,
}
impl PrivateCredentialScope {
    #[must_use]
    pub const fn request(&self) -> &CredentialRequest {
        &self.request
    }
    #[must_use]
    pub fn operation_id(&self) -> Option<&str> {
        self.operation.as_deref()
    }
    #[must_use]
    pub fn candidate_hash(&self) -> Option<&str> {
        self.candidate.as_deref()
    }
    /// # Errors
    /// Refuses phrase input outside its separately revalidated responder preparation arm.
    pub fn data(request: CredentialRequest, operation: Option<String>) -> Result<Self, SdkError> {
        request.validate().map_err(|_| invalid())?;
        if request.action == "phrase" || (request.action == "setup" && operation.is_none()) {
            return Err(invalid());
        }
        if let Some(id) = &operation {
            identifier(id)?;
        }
        Ok(Self { request, operation, candidate: None })
    }
    /// # Errors
    /// Refuses another action/role/stage or invalid operation/candidate identifiers.
    pub fn phrase(
        request: CredentialRequest,
        operation: String,
        candidate: Option<String>,
        role: &str,
        stage: &str,
    ) -> Result<Self, SdkError> {
        request.validate().map_err(|_| invalid())?;
        if request.action != "phrase" || role != "responder" || stage != "awaiting_prepare" {
            return Err(invalid());
        }
        for id in std::iter::once(&operation).chain(candidate.iter()) {
            identifier(id)?;
        }
        Ok(Self { request, operation: Some(operation), candidate })
    }
}
/// One per accepted connection. Cancel/lock/disconnect retires the outstanding slot;
/// issuing another request never reuses a generation, including across accounts.
pub struct PrivateCredentialSlot {
    connection: u64,
    pending: Option<(u64, PrivateCredentialScope)>,
}
impl PrivateCredentialSlot {
    #[must_use]
    pub const fn new(connection: u64) -> Self {
        Self { connection, pending: None }
    }
    /// # Errors
    /// Refuses a concurrent private request or exhausted non-reused generation counter.
    pub fn issue(&mut self, scope: PrivateCredentialScope) -> Result<u64, SdkError> {
        if self.pending.is_some() {
            return Err(SdkError::PairingCode("Busy"));
        }
        let generation = NEXT_REQUEST
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| next.checked_add(1))
            .map_err(|_| invalid())?;
        self.pending = Some((generation, scope));
        Ok(generation)
    }
    pub fn retire(&mut self) {
        self.pending = None;
    }
    /// Consume once only after the daemon revalidates the actual role/stage/candidate scope.
    /// Invalid replies drop their zeroizing buffers and cannot satisfy another callback.
    /// # Errors
    /// Refuses another connection, stale generation, replaced call scope or repeated reply.
    pub fn consume(
        &mut self,
        connection: u64,
        current: &PrivateCredentialScope,
        reply: PrivateCredentialReply,
    ) -> Result<CredentialOutcome, SdkError> {
        let (generation, expected) = self.pending.take().ok_or_else(invalid)?;
        if connection != self.connection
            || generation != reply.generation
            || expected != *current
            || reply.action != expected.request.action
        {
            return Err(invalid());
        }
        Ok(reply.outcome)
    }
}
#[cfg(test)]
mod channel_tests;
#[cfg(test)]
mod tests;
