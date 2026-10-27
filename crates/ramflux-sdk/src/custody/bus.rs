// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exclusive trusted-client transport for secret setup, never ordinary bus response frames.
use super::{CreateInput, CreationState};
use crate::SdkError;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use zeroize::Zeroizing;

pub(crate) const SETUP_FRAME_BYTES: usize = 4096;
pub(crate) const SETUP_REQUEST_ID_BYTES: usize = 128;

pub(crate) struct SecretBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl SecretBuffer {
    pub(crate) fn new(limit: usize) -> Self {
        Self { bytes: Zeroizing::new(Vec::with_capacity(limit)), limit }
    }
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
}
impl std::io::Write for SecretBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "custody setup frame exceeds fixed secret buffer",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Owns a dedicated connection; dropping it cancels and erases the server ceremony.
pub struct CustodyBusClient {
    stream: UnixStream,
    sequence: u64,
}
#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Response {
    Prepared { account_anchor: String },
    Phrase { phrase: Zeroizing<String> },
    Challenge { positions: [u8; 3] },
    NetworkingPending { account: serde_json::Value },
    Cancelled,
    Error { code: String },
}
#[derive(Deserialize)]
struct Reply {
    protocol: String,
    request_id: String,
    result: Response,
}
#[derive(Serialize)]
struct SetupFrame<'a, T> {
    bus_protocol: &'static str,
    frame_id: &'a str,
    kind: &'static str,
    request_id: &'a str,
    account_id: Option<&'a str>,
    sdk_api: &'static str,
    method: &'a str,
    body: T,
    trace_id: Option<&'a str>,
}
/// Public confirmation result. It cannot be mistaken for an established account/session.
#[derive(Debug)]
pub struct ConfirmedAccount {
    pub state: CreationState,
    pub account: serde_json::Value,
}
impl CustodyBusClient {
    /// # Errors
    /// Returns a local connection error. The socket uses the daemon's same-user peer policy.
    pub async fn connect(socket: impl AsRef<std::path::Path>) -> Result<Self, SdkError> {
        Ok(Self { stream: UnixStream::connect(socket).await?, sequence: 0 })
    }
    /// # Errors
    /// Rejects disabled setup, an existing account or invalid public intent.
    pub async fn begin(&mut self, input: &CreateInput) -> Result<String, SdkError> {
        match self.exchange("account.custody.begin", input).await? {
            Response::Prepared { account_anchor } => Ok(account_anchor),
            _ => Err(SdkError::CustodySetupInvalid),
        }
    }
    /// Secret display is deliberately separate from normal `LocalBusClient` responses.
    /// # Errors
    /// Rejects repeat display, an absent ceremony or expiration.
    pub async fn show_once(&mut self) -> Result<Zeroizing<String>, SdkError> {
        match self.exchange("account.custody.show_once", serde_json::json!({})).await? {
            Response::Phrase { phrase } => Ok(phrase),
            _ => Err(SdkError::CustodySetupInvalid),
        }
    }
    /// Call only after erasing the displayed phrase. Positions are selected at this call.
    /// # Errors
    /// Rejects wrong ordering, replay or expiration.
    pub async fn hidden_challenge(&mut self) -> Result<[u8; 3], SdkError> {
        match self.exchange("account.custody.hidden_challenge", serde_json::json!({})).await? {
            Response::Challenge { positions } => Ok(positions),
            _ => Err(SdkError::CustodySetupInvalid),
        }
    }
    /// Consumes the single confirmation attempt. Caller-owned word buffers erase on drop.
    /// # Errors
    /// Rejects wrong words, unavailable primary vaults or failed local persistence.
    pub async fn confirm(
        &mut self,
        words: &[Zeroizing<String>; 3],
    ) -> Result<ConfirmedAccount, SdkError> {
        #[derive(Serialize)]
        struct Words<'a> {
            words: &'a [Zeroizing<String>; 3],
        }
        if words.iter().any(|word| word.len() > 128) {
            return Err(SdkError::CustodySetupInvalid);
        }
        match self.exchange("account.custody.confirm", Words { words }).await? {
            Response::NetworkingPending { account } => {
                Ok(ConfirmedAccount { state: CreationState::NetworkingPending, account })
            }
            _ => Err(SdkError::CustodySetupInvalid),
        }
    }
    /// # Errors
    /// Returns transport or protocol errors.
    pub async fn cancel(&mut self) -> Result<(), SdkError> {
        match self.exchange("account.custody.cancel", serde_json::json!({})).await? {
            Response::Cancelled => Ok(()),
            _ => Err(SdkError::CustodySetupInvalid),
        }
    }
    async fn exchange<T: Serialize>(
        &mut self,
        method: &str,
        body: T,
    ) -> Result<Response, SdkError> {
        self.sequence = self.sequence.checked_add(1).ok_or(SdkError::CustodySetupInvalid)?;
        let request_id = format!("custody-{}", self.sequence);
        let request = SetupFrame {
            bus_protocol: "ramflux.local_bus.v1",
            frame_id: &request_id,
            kind: "request",
            request_id: &request_id,
            account_id: None,
            sdk_api: "account",
            method,
            body,
            trace_id: None,
        };
        let mut bytes = SecretBuffer::new(SETUP_FRAME_BYTES);
        serde_json::to_writer(&mut bytes, &request).map_err(|_| SdkError::CustodySetupInvalid)?;
        let bytes = bytes.finish();
        let len = u32::try_from(bytes.len()).map_err(|_| SdkError::CustodySetupInvalid)?;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        let len = self.stream.read_u32().await?;
        if len > u32::try_from(SETUP_FRAME_BYTES).map_err(|_| SdkError::CustodySetupInvalid)? {
            return Err(SdkError::CustodySetupInvalid);
        }
        let mut bytes = Zeroizing::new(vec![0; len as usize]);
        self.stream.read_exact(&mut bytes).await?;
        let reply: Reply =
            serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
        if reply.protocol != "ramflux.local_bus.custody.v1" || reply.request_id != request_id {
            return Err(SdkError::CustodySetupInvalid);
        }
        if let Response::Error { code } = &reply.result {
            return Err(match code.as_str() {
                "CustodyCreationDisabled" => SdkError::CustodyCreationDisabled,
                "CustodyAccountConflict" => SdkError::CustodyAccountConflict,
                "CustodyConfirmationFailed" => SdkError::CustodyConfirmationFailed,
                "CustodyVaultUnavailable" => SdkError::CustodyVaultUnavailable,
                "NetworkingPending" => SdkError::NetworkingPending,
                _ => SdkError::CustodySetupInvalid,
            });
        }
        Ok(reply.result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximal_confirmation_uses_one_fixed_zeroizing_request_allocation() -> Result<(), SdkError> {
        let words = ["\0".repeat(128), "\0".repeat(128), "\0".repeat(128)];
        let request_id = "r".repeat(SETUP_REQUEST_ID_BYTES);
        let request = SetupFrame {
            bus_protocol: "ramflux.local_bus.v1",
            frame_id: &request_id,
            kind: "request",
            request_id: &request_id,
            account_id: None,
            sdk_api: "account",
            method: "account.custody.confirm",
            body: serde_json::json!({"words":words}),
            trace_id: None,
        };
        let mut bytes = SecretBuffer::new(SETUP_FRAME_BYTES);
        let capacity = bytes.capacity();
        serde_json::to_writer(&mut bytes, &request).map_err(|_| SdkError::CustodySetupInvalid)?;
        assert_eq!(bytes.capacity(), capacity);
        Ok(())
    }
}
