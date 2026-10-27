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
        let bytes = Zeroizing::new(serde_json::to_vec(&request)?);
        if bytes.len() > 4096 {
            return Err(SdkError::CustodySetupInvalid);
        }
        let len = u32::try_from(bytes.len()).map_err(|_| SdkError::CustodySetupInvalid)?;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        let len = self.stream.read_u32().await?;
        if len > 4096 {
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
                "CustodyConfirmationFailed" => SdkError::CustodyConfirmationFailed,
                "CustodyVaultUnavailable" => SdkError::CustodyVaultUnavailable,
                "NetworkingPending" => SdkError::NetworkingPending,
                _ => SdkError::CustodySetupInvalid,
            });
        }
        Ok(reply.result)
    }
}
