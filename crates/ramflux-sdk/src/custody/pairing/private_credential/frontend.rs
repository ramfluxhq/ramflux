// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exclusive attended client: credential replies never become generic request bodies.
use super::{CredentialOutcome, CredentialRequest, encode_reply, invalid};
use crate::{
    LocalBusFrame, LocalBusFrameKind, SdkError, custody::pairing::LocalCredentialProvider,
};
use ramflux_protocol::custody::pairing::PairingWire;
use std::{path::Path, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// A dedicated local connection with one initiating request and one private input window.
/// Dropping an in-flight request closes the connection; never reuse an interrupted exchange.
pub struct PairingBusClient {
    stream: Option<crate::platform::fs::LocalSocketStream>,
    provider: Arc<dyn LocalCredentialProvider>,
    sequence: u64,
}
impl PairingBusClient {
    /// # Errors
    /// Refuses an unavailable same-user local daemon connection.
    pub async fn connect(
        socket: impl AsRef<Path>,
        provider: Arc<dyn LocalCredentialProvider>,
    ) -> Result<Self, SdkError> {
        Ok(Self {
            stream: Some(crate::platform::listener::connect(socket).await?),
            provider,
            sequence: 0,
        })
    }
    /// The public body contains no passphrase or phrase. Input is supplied only after the
    /// daemon's same-connection, parent-correlated metadata prompt.
    /// # Errors
    /// Refuses an invalid prompt, a second input window, daemon errors or transport failure.
    pub async fn request(
        &mut self,
        account_id: Option<String>,
        sdk_api: &str,
        method: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        self.sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
        let request = LocalBusFrame::request(
            format!("attended-{}", self.sequence),
            account_id,
            sdk_api,
            method,
            body,
        );
        // Take ownership before the first await: cancelled futures cannot reuse a stream
        // whose daemon might still be waiting for a secret from the old call.
        let mut stream = self.stream.take().ok_or_else(invalid)?;
        let response = exchange(&mut stream, &request, self.provider.clone()).await?;
        self.stream = Some(stream);
        if response.kind == LocalBusFrameKind::Error {
            return Err(SdkError::LocalBusRefused {
                code: response.error.as_ref().map_or("Unknown", |e| e.code.as_str()).into(),
                message: response
                    .error
                    .as_ref()
                    .map_or("Pairing refused", |e| e.message.as_str())
                    .into(),
                body: Box::new(response.body),
            });
        }
        Ok(response.body)
    }
}
struct Input(Option<Arc<dyn LocalCredentialProvider>>);
impl Drop for Input {
    fn drop(&mut self) {
        if let Some(provider) = &self.0 {
            provider.cancel();
        }
    }
}
fn prompt(
    request: &LocalBusFrame,
    frame: &LocalBusFrame,
) -> Result<(u64, CredentialRequest), SdkError> {
    if frame.kind != LocalBusFrameKind::Request
        || frame.sdk_api != "device"
        || frame.method != "device.credential.request"
        || frame.request_id != request.request_id
        || frame.account_id != request.account_id
    {
        return Err(invalid());
    }
    let generation = frame
        .frame_id
        .strip_prefix("credential-")
        .ok_or_else(invalid)?
        .parse::<u64>()
        .map_err(|_| invalid())?;
    if generation == 0 || frame.frame_id != format!("credential-{generation}") {
        return Err(invalid());
    }
    let metadata: CredentialRequest = serde_json::from_value(frame.body.clone())?;
    metadata.validate().map_err(|_| invalid())?;
    if Some(&metadata.local_account_id) != request.account_id.as_ref() {
        return Err(invalid());
    }
    let allowed = match request.method.as_str() {
        "device.pair.join" | "device.transfer.join" => {
            matches!(metadata.action.as_str(), "setup" | "unlock")
        }
        "device.transfer.prepare" => metadata.action == "phrase",
        "account.unlock" => metadata.action == "unlock" && request.body.get("passphrase").is_none(),
        _ => false,
    };
    if !allowed {
        return Err(invalid());
    }
    Ok((generation, metadata))
}
pub(super) async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &LocalBusFrame,
    provider: Arc<dyn LocalCredentialProvider>,
) -> Result<LocalBusFrame, SdkError> {
    let bytes = zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(request)?);
    crate::bus::io::write_encoded_local_bus_frame(stream, &bytes).await?;
    let mut prompted = false;
    loop {
        let frame = crate::bus::io::read_local_bus_frame(stream).await?;
        if frame.method == "device.credential.request" {
            if prompted {
                return Err(invalid());
            }
            let (generation, metadata) = prompt(request, &frame)?;
            prompted = true;
            let action = metadata.action.clone();
            let mut pending_input = Input(Some(provider.clone()));
            let callback = provider.clone();
            let mut input = tokio::task::spawn_blocking(move || callback.provide(&metadata));
            let outcome = tokio::select! {
                value = &mut input => value.map_err(|_| invalid())?.unwrap_or(CredentialOutcome::Refused),
                // Detect EOF and stop local input even while the synchronous UI is waiting.
                value = crate::bus::io::read_local_bus_frame(stream) => {
                    drop(value);
                    return Err(invalid());
                }
            };
            // The callback has completed; keep its reusable UI provider available for
            // a later attended call. Only an interrupted callback receives cancel().
            pending_input.0 = None;
            let reply = encode_reply(generation, &action, &outcome)?;
            drop(outcome);
            stream.write_all(&reply).await?;
            stream.flush().await?;
        } else {
            if !matches!(frame.kind, LocalBusFrameKind::Response | LocalBusFrameKind::Error)
                || frame.request_id != request.request_id
                || frame.method != request.method
                || frame.account_id != request.account_id
            {
                return Err(invalid());
            }
            return Ok(frame);
        }
    }
}
#[cfg(test)]
mod tests;
