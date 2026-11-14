// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Connection-private credential prompts and pre-JSON binary reply routing.
use super::state::LocalBusConnectionState;
use crate::{
    LocalBusFrame, LocalBusFrameKind, SdkError,
    custody::pairing::private_credential::{
        PrivateCredentialCall, PrivateCredentialCallKind, PrivateCredentialChannel, bind_call,
        parent_request_id, read_reply_after_discriminator,
    },
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) struct ConnectionInput(Arc<PrivateCredentialChannel>);
impl Drop for ConnectionInput {
    fn drop(&mut self) {
        self.0.close();
    }
}
impl ConnectionInput {
    pub(crate) fn channel(&self) -> Arc<PrivateCredentialChannel> {
        self.0.clone()
    }
    pub(super) fn close(&self) {
        self.0.close();
    }
}
pub(crate) fn connection(
    root: PathBuf,
    id: u64,
    outbound: impl Into<super::outbound::LocalBusOutbound>,
) -> ConnectionInput {
    let outbound = outbound.into();
    ConnectionInput(Arc::new(PrivateCredentialChannel::new(
        id,
        Arc::new(move |generation, request| {
            let parent = parent_request_id(&root, &request.local_account_id)?;
            let frame = LocalBusFrame {
                bus_protocol: "ramflux.local_bus.v1".into(),
                frame_id: format!("credential-{generation}"),
                kind: LocalBusFrameKind::Request,
                request_id: parent,
                account_id: Some(request.local_account_id.clone()),
                sdk_api: "device".into(),
                method: "device.credential.request".into(),
                body: serde_json::to_value(request)?,
                trace_id: None,
                seq: None,
                at: None,
                deadline_ms: None,
                operation_id: None,
                ok: None,
                error: None,
            };
            outbound.try_send(frame).map_err(|_| SdkError::PairingCode("Busy"))
        }),
    )))
}
/// Public metadata/connection ownership is captured before an actor can invoke its provider.
pub(super) fn call(
    root: &Path,
    request: &LocalBusFrame,
    connection: &LocalBusConnectionState,
) -> Result<Option<PrivateCredentialCall>, SdkError> {
    let Some(channel) = &connection.credential_channel else {
        return Ok(None);
    };
    let kind = match request.method.as_str() {
        "device.pair.join" | "device.transfer.join" => PrivateCredentialCallKind::Join,
        "device.transfer.prepare" => PrivateCredentialCallKind::Prepare {
            operation_id: request
                .body
                .get("operation_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(SdkError::PairingField("operation_id"))?
                .into(),
        },
        "device.transfer.status" => {
            use ramflux_protocol::custody::pairing::PairingWire as _;
            let status: ramflux_protocol::custody::pairing::local_dto::StatusRequest =
                serde_json::from_value(request.body.clone())?;
            status.validate().map_err(|_| SdkError::PairingField("resume_scope"))?;
            PrivateCredentialCallKind::Resume { operation_id: status.operation_id }
        }
        "account.unlock" if request.body.get("passphrase").is_none() => {
            PrivateCredentialCallKind::Unlock
        }
        _ => return Ok(None),
    };
    let account = request.account_id.as_deref().ok_or(SdkError::PairingField("account_id"))?;
    Ok(Some(bind_call(root, account, request.request_id.clone(), kind, channel.clone())?))
}
/// Acquire the private ordinary-unlock input off the account actor thread. This never
/// constructs a JSON request containing the result.
pub(super) async fn unlock_secret(
    root: PathBuf,
    account: String,
) -> Result<zeroize::Zeroizing<String>, SdkError> {
    tokio::task::spawn_blocking(move || {
        use crate::custody::pairing::{
            PersistedReservation, acquire_unlock, load_reservation, persist_reservation,
            private_credential::provider_for_account,
        };
        if !crate::custody::account_exists(&root, &account)? {
            return Err(SdkError::AccountNotOpen(account));
        }
        if let Some(reason) = crate::custody::failed_setup(&root, &account)? {
            return Err(crate::custody::failed_setup_error(&account, reason));
        }
        // Authority-only creation has no data key to unlock. Refuse before any
        // private challenge, preserving the ordinary pending-account response.
        let index = ramflux_storage::AccountIndex::open(&root)?;
        match index.load_wrapped_db_key(&account) {
            Ok(Some(_)) => {}
            Ok(None) | Err(ramflux_storage::StorageError::AccountNotFound(_)) => {
                return Err(SdkError::CustodySetupInvalid);
            }
            Err(error) => return Err(error.into()),
        }
        let generation = load_reservation(&root, &account)?.map_or(1, |r| r.frontend_generation);
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| SdkError::CustodyRandomUnavailable)?;
        let stored = PersistedReservation {
            account_id: account.clone(),
            reservation_id: ramflux_protocol::encode_base64url(nonce),
            frontend_generation: generation,
        };
        persist_reservation(&root, &stored)?;
        let request = ramflux_protocol::custody::pairing::local_dto::CredentialRequest {
            local_account_id: account.clone(),
            reservation_id: stored.reservation_id.clone(),
            frontend_generation: generation,
            action: "unlock".into(),
        };
        let provider = provider_for_account(&root, account)?;
        let secret = acquire_unlock(&root, &request, provider.as_ref(), &stored)?;
        let text = std::str::from_utf8(secret.as_bytes())
            .map_err(|_| SdkError::PairingField("credential_utf8"))?;
        Ok(zeroize::Zeroizing::new(text.to_owned()))
    })
    .await
    .map_err(|_| SdkError::PairingCode("Retired"))?
}
/// `None` denotes a private reply delivered straight to its same-connection callback.
/// There is no generic decoded frame, trace/event or retry record for those bytes.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    channel: &PrivateCredentialChannel,
    id: u64,
) -> Result<Option<LocalBusFrame>, SdkError> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).await?;
    let len =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| SdkError::PairingField("size"))?;
    if len == 0 || len > super::io::MAX_LOCAL_BUS_FRAME_BYTES {
        return Err(SdkError::PairingField("size"));
    }
    let mut discriminator = [0];
    reader.read_exact(&mut discriminator).await?;
    if let Some((generation, action)) = channel.expected_reply() {
        // A JSON "reply" in a private window is refused before reading its payload.
        let reply =
            read_reply_after_discriminator(reader, prefix, discriminator[0], &action, generation)
                .await?;
        channel.deliver_reply(id, reply)?;
        return Ok(None);
    }
    if discriminator[0] == 0xC1 {
        return Err(SdkError::PairingField("credential_channel"));
    }
    super::io::read_json_after_discriminator(reader, len, discriminator[0]).await.map(Some)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "credentials/contract_tests.rs"]
pub(crate) mod contract_tests;

#[cfg(test)]
pub(crate) mod resume_tests;
