// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-process account-code replies. The code never enters a JSON event or a log line.

use crate::SdkError;
use crate::custody::pairing::private_credential::encode_reply;
use crate::custody::pairing::{CredentialOutcome, LocalCredentialProvider};
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::local_dto::CredentialRequest;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

const PROMPT_METHOD: &str = "device.credential.request";
/// Not a pairing-wire action. A credential reply must never carry this purpose.
const USERNAME_MASTER: &str = "username_master";

#[derive(Default)]
pub(super) struct Bridge {
    provider: Mutex<Option<Arc<super::super::pairing::CallbackProvider>>>,
    parents: Mutex<BTreeMap<u64, Parent>>,
    usernames: Mutex<BTreeMap<u64, UsernameParent>>,
    /// Shared with the in-process supervisor. Unlock reads it after connect, because the
    /// host registers the callback only once the client handle exists.
    callback_ready: Arc<AtomicBool>,
}

pub(super) struct UsernameParent {
    pub method: String,
    pub account_id: String,
}

struct Parent {
    method: String,
    account_id: Option<String>,
    prompted: bool,
}

struct Bound {
    method: String,
    account_id: Option<String>,
}

fn invalid() -> SdkError {
    SdkError::PairingField("credential_frame")
}

fn lock_err() -> SdkError {
    SdkError::LocalBus("credential lock poisoned".into())
}

impl Bridge {
    pub(super) fn note(
        &self,
        id: u64,
        method: &str,
        account_id: Option<&str>,
    ) -> Result<(), SdkError> {
        {
            let mut parents = self.parents.lock().map_err(|_| lock_err())?;
            parents.insert(
                id,
                Parent {
                    method: method.to_owned(),
                    account_id: account_id.map(str::to_owned),
                    prompted: false,
                },
            );
        }
        if let Err(error) = self.remember_username(id, method, account_id) {
            self.forget(id);
            return Err(error);
        }
        Ok(())
    }

    /// Prompt parents end at completion. Username parents stay until release or close.
    pub(super) fn forget(&self, id: u64) {
        if let Ok(mut parents) = self.parents.lock() {
            parents.remove(&id);
        }
    }

    pub(super) fn forget_username(&self, id: u64) {
        if let Ok(mut names) = self.usernames.lock() {
            names.remove(&id);
        }
    }

    pub(super) fn clear_username(&self) {
        if let Ok(mut names) = self.usernames.lock() {
            names.clear();
        }
    }

    pub(super) fn username_parent(&self, id: u64) -> Result<Option<UsernameParent>, SdkError> {
        let names = self.usernames.lock().map_err(|_| lock_err())?;
        Ok(names.get(&id).map(|parent| UsernameParent {
            method: parent.method.clone(),
            account_id: parent.account_id.clone(),
        }))
    }

    pub(super) fn hold_username_master(
        &self,
    ) -> Result<super::super::pairing::UsernameMasterHold, SdkError> {
        let Some(provider) = self.provider()? else {
            return Err(SdkError::PairingField("credential_provider"));
        };
        provider.hold_username_master()
    }

    fn remember_username(
        &self,
        id: u64,
        method: &str,
        account_id: Option<&str>,
    ) -> Result<(), SdkError> {
        if !matches!(method, "username.mutate" | "profile.update") {
            return Ok(());
        }
        let Some(account_id) = account_id.filter(|value| !value.is_empty()) else {
            return Err(SdkError::PairingField("username_account"));
        };
        let mut names = self.usernames.lock().map_err(|_| lock_err())?;
        if !names.contains_key(&id) && names.len() >= super::state::MAX_OPERATIONS {
            return Err(SdkError::PairingField("username_capacity"));
        }
        names.insert(
            id,
            UsernameParent { method: method.to_owned(), account_id: account_id.to_owned() },
        );
        Ok(())
    }

    /// The in-process supervisor reads this at unlock. It is false until `replace` installs a callback.
    pub(super) fn callback_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.callback_ready)
    }

    pub(super) fn replace(
        &self,
        next: Option<Arc<super::super::pairing::CallbackProvider>>,
    ) -> Result<(), SdkError> {
        let installed = next.is_some();
        // Clear before the provider disappears so unlock does not send a prompt nobody answers.
        if !installed {
            self.callback_ready.store(false, Ordering::Release);
        }
        let previous = {
            let mut guard = self.provider.lock().map_err(|_| lock_err())?;
            std::mem::replace(&mut *guard, next)
        };
        if installed {
            self.callback_ready.store(true, Ordering::Release);
        }
        if let Some(previous) = previous {
            previous.stop_and_drain();
        }
        Ok(())
    }

    pub(super) fn shutdown(&self) {
        self.callback_ready.store(false, Ordering::Release);
        let previous =
            self.provider.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(previous) = previous {
            previous.stop_and_drain();
        }
        self.clear_username();
    }

    fn provider(&self) -> Result<Option<Arc<super::super::pairing::CallbackProvider>>, SdkError> {
        Ok(self.provider.lock().map_err(|_| lock_err())?.clone())
    }

    fn begin(&self, id: u64) -> Result<Bound, SdkError> {
        let mut parents = self.parents.lock().map_err(|_| lock_err())?;
        let parent = parents.get_mut(&id).ok_or_else(invalid)?;
        if parent.prompted {
            return Err(invalid());
        }
        parent.prompted = true;
        Ok(Bound { method: parent.method.clone(), account_id: parent.account_id.clone() })
    }
}

pub(super) async fn next_public_frame(
    reader: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    replies: &tokio::sync::mpsc::Sender<Zeroizing<Vec<u8>>>,
    bridge: &Bridge,
) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
    loop {
        let pending = crate::bus::io::read_encoded_local_bus_frame(reader);
        tokio::pin!(pending);
        let mut bytes = tokio::select! {
            _ = shutdown.changed() => return Ok(None),
            result = pending => result?,
        };
        match answer(&bytes, bridge).await {
            Ok(None) => return Ok(Some(bytes)),
            Ok(Some(reply)) => {
                bytes.zeroize();
                replies
                    .send(reply)
                    .await
                    .map_err(|_| SdkError::LocalBus("credential reply lost".into()))?;
            }
            Err(error) => {
                bytes.zeroize();
                return Err(error);
            }
        }
    }
}

async fn answer(bytes: &[u8], bridge: &Bridge) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
    if !bytes.windows(PROMPT_METHOD.len()).any(|window| window == PROMPT_METHOD.as_bytes()) {
        return Ok(None);
    }
    // Same predicate as the socket reader: a prompt is an original local-bus frame.
    // A frame that is not I-JSON is not a prompt and stays on the public path.
    let mut frame: crate::LocalBusFrame = match ramflux_protocol::parse_i_json_secret(bytes) {
        Ok(frame) => frame,
        Err(_) => return Ok(None),
    };
    if frame.method != PROMPT_METHOD {
        crate::bus::inprocess::erase_value(&mut frame.body);
        return Ok(None);
    }
    let result = reply_to(&mut frame, bridge).await;
    crate::bus::inprocess::erase_value(&mut frame.body);
    result.map(Some)
}

async fn reply_to(
    frame: &mut crate::LocalBusFrame,
    bridge: &Bridge,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let (generation, metadata) = correlate(frame, bridge)?;
    let (action, outcome) = invoke(bridge, metadata).await?;
    let reply = encode_reply(generation, &action, &outcome)?;
    drop(outcome);
    Ok(reply)
}

fn correlate(
    frame: &mut crate::LocalBusFrame,
    bridge: &Bridge,
) -> Result<(u64, CredentialRequest), SdkError> {
    if frame.kind != crate::LocalBusFrameKind::Request || frame.sdk_api != "device" {
        return Err(invalid());
    }
    let generation = generation(&frame.frame_id)?;
    let id = parent_id(&frame.request_id)?;
    let metadata: CredentialRequest =
        serde_json::from_value(std::mem::take(&mut frame.body)).map_err(|_| invalid())?;
    metadata.validate().map_err(|_| invalid())?;
    let parent = bridge.begin(id)?;
    if frame.account_id != parent.account_id
        || parent.account_id.as_ref() != Some(&metadata.local_account_id)
        || !allowed(&parent.method, &metadata.action)
    {
        return Err(invalid());
    }
    Ok((generation, metadata))
}

fn generation(frame_id: &str) -> Result<u64, SdkError> {
    let text = frame_id.strip_prefix("credential-").ok_or_else(invalid)?;
    let generation = text.parse::<u64>().map_err(|_| invalid())?;
    if generation == 0 || frame_id != format!("credential-{generation}") {
        return Err(invalid());
    }
    Ok(generation)
}

fn parent_id(request_id: &str) -> Result<u64, SdkError> {
    let id = request_id.parse::<u64>().map_err(|_| invalid())?;
    if request_id != id.to_string() {
        return Err(invalid());
    }
    Ok(id)
}

fn allowed(method: &str, action: &str) -> bool {
    // The username master phrase is a separate borrowed input, never a credential reply.
    if matches!(method, "username.mutate" | "profile.update") || action == USERNAME_MASTER {
        return false;
    }
    match method {
        "device.pair.join" | "device.transfer.join" => matches!(action, "setup" | "unlock"),
        "device.transfer.prepare" => action == "phrase",
        "device.transfer.status" | "account.unlock" => action == "unlock",
        _ => false,
    }
}

async fn invoke(
    bridge: &Bridge,
    metadata: CredentialRequest,
) -> Result<(String, CredentialOutcome), SdkError> {
    let action = metadata.action.clone();
    let provider = bridge.provider()?;
    let outcome = if let Some(provider) = provider {
        match tokio::task::spawn_blocking(move || provider.provide(&metadata)).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(SdkError::PairingCode("Retired")),
        }
    } else {
        CredentialOutcome::Refused
    };
    Ok((action, outcome))
}

/// `encode_reply` already includes the 4-byte length. A second frame prefix would desynchronize the server.
pub(super) async fn write_private(
    writer: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
    bytes: &[u8],
) -> Result<(), SdkError> {
    use tokio::io::AsyncWriteExt;
    let write = async {
        writer.write_all(bytes).await?;
        writer.flush().await?;
        Ok::<(), SdkError>(())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), write).await {
        Ok(result) => result,
        Err(_) => Err(SdkError::LocalBus("credential write timed out".into())),
    }
}
