// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Connection-local secret ceremony, deliberately bypassing actors, retry journals and events.
use crate::{
    LocalBusConfig, LocalBusFrame, SdkError,
    custody::{CreateInput, CreationCeremony, NativePrimaryVault},
};
use serde::Serialize;
use std::{path::Path, sync::Arc};
use zeroize::Zeroizing;

/// Unforgeable outside this module; creation code requires proof that the bus option was enabled.
pub(crate) struct CreationCapability(());
impl CreationCapability {
    fn from_config(config: &LocalBusConfig) -> Result<Self, SdkError> {
        if !config.enable_born_v3_creation {
            return Err(SdkError::CustodyCreationDisabled);
        }
        Ok(Self(()))
    }
}
#[cfg(test)]
pub(crate) fn test_creation_capability() -> CreationCapability {
    CreationCapability(())
}

pub(super) fn handles(method: &str) -> bool {
    method.starts_with("account.custody.")
}
pub(super) struct Incoming(Option<LocalBusFrame>);
impl Incoming {
    pub(super) fn new(frame: LocalBusFrame) -> Self {
        Self(Some(frame))
    }
    pub(super) fn take(&mut self) -> Result<LocalBusFrame, SdkError> {
        self.0.take().ok_or(SdkError::CustodySetupInvalid)
    }
    pub(super) fn frame(&mut self) -> Result<&mut LocalBusFrame, SdkError> {
        self.0.as_mut().ok_or(SdkError::CustodySetupInvalid)
    }
}
impl Drop for Incoming {
    fn drop(&mut self) {
        if let Some(frame) = self.0.as_mut() {
            super::secrets::wipe(&mut frame.body);
        }
    }
}
#[derive(Serialize)]
struct Reply<'a> {
    protocol: &'static str,
    request_id: &'a str,
    result: ResultBody,
}
#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ResultBody {
    Prepared { account_anchor: String },
    Phrase { phrase: Zeroizing<String> },
    Challenge { positions: [u8; 3] },
    NetworkingPending { account: serde_json::Value },
    Cancelled,
    Error { code: &'static str },
}
pub(super) fn now() -> Result<u64, SdkError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| SdkError::CustodySetupInvalid)
}
pub(super) async fn respond(
    request: &mut LocalBusFrame,
    config: &LocalBusConfig,
    ceremony: &mut Option<CreationCeremony>,
    lease: Option<Arc<super::data_root_lock::DataRootLock>>,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    if request.request_id.len() > crate::custody::SETUP_REQUEST_ID_BYTES {
        *ceremony = None;
        return Err(SdkError::CustodySetupInvalid);
    }
    let result = apply(request, config, ceremony, lease).await;
    // Every failed request consumes the pending ceremony, without word-level feedback.
    let result = match result {
        Ok(body) => body,
        Err(error) => {
            *ceremony = None;
            ResultBody::Error { code: super::io::local_bus_error_code(&error) }
        }
    };
    let mut bytes = crate::custody::SecretBuffer::new(crate::custody::SETUP_FRAME_BYTES);
    serde_json::to_writer(
        &mut bytes,
        &Reply {
            protocol: "ramflux.local_bus.custody.v1",
            request_id: &request.request_id,
            result,
        },
    )
    .map_err(|_| SdkError::CustodySetupInvalid)?;
    Ok(bytes.finish())
}
fn empty(request: &LocalBusFrame) -> Result<(), SdkError> {
    if request.body.as_object().is_none_or(|map| !map.is_empty()) {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(())
}
fn primary_vault(config: &LocalBusConfig) -> Arc<dyn crate::custody::PrimaryVault + Send + Sync> {
    #[cfg(test)]
    if let Some(vault) = &config.custody_vault {
        return Arc::clone(vault);
    }
    #[cfg(not(test))]
    let _ = config;
    Arc::new(NativePrimaryVault)
}
async fn apply(
    request: &mut LocalBusFrame,
    config: &LocalBusConfig,
    ceremony: &mut Option<CreationCeremony>,
    lease: Option<Arc<super::data_root_lock::DataRootLock>>,
) -> Result<ResultBody, SdkError> {
    let capability = CreationCapability::from_config(config)?;
    super::requests::deadline(request)?;
    if request.kind != crate::LocalBusFrameKind::Request || request.operation_id.is_some() {
        return Err(SdkError::CustodySetupInvalid);
    }
    match request.method.as_str() {
        "account.custody.begin" => {
            *ceremony = None;
            let input: CreateInput = serde_json::from_value(std::mem::take(&mut request.body))
                .map_err(|_| SdkError::CustodySetupInvalid)?;
            // Existing index entries also reserve an id even if their legacy manifest is missing.
            let index = ramflux_storage::AccountIndex::open(&config.data_root)?;
            if index.account(&input.local_account_id).is_ok() {
                return Err(SdkError::CustodySetupInvalid);
            }
            let vault = primary_vault(config);
            tokio::task::spawn_blocking(move || vault.preflight())
                .await
                .map_err(|_| SdkError::CustodyVaultUnavailable)??;
            let pending = CreationCeremony::begin(&capability, &config.data_root, input, now()?)?;
            let anchor = pending.account_anchor().into();
            *ceremony = Some(pending);
            Ok(ResultBody::Prepared { account_anchor: anchor })
        }
        "account.custody.show_once" => {
            empty(request)?;
            Ok(ResultBody::Phrase {
                phrase: ceremony.as_mut().ok_or(SdkError::CustodySetupInvalid)?.show_once()?,
            })
        }
        "account.custody.hidden_challenge" => {
            empty(request)?;
            Ok(ResultBody::Challenge {
                positions: ceremony
                    .as_mut()
                    .ok_or(SdkError::CustodySetupInvalid)?
                    .hidden_challenge()?,
            })
        }
        "account.custody.confirm" => {
            let pending = ceremony.take().ok_or(SdkError::CustodySetupInvalid)?;
            let map = request
                .body
                .as_object_mut()
                .filter(|m| m.len() == 1)
                .ok_or(SdkError::CustodySetupInvalid)?;
            let values = map
                .get_mut("words")
                .and_then(serde_json::Value::as_array_mut)
                .filter(|a| a.len() == 3)
                .ok_or(SdkError::CustodySetupInvalid)?;
            let mut words = [
                Zeroizing::new(String::new()),
                Zeroizing::new(String::new()),
                Zeroizing::new(String::new()),
            ];
            for (target, value) in words.iter_mut().zip(values) {
                let serde_json::Value::String(word) = std::mem::take(value) else {
                    return Err(SdkError::CustodySetupInvalid);
                };
                *target = Zeroizing::new(word);
            }
            let account = confirm_in_worker(config, pending, words, lease).await?;
            Ok(ResultBody::NetworkingPending { account: account.summary() })
        }
        "account.custody.cancel" => {
            empty(request)?;
            *ceremony = None;
            Ok(ResultBody::Cancelled)
        }
        _ => Err(SdkError::CustodySetupInvalid),
    }
}
async fn confirm_in_worker(
    config: &LocalBusConfig,
    pending: CreationCeremony,
    words: [Zeroizing<String>; 3],
    lease: Option<Arc<super::data_root_lock::DataRootLock>>,
) -> Result<crate::custody::BornAccount, SdkError> {
    let vault = primary_vault(config);
    let confirmed_at = now()?;
    #[cfg(test)]
    let completed = config.custody_confirm_completed.clone();
    tokio::task::spawn_blocking(move || {
        let _root_lease = lease;
        let result = pending.confirm(&words, vault.as_ref(), confirmed_at);
        #[cfg(test)]
        if let Some(completed) = completed {
            completed.notify_one();
        }
        result
    })
    .await
    .map_err(|_| SdkError::CustodyVaultUnavailable)?
}

pub(crate) fn guard_account(
    root: &Path,
    request: &LocalBusFrame,
) -> Result<Option<serde_json::Value>, SdkError> {
    let id = if request.method == "account.create" {
        request.body.get("local_account_id").and_then(serde_json::Value::as_str)
    } else {
        request.account_id.as_deref()
    };
    let Some(id) = id else {
        return Ok(None);
    };
    if !crate::custody::account_exists(root, id)? {
        return Ok(None);
    }
    if request.method == "account.status" {
        return Ok(Some(crate::custody::store::account_summary(root, id, now()?)?));
    }
    Err(SdkError::NetworkingPending)
}
