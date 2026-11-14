// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Connection-local secret ceremony, deliberately bypassing actors, retry journals and events.
#[cfg(not(windows))]
use crate::custody::NativePrimaryVault;
use crate::{
    LocalBusConfig, LocalBusFrame, SdkError,
    custody::{CreateInput, CreationCeremony},
};
use serde::Serialize;
use std::{path::Path, sync::Arc};
use zeroize::Zeroizing;

pub(super) fn handles(method: &str) -> bool {
    method.starts_with("account.custody.")
        || method.starts_with("account.recover.")
        || method == "account.create"
        || method.starts_with("account.create.")
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
    Prepared {
        account_anchor: String,
        ceremony_id: String,
        expires_in_ms: u64,
    },
    Phrase {
        phrase: Zeroizing<String>,
    },
    Challenge {
        positions: [u8; 3],
    },
    NetworkingPending {
        account: serde_json::Value,
    },
    Cancelled,
    Error {
        code: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason_code: Option<&'static str>,
    },
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
    validate_headers(request, ceremony)?;
    let result = apply(request, config, ceremony, lease).await;
    // Every failed request consumes the pending ceremony, without word-level feedback.
    let result = match result {
        Ok(body) => body,
        Err(error) => {
            *ceremony = None;
            if request.method.starts_with("account.create") {
                return super::custody_response::error(request, &error);
            }
            ResultBody::Error {
                code: super::io::local_bus_error_code(&error),
                reason_code: match &error {
                    SdkError::CustodyVault(reason) => Some(reason.as_str()),
                    _ => None,
                },
            }
        }
    };
    if request.method.starts_with("account.create") {
        use super::custody_response::{self as response, Cancelled, Challenge, Pending, Phrase};
        return match result {
            ResultBody::Prepared { ceremony_id, expires_in_ms, .. } => response::success(
                request,
                Pending { ceremony: "pending", ceremony_id, expires_in_ms },
            ),
            ResultBody::Phrase { phrase } => response::success(request, Phrase { phrase }),
            ResultBody::Challenge { positions } => {
                response::success(request, Challenge { positions })
            }
            ResultBody::Cancelled => response::success(request, Cancelled { cancelled: true }),
            ResultBody::NetworkingPending { .. } | ResultBody::Error { .. } => {
                response::error(request, &SdkError::NetworkingPending)
            }
        };
    }
    crate::custody::serialize_secret(
        &Reply {
            protocol: "ramflux.local_bus.custody.v1",
            request_id: &request.request_id,
            result,
        },
        8192,
    )
}
pub(super) fn validate_headers(
    request: &LocalBusFrame,
    ceremony: &mut Option<CreationCeremony>,
) -> Result<(), SdkError> {
    if request.request_id.len() > 128
        || request.sdk_api.len() > 128
        || request.method.len() > 128
        || request.account_id.as_ref().is_some_and(|value| value.len() > 128)
        || request.trace_id.as_ref().is_some_and(|value| value.len() > 128)
    {
        *ceremony = None;
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(())
}
fn empty(request: &LocalBusFrame) -> Result<(), SdkError> {
    if request.body.as_object().is_none_or(|map| !map.is_empty()) {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(())
}
pub(super) fn primary_provider(
    config: &LocalBusConfig,
) -> std::sync::Arc<dyn crate::custody::PrimaryVault> {
    #[cfg(any(test, feature = "itest-memory-vault"))]
    if let Some(vault) = &config.custody_vault {
        return vault.clone();
    }
    #[cfg(windows)]
    {
        std::sync::Arc::new(crate::custody::WindowsDpapiVault::for_data_root(&config.data_root))
    }
    #[cfg(not(windows))]
    {
        #[cfg(not(any(test, feature = "itest-memory-vault")))]
        let _ = config;
        std::sync::Arc::new(NativePrimaryVault)
    }
}

async fn apply(
    request: &mut LocalBusFrame,
    config: &LocalBusConfig,
    ceremony: &mut Option<CreationCeremony>,
    lease: Option<Arc<super::data_root_lock::DataRootLock>>,
) -> Result<ResultBody, SdkError> {
    super::requests::deadline(request)?;
    if request.kind != crate::LocalBusFrameKind::Request || request.operation_id.is_some() {
        return Err(SdkError::CustodySetupInvalid);
    }
    match request.method.as_str() {
        "account.create" | "account.create.begin" => {
            begin_native(request, config, ceremony, lease).await
        }
        "account.custody.begin" => {
            *ceremony = None;
            let input: CreateInput = serde_json::from_value(std::mem::take(&mut request.body))
                .map_err(|_| SdkError::CustodySetupInvalid)?;
            // Non-human accounts have one creation path: the owner-attended
            // account.create.begin ceremony. The compatibility ceremony must never expose a
            // service phrase or accept a caller-selected data passphrase for them.
            if input.principal_kind != ramflux_protocol::PrincipalKind::Human {
                return Err(SdkError::CustodySetupInvalid);
            }
            // Existing index entries also reserve an id even if their legacy manifest is missing.
            let index = ramflux_storage::AccountIndex::open(&config.data_root)?;
            if index.account(&input.local_account_id).is_ok() {
                return Err(SdkError::CustodySetupInvalid);
            }
            let vault = primary_provider(config);
            tokio::task::spawn_blocking(move || vault.preflight())
                .await
                .map_err(|_| SdkError::CustodyVaultUnavailable)??;
            let pending = CreationCeremony::begin_with_lease(
                &config.data_root,
                input,
                now()?,
                match lease {
                    Some(lease) => lease,
                    None => super::data_root_lock::DataRootLock::acquire(&config.data_root)?,
                },
            )?;
            let anchor = pending.account_anchor().into();
            let ceremony_id = pending.ceremony_id().into();
            let expires_in_ms = pending.expires_in_ms();
            *ceremony = Some(pending);
            Ok(ResultBody::Prepared { account_anchor: anchor, ceremony_id, expires_in_ms })
        }
        "account.custody.show_once" | "account.create.show_once" => {
            empty(request)?;
            Ok(ResultBody::Phrase {
                phrase: ceremony.as_mut().ok_or(SdkError::CustodySetupInvalid)?.show_once()?,
            })
        }
        "account.custody.hidden_challenge" | "account.create.hidden_challenge" => {
            empty(request)?;
            Ok(ResultBody::Challenge {
                positions: ceremony
                    .as_mut()
                    .ok_or(SdkError::CustodySetupInvalid)?
                    .hidden_challenge()?,
            })
        }
        "account.custody.confirm" => confirm(request, config, ceremony, lease).await,
        "account.custody.cancel" | "account.create.cancel" => {
            empty(request)?;
            *ceremony = None;
            Ok(ResultBody::Cancelled)
        }
        _ => Err(SdkError::CustodySetupInvalid),
    }
}
async fn begin_native(
    request: &mut LocalBusFrame,
    config: &LocalBusConfig,
    ceremony: &mut Option<CreationCeremony>,
    lease: Option<Arc<super::data_root_lock::DataRootLock>>,
) -> Result<ResultBody, SdkError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        display_name: String,
        principal_kind: ramflux_protocol::PrincipalKind,
        #[serde(default)]
        node_id: Option<String>,
        #[serde(default)]
        custodian_account: Option<String>,
    }
    *ceremony = None;
    let input: Input = serde_json::from_value(std::mem::take(&mut request.body))
        .map_err(|_| SdkError::CustodySetupInvalid)?;
    let valid = match input.principal_kind {
        ramflux_protocol::PrincipalKind::Human => input.custodian_account.is_none(),
        ramflux_protocol::PrincipalKind::HeadlessAi => {
            request.method == "account.create.begin"
                && input.custodian_account.is_some()
                && request.account_id.as_deref() == input.custodian_account.as_deref()
        }
        _ => false,
    };
    if !valid {
        return Err(SdkError::CustodySetupInvalid);
    }
    let display_name = ramflux_protocol::normalize_profile_display_name(&input.display_name)?;
    let home_node_id = input
        .node_id
        .map(|node_id| {
            crate::node::NodeStore::load(&config.data_root, &config.builtin_nodes)?
                .confirmed_for_new_account(&node_id)
                .map(|profile| profile.node_id)
        })
        .transpose()?;
    let vault = primary_provider(config);
    tokio::task::spawn_blocking(move || vault.preflight())
        .await
        .map_err(|_| SdkError::CustodyVaultUnavailable)??;
    let pending = CreationCeremony::begin_account(
        (&config.data_root, lease),
        display_name,
        input.principal_kind,
        input.custodian_account,
        home_node_id,
        now()?,
    )?;
    let prepared = ResultBody::Prepared {
        account_anchor: pending.account_anchor().into(),
        ceremony_id: pending.ceremony_id().into(),
        expires_in_ms: pending.expires_in_ms(),
    };
    *ceremony = Some(pending);
    Ok(prepared)
}

async fn confirm(
    request: &mut LocalBusFrame,
    config: &LocalBusConfig,
    ceremony: &mut Option<CreationCeremony>,
    lease: Option<Arc<super::data_root_lock::DataRootLock>>,
) -> Result<ResultBody, SdkError> {
    let pending = ceremony.take().ok_or(SdkError::CustodySetupInvalid)?;
    if pending.principal_kind() != ramflux_protocol::PrincipalKind::Human {
        return Err(SdkError::CustodySetupInvalid);
    }
    let map = request
        .body
        .as_object_mut()
        .filter(|map| (1..=2).contains(&map.len()))
        .ok_or(SdkError::CustodySetupInvalid)?;
    let passphrase = match map.remove("passphrase") {
        Some(serde_json::Value::String(secret)) => Some(Zeroizing::new(secret)),
        None => None,
        Some(_) => return Err(SdkError::CustodySetupInvalid),
    };
    if map.len() != 1 {
        return Err(SdkError::CustodySetupInvalid);
    }
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
    let vault = primary_provider(config);
    let confirmed_at = now()?;
    #[cfg(test)]
    let completed = config.custody_confirm_completed.clone();
    let account = tokio::task::spawn_blocking(move || {
        let _root_lease = lease;
        let result = if let Some(secret) = passphrase {
            pending.confirm_with_passphrase(&words, vault.as_ref(), confirmed_at, secret.as_bytes())
        } else {
            pending.confirm(&words, vault.as_ref(), confirmed_at)
        };
        #[cfg(test)]
        if let Some(completed) = completed {
            completed.notify_one();
        }
        result
    })
    .await
    .map_err(|_| SdkError::CustodyVaultUnavailable)??;
    Ok(ResultBody::NetworkingPending { account: account.summary() })
}

pub(super) fn guard_account(
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
    if matches!(request.method.as_str(), "account.create" | "account.backup.import") {
        return Err(SdkError::CustodyModeDowngrade);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    #[test]
    fn custody_error_frame_carries_the_reason_only_when_present() -> Result {
        let with = serde_json::to_value(ResultBody::Error {
            code: "CustodyVaultUnavailable",
            reason_code: Some("vault_busy"),
        })?;
        assert_eq!(
            with,
            serde_json::json!({"state":"error","code":"CustodyVaultUnavailable","reason_code":"vault_busy"})
        );
        let without = serde_json::to_value(ResultBody::Error {
            code: "CustodyVaultUnavailable",
            reason_code: None,
        })?;
        assert_eq!(without, serde_json::json!({"state":"error","code":"CustodyVaultUnavailable"}));
        Ok(())
    }
    #[derive(Deserialize)]
    struct Frame<T> {
        bus_protocol: String,
        kind: String,
        request_id: String,
        method: String,
        ok: Option<bool>,
        body: T,
    }
    #[derive(Deserialize)]
    struct Pending {
        ceremony: String,
        ceremony_id: String,
        expires_in_ms: u64,
    }
    #[derive(Deserialize)]
    struct Phrase {
        phrase: Zeroizing<String>,
    }
    #[derive(Deserialize)]
    struct Challenge {
        positions: [u8; 3],
    }

    #[tokio::test]
    async fn ordinary_setup_reply_uses_normal_envelope_and_zeroizing_phrase() -> Result {
        let root = crate::custody::tests::Root::new()?;
        let mut config = LocalBusConfig::new(root.0.join("bus.sock"), &root.0);

        config.custody_vault =
            Some(std::sync::Arc::new(crate::custody::tests::TestVault::default()));
        let mut pending = None;
        let mut request = LocalBusFrame::request(
            "begin",
            None,
            "account",
            "account.create",
            serde_json::json!({"display_name":"Ordinary Human","principal_kind":"human"}),
        );
        let bytes = respond(&mut request, &config, &mut pending, None).await?;
        let response: Frame<Pending> = serde_json::from_slice(&bytes)?;
        assert_eq!(response.bus_protocol, "ramflux.local_bus.v1");
        assert_eq!(response.kind, "response");
        assert_eq!(response.request_id, "begin");
        assert_eq!(response.method, "account.create");
        assert_eq!(response.ok, Some(true));
        assert_eq!(response.body.ceremony, "pending");
        assert!(response.body.ceremony_id.starts_with("ceremony-"));
        assert!((1..=300_000).contains(&response.body.expires_in_ms));
        let mut show = LocalBusFrame::request(
            "show",
            None,
            "account",
            "account.create.show_once",
            serde_json::json!({}),
        );
        let shown = respond(&mut show, &config, &mut pending, None).await?;
        let phrase: Frame<Phrase> = serde_json::from_slice(&shown)?;
        assert_eq!(phrase.body.phrase.split_whitespace().count(), 24);
        drop(phrase);
        drop(shown);
        let mut hide = LocalBusFrame::request(
            "hide",
            None,
            "account",
            "account.create.hidden_challenge",
            serde_json::json!({}),
        );
        let challenge: Frame<Challenge> =
            serde_json::from_slice(&respond(&mut hide, &config, &mut pending, None).await?)?;
        let positions = challenge.body.positions;
        assert!(positions.iter().all(|position| (1..=24).contains(position)));
        assert_ne!(positions[0], positions[1]);
        assert_ne!(positions[0], positions[2]);
        assert_ne!(positions[1], positions[2]);
        assert!(!root.0.join("custody_accounts").exists());
        Ok(())
    }

    #[tokio::test]
    async fn unavailable_vault_refuses_create_begin_before_phrase_or_reservation() -> Result {
        let root = crate::custody::tests::Root::new()?;
        let mut config = LocalBusConfig::new(root.0.join("bus.sock"), &root.0);
        let vault = crate::custody::tests::TestVault::default();
        vault.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        config.custody_vault = Some(std::sync::Arc::new(vault));
        let mut pending = None;
        let mut request = LocalBusFrame::request(
            "begin",
            None,
            "account",
            "account.create.begin",
            serde_json::json!({"display_name":"Ordinary Human","principal_kind":"human"}),
        );
        assert!(matches!(
            apply(&mut request, &config, &mut pending, None).await,
            Err(SdkError::CustodyVaultUnavailable)
        ));
        assert!(pending.is_none());
        let mut show = LocalBusFrame::request(
            "show",
            None,
            "account",
            "account.create.show_once",
            serde_json::json!({}),
        );
        assert!(apply(&mut show, &config, &mut pending, None).await.is_err());
        assert!(!root.0.join("custody_accounts").exists());
        Ok(())
    }

    #[tokio::test]
    async fn oversized_request_id_cancels_pending_setup_before_secret_output() -> Result {
        let root = crate::custody::tests::Root::new()?;
        let config = LocalBusConfig::new(root.0.join("bus.sock"), &root.0);
        let mut pending =
            Some(CreationCeremony::begin(&root.0, crate::custody::tests::input("pending"), 100)?);
        let mut request = LocalBusFrame::request(
            "x".repeat(129),
            None,
            "account",
            "account.create.show_once",
            serde_json::json!({}),
        );
        assert!(matches!(
            respond(&mut request, &config, &mut pending, None).await,
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(pending.is_none());
        assert!(!root.0.join("custody_accounts").exists());
        Ok(())
    }
}
