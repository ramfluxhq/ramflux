// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Connection-local secret ceremony, deliberately bypassing actors, retry journals and events.
use crate::{
    LocalBusConfig, LocalBusFrame, SdkError,
    custody::{CreateInput, CreationCeremony, NativePrimaryVault},
};
use serde::Serialize;
use std::path::Path;
use zeroize::Zeroizing;

pub(super) fn handles(method: &str) -> bool {
    method.starts_with("account.custody.")
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
    Prepared { account_anchor: String, ceremony_id: String, expires_in_ms: u64 },
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
pub(super) fn respond(
    request: &mut LocalBusFrame,
    config: &LocalBusConfig,
    ceremony: &mut Option<CreationCeremony>,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    validate_headers(request, ceremony)?;
    let result = apply(request, config, ceremony);
    // Every failed request consumes the pending ceremony, without word-level feedback.
    let result = match result {
        Ok(body) => body,
        Err(error) => {
            *ceremony = None;
            if request.method.starts_with("account.create") {
                return super::custody_response::error(request, &error);
            }
            ResultBody::Error { code: super::io::local_bus_error_code(&error) }
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
    #[cfg(not(any(test, feature = "itest-memory-vault")))]
    let _ = config;
    std::sync::Arc::new(NativePrimaryVault)
}

fn primary_vault(config: &LocalBusConfig) -> &dyn crate::custody::PrimaryVault {
    static NATIVE: NativePrimaryVault = NativePrimaryVault;
    #[cfg(any(test, feature = "itest-memory-vault"))]
    if let Some(vault) = &config.custody_vault {
        return vault.as_ref();
    }
    #[cfg(not(any(test, feature = "itest-memory-vault")))]
    let _ = config;
    &NATIVE
}
fn apply(
    request: &mut LocalBusFrame,
    config: &LocalBusConfig,
    ceremony: &mut Option<CreationCeremony>,
) -> Result<ResultBody, SdkError> {
    if !config.enable_born_v3_creation {
        return Err(SdkError::CustodyCreationDisabled);
    }
    super::requests::deadline(request)?;
    if request.kind != crate::LocalBusFrameKind::Request || request.operation_id.is_some() {
        return Err(SdkError::CustodySetupInvalid);
    }
    match request.method.as_str() {
        "account.create" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                display_name: String,
                principal_kind: ramflux_protocol::PrincipalKind,
            }
            *ceremony = None;
            let input: Input = serde_json::from_value(std::mem::take(&mut request.body))
                .map_err(|_| SdkError::CustodySetupInvalid)?;
            if input.principal_kind != ramflux_protocol::PrincipalKind::Human {
                return Err(SdkError::CustodySetupInvalid);
            }
            let display_name =
                ramflux_protocol::normalize_profile_display_name(&input.display_name)?;
            primary_vault(config).preflight()?;
            let pending = CreationCeremony::begin_account(
                true,
                &config.data_root,
                display_name,
                input.principal_kind,
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
        "account.custody.begin" => {
            *ceremony = None;
            let input: CreateInput = serde_json::from_value(std::mem::take(&mut request.body))
                .map_err(|_| SdkError::CustodySetupInvalid)?;
            // Existing index entries also reserve an id even if their legacy manifest is missing.
            let index = ramflux_storage::AccountIndex::open(&config.data_root)?;
            if index.account(&input.local_account_id).is_ok() {
                return Err(SdkError::CustodySetupInvalid);
            }
            primary_vault(config).preflight()?;
            let pending = CreationCeremony::begin(true, &config.data_root, input, now()?)?;
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
        "account.custody.confirm" => confirm(request, config, ceremony),
        "account.custody.cancel" | "account.create.cancel" => {
            empty(request)?;
            *ceremony = None;
            Ok(ResultBody::Cancelled)
        }
        _ => Err(SdkError::CustodySetupInvalid),
    }
}
fn confirm(
    request: &mut LocalBusFrame,
    config: &LocalBusConfig,
    ceremony: &mut Option<CreationCeremony>,
) -> Result<ResultBody, SdkError> {
    let pending = ceremony.take().ok_or(SdkError::CustodySetupInvalid)?;
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
    let account = if let Some(secret) = passphrase {
        pending.confirm_with_passphrase(&words, primary_vault(config), now()?, secret.as_bytes())?
    } else {
        pending.confirm(&words, primary_vault(config), now()?)?
    };
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

    #[test]
    fn ordinary_setup_reply_uses_normal_envelope_and_zeroizing_phrase() -> Result {
        let root = crate::custody::tests::Root::new()?;
        let mut config = LocalBusConfig::new(root.0.join("bus.sock"), &root.0);
        config.enable_born_v3_creation = true;
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
        let bytes = respond(&mut request, &config, &mut pending)?;
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
        let shown = respond(&mut show, &config, &mut pending)?;
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
            serde_json::from_slice(&respond(&mut hide, &config, &mut pending)?)?;
        let positions = challenge.body.positions;
        assert!(positions.iter().all(|position| (1..=24).contains(position)));
        assert_ne!(positions[0], positions[1]);
        assert_ne!(positions[0], positions[2]);
        assert_ne!(positions[1], positions[2]);
        assert!(!root.0.join("custody_accounts").exists());
        Ok(())
    }

    #[test]
    fn oversized_request_id_cancels_pending_setup_before_secret_output() -> Result {
        let root = crate::custody::tests::Root::new()?;
        let config = LocalBusConfig::new(root.0.join("bus.sock"), &root.0);
        let mut pending = Some(CreationCeremony::begin(
            true,
            &root.0,
            crate::custody::tests::input("pending"),
            100,
        )?);
        let mut request = LocalBusFrame::request(
            "x".repeat(129),
            None,
            "account",
            "account.create.show_once",
            serde_json::json!({}),
        );
        assert!(matches!(
            respond(&mut request, &config, &mut pending),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(pending.is_none());
        assert!(!root.0.join("custody_accounts").exists());
        Ok(())
    }
}
