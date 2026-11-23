// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `agent.host.manage`. Local connections only. The provider key is a private `provider` reply,
//! never a JSON field.

use super::custody_setup::Incoming;
use crate::custody::pairing::private_credential::PrivateCredentialChannel;
use crate::prx_host::{self, Action, Request};
use crate::{LocalBusFrameKind, SdkError};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const FIELDS: &[&str] = &[
    "action",
    "confirmed",
    "provider",
    "model",
    "native_tools",
    "no_native_tools",
    "target_version",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    action: String,
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    native_tools: bool,
    #[serde(default)]
    no_native_tools: bool,
    #[serde(default)]
    target_version: Option<String>,
}

pub(super) async fn respond(
    incoming: &mut Incoming,
    channel: Arc<PrivateCredentialChannel>,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let request = incoming.frame()?;
    if request.kind != LocalBusFrameKind::Request {
        return super::custody_response::error(
            request,
            &prx_host::refused("field_invalid", "request"),
        );
    }
    if let Err(error) = super::requests::deadline(request) {
        return super::custody_response::error(request, &error);
    }
    let mut raw = std::mem::take(&mut request.body);
    let parsed = decode(&mut raw);
    match parsed {
        Ok(body) => match apply(body, &channel).await {
            Ok(status) => super::custody_response::success(request, status),
            Err(error) => super::custody_response::error(request, &error),
        },
        Err(error) => super::custody_response::error(request, &error),
    }
}

fn decode(body: &mut Value) -> Result<Body, SdkError> {
    let unknown = match body.as_object() {
        Some(object) => object.keys().any(|key| !FIELDS.contains(&key.as_str())),
        None => true,
    };
    if unknown {
        super::secrets::wipe(body);
        return Err(prx_host::refused("field_invalid", "request"));
    }
    let parsed =
        Body::deserialize(&*body).map_err(|_| prx_host::refused("field_invalid", "request"));
    super::secrets::wipe(body);
    parsed
}

async fn apply(
    body: Body,
    channel: &Arc<PrivateCredentialChannel>,
) -> Result<prx_host::Status, SdkError> {
    let action = action(&body.action)?;
    let provider = body.provider.clone();
    let request = Request {
        action,
        provider: body.provider,
        model: body.model,
        native_tools: body.native_tools,
        no_native_tools: body.no_native_tools,
        target_version: body.target_version.filter(|text| !text.is_empty()),
        binary: PathBuf::from("prx"),
        state_dir: None,
        confirmed: body.confirmed,
    };
    prx_host::check(&request)?;
    let mut key = install_key(action, provider.as_deref(), channel).await?;
    prx_host::manage(request, move |asked| match key.take() {
        Some(secret) if provider.as_deref() == Some(asked) => Ok(secret),
        _ => Err(prx_host::refused("credential_unavailable", "provider key")),
    })
    .await
}

fn action(text: &str) -> Result<Action, SdkError> {
    match text {
        "install" => Ok(Action::Install),
        "update" => Ok(Action::Update),
        "restart" => Ok(Action::Restart),
        "stop" => Ok(Action::Stop),
        "status" => Ok(Action::Status),
        "uninstall" => Ok(Action::Uninstall),
        _ => Err(prx_host::refused("field_invalid", "action")),
    }
}

async fn install_key(
    action: Action,
    provider: Option<&str>,
    channel: &Arc<PrivateCredentialChannel>,
) -> Result<Option<Zeroizing<String>>, SdkError> {
    if action != Action::Install || !prx_host::hosts_here() || prx_host::config_exists()? {
        return Ok(None);
    }
    let provider =
        provider.ok_or_else(|| prx_host::refused("provider_missing", "pass --provider"))?;
    let receiver = channel.begin_host(provider)?;
    let waited =
        tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(120)))
            .await
            .map_err(|_| prx_host::refused("credential_unavailable", "provider key"))?;
    match waited {
        Ok(Ok(secret)) => Ok(Some(secret)),
        Ok(Err(error)) => Err(error),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(prx_host::refused("credential_unavailable", "provider key"))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            channel.cancel_host();
            Err(prx_host::refused("credential_unavailable", "provider key"))
        }
    }
}
