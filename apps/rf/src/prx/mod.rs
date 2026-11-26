// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf prx` is a thin wrapper over the SDK host controller. The keychain and stdin stay here.

mod keys;

use crate::RfError;
use keys::{provider_key, stdin_provider_key};
use ramflux_sdk::SdkError;
use ramflux_sdk::prx_host::{self, Action, Request};
use serde_json::json;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) struct Options {
    pub state_dir: Option<PathBuf>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub native_tools: bool,
    pub no_native_tools: bool,
    pub binary: PathBuf,
}

pub(crate) fn refused(code: &str, message: impl Into<String>) -> RfError {
    RfError::Refused { code: static_code(code), message: message.into() }
}

pub(crate) async fn bootstrap(opts: Options) -> Result<(), RfError> {
    let status =
        prx_host::manage(request(Action::Install, opts, true), sdk_key).await.map_err(from_sdk)?;
    print_status(&status);
    Ok(())
}

/// Installs PRX through the running daemon. The key is read from stdin only if the daemon asks
/// for it (no `prx` config yet), and goes back as a private reply; nothing is written to the
/// keychain on this path.
pub(crate) async fn bootstrap_via_bus(
    socket: PathBuf,
    provider: Option<String>,
    model: Option<String>,
    native_tools: bool,
    no_native_tools: bool,
) -> Result<(), RfError> {
    let provider = provider.ok_or_else(|| refused("provider_missing", "pass --provider"))?;
    let bus = ramflux_sdk::LocalBusClient::connect(socket).await?;
    let wanted = provider.clone();
    bus.set_host_key_provider(Some(std::sync::Arc::new(move |asked: &str| {
        (asked == wanted).then(|| stdin_provider_key(asked).ok()).flatten()
    })));
    let mut body = json!({"action": "install", "provider": provider, "confirmed": true});
    if let Some(object) = body.as_object_mut() {
        if let Some(model) = model {
            object.insert("model".into(), json!(model));
        }
        if native_tools {
            object.insert("native_tools".into(), json!(true));
        }
        if no_native_tools {
            object.insert("no_native_tools".into(), json!(true));
        }
    }
    let frame = ramflux_sdk::LocalBusFrame::request(
        "rf-prx-bootstrap",
        None,
        "agent",
        "agent.host.manage",
        body,
    );
    let response = bus.request_frame_response(frame).await?;
    crate::handlers::conversation_ops::commit_write("agent.host.manage", &response)
}

pub(crate) async fn status(state_dir: Option<PathBuf>) -> Result<(), RfError> {
    let status = prx_host::manage(
        Request {
            action: Action::Status,
            provider: None,
            model: None,
            native_tools: false,
            no_native_tools: false,
            target_version: None,
            binary: PathBuf::from("prx"),
            state_dir,
            confirmed: false,
        },
        sdk_key,
    )
    .await
    .map_err(from_sdk)?;
    if status.state == "absent" {
        return Err(refused("runtime_missing", "runtime.json"));
    }
    print_status(&status);
    Ok(())
}

pub(crate) async fn adopt(dir: &Path) -> Result<(String, PathBuf), RfError> {
    prx_host::adopt(dir).await.map_err(from_sdk)
}

fn request(action: Action, opts: Options, confirmed: bool) -> Request {
    Request {
        action,
        provider: opts.provider,
        model: opts.model,
        native_tools: opts.native_tools,
        no_native_tools: opts.no_native_tools,
        target_version: None,
        binary: opts.binary,
        state_dir: opts.state_dir,
        confirmed,
    }
}

fn sdk_key(provider: &str) -> Result<Zeroizing<String>, SdkError> {
    match provider_key(provider) {
        Ok(key) => Ok(key),
        Err(RfError::Refused { code, message }) => Err(prx_host::refused(code, message)),
        Err(RfError::Io(error)) => Err(SdkError::Io(error)),
        Err(error) => Err(SdkError::LocalBus(error.to_string())),
    }
}

fn from_sdk(error: SdkError) -> RfError {
    match error {
        SdkError::LocalBusRefused { code, message, .. } => refused(&code, message),
        SdkError::Io(error) => RfError::Io(error),
        SdkError::Json(error) => RfError::Json(error),
        other => RfError::Sdk(other),
    }
}

fn print_status(status: &prx_host::Status) {
    let body = json!({
        "runtime_path": status.runtime_path,
        "api_base": status.api_base,
        "pid": status.pid,
        "started_at": status.started_at,
        "fresh": status.fresh,
        "prx_version": status.prx_version,
        "owner_id": status.owner_id,
    });
    println!("{body}");
}

fn static_code(code: &str) -> &'static str {
    match code {
        "ancestor_rejected" => "ancestor_rejected",
        "confirmation_required" => "confirmation_required",
        "credential_unavailable" => "credential_unavailable",
        "desktop_required" => "desktop_required",
        "field_invalid" => "field_invalid",
        "home_missing" => "home_missing",
        "input_invalid" => "input_invalid",
        "input_missing" => "input_missing",
        "manifest_unavailable" => "manifest_unavailable",
        "memory_missing" => "memory_missing",
        "model_capabilities_unknown" => "model_capabilities_unknown",
        "provider_missing" => "provider_missing",
        "prx_missing" => "prx_missing",
        "prx_spawn" => "prx_spawn",
        "runtime_invalid" => "runtime_invalid",
        "runtime_missing" => "runtime_missing",
        "runtime_mode" => "runtime_mode",
        "runtime_stale" => "runtime_stale",
        "unsupported_platform" => "unsupported_platform",
        _ => "prx_command",
    }
}
