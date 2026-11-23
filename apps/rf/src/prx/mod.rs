// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf prx` is a thin wrapper over the SDK host controller. The keychain and stdin stay here.

mod keys;

use crate::RfError;
use keys::provider_key;
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
        "prx_command" => "prx_command",
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
