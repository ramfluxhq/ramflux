// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Desktop management of the local PRX host. Phones never host. The provider key is a callback
//! argument, never a field of [`Request`].

use crate::SdkError;
use std::path::{Path, PathBuf};

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
mod runtime;
#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
mod spawn;
#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
mod unix;

/// Closed host actions. There is no separate start: install starts, restart starts an existing host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Install,
    Update,
    Restart,
    Stop,
    Status,
    Uninstall,
}

/// One host operation. `state_dir` and `binary` are for the CLI. The bus leaves the directory
/// empty and uses `prx` on `PATH`.
pub struct Request {
    pub action: Action,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub native_tools: bool,
    pub no_native_tools: bool,
    pub target_version: Option<String>,
    pub binary: PathBuf,
    pub state_dir: Option<PathBuf>,
    pub confirmed: bool,
}

/// Non-secret view of the host. `capabilities` is `host_bootstrap_v1` only while the runtime is fresh.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Status {
    pub state: String,
    pub prx_version: String,
    pub capabilities: Vec<String>,
    pub api_base: String,
    pub pid: u32,
    pub owner_id: String,
    pub started_at: String,
    pub fresh: bool,
    pub runtime_path: String,
}

/// Typed host refusal. `code` is an alphanumeric token. The body carries the same token and no secret.
pub fn refused(code: &'static str, message: impl Into<String>) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.to_owned(),
        message: message.into(),
        body: Box::new(serde_json::json!({ "reason_code": code })),
    }
}

/// Desktop Unix can host. Android, iOS and other targets cannot.
#[must_use]
pub const fn hosts_here() -> bool {
    cfg!(all(unix, not(any(target_os = "android", target_os = "ios"))))
}

/// Run one host action. `key` is called only when install must run `prx init`.
///
/// # Errors
/// Returns a typed [`SdkError::LocalBusRefused`] for a refused action, ancestor, or PRX command.
pub async fn manage<K>(request: Request, key: K) -> Result<Status, SdkError>
where
    K: FnMut(&str) -> Result<zeroize::Zeroizing<String>, SdkError>,
{
    #[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
    {
        unix::manage(request, key).await
    }
    #[cfg(not(all(unix, not(any(target_os = "android", target_os = "ios")))))]
    {
        let _ = (request, key);
        Err(platform_refusal())
    }
}

/// Adopt a fresh runtime the daemon already owns. The returned path is `owner.token`.
///
/// # Errors
/// Returns `runtime_stale` when the runtime is missing or not fresh, and `ancestor_rejected`
/// when a directory on the path to memory is writable by another user.
pub async fn adopt(dir: &Path) -> Result<(String, PathBuf), SdkError> {
    #[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
    {
        unix::adopt(dir).await
    }
    #[cfg(not(all(unix, not(any(target_os = "android", target_os = "ios")))))]
    {
        let _ = dir;
        Err(platform_refusal())
    }
}

/// Reject a request before any prompt or process spawn.
///
/// # Errors
/// Returns the same typed refusal `manage` would return for a bad field or a missing confirmation.
pub fn check(request: &Request) -> Result<(), SdkError> {
    #[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
    {
        unix::validate(request)
    }
    #[cfg(not(all(unix, not(any(target_os = "android", target_os = "ios")))))]
    {
        let _ = request;
        Ok(())
    }
}

/// Whether the default state directory already has `config.toml`. Does not create the directory.
///
/// # Errors
/// Returns `home_missing` when the default directory cannot be resolved.
pub fn config_exists() -> Result<bool, SdkError> {
    #[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
    {
        Ok(unix::resolve(None)?.join("config.toml").is_file())
    }
    #[cfg(not(all(unix, not(any(target_os = "android", target_os = "ios")))))]
    {
        Err(platform_refusal())
    }
}

#[cfg(not(all(unix, not(any(target_os = "android", target_os = "ios")))))]
fn platform_refusal() -> SdkError {
    if cfg!(any(target_os = "android", target_os = "ios")) {
        refused("desktop_required", "phones never host")
    } else {
        refused("unsupported_platform", "prx host")
    }
}
