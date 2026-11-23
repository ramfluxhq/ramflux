// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unix host actions over `prx service` and the 0700 state directory.

use super::runtime::{self, RuntimeView};
use super::spawn::{self, CommandSpec};
use super::{Action, Request, Status, refused};
use crate::SdkError;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub(super) async fn manage<K>(request: Request, mut key: K) -> Result<Status, SdkError>
where
    K: FnMut(&str) -> Result<Zeroizing<String>, SdkError>,
{
    validate(&request)?;
    if request.action == Action::Update && request.target_version.is_some() {
        return Err(refused("manifest_unavailable", "signed manifest is not available"));
    }
    let dir = locate(&request)?;
    match request.action {
        Action::Status => status_of(&dir).await,
        Action::Install => install(&request, &dir, &mut key).await,
        Action::Update => update(&request, &dir).await,
        Action::Restart => restart(&request, &dir).await,
        Action::Stop => stop(&request, &dir).await,
        Action::Uninstall => uninstall(&request, &dir).await,
    }
}

pub(super) async fn adopt(dir: &Path) -> Result<(String, PathBuf), SdkError> {
    runtime::check_dir(dir, false)?;
    let view = runtime::inspect(dir)
        .await?
        .filter(|view| view.fresh)
        .ok_or_else(|| refused("runtime_stale", "run rf prx bootstrap"))?;
    let memory = dir.join("workspace/memory");
    if memory.is_dir() {
        runtime::check_dir(&memory, true)?;
    }
    Ok((view.api_base, dir.join("owner.token")))
}

pub(super) fn resolve(flag: Option<&Path>) -> Result<PathBuf, SdkError> {
    if let Some(path) = flag {
        return Ok(path.to_path_buf());
    }
    let home =
        std::env::var_os("HOME").ok_or_else(|| refused("home_missing", "HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/share/ramflux/prx"))
}

pub(super) fn validate(request: &Request) -> Result<(), SdkError> {
    if request.action != Action::Status && !request.confirmed {
        return Err(refused("confirmation_required", "confirmed"));
    }
    if let Some(provider) = request.provider.as_deref()
        && !spawn::label_ok(provider)
    {
        return Err(refused("field_invalid", "provider"));
    }
    let model = spawn::model_arg(request.model.as_deref())?;
    tool_flag(request.native_tools, request.no_native_tools, model.is_some())?;
    if let Some(version) = request.target_version.as_deref()
        && (version.len() > 64 || version.chars().any(char::is_control))
    {
        return Err(refused("field_invalid", "target_version"));
    }
    Ok(())
}

fn locate(request: &Request) -> Result<PathBuf, SdkError> {
    if request.action == Action::Install {
        prepare(request.state_dir.as_deref())
    } else {
        resolve(request.state_dir.as_deref())
    }
}

async fn install<K>(request: &Request, dir: &Path, key: &mut K) -> Result<Status, SdkError>
where
    K: FnMut(&str) -> Result<Zeroizing<String>, SdkError>,
{
    runtime::check_dir(dir, false)?;
    if let Some(view) = fresh(dir).await? {
        return Ok(from_view(&view));
    }
    ensure_config(request, dir, key).await?;
    check_workspace(dir)?;
    issue(request, dir, false).await?;
    service(request, dir, &["service", "install", "--user", "--yes"]).await?;
    service(request, dir, &["service", "start"]).await?;
    if let Some(view) = wait_fresh(dir).await? {
        check_memory(dir)?;
        return Ok(from_view(&view));
    }
    issue(request, dir, true).await?;
    service(request, dir, &["service", "restart"]).await?;
    let view = wait_fresh(dir)
        .await?
        .ok_or_else(|| refused("runtime_missing", "runtime.json did not become fresh"))?;
    check_memory(dir)?;
    Ok(from_view(&view))
}

async fn update(request: &Request, dir: &Path) -> Result<Status, SdkError> {
    require_config(dir)?;
    runtime::check_dir(dir, false)?;
    service(request, dir, &["service", "install", "--user", "--yes"]).await?;
    service(request, dir, &["service", "restart"]).await?;
    let view = wait_fresh(dir)
        .await?
        .ok_or_else(|| refused("runtime_missing", "runtime.json did not become fresh"))?;
    check_memory(dir)?;
    Ok(from_view(&view))
}

async fn restart(request: &Request, dir: &Path) -> Result<Status, SdkError> {
    require_config(dir)?;
    runtime::check_dir(dir, false)?;
    service(request, dir, &["service", "restart"]).await?;
    let view = wait_fresh(dir)
        .await?
        .ok_or_else(|| refused("runtime_missing", "runtime.json did not become fresh"))?;
    check_memory(dir)?;
    Ok(from_view(&view))
}

async fn stop(request: &Request, dir: &Path) -> Result<Status, SdkError> {
    service(request, dir, &["service", "stop"]).await?;
    status_of(dir).await
}

async fn uninstall(request: &Request, dir: &Path) -> Result<Status, SdkError> {
    let _ = service(request, dir, &["service", "stop"]).await;
    service(request, dir, &["service", "uninstall"]).await?;
    remove_private(dir.join("runtime.json"), "runtime.json must be mode 0600")?;
    remove_private(dir.join("owner.token"), "owner.token must be mode 0600")?;
    Ok(absent())
}

async fn status_of(dir: &Path) -> Result<Status, SdkError> {
    Ok(runtime::inspect(dir).await?.map_or_else(absent, |view| from_view(&view)))
}

fn from_view(view: &RuntimeView) -> Status {
    let state = if view.fresh {
        "running"
    } else if view.alive {
        "stale"
    } else {
        "stopped"
    };
    Status {
        state: state.to_owned(),
        prx_version: view.prx_version.clone(),
        capabilities: if view.fresh { vec!["host_bootstrap_v1".to_owned()] } else { Vec::new() },
        api_base: view.api_base.clone(),
        pid: view.pid,
        owner_id: view.owner_id.clone(),
        started_at: view.started_at.clone(),
        fresh: view.fresh,
        runtime_path: view.path.display().to_string(),
    }
}

fn absent() -> Status {
    Status {
        state: "absent".to_owned(),
        prx_version: String::new(),
        capabilities: Vec::new(),
        api_base: String::new(),
        pid: 0,
        owner_id: String::new(),
        started_at: String::new(),
        fresh: false,
        runtime_path: String::new(),
    }
}

async fn ensure_config<K>(request: &Request, dir: &Path, key: &mut K) -> Result<(), SdkError>
where
    K: FnMut(&str) -> Result<Zeroizing<String>, SdkError>,
{
    if dir.join("config.toml").is_file() {
        return Ok(());
    }
    let provider = request
        .provider
        .as_deref()
        .ok_or_else(|| refused("provider_missing", "pass --provider"))?;
    let secret = key(provider)?;
    let model = spawn::model_arg(request.model.as_deref())?;
    let tools = tool_flag(request.native_tools, request.no_native_tools, model.is_some())?;
    let mut args = vec!["init", "--provider", provider, "--from-stdin"];
    if let Some(model) = model {
        args.extend_from_slice(&["--model", model]);
    }
    if let Some(flag) = tools {
        args.push(flag);
    }
    run_child(spawn::spec(&request.binary, dir, &args, Some(secret))).await
}

fn tool_flag(native: bool, none: bool, has_model: bool) -> Result<Option<&'static str>, SdkError> {
    match (native, none, has_model) {
        (false, false, _) => Ok(None),
        (true, false, true) => Ok(Some("--native-tools")),
        (false, true, true) => Ok(Some("--no-native-tools")),
        _ => Err(refused(
            "field_invalid",
            "pass exactly one of --native-tools or --no-native-tools with --model",
        )),
    }
}

async fn issue(request: &Request, dir: &Path, force: bool) -> Result<(), SdkError> {
    let token = dir.join("owner.token");
    if token.is_file() && !force {
        return Ok(());
    }
    let path = token.to_str().ok_or_else(|| refused("field_invalid", "state dir"))?;
    let mut args = vec!["token", "issue", "--out", path];
    if force {
        args.push("--force");
    }
    service_args(request, dir, &args).await
}

fn check_workspace(dir: &Path) -> Result<(), SdkError> {
    let memory = dir.join("workspace/memory");
    if memory.is_dir() {
        return runtime::check_dir(&memory, true);
    }
    let workspace = dir.join("workspace");
    if workspace.is_dir() {
        runtime::check_dir(&workspace, false)
    } else {
        runtime::check_dir(dir, false)
    }
}

fn check_memory(dir: &Path) -> Result<(), SdkError> {
    let memory = dir.join("workspace/memory");
    if !memory.is_dir() {
        return Err(refused("memory_missing", "workspace/memory"));
    }
    runtime::check_dir(&memory, true)
}

fn require_config(dir: &Path) -> Result<(), SdkError> {
    if dir.join("config.toml").is_file() {
        Ok(())
    } else {
        Err(refused("runtime_missing", "config.toml"))
    }
}

async fn fresh(dir: &Path) -> Result<Option<RuntimeView>, SdkError> {
    Ok(runtime::inspect(dir).await?.filter(|view| view.fresh))
}

async fn wait_fresh(dir: &Path) -> Result<Option<RuntimeView>, SdkError> {
    for _ in 0..150 {
        if let Some(view) = fresh(dir).await? {
            return Ok(Some(view));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(None)
}

async fn service(request: &Request, dir: &Path, args: &[&str]) -> Result<(), SdkError> {
    service_args(request, dir, args).await
}

async fn service_args(request: &Request, dir: &Path, args: &[&str]) -> Result<(), SdkError> {
    run_child(spawn::spec(&request.binary, dir, args, None)).await
}

async fn run_child(spec: CommandSpec) -> Result<(), SdkError> {
    tokio::task::spawn_blocking(move || spawn::run(&spec))
        .await
        .map_err(|_| refused("prx_spawn", "join"))?
}

fn prepare(flag: Option<&Path>) -> Result<PathBuf, SdkError> {
    let dir = resolve(flag)?;
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn remove_private(path: PathBuf, message: &'static str) -> Result<(), SdkError> {
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.mode() & 0o777 != 0o600 {
        return Err(refused("runtime_mode", message));
    }
    std::fs::remove_file(path).map_err(SdkError::from)
}
