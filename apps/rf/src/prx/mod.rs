// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Desktop bootstrap of the local PRX daemon. A fresh `runtime.json` is reused. Otherwise this
//! runs `prx init --from-stdin`, `prx token issue`, and `prx service install --user --yes`.

mod runtime;
mod spawn;

use crate::RfError;
use runtime::RuntimeView;
use serde_json::json;
use spawn::{CommandSpec, model_arg, provider_key, run};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) struct Options {
    pub state_dir: Option<PathBuf>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub native_tools: bool,
    pub no_native_tools: bool,
    pub binary: PathBuf,
}

pub(crate) fn refused(code: &'static str, message: impl Into<String>) -> RfError {
    RfError::Refused { code, message: message.into() }
}

pub(crate) async fn bootstrap(opts: Options) -> Result<(), RfError> {
    let dir = prepare(opts.state_dir.as_deref())?;
    runtime::check_dir(&dir, false)?;
    if let Some(view) = fresh(&dir).await? {
        print_view(&view);
        return Ok(());
    }
    ensure_config(&opts, &dir)?;
    check_workspace(&dir)?;
    issue(&opts, &dir, false)?;
    run(&spec(&opts, &dir, &["service", "install", "--user", "--yes"], None))?;
    run(&spec(&opts, &dir, &["service", "start"], None))?;
    if let Some(view) = wait_fresh(&dir).await? {
        check_memory(&dir)?;
        print_view(&view);
        return Ok(());
    }
    issue(&opts, &dir, true)?;
    run(&spec(&opts, &dir, &["service", "restart"], None))?;
    let view = wait_fresh(&dir)
        .await?
        .ok_or_else(|| refused("runtime_missing", "runtime.json did not become fresh"))?;
    check_memory(&dir)?;
    print_view(&view);
    Ok(())
}

pub(crate) async fn status(state_dir: Option<PathBuf>) -> Result<(), RfError> {
    let dir = resolve(state_dir.as_deref())?;
    let view =
        runtime::inspect(&dir).await?.ok_or_else(|| refused("runtime_missing", "runtime.json"))?;
    print_view(&view);
    Ok(())
}

pub(crate) async fn adopt(dir: &Path) -> Result<(String, PathBuf), RfError> {
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

fn ensure_config(opts: &Options, dir: &Path) -> Result<(), RfError> {
    if dir.join("config.toml").is_file() {
        return Ok(());
    }
    let provider =
        opts.provider.as_deref().ok_or_else(|| refused("provider_missing", "pass --provider"))?;
    let key = provider_key(provider)?;
    let model = model_arg(opts.model.as_deref())?;
    let tools = tool_flag(opts.native_tools, opts.no_native_tools, model.is_some())?;
    let mut args = vec!["init", "--provider", provider, "--from-stdin"];
    if let Some(model) = model {
        args.extend_from_slice(&["--model", model]);
    }
    if let Some(flag) = tools {
        args.push(flag);
    }
    run(&spec(opts, dir, &args, Some(key.as_str())))
}

/// Exactly one catalog declaration, and only beside a real `--model`.
fn tool_flag(native: bool, none: bool, has_model: bool) -> Result<Option<&'static str>, RfError> {
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

fn issue(opts: &Options, dir: &Path, force: bool) -> Result<(), RfError> {
    let token = dir.join("owner.token");
    if token.is_file() && !force {
        return Ok(());
    }
    let path = token.to_str().ok_or_else(|| refused("field_invalid", "state dir"))?;
    let mut args = vec!["token", "issue", "--out", path];
    if force {
        args.push("--force");
    }
    run(&spec(opts, dir, &args, None))
}

fn check_workspace(dir: &Path) -> Result<(), RfError> {
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

fn check_memory(dir: &Path) -> Result<(), RfError> {
    let memory = dir.join("workspace/memory");
    if !memory.is_dir() {
        return Err(refused("memory_missing", "workspace/memory"));
    }
    runtime::check_dir(&memory, true)
}

async fn fresh(dir: &Path) -> Result<Option<RuntimeView>, RfError> {
    Ok(runtime::inspect(dir).await?.filter(|view| view.fresh))
}

async fn wait_fresh(dir: &Path) -> Result<Option<RuntimeView>, RfError> {
    for _ in 0..150 {
        if let Some(view) = fresh(dir).await? {
            return Ok(Some(view));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(None)
}

fn spec<'a>(
    opts: &'a Options,
    dir: &'a Path,
    args: &'a [&'a str],
    key: Option<&'a str>,
) -> CommandSpec<'a> {
    CommandSpec { bin: &opts.binary, state: dir, args, key }
}

fn prepare(flag: Option<&Path>) -> Result<PathBuf, RfError> {
    let dir = resolve(flag)?;
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn resolve(flag: Option<&Path>) -> Result<PathBuf, RfError> {
    if let Some(path) = flag {
        return Ok(path.to_path_buf());
    }
    let home =
        std::env::var_os("HOME").ok_or_else(|| refused("home_missing", "HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/share/ramflux/prx"))
}

fn print_view(view: &RuntimeView) {
    let body = json!({
        "runtime_path": view.path,
        "api_base": view.api_base,
        "pid": view.pid,
        "started_at": view.started_at,
        "fresh": view.fresh,
        "prx_version": view.prx_version,
        "owner_id": view.owner_id,
    });
    println!("{body}");
}
