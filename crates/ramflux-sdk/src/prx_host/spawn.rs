// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Child `prx` processes. The environment is cleared. A provider key travels on stdin only.

use super::refused;
use crate::SdkError;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub(crate) struct CommandSpec {
    pub bin: PathBuf,
    pub state: PathBuf,
    pub args: Vec<String>,
    pub key: Option<Zeroizing<String>>,
}

pub(crate) fn run(spec: &CommandSpec) -> Result<(), SdkError> {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned());
    let home = std::env::var("HOME").map_err(|_| refused("home_missing", "HOME is not set"))?;
    let mut command = Command::new(&spec.bin);
    command
        .args(&spec.args)
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .env("OPENPRX_CONFIG_DIR", &spec.state)
        .env("LC_ALL", "C")
        .stdin(if spec.key.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["USER", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().map_err(spawn_error)?;
    if let Some(key) = spec.key.as_deref() {
        let mut stdin = child.stdin.take().ok_or_else(|| refused("prx_spawn", "stdin"))?;
        if let Err(error) = stdin.write_all(key.as_bytes()) {
            let _ = child.wait();
            return Err(error.into());
        }
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(command_error(&output.stderr, spec.key.as_ref().map(|key| key.as_str())))
}

fn spawn_error(error: std::io::Error) -> SdkError {
    if error.kind() == std::io::ErrorKind::NotFound {
        refused("prx_missing", "prx")
    } else {
        SdkError::Io(error)
    }
}

fn command_error(stderr: &[u8], key: Option<&str>) -> SdkError {
    let text = String::from_utf8_lossy(stderr);
    if text.contains("model_capabilities_unknown") {
        return refused(
            "model_capabilities_unknown",
            "this model is outside the catalog; pass exactly one of --native-tools or --no-native-tools",
        );
    }
    refused("prx_command", redact(stderr, key))
}

pub(crate) fn model_arg(model: Option<&str>) -> Result<Option<&str>, SdkError> {
    match model.map(str::trim).filter(|text| !text.is_empty()) {
        None => Ok(None),
        Some(text) if model_ok(text) => Ok(Some(text)),
        Some(_) => Err(refused("field_invalid", "model")),
    }
}

pub(crate) fn label_ok(value: &str) -> bool {
    let Some((first, rest)) = value.as_bytes().split_first() else {
        return false;
    };
    value.len() <= 64
        && first.is_ascii_alphanumeric()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn model_ok(value: &str) -> bool {
    let Some((first, rest)) = value.as_bytes().split_first() else {
        return false;
    };
    value.len() <= 128
        && (first.is_ascii_alphanumeric() || matches!(*first, b'.' | b'_'))
        && rest.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@')
        })
}

fn redact(bytes: &[u8], key: Option<&str>) -> String {
    let text = String::from_utf8_lossy(bytes);
    let replaced = match key {
        Some(key) if !key.is_empty() => text.replace(key, "[redacted]"),
        _ => text.into_owned(),
    };
    let mut out = String::new();
    for ch in replaced.chars() {
        if out.len() >= 512 {
            break;
        }
        if !ch.is_control() {
            out.push(ch);
        }
    }
    if out.is_empty() { "prx command failed".to_owned() } else { out }
}

pub(crate) fn spec(
    bin: &Path,
    state: &Path,
    args: &[&str],
    key: Option<Zeroizing<String>>,
) -> CommandSpec {
    CommandSpec {
        bin: bin.to_path_buf(),
        state: state.to_path_buf(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        key,
    }
}
