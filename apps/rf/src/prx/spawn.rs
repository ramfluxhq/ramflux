// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Child `prx` processes. The environment is cleared. A provider key travels on stdin only.

use super::refused;
use crate::RfError;
use crate::keychain::{KeyStore, KeychainSecret, OsKeychain};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct CommandSpec<'a> {
    pub bin: &'a Path,
    pub state: &'a Path,
    pub args: &'a [&'a str],
    pub key: Option<&'a str>,
}

pub(crate) fn run(spec: &CommandSpec<'_>) -> Result<(), RfError> {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned());
    let home = std::env::var("HOME").map_err(|_| refused("home_missing", "HOME is not set"))?;
    let mut command = Command::new(spec.bin);
    command
        .args(spec.args)
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .env("OPENPRX_CONFIG_DIR", spec.state)
        .env("LC_ALL", "C")
        .stdin(if spec.key.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Ok(user) = std::env::var("USER") {
        command.env("USER", user);
    }
    let mut child = command.spawn()?;
    if let Some(key) = spec.key {
        let mut stdin = child.stdin.take().ok_or_else(|| refused("prx_spawn", "stdin"))?;
        stdin.write_all(key.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(refused("prx_command", redact(&output.stderr, spec.key)))
}

pub(crate) fn provider_key(provider: &str) -> Result<Zeroizing<String>, RfError> {
    if !label_ok(provider) {
        return Err(refused("field_invalid", "provider"));
    }
    let account = format!("prx-provider:{provider}");
    let store = OsKeychain;
    if let Some(secret) = store.load(&account)? {
        let key = Zeroizing::new(secret.passphrase.clone());
        if !key.trim().is_empty() {
            return Ok(key);
        }
    }
    let key = read_stdin_key()?;
    store.store(&account, &KeychainSecret::new((*key).clone(), None))?;
    Ok(key)
}

pub(crate) fn model_arg(model: Option<&str>) -> Result<Option<&str>, RfError> {
    match model.map(str::trim).filter(|text| !text.is_empty()) {
        None => Ok(None),
        Some(text) if model_ok(text) => Ok(Some(text)),
        Some(_) => Err(refused("field_invalid", "model")),
    }
}

fn read_stdin_key() -> Result<Zeroizing<String>, RfError> {
    let mut buf = Zeroizing::new(Vec::new());
    let mut stdin = std::io::stdin();
    let mut chunk = Zeroizing::new([0_u8; 4096]);
    loop {
        let n = stdin.read(&mut chunk[..])?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > 64 * 1024 + 1 {
            return Err(refused("input_invalid", "provider key too large"));
        }
        buf.extend_from_slice(&chunk[..n]);
        chunk[..n].zeroize();
    }
    while buf.last().is_some_and(|byte| *byte == b'\n' || *byte == b'\r') {
        buf.pop();
    }
    if buf.is_empty() || buf.iter().all(u8::is_ascii_whitespace) {
        return Err(refused("input_missing", "provider key on stdin"));
    }
    let taken = std::mem::take(&mut *buf);
    match String::from_utf8(taken) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(refused("input_invalid", "provider key is not utf-8"))
        }
    }
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

fn label_ok(value: &str) -> bool {
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
