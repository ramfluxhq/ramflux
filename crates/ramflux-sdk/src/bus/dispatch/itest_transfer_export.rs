// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Integration-only transfer export probes for Linux fixtures: A's canonical export of an
//! unlocked account into a private directory, and B's hardened open plus clean copy of a file.
//! The export key is written beside the file (0600) for the fixture's B side; it is never
//! returned in a response or logged.

use crate::prelude::*;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const KEY_FILE_BYTES: u64 = 64;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    account: String,
    directory: PathBuf,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    file: PathBuf,
    key_file: PathBuf,
    expected_root: String,
    clean_copy: PathBuf,
}

fn invalid(reason: &'static str) -> SdkError {
    SdkError::LocalBusRefused {
        code: "TransferProbeInvalid".into(),
        message: reason.into(),
        body: Box::new(serde_json::json!({ "reason_code": reason })),
    }
}

/// The probe writes only into an existing absolute directory that only its owner can open.
fn private_directory(path: &Path) -> Result<(), SdkError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid("directory"))?;
    if !path.is_absolute() || !metadata.is_dir() {
        return Err(invalid("directory"));
    }
    #[cfg(unix)]
    if std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o077 != 0 {
        return Err(invalid("directory"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> zeroize::Zeroizing<String> {
    let mut text = zeroize::Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            text.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    text
}

fn read_key(path: &Path) -> Result<ramflux_storage::AccountDbKey, SdkError> {
    let mut text = zeroize::Zeroizing::new(String::new());
    std::fs::File::open(path)
        .map_err(|_| invalid("key_file"))?
        .take(KEY_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| invalid("key_file"))?;
    let digits = text.trim();
    if digits.len() != 64 {
        return Err(invalid("key_file"));
    }
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    for (index, slot) in bytes.iter_mut().enumerate() {
        let pair = digits.get(index * 2..index * 2 + 2).ok_or_else(|| invalid("key_file"))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| invalid("key_file"))?;
    }
    Ok(ramflux_storage::AccountDbKey::from_bytes(*bytes))
}

pub(crate) fn dispatch(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "itest.transfer_export.write" => export(request, state),
        "itest.transfer_export.open" => open(request),
        "itest.transfer_export.fresh" => fresh(request, state),
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn export(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: Export = serde_json::from_value(request.body.clone())?;
    if request.account_id.as_deref() != Some(body.account.as_str()) {
        return Err(invalid("account"));
    }
    private_directory(&body.directory)?;
    let account = local_bus_account(state, &body.account)?;
    let db = account.client.account_db()?;
    let file = body.directory.join("export.db");
    let key = ramflux_storage::AccountDbKey::generate()?;
    let written = db.itest_transfer_export(&file, &key)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(body.directory.join("export.key"))?.write_all(hex(key.bytes()).as_bytes())?;
    Ok(local_bus_ok(serde_json::json!({
        "file": file,
        "rows": written.rows,
        "bytes": written.bytes,
        "framed_bytes": written.framed_bytes,
        "contract_digest": ramflux_protocol::encode_base64url(written.contract_digest),
        "elapsed_ms": written.elapsed_ms,
        "tables": written.tables.iter().map(|(name, rows)| serde_json::json!([name, rows])).collect::<Vec<_>>(),
        "directory": directory_json(&written.directory),
        "root": written.root,
    })))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fresh {
    account: String,
}

fn fresh(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: Fresh = serde_json::from_value(request.body.clone())?;
    if request.account_id.as_deref() != Some(body.account.as_str()) {
        return Err(invalid("account"));
    }
    let account = local_bus_account(state, &body.account)?;
    let outcome = account.client.account_db()?.require_fresh_transfer_target();
    Ok(local_bus_ok(match outcome {
        Ok(()) => serde_json::json!({ "fresh": true }),
        Err(ramflux_storage::StorageError::PairingField(code)) => {
            serde_json::json!({ "fresh": false, "code": code })
        }
        Err(error) => return Err(error.into()),
    }))
}

fn open(request: &LocalBusFrame) -> Result<LocalBusDispatchResult, SdkError> {
    let body: Open = serde_json::from_value(request.body.clone())?;
    let parent = body.clean_copy.parent().ok_or_else(|| invalid("clean_copy"))?;
    private_directory(parent)?;
    let key = read_key(&body.key_file)?;
    let outcome = ramflux_storage::itest_transfer_open(
        &body.file,
        &key,
        &body.expected_root,
        &body.clean_copy,
    );
    Ok(local_bus_ok(match outcome {
        Ok(opened) => serde_json::json!({
            "step": "ok",
            "rows": opened.rows,
            "bytes": opened.bytes,
            "open_ms": opened.open_ms,
            "copy_ms": opened.copy_ms,
            "tables": opened.tables.iter().map(|(name, rows)| serde_json::json!([name, rows])).collect::<Vec<_>>(),
            "directory": directory_json(&opened.directory),
        }),
        Err(ramflux_storage::StorageError::TransferExportRefused(step)) => {
            serde_json::json!({ "step": step, "refused": true })
        }
        Err(ramflux_storage::StorageError::Sqlite(error)) => serde_json::json!({
            "step": "sqlite", "refused": true, "code": format!("{:?}", error.sqlite_error_code()),
        }),
        Err(ramflux_storage::StorageError::PairingField(code)) => {
            serde_json::json!({ "step": code, "refused": true })
        }
        Err(_) => serde_json::json!({ "step": "storage", "refused": true }),
    }))
}

/// Prefix, row count, and JSON key names. Values stay out of the response.
fn directory_json(shapes: &[ramflux_storage::DirectoryKeys]) -> Vec<serde_json::Value> {
    shapes.iter().map(|shape| serde_json::json!([shape.prefix, shape.rows, shape.keys])).collect()
}
