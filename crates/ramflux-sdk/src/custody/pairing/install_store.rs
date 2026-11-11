// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed Install file codec. Holds refs, hashes and phase only; never seeds.

use crate::SdkError;
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::{
    MAX_SAFE_JSON_INTEGER, canonical_json_bytes, decode_base64url, encode_base64url, parse_i_json,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(crate) const LIMIT: usize = 4096;
pub(crate) const PENDING_CAP: usize = 3;
const ID_MAX: usize = 128;
const SCHEMA: &str = "ramflux.pairing.Install.v2";

/// Closed T(Install) record. Public refs and hashes only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Install {
    pub schema: String,
    pub version: u32,
    pub account_id: String,
    pub account_anchor: String,
    pub operation_id: String,
    pub recipient_ref: DeviceRef,
    pub recipient_mode: String,
    pub install_purpose: String,
    pub record_hash: Option<String>,
    pub prior_record_hash: Option<String>,
    pub branch_vault_ref: String,
    pub data_vault_ref: String,
    pub primary_vault_ref: Option<String>,
    pub state: String,
    pub cleanup_ref: Option<String>,
    pub cleanup_owner_ref: Option<DeviceRef>,
}

fn field(name: &'static str) -> SdkError {
    SdkError::PairingField(name)
}

fn require(ok: bool, name: &'static str) -> Result<(), SdkError> {
    if ok { Ok(()) } else { Err(field(name)) }
}

fn b32(value: &str, name: &'static str) -> Result<(), SdkError> {
    require(
        value.len() == 43
            && decode_base64url(value)
                .is_ok_and(|v| v.len() == 32 && encode_base64url(&v) == value),
        name,
    )
}

fn ident(value: &str, name: &'static str) -> Result<(), SdkError> {
    require(
        !value.is_empty()
            && value.len() <= ID_MAX
            && !value.chars().any(char::is_control)
            && !value.contains(['/', '\\'])
            && value != "."
            && value != "..",
        name,
    )
}

fn optional_b32(value: Option<&str>, name: &'static str) -> Result<(), SdkError> {
    match value {
        None => Ok(()),
        Some(v) => b32(v, name),
    }
}

fn require_ref(value: &DeviceRef) -> Result<(), SdkError> {
    b32(&value.account_anchor, "ref.account_anchor")?;
    require(
        !value.device_id.is_empty()
            && value.device_id.len() <= ID_MAX
            && !value.device_id.chars().any(char::is_control),
        "ref.device_id",
    )?;
    require(
        value.device_epoch >= 1 && value.device_epoch <= MAX_SAFE_JSON_INTEGER,
        "ref.device_epoch",
    )
}

impl Install {
    /// Closed Install rules, including reserved null-hash and role/purpose/cleanup arms.
    ///
    /// # Errors
    /// Returns the exact invalid field.
    pub fn validate(&self) -> Result<(), SdkError> {
        require(self.schema == SCHEMA, "schema")?;
        require(self.version == 2, "version")?;
        ident(&self.account_id, "account_id")?;
        b32(&self.account_anchor, "account_anchor")?;
        b32(&self.operation_id, "operation_id")?;
        require_ref(&self.recipient_ref)?;
        require(self.recipient_ref.account_anchor == self.account_anchor, "ref.account_anchor")?;
        require(matches!(self.recipient_mode.as_str(), "new" | "existing"), "recipient_mode")?;
        require(
            matches!(
                self.install_purpose.as_str(),
                "enroll" | "transfer_destination" | "transfer_source" | "authority_refresh"
            ),
            "install_purpose",
        )?;
        optional_b32(self.record_hash.as_deref(), "record_hash")?;
        optional_b32(self.prior_record_hash.as_deref(), "prior_record_hash")?;
        match self.recipient_mode.as_str() {
            "new" => require(self.prior_record_hash.is_none(), "prior_record_hash")?,
            "existing" => require(self.prior_record_hash.is_some(), "prior_record_hash")?,
            _ => {}
        }
        ident(&self.branch_vault_ref, "branch_vault_ref")?;
        ident(&self.data_vault_ref, "data_vault_ref")?;
        require(self.data_vault_ref != self.branch_vault_ref, "data_vault_ref")?;
        match self.primary_vault_ref.as_deref() {
            None => Ok(()),
            Some(v) => {
                ident(v, "primary_vault_ref")?;
                require(self.data_vault_ref != v, "data_vault_ref")
            }
        }?;
        require(
            matches!(
                self.state.as_str(),
                "reserved"
                    | "vault_durable"
                    | "adopt_prepared"
                    | "authority_durable"
                    | "installed"
                    | "cleanup_pending"
            ),
            "state",
        )?;
        self.validate_hash_arms()?;
        self.validate_role_arms()?;
        self.validate_cleanup_arms()
    }

    fn validate_hash_arms(&self) -> Result<(), SdkError> {
        match self.state.as_str() {
            "reserved" => {
                require(self.record_hash.is_none(), "record_hash")?;
            }
            "vault_durable" => {}
            "adopt_prepared" | "authority_durable" | "installed" | "cleanup_pending" => {
                require(self.record_hash.is_some(), "record_hash")?;
            }
            _ => return Err(field("state")),
        }
        Ok(())
    }

    fn validate_role_arms(&self) -> Result<(), SdkError> {
        match self.install_purpose.as_str() {
            "enroll" | "transfer_source" => {
                require(self.primary_vault_ref.is_none(), "primary_vault_ref")
            }
            "transfer_destination" => {
                require(self.primary_vault_ref.is_some(), "primary_vault_ref")
            }
            "authority_refresh" => Ok(()),
            _ => Err(field("install_purpose")),
        }
    }

    fn validate_cleanup_arms(&self) -> Result<(), SdkError> {
        let pending = self.state == "cleanup_pending";
        require(self.cleanup_ref.is_some() == pending, "cleanup_ref")?;
        require(self.cleanup_owner_ref.is_some() == pending, "cleanup_owner_ref")?;
        if pending {
            require(self.install_purpose == "transfer_source", "cleanup_pending")?;
            let cleanup = self.cleanup_ref.as_deref().ok_or(field("cleanup_ref"))?;
            ident(cleanup, "cleanup_ref")?;
            let owner = self.cleanup_owner_ref.as_ref().ok_or(field("cleanup_owner_ref"))?;
            require_ref(owner)?;
            require(owner.account_anchor == self.account_anchor, "ref.account_anchor")?;
            require(cleanup != self.branch_vault_ref, "cleanup_ref")?;
            require(cleanup != self.data_vault_ref, "cleanup_ref")?;
            require(Some(cleanup) != self.primary_vault_ref.as_deref(), "cleanup_ref")?;
        }
        if self.install_purpose == "authority_refresh" {
            require(self.cleanup_ref.is_none(), "cleanup_ref")?;
            require(self.cleanup_owner_ref.is_none(), "cleanup_owner_ref")?;
        }
        Ok(())
    }
}

/// Encode a validated Install to canonical bytes.
///
/// # Errors
/// Returns the exact invalid field or size error.
pub fn encode(value: &Install) -> Result<Vec<u8>, SdkError> {
    value.validate()?;
    let bytes = canonical_json_bytes(value).map_err(|_| field("json"))?;
    require(bytes.len() <= LIMIT, "size")?;
    Ok(bytes)
}

/// Decode canonical Install bytes.
///
/// # Errors
/// Returns the exact invalid field, size, or noncanonical error.
pub fn decode(bytes: &[u8]) -> Result<Install, SdkError> {
    require(bytes.len() <= LIMIT, "size")?;
    let value: Install = parse_i_json(bytes).map_err(|_| field("json"))?;
    value.validate()?;
    if canonical_json_bytes(&value).map_err(|_| field("json"))? != bytes {
        return Err(field("noncanonical"));
    }
    Ok(value)
}

/// Pending operation file under the authenticated account.
#[must_use]
pub fn pending_path(root: &Path, account_id: &str, operation_id: &str) -> PathBuf {
    root.join("custody_accounts")
        .join(account_id)
        .join("pairing-install")
        .join(format!("{operation_id}.json"))
}

/// Current installed marker for the authenticated account.
#[must_use]
pub fn installed_path(root: &Path, account_id: &str) -> PathBuf {
    root.join("custody_accounts").join(account_id).join("pairing-install").join("installed.json")
}

/// Persist a pending Install. At most three pending files per account.
///
/// # Errors
/// Returns field, cap, or I/O errors.
pub fn write_pending(root: &Path, value: &Install) -> Result<(), SdkError> {
    ident(&value.account_id, "account_id")?;
    b32(&value.operation_id, "operation_id")?;
    let dir = root.join("custody_accounts").join(&value.account_id).join("pairing-install");
    ensure_dir(&dir)?;
    let pending = count_pending(&dir)?;
    let path = pending_path(root, &value.account_id, &value.operation_id);
    let replacing = path.is_file();
    require(replacing || pending < PENDING_CAP, "pending_cap")?;
    write_file(&path, &encode(value)?)
}

/// Persist the current installed marker.
///
/// # Errors
/// Returns field or I/O errors.
pub fn write_installed(root: &Path, value: &Install) -> Result<(), SdkError> {
    require(value.state == "installed", "state")?;
    let dir = root.join("custody_accounts").join(&value.account_id).join("pairing-install");
    ensure_dir(&dir)?;
    write_file(&installed_path(root, &value.account_id), &encode(value)?)
}

/// Read a pending Install if the file exists.
///
/// # Errors
/// Returns field, size, or I/O errors.
pub fn read_pending(
    root: &Path,
    account_id: &str,
    operation_id: &str,
) -> Result<Option<Install>, SdkError> {
    ident(account_id, "account_id")?;
    b32(operation_id, "operation_id")?;
    read_install(&pending_path(root, account_id, operation_id))
}

/// Read the current installed marker if present.
///
/// # Errors
/// Returns field, size, or I/O errors.
pub fn read_installed(root: &Path, account_id: &str) -> Result<Option<Install>, SdkError> {
    ident(account_id, "account_id")?;
    read_install(&installed_path(root, account_id))
}

/// Pending Install files for one account, excluding `installed.json`.
///
/// # Errors
/// Returns field or I/O errors.
pub fn list_pending(root: &Path, account_id: &str) -> Result<Vec<Install>, SdkError> {
    ident(account_id, "account_id")?;
    let dir = root.join("custody_accounts").join(account_id).join("pairing-install");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut rows = Vec::new();
    for entry in fs::read_dir(&dir).map_err(SdkError::from)? {
        let entry = entry.map_err(SdkError::from)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "installed.json" || !name.ends_with(".json") || name.starts_with('.') {
            continue;
        }
        let stem = name.strip_suffix(".json").ok_or(field("operation_id"))?;
        b32(stem, "operation_id")?;
        require(rows.len() < PENDING_CAP, "pending_cap")?;
        let row = read_install(&entry.path())?.ok_or(field("operation_id"))?;
        require(row.operation_id == stem, "operation_id")?;
        require(row.account_id == account_id, "account_id")?;
        rows.push(row);
    }
    Ok(rows)
}

/// Remove one pending operation file and fsync the directory.
///
/// # Errors
/// Returns field or I/O errors.
pub fn remove_pending(root: &Path, account_id: &str, operation_id: &str) -> Result<(), SdkError> {
    ident(account_id, "account_id")?;
    b32(operation_id, "operation_id")?;
    let path = pending_path(root, account_id, operation_id);
    match fs::remove_file(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(()) => {}
    }
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// True when a path is pairing install-store metadata excluded from backup.
#[must_use]
pub fn backup_excluded(path: &Path) -> bool {
    path.iter().any(|component| component == "pairing-install")
}

/// Strip pairing-install files from a backup tree. Floors live in the account DB.
///
/// # Errors
/// Returns field or I/O errors.
pub fn strip_backup_installs(root: &Path, account_id: &str) -> Result<(), SdkError> {
    ident(account_id, "account_id")?;
    let dir = root.join("custody_accounts").join(account_id).join("pairing-install");
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(SdkError::from)?;
    }
    Ok(())
}

fn read_install(path: &Path) -> Result<Option<Install>, SdkError> {
    let file = match File::open(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(file) => file,
    };
    let mut bytes = Vec::new();
    let cap = u64::try_from(LIMIT.saturating_add(1)).unwrap_or(u64::MAX);
    file.take(cap).read_to_end(&mut bytes)?;
    require(bytes.len() <= LIMIT, "size")?;
    decode(&bytes).map(Some)
}

fn ensure_dir(dir: &Path) -> Result<(), SdkError> {
    fs::create_dir_all(dir).map_err(SdkError::from)?;
    crate::platform::fs::set_owner_only_dir(dir)
}

fn count_pending(dir: &Path) -> Result<usize, SdkError> {
    let mut n = 0;
    if !dir.exists() {
        return Ok(0);
    }
    for entry in fs::read_dir(dir).map_err(SdkError::from)? {
        let entry = entry.map_err(SdkError::from)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "installed.json" || !name.ends_with(".json") || name.starts_with('.') {
            continue;
        }
        n += 1;
    }
    Ok(n)
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), SdkError> {
    let parent = path.parent().ok_or(field("path"))?;
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    let temporary = parent.join(format!(".install-{}.tmp", encode_base64url(seed)));
    seed.fill(0);
    let mut file = crate::platform::fs::create_new_owner_only(&temporary)?;
    let result: Result<(), SdkError> = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests;
