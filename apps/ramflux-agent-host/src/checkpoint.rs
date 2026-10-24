// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Crash-safe cursor plus one write-ahead reply. No account keys are stored here.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
};
const MAX_STATE_BYTES: u64 = 524_288;
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub account_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub cursor: Option<u64>,
    #[serde(default)]
    pub last_refusal: Option<OutputRefusal>,
    pub last_reply_ms: BTreeMap<String, u64>,
    pub(crate) pending: Option<Pending>,
    #[serde(default)]
    pub(crate) handled_actions: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    pub seq: u64,
    pub conversation_id: String,
    pub method: String,
    pub operation_id: String,
    pub body: Value,
    #[serde(default)]
    pub remaining: Vec<Output>,
    #[serde(default)]
    pub action: Option<ActionWork>,
    #[serde(default)]
    pub plan: Option<crate::surface_plan::SurfacePlan>,
    #[serde(default)]
    pub needs_rederive: Option<ramflux_sdk::SurfaceRefusalCode>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Output {
    pub method: String,
    pub operation_id: String,
    pub body: Value,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActionWork {
    pub surface_ref: String,
    pub action_id: String,
    pub attempts: u8,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRefusal {
    pub conversation_id: String,
    pub surface_id: Option<String>,
    pub reason: ramflux_sdk::SurfaceRefusalCode,
}
pub struct CheckpointStore {
    path: PathBuf,
    _lock: std::fs::File,
}
impl CheckpointStore {
    /// # Errors
    /// Requires an existing private parent directory and exclusive ownership of this checkpoint.
    pub fn new(path: PathBuf) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        if std::fs::metadata(parent).map_err(|_| Error::Storage)?.permissions().mode() & 0o077 != 0
        {
            return Err(Error::Storage);
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(sidecar(&path, ".lock"))
            .map_err(|_| Error::Storage)?;
        lock.try_lock().map_err(|_| Error::Storage)?;
        let temp = sidecar(&path, ".next");
        match std::fs::remove_file(temp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Storage),
        }
        Ok(Self { path, _lock: lock })
    }
    /// # Errors
    /// Rejects corrupt, oversized or inaccessible checkpoints; missing state starts fresh.
    pub fn load(&self) -> Result<Checkpoint> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Checkpoint::default()),
            Err(_) => return Err(Error::Storage),
        };
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes).map_err(|_| Error::Storage)?;
        if bytes.len() > usize::try_from(MAX_STATE_BYTES).map_err(|_| Error::Limit)? {
            return Err(Error::Storage);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Storage)
    }
    /// # Errors
    /// Writes with owner-only permissions, fsync, atomic rename and a synced parent directory.
    pub fn save(&self, state: &Checkpoint) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let bytes = serde_json::to_vec(state).map_err(|_| Error::Storage)?;
        if bytes.len() > usize::try_from(MAX_STATE_BYTES).map_err(|_| Error::Limit)? {
            return Err(Error::Limit);
        }
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let temp = sidecar(&self.path, ".next");
        let result = (|| -> std::io::Result<()> {
            let mut file =
                std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp, &self.path)?;
            std::fs::File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
            return Err(Error::Storage);
        }
        Ok(())
    }
}

fn sidecar(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
