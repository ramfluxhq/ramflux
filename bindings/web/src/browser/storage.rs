// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Origin storage: the persistence request, quota, the OPFS directories and what is found at
//! start. The database itself is opened through `store_policy::StoreEngine`.

use wasm_bindgen::JsValue;

use super::js;
use super::vault::BrowserVault;
use crate::WebError;
use crate::store_policy::{
    OPFS_POOL_DIRECTORY, Persistence, SPOOL_DIRECTORY, StoreInventory, write_allowed,
};

fn storage_manager() -> Result<JsValue, WebError> {
    js::get(&js::get(&js::global(), "navigator")?, "storage")
}

/// `navigator.storage.persisted()`.
pub async fn persistence() -> Persistence {
    answer(js::call_async_optional("persisted").await)
}

/// The answer of `navigator.storage.persist()`, which the page must call: the method does not
/// exist in workers. The page calls it after linking (a user gesture) and passes the result
/// here. A refusal is normal and is shown, never treated as an error.
#[must_use]
pub fn persistence_from_page(granted: Option<bool>) -> Persistence {
    answer(granted.map(JsValue::from_bool))
}

fn answer(value: Option<JsValue>) -> Persistence {
    match value.and_then(|value| value.as_bool()) {
        Some(true) => Persistence::Persistent,
        Some(false) => Persistence::BestEffort,
        None => Persistence::Unknown,
    }
}

/// `navigator.storage.estimate()` as `(usage, quota)` in bytes.
pub async fn estimate() -> Option<(u64, u64)> {
    let estimate = js::call_async_optional("estimate").await?;
    let read = |key: &str| {
        js::get_optional(&estimate, key).and_then(|value| value.as_f64()).map(|value| {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let value = value.max(0.0) as u64;
            value
        })
    };
    Some((read("usage")?, read("quota")?))
}

/// Whether a write may start. Without an estimate the write is attempted and a
/// `QuotaExceededError` fails it; nothing is ever deleted to make room.
pub async fn may_write(write_bytes: u64) -> bool {
    estimate().await.is_none_or(|(usage, quota)| write_allowed(usage, quota, write_bytes))
}

/// The origin-private file system root, or an error where OPFS does not exist.
///
/// # Errors
/// Returns [`WebError::Browser`] when OPFS is unavailable (some private modes).
pub async fn opfs_root() -> Result<JsValue, WebError> {
    js::call_async(&storage_manager()?, "getDirectory", &[]).await
}

async fn directory_exists(name: &'static str) -> bool {
    let Ok(root) = opfs_root().await else { return false };
    let options = js::object(&[("create", JsValue::FALSE)]);
    js::call_async(&root, "getDirectoryHandle", &[JsValue::from_str(name), options]).await.is_ok()
}

async fn remove_directory(name: &'static str) {
    if let Ok(root) = opfs_root().await {
        let options = js::object(&[("recursive", JsValue::TRUE)]);
        // A missing entry rejects with `NotFoundError`, which is the wanted end state.
        let _ = js::call_async(&root, "removeEntry", &[JsValue::from_str(name), options]).await;
    }
}

/// Delete whatever an aborted transfer left and recreate the empty spool directory.
///
/// # Errors
/// Returns [`WebError::Browser`] when OPFS is unavailable.
pub async fn sweep_spool() -> Result<(), WebError> {
    remove_directory(SPOOL_DIRECTORY).await;
    let root = opfs_root().await?;
    let options = js::object(&[("create", JsValue::TRUE)]);
    js::call_async(&root, "getDirectoryHandle", &[JsValue::from_str(SPOOL_DIRECTORY), options])
        .await
        .map(|_| ())
}

/// What exists at start. The pool directory stands for the database: the pool keeps its files
/// under opaque names, so the engine confirms the file itself when it opens.
pub async fn inventory(vault: &BrowserVault) -> StoreInventory {
    StoreInventory {
        sentinel: vault.is_marked_linked().await,
        database: directory_exists(OPFS_POOL_DIRECTORY).await,
        vault: vault.has_secrets().await,
    }
}

/// Remove the database pool and the spool. Part of unlink and of loss handling.
pub async fn wipe_files() {
    remove_directory(OPFS_POOL_DIRECTORY).await;
    remove_directory(SPOOL_DIRECTORY).await;
}
