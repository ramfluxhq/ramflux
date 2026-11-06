// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opt-in observers on the real SQLite worker, keyed by database path.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

/// SQL boundary observer: SQL, completed, and SQLite autocommit state.
pub type Observer = Arc<dyn Fn(&str, bool, bool) -> rusqlite::Result<()> + Send + Sync>;
fn observers() -> &'static Mutex<BTreeMap<PathBuf, Observer>> {
    static OBSERVERS: OnceLock<Mutex<BTreeMap<PathBuf, Observer>>> = OnceLock::new();
    OBSERVERS.get_or_init(Mutex::default)
}
/// Owns a path registration until dropped.
pub struct Registration(PathBuf);
/// Installs an observer for one real database file.
/// # Errors
/// Rejects duplicate registrations without replacing the existing observer.
pub fn observe(path: PathBuf, observer: Observer) -> rusqlite::Result<Registration> {
    let mut entries = observers().lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
    if entries.contains_key(&path) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    entries.insert(path.clone(), observer);
    Ok(Registration(path))
}
impl Drop for Registration {
    fn drop(&mut self) {
        observers().lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&self.0);
    }
}
pub(crate) fn notify(
    path: &Path,
    sql: &str,
    completed: bool,
    autocommit: bool,
) -> rusqlite::Result<()> {
    let callback =
        observers().lock().map_err(|_| rusqlite::Error::InvalidQuery)?.get(path).cloned();
    if let Some(callback) = callback {
        callback(sql, completed, autocommit)?;
    }
    Ok(())
}
