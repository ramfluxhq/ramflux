// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opt-in, path-keyed observers at physical durability boundaries.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// A boundary callback; `completed` is true only after the physical operation succeeds.
pub type Observer = Arc<dyn Fn(&Path, &str, bool) -> io::Result<()> + Send + Sync>;

fn observers() -> &'static Mutex<BTreeMap<PathBuf, Observer>> {
    static OBSERVERS: OnceLock<Mutex<BTreeMap<PathBuf, Observer>>> = OnceLock::new();
    OBSERVERS.get_or_init(Mutex::default)
}

/// Removes an installed observer when its fixture ends.
pub struct Registration(PathBuf);

/// Installs one observer for a real store root and its descendants.
///
/// # Panics
/// Panics if the root already has an observer or the registry is poisoned.
#[must_use]
pub fn observe(root: PathBuf, observer: Observer) -> Registration {
    assert!(
        observers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(root.clone(), observer)
            .is_none()
    );
    Registration(root)
}

impl Drop for Registration {
    fn drop(&mut self) {
        observers().lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&self.0);
    }
}

pub(crate) fn notify(path: &Path, operation: &str, completed: bool) -> io::Result<()> {
    let callbacks: Vec<_> = observers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|(root, _)| path.starts_with(root))
        .map(|(_, callback)| Arc::clone(callback))
        .collect();
    for callback in callbacks {
        callback(path, operation, completed)?;
    }
    Ok(())
}
