// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-wide transfer ownership spans file mutation and metadata publication.
use crate::StorageError;
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};
fn owners() -> &'static Mutex<BTreeSet<PathBuf>> {
    static OWNERS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(BTreeSet::new()))
}
pub(super) struct Lease(PathBuf);
impl Lease {
    pub(super) fn acquire(path: PathBuf) -> Result<Self, StorageError> {
        let mut owners = owners().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !owners.insert(path.clone()) {
            return Err(StorageError::AccountWriterBusy(
                "segment transfer has an active I/O owner".into(),
            ));
        }
        Ok(Self(path))
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        owners().lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&self.0);
    }
}
