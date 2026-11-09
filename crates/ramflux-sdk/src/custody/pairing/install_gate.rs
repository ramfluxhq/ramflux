// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reopen admission latch for pairing install files. Authority.json agreement is P10.

use super::install_store::{self, Install};
use crate::SdkError;
use std::path::Path;

/// Ordinary networking stays closed until install, DB, vault and authority agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Closed,
    Open,
}

/// Recovered install-store view after a crash reopen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReopenGate {
    pub admission: Admission,
    pub pending: Vec<Install>,
    pub installed: Option<Install>,
    pub files_and_db_agree: bool,
    pub expected_hash: Option<String>,
}

/// Reopen the install latch. `authority_present` is false until P10's authority-file writer.
///
/// # Errors
/// Returns field, size, or I/O errors.
pub fn reopen(
    root: &Path,
    account_id: &str,
    adoption_hash: Option<&str>,
    authority_present: bool,
) -> Result<ReopenGate, SdkError> {
    let pending = install_store::list_pending(root, account_id)?;
    let installed = install_store::read_installed(root, account_id)?;
    let expected_hash = installed.as_ref().and_then(|row| row.record_hash.clone());
    let files_and_db_agree = match (installed.as_ref(), adoption_hash) {
        (Some(row), Some(hash)) => row.record_hash.as_deref() == Some(hash),
        _ => false,
    };
    let restrictive = !pending.is_empty()
        || installed.as_ref().is_some_and(|row| row.state != "installed")
        || !files_and_db_agree
        || !authority_present;
    let admission = if restrictive { Admission::Closed } else { Admission::Open };
    Ok(ReopenGate { admission, pending, installed, files_and_db_agree, expected_hash })
}

impl ReopenGate {
    /// Ordinary register/session/own-sync stay closed while the latch disagrees.
    #[must_use]
    pub const fn admits_ordinary_networking(&self) -> bool {
        matches!(self.admission, Admission::Open)
    }
}

#[cfg(test)]
mod tests;
