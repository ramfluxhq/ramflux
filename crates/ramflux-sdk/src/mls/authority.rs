// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Directory-path device authority for MLS: the verified custody heads the client's custody
//! directory holds, as a snapshot the MLS crate can read without the client.
//!
//! The directory (`identity_authority/custody_directory.rs`) owns pins, fences and rollback
//! protection; this type only copies its current verified record per anchor into a shared map
//! (`refresh`). The engine refreshes an anchor on the head-refresh triggers of the card (T1-T7)
//! before it retries an `authority_needed` answer.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ramflux_crypto::custody::VerifiedRecord;
use ramflux_mls::DeviceAuthority;

use crate::{RamfluxClient, SdkError};

/// Verified custody heads by account anchor.
#[derive(Default)]
pub(crate) struct SdkAuthority {
    heads: Mutex<BTreeMap<String, VerifiedRecord>>,
}

impl SdkAuthority {
    /// Copy the directory's current verified record of `anchor` into the snapshot. `Ok(false)`
    /// when the directory has none (the entry is dropped so a stale head cannot outlive it).
    ///
    /// # Errors
    /// The directory fails (locked database, pin conflict, invalid cache).
    pub(crate) fn refresh(&self, client: &RamfluxClient, anchor: &str) -> Result<bool, SdkError> {
        let now = crate::custody::network_now()?;
        let record = client.current_custody_authority(anchor, now)?;
        let mut heads = self.heads.lock().map_err(|_| SdkError::Mls {
            code: "internal",
            detail: "the authority snapshot lock is poisoned".to_owned(),
        })?;
        match record {
            Some(record) => {
                heads.insert(anchor.to_owned(), record);
                Ok(true)
            }
            None => {
                heads.remove(anchor);
                Ok(false)
            }
        }
    }
}

impl DeviceAuthority for SdkAuthority {
    fn current(&self, anchor: &[u8]) -> Option<VerifiedRecord> {
        let anchor = std::str::from_utf8(anchor).ok()?;
        self.heads.lock().ok()?.get(anchor).cloned()
    }
}
