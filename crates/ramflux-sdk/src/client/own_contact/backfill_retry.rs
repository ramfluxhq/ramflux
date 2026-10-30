// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wake completed parked-contact scans after verified directory changes or a bounded delay.
use crate::{RamfluxClient, SdkError, prekey::SdkDeviceManifestResponse};

pub(super) const PARKED_RETRY_SECS: i64 = 300;

pub(super) fn parked_key(link: &str) -> String {
    let key = ramflux_protocol::hash_base64url("ramflux.own_contact.parked.v1", link.as_bytes());
    format!("own-contact/parked/{key}")
}

impl RamfluxClient {
    // Called inside the directory write transaction, before replacing the previous manifest.
    pub(crate) fn record_contact_directory_change(
        &self,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let previous = db.load_actor_state::<serde_json::Value>(&format!(
            "identity/manifest-root/{}",
            manifest.principal_commitment
        ))?;
        if previous.as_ref() != Some(&serde_json::to_value(manifest)?) {
            let generation = db
                .load_actor_state::<u64>("own-contact/directory-generation")?
                .unwrap_or(0)
                .wrapping_add(1);
            db.persist_actor_state("own-contact/directory-generation", &generation)?;
        }
        Ok(())
    }
}
