// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Roll back a stranger's speculative decrypt before resolving delayed public evidence.
use super::{GatewayInboxEntry, RamfluxClient, Routing, SdkError};
use crate::prekey::SdkDeviceManifestResponse;
use zeroize::Zeroizing;

type Preview = Option<(Routing, Zeroizing<Vec<u8>>)>;
enum Rollback {
    Ready(Preview),
    Failed(SdkError),
}
impl From<SdkError> for Rollback {
    fn from(error: SdkError) -> Self {
        Self::Failed(error)
    }
}
impl From<ramflux_storage::StorageError> for Rollback {
    fn from(error: ramflux_storage::StorageError) -> Self {
        Self::Failed(error.into())
    }
}

impl RamfluxClient {
    pub(super) fn preview_native_contact_request(
        &self,
        entry: &GatewayInboxEntry,
        manifest: &SdkDeviceManifestResponse,
        local: &str,
    ) -> Result<Preview, SdkError> {
        let result: Result<(), Rollback> = self.account_db()?.write_transaction(|| {
            self.remember_contact_request_cache(manifest)?;
            self.persist_root_verified_directory(manifest)?;
            let receipt = self.authenticated_committed_key(entry)?;
            if self.account_db()?.actor_state_exists(&receipt)? {
                return Err(Rollback::Ready(None));
            }
            let opened = self.open_routed(entry, local)?;
            // Ready is deliberately an error to the managed writer: every speculative cache,
            // journal and ratchet change is rolled back before any network await. The final
            // receive transaction decrypts again and independently rechecks all authority.
            Err(Rollback::Ready(Some((opened.routing, opened.body))))
        });
        match result {
            Err(Rollback::Ready(preview)) => Ok(preview),
            Err(Rollback::Failed(error)) => Err(error),
            Ok(()) => Err(super::invalid("contact preview unexpectedly committed")),
        }
    }
}
