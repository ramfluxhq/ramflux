// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Roll back a stranger's speculative decrypt before resolving delayed public evidence.
use super::{GatewayInboxEntry, RamfluxClient, Routing, SdkError};
use crate::client::identity_authority::HeadUse;
use crate::prekey::SdkDeviceManifestResponse;
use zeroize::Zeroizing;

type Preview = Option<(Routing, Zeroizing<Vec<u8>>)>;
enum Rollback<T> {
    Ready(T),
    Failed(SdkError),
}
impl<T> From<SdkError> for Rollback<T> {
    fn from(error: SdkError) -> Self {
        Self::Failed(error)
    }
}
impl<T> From<ramflux_storage::StorageError> for Rollback<T> {
    fn from(error: ramflux_storage::StorageError) -> Self {
        Self::Failed(error.into())
    }
}

impl RamfluxClient {
    /// Authenticate and decrypt from current cached authority without preparing directory state.
    /// Missing directory evidence stays pending for the independent authority reader. Group
    /// binding runs after rollback and before consent, directory adoption or payload effects.
    pub(crate) fn preview_reach_route(
        &self,
        entry: &GatewayInboxEntry,
        local: &str,
    ) -> Result<Preview, SdkError> {
        self.require_reach_entry_authority(entry)?;
        if self.inbound_device_manifest_request(entry)?.is_some() {
            return Err(SdkError::InboundPending(
                "current reach source directory unavailable".into(),
            ));
        }
        let result: Result<(), Rollback<Box<super::Opened>>> =
            self.account_db()?.write_transaction(|| {
                self.require_pair_device_active(&self.local_device_identity(local)?)?;
                let opened = self.open_routed(entry, local)?;
                Err(Rollback::Ready(Box::new(opened)))
            });
        match result {
            Err(Rollback::Ready(opened)) => {
                self.require_reach_entry_authority(entry)?;
                self.require_reach_decrypted_route(entry, &opened, &opened.body)?;
                Ok(Some((opened.routing, opened.body)))
            }
            Err(Rollback::Failed(error)) => Err(error),
            Ok(()) => Err(super::invalid("reach preview unexpectedly committed")),
        }
    }

    pub(crate) fn preview_inbound_route(
        &self,
        entry: &GatewayInboxEntry,
        local: &str,
    ) -> Result<Preview, SdkError> {
        let result: Result<(), Rollback<Box<Preview>>> =
            self.account_db()?.write_transaction(|| {
                self.require_pair_device_active(&self.local_device_identity(local)?)?;
                let opened = self.open_routed(entry, local)?;
                Err(Rollback::Ready(Box::new(Some((opened.routing, opened.body)))))
            });
        match result {
            Err(Rollback::Ready(preview)) => Ok(*preview),
            Err(Rollback::Failed(error)) => Err(error),
            Ok(()) => Err(super::invalid("receive preview unexpectedly committed")),
        }
    }

    pub(crate) fn preview_native_contact_request(
        &self,
        entry: &GatewayInboxEntry,
        manifest: &SdkDeviceManifestResponse,
        local: &str,
    ) -> Result<Preview, SdkError> {
        let result: Result<(), Rollback<Box<Preview>>> =
            self.account_db()?.write_transaction(|| {
                self.remember_contact_request_cache(manifest)?;
                self.persist_fetched_identity_directory(manifest)?;
                let receipt = self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?;
                if self.account_db()?.actor_state_exists(&receipt)? {
                    return Err(Rollback::Ready(Box::new(None)));
                }
                let opened = self.open_routed(entry, local)?;
                // Ready is deliberately an error to the managed writer: every speculative cache,
                // journal and ratchet change is rolled back before any network await. The final
                // receive transaction decrypts again and independently rechecks all authority.
                Err(Rollback::Ready(Box::new(Some((opened.routing, opened.body)))))
            });
        match result {
            Err(Rollback::Ready(preview)) => Ok(*preview),
            Err(Rollback::Failed(error)) => Err(error),
            Ok(()) => Err(super::invalid("contact preview unexpectedly committed")),
        }
    }
}
