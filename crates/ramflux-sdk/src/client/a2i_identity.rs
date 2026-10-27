// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bind control attribution and lookup identities to verified roots, never payload device names.
use crate::client::identity_authority::invalid;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_sync::A2iControlEvent;
impl RamfluxClient {
    pub(crate) fn bind_owned_a2i_event(
        &self,
        event: &mut A2iControlEvent,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let source = self.owned_device_identity()?;
        bind(event, &branch.principal_id, &source)?;
        Ok(source)
    }
    pub(crate) fn bind_received_a2i_event(
        &self,
        event: &mut A2iControlEvent,
        entry: &GatewayInboxEntry,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        let source = self.authenticated_device_identity(entry)?;
        bind(event, &entry.envelope.source_principal_id, &source)?;
        Ok(source)
    }
    pub(crate) fn a2i_event_identity(
        &self,
        event: &A2iControlEvent,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        let root = event
            .source_principal_commitment
            .as_deref()
            .ok_or_else(|| invalid("legacy A2I has no verified root"))?;
        if let Some(authority) =
            self.current_custody_authority(root, crate::custody::network_now()?)?
        {
            if event.source_principal_id.as_deref()
                != Some(authority.envelope().body.principal_id.as_str())
            {
                return Err(invalid("A2I principal differs from native authority"));
            }
            return self.device_identity_for_root(root, &event.source_device_id);
        }
        let record =
            self.observed_device_set(root)?.ok_or_else(|| invalid("A2I authority unavailable"))?;
        if event.source_principal_id.as_deref() != Some(&record.principal_id) {
            return Err(invalid("A2I principal differs from signed root"));
        }
        self.device_identity_for_root(root, &event.source_device_id)
    }
}
fn bind(
    event: &mut A2iControlEvent,
    principal: &str,
    source: &RootQualifiedDeviceRef,
) -> Result<(), SdkError> {
    if event.source_device_id != source.device_id()
        || event.source_principal_id.as_deref().is_some_and(|claim| claim != principal)
        || event
            .source_principal_commitment
            .as_deref()
            .is_some_and(|claim| claim != source.root_commitment())
    {
        return Err(invalid("A2I source attribution differs from authenticated sender"));
    }
    event.source_principal_id = Some(principal.into());
    event.source_principal_commitment = Some(source.root_commitment().into());
    Ok(())
}
