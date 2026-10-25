// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group membership binds principal, commitment and device to an immutable signing-key pin.
use crate::prelude::*;
impl RamfluxClient {
    /// Read-model metadata may be unknown; unresolved legacy names never select a root.
    pub(crate) fn group_device_metadata(
        &self,
        group: &str,
        raw: &str,
    ) -> Result<Option<serde_json::Value>, SdkError> {
        match self.group_device_reference(group, raw) {
            Ok(reference) => Ok(self.account_db()?.client_record("device", &reference)?),
            Err(
                SdkError::InboundPending(_) | SdkError::Storage(StorageError::AmbiguousDeviceId(_)),
            ) => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn group_device_reference(
        &self,
        group: &str,
        raw: &str,
    ) -> Result<String, SdkError> {
        Ok(self
            .group_route_identity(group, raw)?
            .ok_or_else(|| {
                SdkError::InboundPending("group member root context unavailable".into())
            })?
            .storage_key()
            .to_owned())
    }
    pub(super) fn group_route_identity(
        &self,
        group: &str,
        raw: &str,
    ) -> Result<Option<ramflux_crypto::RootQualifiedDeviceRef>, SdkError> {
        if let Some(binding) = self.account_db()?.group_member_identity_metadata(group, raw)?
            && let Some(root) = binding.principal_commitment
        {
            return self.device_identity_for_root(&root, raw).map(Some);
        }
        if self.device_branch.as_ref().is_some_and(|own| own.device_id == raw) {
            return self.local_device_identity(raw).map(Some);
        }
        let mut identities = std::collections::BTreeSet::new();
        for route in self.account_db()?.list_actor_states::<LocalBusGroupMemberRoute>(
            &crate::group::group_route_prefix(group),
        )? {
            if route.member_id == raw
                && let Some(root) = route.member_principal_commitment
            {
                identities.insert(self.device_identity_for_root(&root, raw)?);
            }
        }
        if identities.len() > 1 {
            return Err(SdkError::InboundPending("ambiguous group route root".into()));
        }
        if let Some(device) = identities.into_iter().next() {
            return Ok(Some(device));
        }
        Ok(self.legacy_group_member_route(group, raw)?.map(|(device, _)| device))
    }
    pub(super) fn legacy_group_member_route(
        &self,
        group: &str,
        raw: &str,
    ) -> Result<Option<(ramflux_crypto::RootQualifiedDeviceRef, LocalBusGroupMemberRoute)>, SdkError>
    {
        let id = crate::group::legacy_group_member_route_event_id(group, raw);
        let Some(bytes) = self.event_body(&id)? else { return Ok(None) };
        let route: LocalBusGroupMemberRoute = serde_json::from_slice(&bytes)?;
        if route.member_id != raw {
            return Err(SdkError::InboundRejected("legacy group route name mismatch".into()));
        }
        let Some(root) = &route.member_principal_commitment else { return Ok(None) };
        let identity = self.device_identity_for_root(root, raw)?;
        Ok(Some((identity, route)))
    }
    pub(crate) fn require_group_payload_sender(
        &self,
        group: &str,
        claimed_sender: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        if claimed_sender != entry.envelope.source_device_id {
            return Err(SdkError::InboundRejected(
                "group payload sender differs from authenticated source device".into(),
            ));
        }
        if !self.local_is_group_member(group)? {
            return Err(SdkError::InboundRejected(
                "local device is not a current group member".into(),
            ));
        }
        self.require_group_sender_pin(
            group,
            &entry.envelope.source_principal_id,
            &self.authenticated_device_identity(entry)?,
        )
    }

    pub(crate) fn require_group_sender_pin(
        &self,
        group: &str,
        principal: &str,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let owner = db
            .client_record("identity", principal)?
            .ok_or_else(|| SdkError::InboundPending("group root unavailable".into()))?;
        if owner["contact_identity_commitment"].as_str() != Some(device.root_commitment()) {
            return Err(SdkError::InboundRejected(
                "group sender root differs from pinned relationship".into(),
            ));
        }
        let record = self.trusted_device(device)?;
        if let Some(state) = db.shared_group_state(group)? {
            if state.view().effective_role(device.root_commitment(), device.device_id()).is_none() {
                return Err(StorageError::GroupPermissionDenied.into());
            }
            let key = record["signing_public_key"]
                .as_str()
                .ok_or_else(|| SdkError::InboundPending("group member key unavailable".into()))?;
            if let Some(binding) = db.group_member_key_binding(group, device)? {
                if binding.signing_public_key != key {
                    db.rotate_root_authorized_group_device_key(
                        ramflux_storage::RootAuthorizedGroupKeyRotation {
                            group_id: group,
                            device_id: device,
                            principal_id: principal,
                            principal_commitment: device.root_commitment(),
                            previous_key: &binding.signing_public_key,
                            next_key: key,
                        },
                    )?;
                }
            } else {
                db.materialize_shared_group_member(
                    group,
                    device,
                    &ramflux_protocol::group_state::GroupMemberIdentity {
                        principal_id: principal.into(),
                        root_commitment: device.root_commitment().into(),
                        device_id: device.device_id().into(),
                        signing_public_key: key.into(),
                        target_delivery_id: record["target_delivery_id"]
                            .as_str()
                            .unwrap_or_default()
                            .into(),
                    },
                )?;
            }
        }
        let binding = db
            .group_member_key_binding(group, device)?
            .ok_or_else(|| SdkError::InboundPending("group member key not pinned".into()))?;
        let pin = binding.signing_public_key;
        let bound_principal = binding.principal_id;
        let bound_commitment = binding.principal_commitment;
        let commitment = record["principal_commitment"].as_str().ok_or_else(|| {
            SdkError::InboundPending("group member commitment unavailable".into())
        })?;
        if record["principal_id"] != principal
            || record["signing_public_key"] != pin
            || bound_principal.as_deref().is_some_and(|id| id != principal)
            || bound_commitment.as_deref().is_some_and(|id| id != commitment)
        {
            return Err(SdkError::InboundRejected(
                "safety: group sender differs from pinned member identity".into(),
            ));
        }
        if bound_principal.is_none() {
            db.bind_group_member_key_identity(group, device, principal, commitment, &pin)?;
        }
        Ok(())
    }
    pub(crate) fn pin_local_group_member(&self, group: &str) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let public =
            ramflux_protocol::encode_base64url(local.signing_key.verifying_key().to_bytes());
        let root_public =
            ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
        let db = self.account_db()?;
        let commitment = crate::prekey::identity_root_public_key_commitment(&root_public)?;
        let identity = self.owned_device_identity()?;
        if let Some(binding) = db.group_member_key_binding(group, &identity)?
            && binding.signing_public_key == public
            && binding.principal_id.as_deref() == Some(local.principal_id.as_str())
            && binding.principal_commitment.as_deref() == Some(commitment.as_str())
        {
            return Ok(());
        }
        if db.shared_group_state(group)?.is_some() {
            let binding = db
                .group_member_key_binding(group, &identity)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            if binding.principal_id.as_deref() != Some(&local.principal_id)
                || binding.principal_commitment.as_deref() != Some(&commitment)
            {
                return Err(StorageError::GroupPermissionDenied.into());
            }
            // The owned root authenticates this local branch; no directory claim selects it.
            db.rotate_root_authorized_group_device_key(
                ramflux_storage::RootAuthorizedGroupKeyRotation {
                    group_id: group,
                    device_id: &identity,
                    principal_id: &local.principal_id,
                    principal_commitment: &commitment,
                    previous_key: &binding.signing_public_key,
                    next_key: &public,
                },
            )?;
            return Ok(());
        }
        db.persist_group_member_device_key(group, &identity, &public)?;
        db.bind_group_member_key_identity(
            group,
            &identity,
            &local.principal_id,
            &crate::prekey::identity_root_public_key_commitment(&root_public)?,
            &public,
        )?;
        Ok(())
    }
    pub(crate) fn pin_joined_group_member(
        &self,
        group: &str,
        device: &str,
    ) -> Result<(), SdkError> {
        let reference = ramflux_protocol::parse_qualified_device_id(device)?;
        if let Some(own) = self.device_branch.as_ref() {
            let raw = reference.as_ref().map_or(device, |(_, raw)| raw.as_str());
            if own.device_id == raw
                && (reference.is_none() || self.local_device_reference(raw)? == device)
            {
                return self.pin_local_group_member(group);
            }
        }
        let device = if reference.is_some() {
            device.to_owned()
        } else {
            self.group_device_reference(group, device)?
        };
        let identity = self.device_identity(&device)?;
        let device = identity.storage_key();
        let db = self.account_db()?;
        if db.client_record("device", device)?.is_none() {
            return Err(SdkError::InboundPending("joined member identity unavailable".into()));
        }
        let record = self.trusted_device(&identity)?;
        let (Some(principal), Some(commitment), Some(key)) = (
            record["principal_id"].as_str(),
            record["principal_commitment"].as_str(),
            record["signing_public_key"].as_str(),
        ) else {
            return Err(SdkError::InboundPending("joined member identity incomplete".into()));
        };
        db.persist_group_member_device_key(group, &identity, key)?;
        db.bind_group_member_key_identity(group, &identity, principal, commitment, key)?;
        Ok(())
    }
}
