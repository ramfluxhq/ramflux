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
        if let Some(binding) = self
            .account_db()?
            .group_member_key_binding_by_name(group, raw)
            .map_err(|error| match error {
                StorageError::AmbiguousDeviceId(_) => {
                    SdkError::InboundPending("ambiguous group member root".into())
                }
                other => other.into(),
            })?
            && let Some(root) = binding.principal_commitment
        {
            return Ok(ramflux_protocol::qualified_device_id(&root, raw)?);
        }
        if self.device_branch.as_ref().is_some_and(|own| own.device_id == raw) {
            return self.local_device_reference(raw);
        }
        if let Some(root) = self
            .group_member_routes(group)?
            .iter()
            .find(|route| route.member_id == raw)
            .and_then(|route| route.member_principal_commitment.as_ref())
        {
            return Ok(ramflux_protocol::qualified_device_id(root, raw)?);
        }
        Err(SdkError::InboundPending("group member root context unavailable".into()))
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
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if !self.group_state(group)?.members.contains(&local.device_id) {
            return Err(SdkError::InboundRejected(
                "local device is not a current group member".into(),
            ));
        }
        self.require_group_sender_pin(
            group,
            &entry.envelope.source_principal_id,
            &entry.envelope.source_device_id,
        )
    }

    pub(crate) fn require_group_sender_pin(
        &self,
        group: &str,
        principal: &str,
        device: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let owner = db
            .client_record("identity", principal)?
            .ok_or_else(|| SdkError::InboundPending("group root unavailable".into()))?;
        let root = owner["contact_identity_commitment"]
            .as_str()
            .ok_or_else(|| SdkError::InboundPending("group root missing".into()))?;
        let reference = ramflux_protocol::qualified_device_id(root, device)?;
        let device = reference.as_str();
        let binding = db
            .group_member_key_binding(group, device)?
            .ok_or_else(|| SdkError::InboundPending("group member key not pinned".into()))?;
        let pin = binding.signing_public_key;
        let bound_principal = binding.principal_id;
        let bound_commitment = binding.principal_commitment;
        let record = db
            .client_record("device", device)?
            .ok_or_else(|| SdkError::InboundPending("group member identity unavailable".into()))?;
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
        let reference = ramflux_protocol::qualified_device_id(
            &crate::identity_root_public_key_commitment(&root_public)?,
            &local.device_id,
        )?;
        let commitment = crate::prekey::identity_root_public_key_commitment(&root_public)?;
        if let Some(binding) = db.group_member_key_binding(group, &reference)?
            && binding.signing_public_key == public
            && binding.principal_id.as_deref() == Some(local.principal_id.as_str())
            && binding.principal_commitment.as_deref() == Some(commitment.as_str())
        {
            return Ok(());
        }
        db.persist_group_member_device_key(group, &reference, &public)?;
        db.bind_group_member_key_identity(
            group,
            &reference,
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
        let device = device.as_str();
        let db = self.account_db()?;
        if db.client_record("device", device)?.is_none() {
            return Err(SdkError::InboundPending("joined member identity unavailable".into()));
        }
        let record = self.trusted_device(device)?;
        let (Some(principal), Some(commitment), Some(key)) = (
            record["principal_id"].as_str(),
            record["principal_commitment"].as_str(),
            record["signing_public_key"].as_str(),
        ) else {
            return Err(SdkError::InboundPending("joined member identity incomplete".into()));
        };
        db.persist_group_member_device_key(group, device, key)?;
        db.bind_group_member_key_identity(group, device, principal, commitment, key)?;
        Ok(())
    }
}
