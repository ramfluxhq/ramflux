// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group membership binds principal, commitment and device to an immutable signing-key pin.
use crate::prelude::*;
impl RamfluxClient {
    pub(crate) fn require_group_sender_pin(
        &self,
        group: &str,
        principal: &str,
        device: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
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
        let commitment = crate::prekey::identity_root_public_key_commitment(&root_public)?;
        if let Some(binding) = db.group_member_key_binding(group, &local.device_id)?
            && binding.signing_public_key == public
            && binding.principal_id.as_deref() == Some(local.principal_id.as_str())
            && binding.principal_commitment.as_deref() == Some(commitment.as_str())
        {
            return Ok(());
        }
        db.persist_group_member_device_key(group, &local.device_id, &public)?;
        db.bind_group_member_key_identity(
            group,
            &local.device_id,
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
        if self.device_branch.as_ref().is_some_and(|own| own.device_id == device) {
            return self.pin_local_group_member(group);
        }
        let db = self.account_db()?;
        let record = db
            .client_record("device", device)?
            .ok_or_else(|| SdkError::InboundPending("joined member identity unavailable".into()))?;
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
