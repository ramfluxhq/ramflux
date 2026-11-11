// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-profile SAS bindings. V2 codecs remain closed and retain their exact bytes/domains.
use super::{
    Common, DataSelection, DeviceRef, PairingWire, Result, RoleContext, budget, bytes, require,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullAccountData {}

/// An externally tagged union: exactly one key, including a closed empty full-data object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DataSelectionV3 {
    SelectedKeys(Vec<DataSelection>),
    FullAccountDataV1(FullAccountData),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonV3 {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub account_anchor: String,
    pub master_public_key: String,
    pub record_hash: String,
    pub device_set_epoch: u64,
    pub principal_kind: String,
    pub sas_suite: String,
    #[serde(deserialize_with = "super::required_nullable")]
    pub hpke_suite: Option<String>,
    pub purpose: String,
    pub requested_role: String,
    pub recipient_mode: String,
    #[serde(deserialize_with = "super::required_nullable")]
    pub destination_ref: Option<DeviceRef>,
    pub capabilities: Vec<String>,
    pub lease_not_before: u64,
    pub lease_expires_at: u64,
    pub expires_at: u64,
    #[serde(deserialize_with = "super::required_nullable")]
    pub transfer_id: Option<String>,
    pub data_selection: DataSelectionV3,
}
impl CommonV3 {
    /// Project a verified native invitation into the explicit full-data committed profile.
    /// Signature, current-head pins and attended intent remain with the coordinator.
    /// # Errors
    /// Refuses an add-device/selected-key descriptor and malformed public bindings.
    pub fn from_full_invitation(
        invitation: &super::native::Invitation,
        master_public_key: String,
    ) -> Result<Self> {
        require(
            invitation.purpose == "primary_transfer" && invitation.data_selection.is_empty(),
            "UpdateRequired",
        )?;
        let Common {
            schema: _,
            version: _,
            invitation_id,
            issuer_seq,
            account_anchor,
            master_public_key,
            record_hash,
            device_set_epoch,
            principal_kind,
            sas_suite,
            hpke_suite,
            purpose,
            requested_role,
            recipient_mode,
            destination_ref,
            capabilities,
            lease_not_before,
            lease_expires_at,
            expires_at,
            transfer_id,
            data_selection: _,
        } = invitation.project_common(master_public_key)?;
        let common = Self {
            schema: "ramflux.pairing.Common.v3".into(),
            version: 3,
            invitation_id,
            issuer_seq,
            account_anchor,
            master_public_key,
            record_hash,
            device_set_epoch,
            principal_kind,
            sas_suite,
            hpke_suite,
            purpose,
            requested_role,
            recipient_mode,
            destination_ref,
            capabilities,
            lease_not_before,
            lease_expires_at,
            expires_at,
            transfer_id,
            data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
        };
        common.validate()?;
        Ok(common)
    }
    // Validation view only: never serialized into a commitment or sent as a fallback.
    fn scalar_context(&self) -> Common {
        Common {
            schema: "ramflux.pairing.Common.v2".into(),
            version: 2,
            invitation_id: self.invitation_id.clone(),
            issuer_seq: self.issuer_seq,
            account_anchor: self.account_anchor.clone(),
            master_public_key: self.master_public_key.clone(),
            record_hash: self.record_hash.clone(),
            device_set_epoch: self.device_set_epoch,
            principal_kind: self.principal_kind.clone(),
            sas_suite: self.sas_suite.clone(),
            hpke_suite: self.hpke_suite.clone(),
            purpose: self.purpose.clone(),
            requested_role: self.requested_role.clone(),
            recipient_mode: self.recipient_mode.clone(),
            destination_ref: self.destination_ref.clone(),
            capabilities: self.capabilities.clone(),
            lease_not_before: self.lease_not_before,
            lease_expires_at: self.lease_expires_at,
            expires_at: self.expires_at,
            transfer_id: self.transfer_id.clone(),
            data_selection: match &self.data_selection {
                DataSelectionV3::SelectedKeys(keys) => keys.clone(),
                DataSelectionV3::FullAccountDataV1(_) => Vec::new(),
            },
        }
    }
    /// # Errors
    /// Refuses invalid invitation/authority bounds using the same scalar rules as v2.
    pub fn validate_bounds(
        &self,
        created_at: u64,
        authority_start: u64,
        authority_end: u64,
    ) -> Result<()> {
        self.validate()?;
        self.scalar_context().validate_bounds(created_at, authority_start, authority_end)
    }
}
impl PairingWire for CommonV3 {
    const LIMIT: usize = super::MAX_COMMON_BYTES;
    fn normalize(&mut self) {
        self.capabilities.sort();
        if let DataSelectionV3::SelectedKeys(keys) = &mut self.data_selection {
            keys.sort();
        }
    }
    fn validate(&self) -> Result<()> {
        require(self.schema == "ramflux.pairing.Common.v3", "schema")?;
        require(self.version == 3, "version")?;
        self.scalar_context().validate()?;
        if matches!(&self.data_selection, DataSelectionV3::FullAccountDataV1(_)) {
            require(self.purpose == "primary_transfer", "transfer_context")?;
        }
        budget(self, Self::LIMIT)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferProfile {
    #[serde(rename = "full_account_data_v1")]
    FullAccountDataV1,
}
fn present_profile<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<TransferProfile>, D::Error> {
    TransferProfile::deserialize(decoder).map(Some)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleContextV3 {
    pub schema: String,
    pub version: u32,
    pub role: String,
    pub common: CommonV3,
    pub device_ref: DeviceRef,
    pub branch_key: String,
    pub agreement_key: String,
    pub sas_key: String,
    #[serde(deserialize_with = "super::required_nullable")]
    pub hpke_key: Option<String>,
    pub display_name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_profile"
    )]
    pub transfer_profile: Option<TransferProfile>,
}
impl PairingWire for RoleContextV3 {
    const LIMIT: usize = super::MAX_ROLE_BYTES;
    fn normalize(&mut self) {
        self.common.normalize();
    }
    fn validate(&self) -> Result<()> {
        require(self.schema == "ramflux.pairing.RoleContext.v3", "schema")?;
        require(self.version == 3, "version")?;
        self.common.validate()?;
        if self.common.purpose == "primary_transfer" {
            require(
                matches!(&self.common.data_selection, DataSelectionV3::FullAccountDataV1(_)),
                "UpdateRequired",
            )?;
        }
        require(
            self.transfer_profile.is_some() == (self.common.purpose == "primary_transfer"),
            "transfer_profile",
        )?;
        RoleContext {
            schema: "ramflux.pairing.RoleContext.v2".into(),
            version: 2,
            role: self.role.clone(),
            common: self.common.scalar_context(),
            device_ref: self.device_ref.clone(),
            branch_key: self.branch_key.clone(),
            agreement_key: self.agreement_key.clone(),
            sas_key: self.sas_key.clone(),
            hpke_key: self.hpke_key.clone(),
            display_name: self.display_name.clone(),
        }
        .validate()?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptV3 {
    pub schema: String,
    pub version: u32,
    pub initiator: RoleContextV3,
    pub responder: RoleContextV3,
}
impl PairingWire for TranscriptV3 {
    const LIMIT: usize = super::MAX_TRANSCRIPT_BYTES;
    fn normalize(&mut self) {
        self.initiator.normalize();
        self.responder.normalize();
    }
    fn validate(&self) -> Result<()> {
        require(self.schema == "ramflux.pairing.Transcript.v3", "schema")?;
        require(self.version == 3, "version")?;
        self.initiator.validate()?;
        self.responder.validate()?;
        require(
            self.initiator.role == "initiator" && self.responder.role == "responder",
            "role_slots",
        )?;
        require(
            self.initiator.common == self.responder.common
                && self.initiator.transfer_profile == self.responder.transfer_profile,
            "common_binding",
        )?;
        require(self.initiator.sas_key != self.responder.sas_key, "distinct_sas_keys")?;
        if self.initiator.common.purpose == "primary_transfer" {
            require(self.initiator.hpke_key != self.responder.hpke_key, "distinct_hpke_keys")?;
        }
        require(
            self.initiator.device_ref.device_id != self.responder.device_ref.device_id,
            "distinct_devices",
        )?;
        budget(self, Self::LIMIT)
    }
}

/// # Errors
/// Rejects invalid full-profile context. Frozen fields are never projected to v2 bytes.
pub fn context_commitment_preimage(context: &RoleContextV3, salt: &[u8; 32]) -> Result<Vec<u8>> {
    context.validate()?;
    let mut out = b"ramflux.identity.pairing.context_commitment.v3\0".to_vec();
    out.push(u8::from(context.role == "responder"));
    out.extend_from_slice(salt);
    out.extend(bytes(context)?);
    Ok(out)
}
/// # Errors
/// Rejects invalid/mismatched frozen role contexts.
pub fn transcript_preimage(transcript: &TranscriptV3) -> Result<Vec<u8>> {
    transcript.validate()?;
    let mut out = b"ramflux.identity.pairing_transcript.v3\0".to_vec();
    out.extend(bytes(transcript)?);
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests;
