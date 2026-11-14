// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit Move primary intent. The old selected-key DTO cannot become a full-copy request.
use super::{DeviceRef, PairingWire, Result, budget, name, reference, require, rights};
use crate::custody::pairing::context_v3::{DataSelectionV3, TransferProfile};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullTransferBegin {
    pub schema: String,
    pub version: u32,
    pub recipient_mode: String,
    #[serde(deserialize_with = "super::super::required_nullable")]
    pub destination_ref: Option<DeviceRef>,
    pub capabilities: Vec<String>,
    pub lease_not_before: u64,
    pub lease_expires_at: u64,
    pub data_selection: DataSelectionV3,
    pub transfer_profile: TransferProfile,
    pub display_name: String,
}
impl PairingWire for FullTransferBegin {
    const LIMIT: usize = 16_384;
    fn normalize(&mut self) {
        self.capabilities.sort();
    }
    fn validate(&self) -> Result<()> {
        require(self.schema == "ramflux.pairing.TransferBegin.v3" && self.version == 3, "schema")?;
        rights(&self.capabilities, self.lease_not_before, self.lease_expires_at)?;
        name(&self.display_name)?;
        require(matches!(self.recipient_mode.as_str(), "new" | "existing"), "recipient_mode")?;
        require(
            self.destination_ref.is_some() == (self.recipient_mode == "existing"),
            "destination_ref",
        )?;
        if let Some(reference_value) = &self.destination_ref {
            reference(reference_value)?;
        }
        require(
            matches!(&self.data_selection, DataSelectionV3::FullAccountDataV1(_)),
            "UpdateRequired",
        )?;
        require(self.transfer_profile == TransferProfile::FullAccountDataV1, "UpdateRequired")?;
        budget(self, Self::LIMIT)
    }
}

impl FullTransferBegin {
    /// Freeze the existing native invitation carrier for an explicit full-data ceremony.
    /// The SAS context still uses v3; this does not negotiate or fall back to a v2 transfer.
    /// # Errors
    /// Refuses invalid intent, a self-transfer or inconsistent native reference/head fields.
    pub fn create_spec(
        &self,
        primary_ref: DeviceRef,
        base_record_hash: String,
        base_epoch: u64,
    ) -> Result<crate::custody::pairing::native::CreateSpec> {
        self.validate()?;
        require(self.destination_ref.as_ref() != Some(&primary_ref), "destination_ref")?;
        let spec = crate::custody::pairing::native::CreateSpec {
            schema: "ramflux.pairing.CreateSpec.v2".into(),
            version: 2,
            account_anchor: primary_ref.account_anchor.clone(),
            primary_ref,
            base_record_hash,
            base_epoch,
            purpose: "primary_transfer".into(),
            recipient_mode: self.recipient_mode.clone(),
            destination_ref: self.destination_ref.clone(),
            capabilities: self.capabilities.clone(),
            lease_not_before: self.lease_not_before,
            lease_expires_at: self.lease_expires_at,
            data_selection: Vec::new(),
            ttl_seconds: 300,
        };
        spec.validate()?;
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::pairing::{WireError, context_v3::FullAccountData};
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn full_transfer_local_intent_is_explicit_and_old_partial_dto_stays_closed() -> TestResult {
        let mut request = FullTransferBegin {
            schema: "ramflux.pairing.TransferBegin.v3".into(),
            version: 3,
            recipient_mode: "new".into(),
            destination_ref: None,
            capabilities: vec!["message".into()],
            lease_not_before: 100,
            lease_expires_at: 200,
            data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
            transfer_profile: TransferProfile::FullAccountDataV1,
            display_name: "New primary".into(),
        };
        let wire = request.to_wire_bytes()?;
        assert_eq!(FullTransferBegin::from_wire_bytes(&wire)?, request);
        assert!(super::super::TransferBegin::from_wire_bytes(&wire).is_err());
        let reference = DeviceRef {
            account_anchor: crate::encode_base64url([3; 32]),
            device_id: "a".into(),
            device_epoch: 1,
        };
        let spec = request.create_spec(reference, crate::encode_base64url([4; 32]), 1)?;
        assert_eq!(spec.purpose, "primary_transfer");
        assert_eq!(spec.data_selection, []);

        request.data_selection = DataSelectionV3::SelectedKeys(Vec::new());
        assert_eq!(request.validate(), Err(WireError::Field("UpdateRequired")));
        request.data_selection = DataSelectionV3::FullAccountDataV1(FullAccountData {});
        request.recipient_mode = "existing".into();
        assert!(request.validate().is_err());
        Ok(())
    }
}
