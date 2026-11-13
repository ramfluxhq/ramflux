// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An attended source approval names one immutable candidate; it is never SAS Confirm.
use super::{Deserialize, PairingWire, Result, Serialize, b32, budget, header, local_base};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferAffirm {
    pub schema: String,
    pub version: u32,
    pub operation_id: String,
    pub generation: u64,
    pub transcript_hash: String,
    pub new_record_hash: String,
    pub approved: bool,
}
impl PairingWire for TransferAffirm {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "TransferAffirm")?;
        local_base(&self.operation_id, self.generation)?;
        b32(&self.transcript_hash, "transcript_hash")?;
        b32(&self.new_record_hash, "new_record_hash")?;
        budget(self, Self::LIMIT)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::pairing::local_dto::Confirm;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    const EXACT:&[u8]=br#"{"approved":true,"generation":1,"new_record_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","operation_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","schema":"ramflux.pairing.TransferAffirm.v2","transcript_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","version":2}"#;
    #[test]
    fn pairing_transfer_affirm_is_closed_and_cannot_be_confused_with_sas_confirm() -> TestResult {
        let request = TransferAffirm::from_wire_bytes(EXACT)?;
        assert_eq!(
            request.to_wire_bytes()?,
            EXACT,
            "test: exact candidate affirmation bytes changed"
        );
        assert!(
            Confirm::from_wire_bytes(EXACT).is_err(),
            "test: source affirmation aliased initial SAS confirmation"
        );
        let mut extra: serde_json::Value = serde_json::from_slice(EXACT)?;
        extra["match"] = true.into();
        let bytes = crate::canonical_json_bytes(&extra)?;
        assert!(
            TransferAffirm::from_wire_bytes(&bytes).is_err(),
            "test: mixed SAS/source approval fields accepted"
        );
        let mut invalid = request.clone();
        invalid.new_record_hash.clear();
        assert!(invalid.validate().is_err(), "test: affirmation did not bind an exact candidate");
        invalid = request;
        invalid.generation = 0;
        assert!(
            invalid.validate().is_err(),
            "test: affirmation accepted an unowned frontend generation"
        );
        Ok(())
    }
}
