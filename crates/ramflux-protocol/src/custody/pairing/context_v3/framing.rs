// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit v3 objects inside the existing bounded offer/reveal chunk carriers.
use super::super::{PairingWire, Result, b32, budget, require};
use super::{CommonV3, RoleContextV3};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextOfferV3 {
    pub schema: String,
    pub version: u32,
    pub common: CommonV3,
}
impl PairingWire for ContextOfferV3 {
    const LIMIT: usize = 16_384;
    fn normalize(&mut self) {
        self.common.normalize();
    }
    fn validate(&self) -> Result<()> {
        require(self.schema == "ramflux.pairing.ContextOffer.v3" && self.version == 3, "schema")?;
        self.common.validate()?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevealV3 {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub role: String,
    pub salt: String,
    pub context: RoleContextV3,
}
impl PairingWire for RevealV3 {
    const LIMIT: usize = 24_576;
    fn normalize(&mut self) {
        self.context.normalize();
    }
    fn validate(&self) -> Result<()> {
        require(self.schema == "ramflux.pairing.Reveal.v3" && self.version == 3, "schema")?;
        b32(&self.invitation_id, "invitation_id")?;
        b32(&self.salt, "salt")?;
        self.context.validate()?;
        require(self.role == self.context.role, "reveal_role")?;
        require(self.invitation_id == self.context.common.invitation_id, "reveal_invitation")?;
        budget(self, Self::LIMIT)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    type ResultOf = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn pairing_full_v3_offer_reveal_are_closed_and_v2_decoders_refuse() -> ResultOf {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/pairing_v3/vectors.json"))?;
        let transcript = super::super::TranscriptV3::from_wire_bytes(
            &crate::canonical_json_bytes(&vectors["transcript"])?,
        )?;
        let context = transcript.initiator;
        let offer = ContextOfferV3 {
            schema: "ramflux.pairing.ContextOffer.v3".into(),
            version: 3,
            common: context.common.clone(),
        };
        let offer_bytes = offer.to_wire_bytes()?;
        assert_eq!(ContextOfferV3::from_wire_bytes(&offer_bytes)?, offer);
        assert!(super::super::super::ContextOffer::from_wire_bytes(&offer_bytes).is_err());
        let reveal = RevealV3 {
            schema: "ramflux.pairing.Reveal.v3".into(),
            version: 3,
            invitation_id: context.common.invitation_id.clone(),
            role: context.role.clone(),
            salt: crate::encode_base64url([13; 32]),
            context,
        };
        let reveal_bytes = reveal.to_wire_bytes()?;
        assert_eq!(RevealV3::from_wire_bytes(&reveal_bytes)?, reveal);
        assert!(super::super::super::Reveal::from_wire_bytes(&reveal_bytes).is_err());
        for bytes in [&offer_bytes, &reveal_bytes] {
            let mut extended: serde_json::Value = crate::parse_i_json(bytes)?;
            extended
                .as_object_mut()
                .ok_or("object")?
                .insert("uncommitted_profile".into(), true.into());
            let bytes = crate::canonical_json_bytes(&extended)?;
            assert!(ContextOfferV3::from_wire_bytes(&bytes).is_err());
            assert!(RevealV3::from_wire_bytes(&bytes).is_err());
        }
        let mut altered = reveal;
        altered.role = "responder".into();
        assert!(altered.to_wire_bytes().is_err());
        Ok(())
    }
}
