// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! OVP-01: four v3-only encrypted bootstrap controls, never accepted by the v2 decoder.
use super::super::{
    PROFILE, PairingWire, Result, WireError, budget,
    lease::{DataGrant, DataLease},
    require,
};
use super::StartFull;
use crate::custody::Envelope;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantOfferFull {
    pub grant: DataGrant,
    pub kind: String,
    pub profile: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSignedFull {
    pub destination_signature: String,
    pub kind: String,
    pub profile: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseFull {
    pub kind: String,
    pub lease: Envelope<DataLease>,
    pub profile: String,
}
fn signature(value: &str) -> Result<()> {
    let raw = crate::decode_base64url(value).map_err(|_| WireError::Field("signature"))?;
    require(raw.len() == 64 && crate::encode_base64url(raw) == value, "signature")
}
impl PairingWire for GrantOfferFull {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        require(self.kind == "grant_offer_full" && self.profile == PROFILE, "profile")?;
        self.grant.validate()?;
        budget(self, Self::LIMIT)
    }
}
impl PairingWire for GrantSignedFull {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        require(self.kind == "grant_signed_full" && self.profile == PROFILE, "profile")?;
        signature(&self.destination_signature)?;
        budget(self, Self::LIMIT)
    }
}
impl PairingWire for LeaseFull {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        require(self.kind == "lease_full" && self.profile == PROFILE, "profile")?;
        self.lease.body.validate()?;
        signature(&self.lease.signature)?;
        budget(self, Self::LIMIT)
    }
}
/// V3-only bootstrap union. Original-kind preflight never builds a Value holding the opening.
#[derive(Clone)]
pub enum FullSasControl {
    Start(StartFull),
    GrantOffer(GrantOfferFull),
    GrantSigned(GrantSignedFull),
    Lease(LeaseFull),
}
impl FullSasControl {
    /// # Errors
    /// Refuses another arm/profile, excess bytes or noncanonical original input.
    pub fn from_wire_bytes(input: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Kind {
            #[serde(rename = "start_full")]
            Start,
            #[serde(rename = "grant_offer_full")]
            GrantOffer,
            #[serde(rename = "grant_signed_full")]
            GrantSigned,
            #[serde(rename = "lease_full")]
            Lease,
        }
        #[derive(Deserialize)]
        struct Header {
            kind: Kind,
        }
        require(input.len() <= 8192, "control_size")?;
        let header: Header = crate::parse_i_json_secret(input).map_err(|_| WireError::Shape)?;
        match header.kind {
            Kind::Start => StartFull::from_wire_bytes(input).map(Self::Start),
            Kind::GrantOffer => GrantOfferFull::from_wire_bytes(input).map(Self::GrantOffer),
            Kind::GrantSigned => GrantSignedFull::from_wire_bytes(input).map(Self::GrantSigned),
            Kind::Lease => LeaseFull::from_wire_bytes(input).map(Self::Lease),
        }
    }
    /// # Errors
    /// Refuses malformed fields or complete output exceeding the bootstrap limit.
    pub fn encode_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Start(value) => value.encode_secret(),
            Self::GrantOffer(value) => value.to_wire_bytes().map(Zeroizing::new),
            Self::GrantSigned(value) => value.to_wire_bytes().map(Zeroizing::new),
            Self::Lease(value) => value.to_wire_bytes().map(Zeroizing::new),
        }
    }
}
