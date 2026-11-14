// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A3 discovery. The lease is confidential; authority requires both SAS-pinned branch proofs.
use super::super::{
    PairingWire, Result, WireError, b32, budget,
    lease::{DataLease, ResumeProof},
    require,
};
use crate::custody::Envelope;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloFull {
    pub epoch: String,
    pub hpke_key: String,
    pub kind: String,
    pub lease: Envelope<DataLease>,
    pub profile: String,
    pub role: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollFullDiscovery {
    pub kind: String,
    pub lease: Envelope<DataLease>,
    pub profile: String,
    pub role: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryKeys {
    #[serde(deserialize_with = "super::super::super::required_nullable")]
    pub destination: Option<String>,
    pub source: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullDiscovery {
    pub epoch: String,
    pub expires_in_ms: super::super::U64,
    pub hpke_keys: DiscoveryKeys,
    pub kind: String,
    pub lease_id: String,
    pub profile: String,
    #[serde(deserialize_with = "super::super::super::required_nullable")]
    pub template: Option<ResumeProof>,
}
fn lease(value: &Envelope<DataLease>) -> Result<()> {
    value.body.validate()?;
    let signature =
        crate::decode_base64url(&value.signature).map_err(|_| WireError::Field("signature"))?;
    require(
        signature.len() == 64 && crate::encode_base64url(signature) == value.signature,
        "signature",
    )
}
impl PairingWire for HelloFull {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        require(
            self.kind == "hello_full"
                && self.profile == super::super::PROFILE
                && matches!(self.role.as_str(), "initiator" | "responder"),
            "role",
        )?;
        b32(&self.epoch, "epoch")?;
        b32(&self.hpke_key, "hpke_key")?;
        lease(&self.lease)?;
        budget(self, Self::LIMIT)
    }
}
impl PairingWire for PollFullDiscovery {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        require(
            self.kind == "poll_full_discovery"
                && self.profile == super::super::PROFILE
                && matches!(self.role.as_str(), "initiator" | "responder"),
            "role",
        )?;
        lease(&self.lease)?;
        budget(self, Self::LIMIT)
    }
}
impl PairingWire for FullDiscovery {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        require(self.kind == "full_discovery" && self.profile == super::super::PROFILE, "profile")?;
        require((1..=10_000).contains(&self.expires_in_ms.0), "discovery_deadline")?;
        b32(&self.epoch, "epoch")?;
        b32(&self.lease_id, "lease_id")?;
        b32(&self.hpke_keys.source, "hpke_key")?;
        match (&self.hpke_keys.destination, &self.template) {
            (Some(destination), Some(template)) => {
                b32(destination, "hpke_key")?;
                template.validate()?;
                require(
                    template.role == "initiator"
                        && template.epoch == self.epoch
                        && template.lease_id == self.lease_id
                        && template.hpke_keys.source == self.hpke_keys.source
                        && template.hpke_keys.destination == *destination,
                    "discovery_context",
                )?;
            }
            (None, None) => {}
            _ => return Err(WireError::Field("discovery_context")),
        }
        budget(self, Self::LIMIT)
    }
}
