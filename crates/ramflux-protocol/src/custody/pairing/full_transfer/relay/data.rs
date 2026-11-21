// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! One full packet per poll. Nodes write a shared packet slice rather than cloning this DTO.
use super::{EncryptedPacket, PairingWire, Result, budget, require};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolledFull {
    pub kind: String,
    #[serde(deserialize_with = "super::super::super::required_nullable")]
    pub packet: Option<EncryptedPacket>,
    pub profile: String,
}
impl PairingWire for PolledFull {
    const LIMIT: usize = super::super::PACKET_BYTES;
    fn validate(&self) -> Result<()> {
        require(self.kind == "polled_full" && self.profile == super::super::PROFILE, "profile")?;
        if let Some(packet) = &self.packet {
            packet.validate()?;
        }
        budget(self, Self::LIMIT)
    }
}
