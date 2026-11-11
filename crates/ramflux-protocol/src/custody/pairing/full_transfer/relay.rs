// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-data relay framing. Ciphertext has one outer base64 carrier; bootstrap stays secret.
use super::{PairingWire, Result, U64, WireError, b32, budget, require};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
mod bootstrap;
pub use bootstrap::{FullSasControl, GrantOfferFull, GrantSignedFull, LeaseFull};
mod data;
pub use data::PolledFull;
mod discovery;
pub use discovery::{DiscoveryKeys, FullDiscovery, HelloFull, PollFullDiscovery};
mod control;
pub use control::{
    CloseFull, ClosedFull, HpkeConfirmFull, PollFull, PollFullControl, PolledFullControl,
    ProveFull, ResumePendingFull, ResumeTokenFull, SendFullControl, SentFull,
};
mod send;
pub use send::{BorrowedPacket, BorrowedSendFull, SendFull};

/// Private control sent only after both SAS confirmations on the v3 channel.
/// Field declaration order is JCS order, allowing direct secret serialization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartFull {
    pub commitment_opening: super::SecretBase64,
    pub kind: String,
    pub manifest_hash: String,
    pub opaque_commitment: String,
    pub profile: String,
    pub snapshot_id: String,
    pub transfer_id: String,
}
impl StartFull {
    /// Bind the private manifest opening before Auth-HPKE setup.
    /// # Errors
    /// Refuses a changed opening or malformed complete bootstrap.
    pub fn encode_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(Self::LIMIT));
        serde_json::to_writer(&mut *bytes, self).map_err(|_| WireError::Json)?;
        Ok(bytes)
    }
}
impl PairingWire for StartFull {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        require(self.kind == "start_full" && self.profile == super::PROFILE, "profile")?;
        for value in
            [&self.manifest_hash, &self.opaque_commitment, &self.snapshot_id, &self.transfer_id]
        {
            b32(value, "start_full")?;
        }
        let opening = self.commitment_opening.decode(32)?;
        let opening: &[u8; 32] =
            opening.as_slice().try_into().map_err(|_| WireError::Field("opening"))?;
        let hash = Zeroizing::new(
            crate::decode_base64url(&self.manifest_hash)
                .map_err(|_| WireError::Field("manifest_hash"))?,
        );
        let hash: &[u8; 32] =
            hash.as_slice().try_into().map_err(|_| WireError::Field("manifest_hash"))?;
        require(
            crate::encode_base64url(super::lease::opaque_commitment(hash, opening))
                == self.opaque_commitment,
            "lease_context",
        )?;
        budget(self, Self::LIMIT)
    }
    fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        let mut encoded = self.encode_secret()?;
        Ok(std::mem::take(&mut *encoded))
    }
    fn from_wire_bytes(input: &[u8]) -> Result<Self> {
        require(input.len() <= Self::LIMIT, "control_size")?;
        let value: Self = crate::parse_i_json_secret(input).map_err(|_| WireError::Shape)?;
        if value.encode_secret()?.as_slice() != input {
            return Err(WireError::NonCanonical);
        }
        Ok(value)
    }
}

/// Exactly one encrypted packet. This is never a bearer authorization by itself.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedPacket {
    pub ciphertext: String,
    pub counter: U64,
    pub epoch: String,
    pub lease_id: String,
    pub role: String,
}
impl PairingWire for EncryptedPacket {
    // Reserve the approved relay metadata budget within the complete 512-KiB HTTP body.
    const LIMIT: usize = super::PACKET_BYTES - 4096;
    fn validate(&self) -> Result<()> {
        b32(&self.lease_id, "lease_id")?;
        b32(&self.epoch, "epoch")?;
        require(matches!(self.role.as_str(), "initiator" | "responder"), "role")?;
        require(self.counter.0 < super::PACKETS_PER_KEY, "ResumeRequired")?;
        require(self.ciphertext.len() <= Self::LIMIT, "ciphertext")?;
        let bytes = crate::decode_base64url(&self.ciphertext)
            .map_err(|_| WireError::Field("ciphertext"))?;
        require(
            (16..=super::PACKET_CIPHERTEXT_BYTES).contains(&bytes.len())
                && crate::encode_base64url(&bytes) == self.ciphertext,
            "ciphertext",
        )?;
        budget(self, Self::LIMIT)
    }
    fn received_limit(&self) -> usize {
        Self::LIMIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn b(byte: u8) -> String {
        crate::encode_base64url([byte; 32])
    }
    #[test]
    fn full_bootstrap_private_opening_is_exact_and_closed() -> TestResult {
        let mut start = StartFull {
            commitment_opening: super::super::SecretBase64::from_bytes(&[2; 32]),
            kind: "start_full".into(),
            manifest_hash: b(1),
            opaque_commitment: crate::encode_base64url(super::super::lease::opaque_commitment(
                &[1; 32], &[2; 32],
            )),
            profile: super::super::PROFILE.into(),
            snapshot_id: b(3),
            transfer_id: b(4),
        };
        let bytes = start.encode_secret()?;
        assert_eq!(
            StartFull::from_wire_bytes(&bytes)?.encode_secret()?.as_slice(),
            bytes.as_slice()
        );
        let mut unknown = bytes.to_vec();
        unknown.pop();
        unknown.extend_from_slice(b",\"unknown\":0}");
        assert!(StartFull::from_wire_bytes(&unknown).is_err());
        start.commitment_opening = super::super::SecretBase64::from_bytes(&[5; 32]);
        assert!(start.encode_secret().is_err());
        Ok(())
    }
    #[test]
    fn full_packet_double_base64_fits_and_key_limit_refuses() -> TestResult {
        let mut packet = EncryptedPacket {
            lease_id: b(1),
            epoch: b(2),
            role: "initiator".into(),
            counter: U64(65_535),
            ciphertext: crate::encode_base64url(vec![0; 349_528 + 1024 + 16]),
        };
        let bytes = packet.to_wire_bytes()?;
        assert!(bytes.len() + 4096 < super::super::PACKET_BYTES);
        assert_eq!(EncryptedPacket::from_wire_bytes(&bytes)?.counter, U64(65_535));
        packet.counter = U64(65_536);
        assert!(matches!(packet.validate(), Err(WireError::Field("ResumeRequired"))));
        packet.counter = U64(0);
        packet.ciphertext.push('=');
        assert!(packet.validate().is_err());
        Ok(())
    }
}
