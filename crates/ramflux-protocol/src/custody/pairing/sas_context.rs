// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Sealed shared SAS inputs: one crypto implementation, two closed committed profiles.
use super::{
    PairingWire, Result, RoleContext, Transcript, WireError,
    context_v3::{self, RoleContextV3, TranscriptV3},
};

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::RoleContext {}
    impl Sealed for super::RoleContextV3 {}
}
pub trait SasContext: PairingWire + sealed::Sealed {
    const VERSION: u32;
    fn role(&self) -> &str;
    fn purpose(&self) -> &str;
    fn sas_key(&self) -> &str;
    /// # Errors
    /// Returns field/shape failures without normalizing the committed context.
    fn commitment_preimage(&self, salt: &[u8; 32]) -> Result<Vec<u8>>;
    /// # Errors
    /// Refuses different common bindings, role reflection and invalid contexts.
    fn paired_preimage(&self, peer: &Self, initiator: bool) -> Result<Vec<u8>>;
}
impl SasContext for RoleContext {
    const VERSION: u32 = 2;
    fn role(&self) -> &str {
        &self.role
    }
    fn purpose(&self) -> &str {
        &self.common.purpose
    }
    fn sas_key(&self) -> &str {
        &self.sas_key
    }
    fn commitment_preimage(&self, salt: &[u8; 32]) -> Result<Vec<u8>> {
        super::context_commitment_preimage(self, salt)
    }
    fn paired_preimage(&self, peer: &Self, initiator: bool) -> Result<Vec<u8>> {
        let (initiator, responder) =
            if initiator { (self.clone(), peer.clone()) } else { (peer.clone(), self.clone()) };
        super::transcript_preimage(&Transcript {
            schema: "ramflux.pairing.Transcript.v2".into(),
            version: 2,
            initiator,
            responder,
        })
    }
}
impl SasContext for RoleContextV3 {
    const VERSION: u32 = 3;
    fn role(&self) -> &str {
        &self.role
    }
    fn purpose(&self) -> &str {
        &self.common.purpose
    }
    fn sas_key(&self) -> &str {
        &self.sas_key
    }
    fn commitment_preimage(&self, salt: &[u8; 32]) -> Result<Vec<u8>> {
        context_v3::context_commitment_preimage(self, salt)
    }
    fn paired_preimage(&self, peer: &Self, initiator: bool) -> Result<Vec<u8>> {
        let (initiator, responder) =
            if initiator { (self.clone(), peer.clone()) } else { (peer.clone(), self.clone()) };
        context_v3::transcript_preimage(&TranscriptV3 {
            schema: "ramflux.pairing.Transcript.v3".into(),
            version: 3,
            initiator,
            responder,
        })
    }
}
/// Peek only the version, followed by the selected closed decoder. No permissive fallback.
/// # Errors
/// Version mismatch is `UpdateRequired`; malformed/non-I-JSON or oversize bytes are refused.
pub fn require_context_version(bytes: &[u8], expected: u32) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Version {
        version: u32,
    }
    if bytes.len() > super::MAX_ROLE_BYTES {
        return Err(WireError::Size);
    }
    let version: Version = crate::parse_i_json_secret(bytes).map_err(|_| WireError::Json)?;
    super::require(version.version == expected, "UpdateRequired")
}
