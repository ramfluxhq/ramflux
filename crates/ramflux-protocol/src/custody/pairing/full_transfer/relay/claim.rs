// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed pre-token claim/proof unions. Kind preflight never builds a secret-bearing Value.
use super::super::{PairingWire, Result, WireError, require};
use super::{HelloFull, PollFullDiscovery, ProveFull, ResumePendingFull, ResumeTokenFull};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Clone)]
pub enum FullClaim {
    Hello(Box<HelloFull>),
    Discovery(Box<PollFullDiscovery>),
    Proof(Box<ProveFull>),
}
#[derive(Clone)]
pub enum FullProofReply {
    Pending(ResumePendingFull),
    Ready(Box<ResumeTokenFull>),
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClaimKind {
    HelloFull,
    PollFullDiscovery,
    ProveFull,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProofKind {
    ResumePendingFull,
    ResumeTokenFull,
}
fn kind<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T> {
    #[derive(Deserialize)]
    struct Header<T> {
        kind: T,
    }
    require(input.len() <= 8192, "control_size")?;
    let header: Header<T> = crate::parse_i_json_secret(input).map_err(|_| WireError::Shape)?;
    Ok(header.kind)
}
impl FullClaim {
    /// # Errors
    /// Refuses unknown/noncanonical/duplicate/oversized original claim controls.
    pub fn from_wire_bytes(input: &[u8]) -> Result<Self> {
        match kind::<ClaimKind>(input)? {
            ClaimKind::HelloFull => {
                HelloFull::from_wire_bytes(input).map(Box::new).map(Self::Hello)
            }
            ClaimKind::PollFullDiscovery => {
                PollFullDiscovery::from_wire_bytes(input).map(Box::new).map(Self::Discovery)
            }
            ClaimKind::ProveFull => {
                ProveFull::from_wire_bytes(input).map(Box::new).map(Self::Proof)
            }
        }
    }
    /// # Errors
    /// Refuses malformed fields or output beyond the 8-KiB complete control bound.
    pub fn encode_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Hello(value) => value.to_wire_bytes().map(Zeroizing::new),
            Self::Discovery(value) => value.to_wire_bytes().map(Zeroizing::new),
            Self::Proof(value) => value.encode_secret(),
        }
    }
}
impl FullProofReply {
    /// # Errors
    /// Refuses another arm/profile, malformed peer proof or noncanonical original bytes.
    pub fn from_wire_bytes(input: &[u8]) -> Result<Self> {
        match kind::<ProofKind>(input)? {
            ProofKind::ResumePendingFull => {
                ResumePendingFull::from_wire_bytes(input).map(Self::Pending)
            }
            ProofKind::ResumeTokenFull => {
                ResumeTokenFull::from_wire_bytes(input).map(Box::new).map(Self::Ready)
            }
        }
    }
    /// # Errors
    /// Refuses invalid fields or complete output beyond 8 KiB.
    pub fn encode_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Pending(value) => value.encode_secret(),
            Self::Ready(value) => value.encode_secret(),
        }
    }
}
