// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant public agent metadata. Native custody remains the sole identity authority.
use crate::{MAX_SAFE_JSON_INTEGER, custody, domain};
use serde::{Deserialize, Serialize};
use unicode_normalization::{UnicodeNormalization, is_nfc};

pub const MAX_AGENT_PROFILE_BYTES: usize = 4096;

/// Closed public sidecar body; contains neither persona plaintext nor execution grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfileV1 {
    pub schema: String,
    pub version: u32,
    pub agent_anchor: String,
    pub agent_custody_hash: String,
    pub custodian_anchor: String,
    pub custodian_primary: custody::DeviceRef,
    pub kind: String,
    pub profile_epoch: u64,
    pub responsibility: String,
    pub provider: String,
    pub model: String,
    pub persona_version: u64,
    pub persona_hash: String,
}

pub type AgentProfileEnvelope = custody::Envelope<AgentProfileV1>;

/// Stable refusal categories shared by the codec and authority verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentProfileError {
    #[error("agent profile byte budget exceeded")]
    TooLarge,
    #[error("agent profile wire schema is malformed")]
    Wire,
    #[error("agent profile wire bytes are not canonical")]
    Noncanonical,
    #[error("agent profile upgrade required")]
    AgentProfileUpgradeRequired,
    #[error("invalid agent profile field: {0}")]
    Field(&'static str),
    #[error("agent profile native authority unavailable")]
    NativeAuthority,
    #[error("agent profile agent anchor mismatch")]
    AgentAnchor,
    #[error("agent profile native head mismatch")]
    NativeHead,
    #[error("agent profile custodian mismatch")]
    Custodian,
    #[error("agent profile requires a headless AI native account")]
    Kind,
    #[error("agent profile requires the certified primary signer")]
    Signer,
    #[error("agent profile signature verification failed")]
    Signature,
}
use AgentProfileError as E;

fn binary(value: &str, count: usize, field: &'static str) -> Result<(), E> {
    if value.len() != (count * 8).div_ceil(6) {
        return Err(E::Field(field));
    }
    let raw = crate::decode_base64url(value).map_err(|_| E::Field(field))?;
    if raw.len() != count || crate::encode_base64url(&raw) != value {
        return Err(E::Field(field));
    }
    Ok(())
}

impl AgentProfileV1 {
    /// Normalize permitted local Unicode text before validating or signing.
    /// # Errors
    /// Rejects invalid schema, binary fields, bounds, text or custodian relationships.
    pub fn normalize_local(mut self) -> Result<Self, E> {
        self.responsibility = self.responsibility.nfc().collect();
        self.validate()?;
        Ok(self)
    }

    /// Validate received values without normalizing them.
    /// # Errors
    /// Returns the exact invalid field or unsupported-version category.
    pub fn validate(&self) -> Result<(), E> {
        if self.version != 1 {
            return Err(E::AgentProfileUpgradeRequired);
        }
        if self.schema != domain::AGENT_PROFILE {
            return Err(E::Field("schema"));
        }
        if self.kind != "headless_ai" {
            return Err(E::Field("kind"));
        }
        for (value, name) in [
            (&self.agent_anchor, "agent_anchor"),
            (&self.agent_custody_hash, "agent_custody_hash"),
            (&self.custodian_anchor, "custodian_anchor"),
            (&self.custodian_primary.account_anchor, "custodian_primary.account_anchor"),
            (&self.persona_hash, "persona_hash"),
        ] {
            binary(value, 32, name)?;
        }
        let id = &self.custodian_primary.device_id;
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(E::Field("custodian_primary.device_id"));
        }
        for (value, name) in [
            (self.profile_epoch, "profile_epoch"),
            (self.persona_version, "persona_version"),
            (self.custodian_primary.device_epoch, "custodian_primary.device_epoch"),
        ] {
            if value == 0 || value > MAX_SAFE_JSON_INTEGER {
                return Err(E::Field(name));
            }
        }
        if self.responsibility.len() > 256
            || !crate::text_safety::single_line_is_safe(&self.responsibility)
            || !is_nfc(&self.responsibility)
        {
            return Err(E::Field("responsibility"));
        }
        for (value, name) in [(&self.provider, "provider"), (&self.model, "model")] {
            if value.len() > 128 || !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                return Err(E::Field(name));
            }
        }
        if self.custodian_primary.account_anchor != self.custodian_anchor {
            return Err(E::Custodian);
        }
        Ok(())
    }
}

/// Decode original bounded bytes, enforcing closed fields and exact canonical identity.
/// # Errors
/// Refuses oversized input before parsing, malformed or noncanonical JSON and invalid fields.
pub fn decode_agent_profile(bytes: &[u8]) -> Result<AgentProfileEnvelope, E> {
    if bytes.len() > MAX_AGENT_PROFILE_BYTES {
        return Err(E::TooLarge);
    }
    let envelope: AgentProfileEnvelope =
        custody::decode(bytes, MAX_AGENT_PROFILE_BYTES).map_err(|_| E::Wire)?;
    envelope.body.validate()?;
    binary(&envelope.signature, 64, "signature")?;
    if encode_agent_profile(&envelope)? != bytes {
        return Err(E::Noncanonical);
    }
    Ok(envelope)
}

/// Encode a validated complete signed sidecar without changing received text.
/// # Errors
/// Rejects invalid fields, signatures or the envelope byte bound.
pub fn encode_agent_profile(envelope: &AgentProfileEnvelope) -> Result<Vec<u8>, E> {
    envelope.body.validate()?;
    binary(&envelope.signature, 64, "signature")?;
    let bytes = crate::canonical_json_bytes(envelope).map_err(|_| E::Wire)?;
    if bytes.len() > MAX_AGENT_PROFILE_BYTES {
        return Err(E::TooLarge);
    }
    Ok(bytes)
}

/// Digest the entire validated envelope, including its signature.
/// # Errors
/// Rejects invalid or oversized sidecars.
pub fn agent_profile_digest(envelope: &AgentProfileEnvelope) -> Result<String, E> {
    encode_agent_profile(envelope)?;
    custody::framed_hash(domain::AGENT_PROFILE_HASH, envelope).map_err(|_| E::Wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_profile_codec_preserves_received_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let anchor = crate::encode_base64url([0; 32]);
        let mut profile = AgentProfileEnvelope {
            body: AgentProfileV1 {
                schema: domain::AGENT_PROFILE.into(),
                version: 1,
                agent_anchor: anchor.clone(),
                agent_custody_hash: anchor.clone(),
                custodian_anchor: anchor.clone(),
                custodian_primary: custody::DeviceRef {
                    account_anchor: anchor.clone(),
                    device_id: "primary".into(),
                    device_epoch: 1,
                },
                kind: "headless_ai".into(),
                profile_epoch: 1,
                responsibility: String::new(),
                provider: String::new(),
                model: String::new(),
                persona_version: 1,
                persona_hash: anchor,
            },
            signature: crate::encode_base64url([0; 64]),
        };
        // Empty public labels are permitted; byte ceilings do not impose extra content policy.
        let bytes = encode_agent_profile(&profile)?;
        assert_eq!(decode_agent_profile(&bytes)?, profile);
        profile.body.responsibility = "e\u{301}".into();
        assert_eq!(encode_agent_profile(&profile), Err(E::Field("responsibility")));
        profile.body = profile.body.normalize_local()?;
        assert_eq!(profile.body.responsibility, "é");
        let bytes = encode_agent_profile(&profile)?;
        assert_eq!(encode_agent_profile(&decode_agent_profile(&bytes)?)?, bytes);
        let mut alternate = bytes;
        alternate.push(b'\n');
        assert_eq!(decode_agent_profile(&alternate), Err(E::Noncanonical));
        Ok(())
    }
}
