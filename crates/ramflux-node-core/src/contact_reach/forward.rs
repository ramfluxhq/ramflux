// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The closed forward carrier signs the complete sealed Submission, including nullable work.
use super::{Result, refuse};
use crate::{ForwardedMigrationEvidence, MeshPeerIdentity};
use ramflux_protocol::{
    DeliveryClass, SignatureAlg,
    contact_reach::{self as wire, Reason, Submission},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachDeliveryClass {
    Message,
    CallWake,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReachCapability {
    #[serde(rename = "contact_reach.v1")]
    V1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachForward {
    pub signing_key_id: String,
    pub signature_alg: SignatureAlg,
    pub signature: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub delivery_class: ReachDeliveryClass,
    pub required_capability: ReachCapability,
    pub submission: Submission,
    pub migration_evidence: Option<ForwardedMigrationEvidence>,
}
impl ReachForward {
    /// Decode the original bytes before trusting a discriminant or nullable field.
    /// # Errors
    /// Refuses duplicate/unknown/missing fields, old envelope/admin carriers and size/depth overflow.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(wire::decode(bytes, wire::MAX_FRAME_BYTES)?)
    }
    fn shape(&self) -> Result<()> {
        self.submission.route.body.validate()?;
        if ramflux_protocol::canonical_json_bytes(self)?.len() > wire::MAX_FRAME_BYTES
            || self.signing_key_id != format!("{}#federation", self.source_node_id)
            || self.source_node_id == self.target_node_id
            || !matches!(
                (self.delivery_class, &self.submission.envelope.delivery_class),
                (ReachDeliveryClass::Message, DeliveryClass::Message)
                    | (ReachDeliveryClass::CallWake, DeliveryClass::CallWake)
            )
        {
            return Err(refuse(Reason::ReachRouteInvalid));
        }
        Ok(())
    }
    /// Sign once with the configured source node signer, after sealing every recipient envelope.
    /// # Errors
    /// Refuses a mismatched configured source node, malformed metadata or an invalid delivery class.
    pub fn sign(&mut self, source_node: &str, seed: [u8; 32]) -> Result<()> {
        if self.source_node_id != source_node {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        self.signing_key_id = format!("{source_node}#federation");
        self.signature_alg = SignatureAlg::Ed25519;
        self.signature.clear();
        self.shape()?;
        self.signature = ramflux_crypto::sign_protocol_object_with_seed(self, seed)?;
        Ok(())
    }
    /// Authenticate source transport/node proof before recipient admission or trust writes.
    /// The caller rechecks current local policy and target ownership under the home writer.
    /// # Errors
    /// Refuses service/node/key substitution, stale source proof, changed nested bytes and TTL.
    pub fn verify(
        &self,
        peer: &MeshPeerIdentity,
        source: &ramflux_crypto::contact_reach::VerifiedPeer,
        target_node: &str,
        now: u64,
    ) -> Result<()> {
        self.shape()?;
        let parsed = crate::parse_mesh_spiffe_uri(&peer.spiffe_uri)?;
        if peer.node_id != self.source_node_id
            || parsed.node_id != peer.node_id
            || parsed.service_id != "ramflux-federation"
            || peer.service_id != parsed.service_id
            || self.source_node_id != source.node()
            || self.target_node_id != target_node
            || source.root() != self.submission.route.body.source.account_anchor
            || source.expires_at() <= now
        {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(self)?,
            &self.signature,
            source.node_key(),
        )?;
        ramflux_crypto::contact_reach::verify_current_source_submission(
            &self.submission,
            source.authority(),
            now,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
