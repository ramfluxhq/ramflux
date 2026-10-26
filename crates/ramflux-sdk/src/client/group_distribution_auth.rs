// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sender-authorized shared-group rekeys bind a fresh chain to its verified state head.
use crate::prelude::*;

fn body(
    distribution: &SdkGroupSenderKeyDistribution,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
) -> serde_json::Value {
    serde_json::json!({
        "domain":"ramflux.group.sender_key.distribution.v4",
        "source":source.storage_key(),
        "schema":distribution.schema,
        "version":distribution.version,
        "group_id":distribution.group_id,
        "sender_id":distribution.sender_id,
        "group_key_epoch":distribution.group_key_epoch,
        "group_state_hash":distribution.group_state_hash,
        "signing_public_key":distribution.sender_device_signing_public_key,
        "seed_hash":ramflux_protocol::hash_base64url("ramflux.group.sender.seed-id.v4",&distribution.sender_key_seed),
    })
}
impl RamfluxClient {
    pub(crate) fn sign_group_distribution(
        &self,
        distribution: &mut SdkGroupSenderKeyDistribution,
    ) -> Result<(), SdkError> {
        let source = self.owned_device_identity()?;
        if distribution.version != 4
            || distribution.sender_id != source.device_id()
            || distribution.group_state_hash.is_none()
        {
            return Err(SdkError::InboundRejected("invalid shared rekey signing scope".into()));
        }
        distribution.sender_key_signature = Some(ramflux_crypto::sign_with_device_branch(
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &body(distribution, &source),
        )?);
        Ok(())
    }
    pub(super) fn verify_group_distribution_auth(
        distribution: &SdkGroupSenderKeyDistribution,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        if distribution.version != 4 {
            if distribution.sender_key_signature.is_some() {
                return Err(SdkError::InboundRejected("unexpected legacy rekey signature".into()));
            }
            return Ok(());
        }
        let public_key = distribution
            .sender_device_signing_public_key
            .as_deref()
            .ok_or_else(|| SdkError::InboundRejected("shared rekey signing key missing".into()))?;
        let signature = distribution
            .sender_key_signature
            .as_deref()
            .ok_or_else(|| SdkError::InboundRejected("shared rekey signature missing".into()))?;
        ramflux_crypto::verify_device_branch_signature(
            public_key,
            &body(distribution, source),
            signature,
        )?;
        Ok(())
    }
}
