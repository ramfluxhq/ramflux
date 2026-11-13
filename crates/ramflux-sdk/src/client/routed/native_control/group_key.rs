// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `CONTROL_GROUP_KEY` (operation 5): a member device hands its sender key to this device.
//! The typed distribution converts to the native distribution and enters the native importer.
use super::{authority, content};
use crate::client::identity_authority::{HeadUse, NativeOperation};
use crate::client::routed::{Kind, Opened};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError, SdkGroupSenderKeyDistribution};
use prost::Message as _;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::message as g;
use zeroize::{Zeroize, Zeroizing};

pub(super) const WRAPPER_SCHEMA: &str = "ramflux.sdk.group_sender_key.distribution_envelope.v1";
const MAX_DISTRIBUTION_BYTES: usize = 4096;

/// Closed grammar of the typed distribution, bounded before any native parsing.
fn distribution(body: &g::GroupKeyControl) -> Result<&g::GroupKeyDistribution, SdkError> {
    if body.schema != WRAPPER_SCHEMA || body.version != 1 {
        return Err(content("group key wrapper schema or version unknown"));
    }
    let value = body.distribution.as_ref().ok_or_else(|| content("group key distribution"))?;
    if value.encoded_len() > MAX_DISTRIBUTION_BYTES
        || value.sender_key_seed.len() != 32
        || value.group_id.is_empty()
        || value.sender_id.is_empty()
        || value.group_key_epoch == 0
        || !matches!(
            (value.schema.as_str(), value.version),
            ("ramflux.sdk.group_sender_key.distribution.v3", 3)
                | ("ramflux.sdk.group_sender_key.distribution.v4", 4)
        )
    {
        return Err(content("group key distribution grammar invalid"));
    }
    Ok(value)
}

/// Exact native canonical bytes the native importer and its signature check consume.
fn native_bytes(value: &g::GroupKeyDistribution) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let mut native = SdkGroupSenderKeyDistribution {
        schema: value.schema.clone(),
        version: value.version,
        group_id: value.group_id.clone(),
        sender_id: value.sender_id.clone(),
        group_key_epoch: value.group_key_epoch,
        group_state_hash: value.group_state_hash.clone(),
        sender_key_seed: value
            .sender_key_seed
            .as_slice()
            .try_into()
            .map_err(|_| content("group key seed length"))?,
        sender_key_signature: value.sender_key_signature.clone(),
        sender_device_signing_public_key: value.sender_device_signing_public_key.clone(),
    };
    let bytes = ramflux_protocol::canonical_json_bytes(&native);
    native.sender_key_seed.zeroize();
    Ok(Zeroizing::new(bytes?))
}

pub(super) fn generated_distribution(
    native: &SdkGroupSenderKeyDistribution,
) -> g::GroupKeyDistribution {
    g::GroupKeyDistribution {
        schema: native.schema.clone(),
        version: native.version,
        group_id: native.group_id.clone(),
        sender_id: native.sender_id.clone(),
        group_key_epoch: native.group_key_epoch,
        group_state_hash: native.group_state_hash.clone(),
        sender_key_seed: native.sender_key_seed.to_vec(),
        sender_key_signature: native.sender_key_signature.clone(),
        sender_device_signing_public_key: native.sender_device_signing_public_key.clone(),
    }
}

impl RamfluxClient {
    /// Sender rule: a member device of the named group whose distribution names itself.
    /// Runs before retention and again inside the executor.
    pub(in crate::client::routed) fn authorize_generated_group_key(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &g::GroupKeyControl,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        let value = distribution(body)?;
        // Join bootstrap travels in the signed Snapshot arm of GROUP_STATE. This executor has no
        // verified gateway context for a membership event, so it never installs one.
        if body.membership_event.is_some() || body.actor_manifest_url.is_some() {
            return Err(content("group key membership bootstrap is not carried by GROUP_KEY"));
        }
        if opened.routing.kind != Kind::GroupControl
            || opened.routing.group_id.as_deref() != Some(value.group_id.as_str())
        {
            return Err(authority("group key route differs from its group"));
        }
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if source != opened.remote_device || value.sender_id != source.device_id() {
            return Err(authority("group key sender is not the pair-session peer"));
        }
        self.require_native_operation(&source, NativeOperation::Group)?;
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Group)?;
        if !self.group_state(&value.group_id)?.members.contains(source.device_id()) {
            return Err(authority("group key sender is not a current member device"));
        }
        self.require_group_payload_sender(&value.group_id, &value.sender_id, entry)?;
        Ok(source)
    }

    /// Native importer: pinned member key, distribution signature, epoch and head checks, then
    /// the sender-key state write. Joins the exact-replay ledger transaction.
    pub(in crate::client::routed) fn apply_generated_group_key(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        identity: &g::EventIdentity,
        body: &g::GroupKeyControl,
        exact_inner: &[u8],
    ) -> Result<bool, SdkError> {
        self.authorize_generated_group_key(opened, entry, body)?;
        if identity.group_id.as_deref() != opened.routing.group_id.as_deref() {
            return Err(authority("group key identity differs from its group route"));
        }
        let bytes = native_bytes(distribution(body)?)?;
        self.apply_generated_peer_control_once(entry, identity, exact_inner, 5, |source| {
            self.import_group_key_for_identity(&bytes, source, false).map(|_| ())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> g::GroupKeyControl {
        g::GroupKeyControl {
            schema: WRAPPER_SCHEMA.into(),
            version: 1,
            membership_event: None,
            actor_manifest_url: None,
            distribution: Some(g::GroupKeyDistribution {
                schema: "ramflux.sdk.group_sender_key.distribution.v4".into(),
                version: 4,
                group_id: "group".into(),
                sender_id: "device".into(),
                group_key_epoch: 2,
                group_state_hash: Some("head".into()),
                sender_key_seed: vec![7; 32],
                sender_key_signature: Some("sig".into()),
                sender_device_signing_public_key: Some("key".into()),
            }),
        }
    }

    #[test]
    fn group_key_distribution_grammar_is_closed() -> Result<(), SdkError> {
        let good = sample();
        let native: SdkGroupSenderKeyDistribution =
            ramflux_protocol::parse_i_json(&native_bytes(distribution(&good)?)?)?;
        assert_eq!(generated_distribution(&native), good.distribution.clone().unwrap_or_default());
        for seed in [0usize, 31, 33, 64] {
            let mut bad = sample();
            if let Some(value) = bad.distribution.as_mut() {
                value.sender_key_seed = vec![7; seed];
            }
            assert!(distribution(&bad).is_err(), "seed length {seed} admitted");
        }
        let mut legacy = sample();
        if let Some(value) = legacy.distribution.as_mut() {
            value.schema = "ramflux.sdk.group_sender_key.distribution.v1".into();
            value.version = 1;
        }
        assert!(distribution(&legacy).is_err(), "legacy distribution schema admitted");
        let mut wrapper = sample();
        wrapper.version = 2;
        assert!(distribution(&wrapper).is_err(), "unknown wrapper version admitted");
        Ok(())
    }
}
