// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client refusal for a node whose discovery record does not advertise device pairing.
use crate::SdkError;
use crate::node::NodeProfile;

/// Capability a pairing-enabled node advertises in its client discovery record.
const DEVICE_PAIRING_CAPABILITY: &str = "device_pairing_v2";

/// Refuse to start a pairing ceremony with a node that does not advertise `device_pairing_v2`.
/// # Errors
/// `CapabilityDenied`, naming the missing capability, when the selected node profile lacks it.
pub(super) fn require_device_pairing(profile: &NodeProfile) -> Result<(), SdkError> {
    if profile.client_capabilities.iter().any(|capability| capability == DEVICE_PAIRING_CAPABILITY)
    {
        return Ok(());
    }
    Err(SdkError::CapabilityDenied(format!(
        "{DEVICE_PAIRING_CAPABILITY} is not advertised by the selected node"
    )))
}

/// A new ceremony (begin, join, transfer begin) needs a node that advertises pairing; a staged
/// resume of an existing ceremony does not.
/// # Errors
/// `CapabilityDenied` for a new ceremony against a node without the capability.
pub(super) fn require_for_new_ceremony(
    profile: &NodeProfile,
    new_ceremony: bool,
) -> Result<(), SdkError> {
    if new_ceremony { require_device_pairing(profile) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeGateway, NodePinSource, NodeRelay};
    use std::collections::BTreeSet;

    fn profile(capabilities: &[&str]) -> NodeProfile {
        NodeProfile {
            discovery_url: String::new(),
            node_id: "node-under-test".into(),
            node_public_key: "public-key".into(),
            pin_source: NodePinSource::Tofu,
            ca_cert_pem: String::new(),
            gateway: NodeGateway {
                quic_addr: "gateway.invalid:443".into(),
                tcp_addr: "gateway.invalid:443".into(),
                server_name: "ramflux-gateway".into(),
            },
            relay: NodeRelay {
                quic_addr: "relay.invalid:17447".into(),
                server_name: "ramflux-relay".into(),
            },
            prekey_http_url: String::new(),
            signaling_turn_addr: String::new(),
            protocol_versions: Vec::new(),
            client_capabilities: capabilities.iter().map(|name| (*name).to_owned()).collect(),
            discovered_at: 0,
            expires_at: u64::MAX,
            enabled: true,
            builtin: false,
            safety_warnings: BTreeSet::new(),
        }
    }

    #[test]
    fn node_without_device_pairing_refuses_naming_the_capability() {
        let refusal = require_device_pairing(&profile(&["prekey", "object_relay"])).err();
        assert!(
            matches!(
                &refusal,
                Some(SdkError::CapabilityDenied(message))
                    if message.contains(DEVICE_PAIRING_CAPABILITY)
            ),
            "test: a node without device_pairing_v2 must refuse with CapabilityDenied naming it, got {refusal:?}"
        );
    }

    #[test]
    fn staged_resume_is_not_gated_by_the_capability() {
        assert!(
            require_for_new_ceremony(&profile(&["prekey"]), false).is_ok(),
            "test: a staged resume of an existing ceremony must not be refused by the capability"
        );
    }

    #[test]
    fn node_advertising_device_pairing_is_allowed() {
        assert!(
            require_device_pairing(&profile(&["prekey", DEVICE_PAIRING_CAPABILITY])).is_ok(),
            "test: a node advertising device_pairing_v2 must be accepted for pairing"
        );
    }
}
