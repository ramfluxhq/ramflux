// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home pin copied from federation trust onto the router-bound envelope.
//! The sender transcript ignores this field. A missing or partial pin is not stamped.

use ramflux_node_core::NodeCoreError;

const NODE_KEY_DOMAIN: &str = "ramflux.contact.node-key.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedSourceHome {
    pub(crate) node_id: String,
    pub(crate) key_fingerprint: String,
}

/// Pin recorded for `source_node_id` after inbound authentication.
///
/// # Errors
/// Returns an error when the trust snapshot cannot be read, or when a pin is
/// present but is not a 32-byte node public key. A missing pin is `Ok(None)`.
pub(crate) fn from_pin(
    state: &crate::SharedFederationTrustState,
    source_node_id: &str,
) -> Result<Option<VerifiedSourceHome>, NodeCoreError> {
    let snapshot = state.snapshot()?;
    let Some(key) = snapshot.pinned_node_public_key(source_node_id) else {
        return Ok(None);
    };
    let bytes = ramflux_protocol::decode_base64url(&key)
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| NodeCoreError::ItestHttp("pinned node key is not 32 bytes".into()))?;
    Ok(Some(VerifiedSourceHome {
        node_id: source_node_id.to_owned(),
        key_fingerprint: ramflux_protocol::hash_hex(NODE_KEY_DOMAIN, &bytes),
    }))
}

/// Replace any sender-supplied home with `home`. `None` removes the field.
pub(crate) fn apply(envelope: &mut ramflux_protocol::Envelope, home: Option<&VerifiedSourceHome>) {
    envelope.ext.ext.remove(ramflux_protocol::VERIFIED_SOURCE_HOME);
    let Some(home) = home else {
        return;
    };
    envelope.ext.ext.insert(
        ramflux_protocol::VERIFIED_SOURCE_HOME.to_owned(),
        serde_json::json!({
            "node_id": home.node_id,
            "key_fingerprint": home.key_fingerprint,
        }),
    );
}
