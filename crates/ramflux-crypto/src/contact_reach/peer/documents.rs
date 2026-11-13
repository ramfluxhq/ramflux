// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original nested-document limits and certified sidecars remain independent of the outer snapshot.
use super::{CryptoError, VerifiedRecord, custody, reject, wire};
pub(super) fn check_budgets(p: &wire::SnapshotPayload) -> Result<(), CryptoError> {
    wire::original_document(&p.home, 1024 * 1024)?;
    wire::original_document(&p.discovery.client, 1024 * 1024)?;
    wire::original_document(&p.discovery.server, 1024 * 1024)?;
    wire::original_document(&p.manifest, 3 * 1024 * 1024)?;
    if let Some(prekey) = &p.prekey {
        wire::original_document(prekey, 512 * 1024)?;
    }
    wire::original_document(&p.node_continuity, 1024 * 1024)?;
    if p.node_continuity.len() > 32
        || ramflux_protocol::canonical_json_bytes(&p.reach)?.len() > 4096
    {
        return Err(reject("peer continuity/policy budget"));
    }
    Ok(())
}
pub(super) fn verify_server(
    discovery: &wire::Discovery,
    node: &str,
    key: &str,
    now: u64,
) -> Result<(), CryptoError> {
    let server = &discovery.server;
    let text = |field| server.get(field).and_then(serde_json::Value::as_str);
    let signature =
        text("signature").ok_or_else(|| reject("server discovery signature missing"))?;
    let time = |field| {
        server
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .filter(|value| *value <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| reject("server discovery time missing or unsafe"))
    };
    ramflux_protocol::verify_discovery_freshness(time("updated_at")?, time("expires_at")?, now)?;
    if text("schema") != Some("ramflux.well_known_server.v1")
        || text("node_public_key") != Some(key)
        || text("node_id") != Some(node)
        || text("node_ca_cert_pem") != Some(discovery.client.node_ca_cert_pem.as_str())
        || [wire::CAPABILITY, wire::EPHEMERAL_CAPABILITY].into_iter().any(|required| {
            !server
                .get("node_capabilities")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|caps| caps.iter().any(|cap| cap.as_str() == Some(required)))
        })
    {
        return Err(reject("peer server discovery mismatch"));
    }
    crate::verify_canonical_signature(&ramflux_protocol::signed_bytes(server)?, signature, key)
}
pub(super) fn verify_sidecars(
    payload: &wire::SnapshotPayload,
    authority: &VerifiedRecord,
    home_hash: &str,
    home_node: &str,
) -> Result<(), CryptoError> {
    if let Some(profile) = &payload.profile {
        super::super::directory::verify_profile(profile, authority, home_hash)?;
        if profile.body.deleted || !profile.body.discoverable {
            return Err(reject("suppressed profile in public snapshot"));
        }
    }
    if let Some(directory) = &payload.directory {
        super::super::directory::verify_binding(&directory.binding, authority, home_hash)?;
        if directory.binding.body.home_node != home_node {
            return Err(reject("peer directory home mismatch"));
        }
        // A historical receipt is retained provenance. Fresh name discovery still requires
        // an independently pinned centre response; this verifier installs no centre key.
        directory.receipt.body.validate()?;
        let receipt = &directory.receipt.body;
        if receipt.state != ramflux_protocol::username_directory::ReceiptState::Committed
            || receipt.account_anchor != directory.binding.body.account_anchor
            || receipt.epoch != directory.binding.body.epoch
            || receipt.binding_hash.as_deref()
                != Some(
                    custody::framed_hash(wire::directory::BINDING_HASH_DOMAIN, &directory.binding)?
                        .as_str(),
                )
            || ramflux_protocol::canonical_json_bytes(&directory.receipt)?.len() > 4096
        {
            return Err(reject("peer directory receipt tuple mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
