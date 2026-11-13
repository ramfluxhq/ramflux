// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pure verification of bounded candidate peer evidence; this module never adopts trust.
use super::{reject, verify};
use crate::{CryptoError, custody::VerifiedRecord};
use ramflux_protocol::{
    contact_reach as wire,
    custody::{self, CustodyAuthority, CustodyManifest, framed_hash, object_hash},
};

/// Proof of complete signed peer/home correlation, without permanent trust adoption.
pub struct VerifiedPeer {
    root: String,
    node: String,
    node_key: String,
    snapshot_hash: String,
    expires_at: u64,
    authority: VerifiedRecord,
    home: crate::home_migration::VerifiedHome,
}
impl VerifiedPeer {
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }
    #[must_use]
    pub fn node_key(&self) -> &str {
        &self.node_key
    }
    #[must_use]
    pub fn snapshot_hash(&self) -> &str {
        &self.snapshot_hash
    }
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub fn authority(&self) -> &VerifiedRecord {
        &self.authority
    }
    #[must_use]
    pub fn home(&self) -> &crate::home_migration::VerifiedHome {
        &self.home
    }
}

/// Verify peer evidence under an independently authenticated node key and retained home base.
/// An absent base permits only complete genesis bootstrap; retained custody floors are checked
/// by the caller before adopting the result. No signature proves an intended human identity.
/// # Errors
/// Refuses substituted snapshots, homes, authority, policy or discovery keys and stale responses.
pub fn verify_peer_reply(
    reply: &wire::PeerReply,
    query: &wire::Query,
    authenticated_node_key: &str,
    base: Option<&ramflux_protocol::home_migration::RecordEvidence>,
    now: u64,
) -> Result<VerifiedPeer, CryptoError> {
    query.validate()?;
    if ramflux_protocol::canonical_json_bytes(reply)?.len() > wire::MAX_REPLY_BYTES {
        return Err(reject("peer reply byte budget"));
    }
    let b = &reply.snapshot.body;
    let p = &reply.payload;
    if query.version != 1
        || b.version != 1
        || b.source_node != query.target_node
        || b.target_node != query.source_node
        || b.account_anchor != query.account_anchor
        || b.request_nonce != query.nonce
        || b.request_hash != framed_hash(wire::QUERY_HASH_DOMAIN, query)?
        || b.payload_hash != framed_hash(wire::PAYLOAD_HASH_DOMAIN, p)?
        || b.issued_at.checked_add(60) != Some(b.expires_at)
    {
        return Err(reject("peer snapshot correlation mismatch"));
    }
    wire::check_submission_time(b.issued_at, b.expires_at, now)?;
    verify(wire::SNAPSHOT_DOMAIN, &reply.snapshot, authenticated_node_key)?;
    verify_discovery(p, &b.source_node, authenticated_node_key, now)?;
    let manifest_value =
        p.manifest.get("custody").ok_or_else(|| reject("native peer authority required"))?;
    let manifest: CustodyManifest =
        custody::decode(&ramflux_protocol::canonical_json_bytes(manifest_value)?, 3 * 1024 * 1024)?;
    let authority = crate::custody::verify_publication(
        &CustodyAuthority {
            publication: manifest.publication.clone(),
            custodian_publication: manifest.custodian_publication.clone(),
        },
        now,
    )?;
    if authority.envelope().body.account_anchor != b.account_anchor {
        return Err(reject("peer native anchor mismatch"));
    }
    if query.device_ref.is_some() != p.prekey.is_some() {
        return Err(reject("peer prekey request mismatch"));
    }
    let initial = if let Some(base) = base {
        base
    } else {
        p.home.predecessors.first().unwrap_or(&p.home.home)
    };
    if base.is_none()
        && !matches!(initial.record, ramflux_protocol::home_migration::HomeRecord::Genesis { .. })
    {
        return Err(reject("peer genesis required for bootstrap"));
    }
    let home = crate::home_migration::verify_home_chain_with_custodians(
        &p.home,
        initial,
        &p.custodian_history,
        now,
    )?;
    if home.home() != (b.source_node.as_str(), authenticated_node_key)
        || home.evidence().record.account_anchor() != b.account_anchor
    {
        return Err(reject("peer current home mismatch"));
    }
    let policy = &p.reach.body;
    policy.validate()?;
    if policy.account_anchor != b.account_anchor
        || policy.home_head_hash != home.hash()
        || policy.master_certificate_hash
            != object_hash(&authority.envelope().body.master_certificate)?
    {
        return Err(reject("peer reach policy authority mismatch"));
    }
    authority.authorize_primary_management(&policy.actor, "contact_consent", now)?;
    verify(
        wire::POLICY_DOMAIN,
        &p.reach,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )?;
    Ok(VerifiedPeer {
        root: b.account_anchor.clone(),
        node: b.source_node.clone(),
        node_key: authenticated_node_key.into(),
        snapshot_hash: object_hash(&reply.snapshot)?,
        expires_at: b.expires_at,
        authority,
        home,
    })
}

fn verify_discovery(
    p: &wire::SnapshotPayload,
    source_node: &str,
    authenticated_node_key: &str,
    now: u64,
) -> Result<(), CryptoError> {
    ramflux_protocol::verify_client_discovery_record(&p.discovery.client, now)?;
    let client = &p.discovery.client;
    if client.node_id != source_node
        || client.node_public_key != authenticated_node_key
        || !client.client_capabilities.iter().any(|c| c == wire::CAPABILITY)
    {
        return Err(reject("peer client discovery mismatch"));
    }
    let server = &p.discovery.server;
    let server_key = server.get("node_public_key").and_then(serde_json::Value::as_str);
    let server_id = server.get("node_id").and_then(serde_json::Value::as_str);
    let signature = server
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| reject("server discovery signature missing"))?;
    if server_key != Some(authenticated_node_key)
        || server_id != Some(source_node)
        || server.get("node_ca_cert_pem").and_then(serde_json::Value::as_str)
            != Some(client.node_ca_cert_pem.as_str())
    {
        return Err(reject("peer server discovery mismatch"));
    }
    crate::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(server)?,
        signature,
        authenticated_node_key,
    )?;
    Ok(())
}

/// Recompute cryptographic notice facts before a primary-signed admission is applied.
/// # Errors
/// Refuses substituted recipients, safety numbers, peer/node keys and oversized notices.
pub fn verify_notice(
    notice: &wire::Notice,
    recipient: &str,
    peer: &VerifiedPeer,
) -> Result<(), CryptoError> {
    let expected = crate::custody::safety_fingerprint(recipient, peer.root())?;
    let groups = crate::custody::safety_number(recipient, peer.root())?;
    let node_bytes = ramflux_protocol::decode_base64url(peer.node_key())?;
    if notice.recipient_root != recipient
        || notice.peer_root != peer.root()
        || notice.account_safety_fingerprint != ramflux_protocol::encode_base64url(expected)
        || notice.safety_algorithm != 2
        || notice.safety_number.as_slice() != groups.as_slice()
        || notice.node_id != peer.node()
        || notice.node_fingerprint
            != ramflux_protocol::hash_hex("ramflux.contact.node-key.v1", &node_bytes)
        || notice.source_locator.as_ref().is_some_and(|s| s.len() > 2048)
        || ramflux_protocol::canonical_json_bytes(notice)?.len() > 4096
    {
        return Err(reject("contact notice facts mismatch"));
    }
    Ok(())
}
