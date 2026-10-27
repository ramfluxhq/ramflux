// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node identity authentication against an independently retained receiving-node pin.

use super::validate::{bytes, id, key, positive, reject, signature, time};
use crate::CryptoError;
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::{
    custody::{
        CLOCK_SKEW_SECONDS, Envelope, MAX_BRANCH_LEASE_SECONDS, NodeIdentityRecord, object_hash,
        signing_bytes,
    },
    domain, encode_base64url,
};
use std::collections::BTreeSet;

/// A signed node record authenticated with an independently trusted identity key.
/// This capability cannot be deserialized from an untrusted discovery reply.
#[derive(Clone, Debug)]
pub struct VerifiedNodeRecord {
    record: Envelope<NodeIdentityRecord>,
    hash: String,
}
impl VerifiedNodeRecord {
    #[must_use]
    pub const fn envelope(&self) -> &Envelope<NodeIdentityRecord> {
        &self.record
    }
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Verify epoch continuity, cumulative denials and immutable key-id bindings.
    /// `known_key` must consult the durable index, including retired historical keys.
    /// # Errors
    /// Rejects rollback, equivocation, missing revocations and recycled identities.
    pub fn verify_successor(
        &self,
        next: &Self,
        known_key: impl Fn(&str) -> Option<(String, String)>,
        known_public_key: impl Fn(&str) -> Option<String>,
    ) -> Result<(), CryptoError> {
        let old = &self.record.body;
        let new = &next.record.body;
        if old.node_id != new.node_id
            || old.node_signing_public_key != new.node_signing_public_key
            || new.epoch < old.epoch
            || (new.epoch == old.epoch && self.hash != next.hash)
        {
            return Err(reject("node identity pin rollback or equivocation"));
        }
        if new.epoch > old.epoch && new.previous_record_hash.as_deref() != Some(self.hash()) {
            return Err(reject("node identity predecessor unavailable"));
        }
        if !old.revoked_proxy_key_ids.iter().all(|v| new.revoked_proxy_key_ids.contains(v))
            || !old.revoked_receipt_key_ids.iter().all(|v| new.revoked_receipt_key_ids.contains(v))
        {
            return Err(reject("node identity revocations cannot shrink"));
        }
        for (key_id, public, role) in bindings(new) {
            if known_key(key_id)
                .is_some_and(|(old_public, old_role)| old_public != public || old_role != role)
                || known_public_key(public).is_some_and(|old_id| old_id != key_id)
            {
                return Err(reject("node signing key identity cannot be recycled"));
            }
        }
        for old_key in &old.proxy_keys {
            if let Some(updated) = new.proxy_keys.iter().find(|key| key.key_id == old_key.key_id)
                && (updated.not_before != old_key.not_before
                    || updated.sign_until != old_key.sign_until
                    || updated.overlap_until < old_key.overlap_until)
            {
                return Err(reject("proxy rotation cannot extend signing or shrink retention"));
            }
        }
        for old_key in &old.receipt_keys {
            if let Some(updated) = new.receipt_keys.iter().find(|key| key.key_id == old_key.key_id)
                && (updated.not_before != old_key.not_before
                    || updated.sign_until != old_key.sign_until
                    || updated.overlap_until < old_key.overlap_until)
            {
                return Err(reject("receipt rotation cannot extend signing or shrink retention"));
            }
        }
        // A rotated signing key remains in the current descriptor set through the
        // full delivery overlap; revocation is the explicit compromise exception.
        for old_key in &old.proxy_keys {
            if new.issued_at <= old_key.overlap_until
                && !new.revoked_proxy_key_ids.contains(&old_key.key_id)
                && !new
                    .proxy_keys
                    .iter()
                    .any(|v| v.key_id == old_key.key_id && v.public_key == old_key.public_key)
            {
                return Err(reject("node proxy rotation removed overlap evidence"));
            }
        }
        for old_key in &old.receipt_keys {
            if new.issued_at <= old_key.overlap_until
                && !new.revoked_receipt_key_ids.contains(&old_key.key_id)
                && !new
                    .receipt_keys
                    .iter()
                    .any(|v| v.key_id == old_key.key_id && v.public_key == old_key.public_key)
            {
                return Err(reject("node receipt rotation removed overlap evidence"));
            }
        }
        Ok(())
    }
}

fn bindings(body: &NodeIdentityRecord) -> impl Iterator<Item = (&str, &str, String)> {
    body.receipt_keys
        .iter()
        .map(|k| (k.key_id.as_str(), k.public_key.as_str(), "home_relay".into()))
        .chain(body.proxy_keys.iter().map(|k| {
            (k.key_id.as_str(), k.public_key.as_str(), format!("node_proxy:{}", k.proxy_id))
        }))
}

fn sorted_hashes(values: &[String]) -> Result<(), CryptoError> {
    if values.windows(2).any(|v| v[0] >= v[1]) {
        return Err(reject("node revocations must be sorted and unique"));
    }
    for value in values {
        bytes(value, 32)?;
    }
    Ok(())
}
fn interval(start: u64, until: u64, overlap: u64) -> Result<(), CryptoError> {
    time(start)?;
    time(until)?;
    time(overlap)?;
    if start >= until || until > overlap {
        return Err(reject("invalid node signing interval"));
    }
    Ok(())
}
fn structure(body: &NodeIdentityRecord) -> Result<(), CryptoError> {
    if body.schema != domain::CUSTODY_NODE_RECORD || body.version != 1 {
        return Err(reject("unsupported custody node record"));
    }
    id(&body.node_id)?;
    key(&body.node_signing_public_key)?;
    positive(body.epoch)?;
    time(body.issued_at)?;
    if let Some(hash) = &body.previous_record_hash {
        bytes(hash, 32)?;
    }
    if body.receipt_keys.len().saturating_add(body.proxy_keys.len()) > 16
        || body.channel_binding_modes.is_empty()
        || body.channel_binding_modes.windows(2).any(|v| v[0] >= v[1])
    {
        return Err(reject("invalid node descriptor or binding-mode capacity"));
    }
    sorted_hashes(&body.revoked_proxy_key_ids)?;
    sorted_hashes(&body.revoked_receipt_key_ids)?;
    if body.revoked_proxy_key_ids.iter().any(|id| body.revoked_receipt_key_ids.contains(id)) {
        return Err(reject("node signing roles must have distinct key identities"));
    }
    let mut ids = BTreeSet::new();
    let mut publics = BTreeSet::new();
    for (id, public, _) in bindings(body) {
        bytes(id, 32)?;
        key(public)?;
        if !ids.insert(id) || !publics.insert(public) || public == body.node_signing_public_key {
            return Err(reject("node receipt, proxy and identity keys must be independent"));
        }
    }
    let receipt_replacement_start = body
        .receipt_keys
        .iter()
        .filter(|key| key.status == ramflux_protocol::custody::ReceiptKeyStatus::Active)
        .map(|key| key.not_before)
        .max();
    for descriptor in &body.receipt_keys {
        interval(descriptor.not_before, descriptor.sign_until, descriptor.overlap_until)?;
        if descriptor.status == ramflux_protocol::custody::ReceiptKeyStatus::Retiring
            && receipt_replacement_start
                .is_some_and(|start| descriptor.overlap_until < start.saturating_add(604_800 + 600))
        {
            return Err(reject("receipt rotation overlap is shorter than delivery retention"));
        }
        if body.revoked_proxy_key_ids.contains(&descriptor.key_id) {
            return Err(reject("node key role rebound"));
        }
    }
    let replacement_start = body
        .proxy_keys
        .iter()
        .filter(|key| key.status == ramflux_protocol::custody::ReceiptKeyStatus::Active)
        .map(|key| key.not_before)
        .max();
    for descriptor in &body.proxy_keys {
        interval(descriptor.not_before, descriptor.sign_until, descriptor.overlap_until)?;
        id(&descriptor.proxy_id)?;
        if descriptor.sign_until - descriptor.not_before > MAX_BRANCH_LEASE_SECONDS
            || descriptor.audiences.is_empty()
            || descriptor.audiences.len() > 64
            || descriptor.audiences.windows(2).any(|v| v[0] >= v[1])
            || body.revoked_receipt_key_ids.contains(&descriptor.key_id)
        {
            return Err(reject("invalid node proxy role, audience or lease"));
        }
        if descriptor.status == ramflux_protocol::custody::ReceiptKeyStatus::Retiring
            && replacement_start
                .is_some_and(|start| descriptor.overlap_until < start.saturating_add(604_800 + 600))
        {
            return Err(reject("proxy rotation overlap is shorter than delivery retention"));
        }
        for audience in &descriptor.audiences {
            id(audience)?;
        }
    }
    Ok(())
}

/// Sign only the exact node-record envelope with the configured node identity key.
/// # Errors
/// Rejects malformed descriptors, wrong identity key and size/encoding violations.
pub fn sign_node_identity_record(
    keypair: &SigningKey,
    body: NodeIdentityRecord,
) -> Result<Envelope<NodeIdentityRecord>, CryptoError> {
    structure(&body)?;
    if encode_base64url(keypair.verifying_key().to_bytes()) != body.node_signing_public_key {
        return Err(reject("node identity signing key mismatch"));
    }
    let signature = encode_base64url(
        keypair.sign(&signing_bytes(domain::CUSTODY_NODE_RECORD, &body)?).to_bytes(),
    );
    let record = Envelope { body, signature };
    if ramflux_protocol::canonical_json_bytes(&record)?.len() > 512 * 1024 {
        return Err(reject("node record byte limit"));
    }
    Ok(record)
}

/// Authenticate discovery with a pre-existing node identity pin, never its supplied key.
/// # Errors
/// Rejects wrong node/key, malformed roles, future time and invalid signatures.
pub fn verify_node_identity_record(
    record: &Envelope<NodeIdentityRecord>,
    trusted_node_id: &str,
    trusted_node_public_key: &str,
    now: u64,
) -> Result<VerifiedNodeRecord, CryptoError> {
    if ramflux_protocol::canonical_json_bytes(record)?.len() > 512 * 1024 {
        return Err(reject("node record byte limit"));
    }
    structure(&record.body)?;
    time(now)?;
    if record.body.node_id != trusted_node_id
        || record.body.node_signing_public_key != trusted_node_public_key
        || record.body.issued_at > now.saturating_add(CLOCK_SKEW_SECONDS)
    {
        return Err(reject("node identity does not match retained trust pin"));
    }
    signature(&key(trusted_node_public_key)?, domain::CUSTODY_NODE_RECORD, record)?;
    Ok(VerifiedNodeRecord { hash: object_hash(record)?, record: record.clone() })
}
