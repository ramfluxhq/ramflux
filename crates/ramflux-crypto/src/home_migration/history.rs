// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Historical home evidence is a routing capability, never fresh branch authority.
use super::{
    CryptoError, authorization_bounds, hard_deadline, reject, verify_node, verify_signatures,
};
use ramflux_protocol::{
    custody::{Envelope, MasterCertificate, object_hash},
    home_migration::{
        Authorization, FORWARD_SECONDS, HomeRecord, MAX_CHAIN_RECORDS, MAX_RESOLVE_BYTES,
        RecordEvidence, ResolveResult, Role, SKEW_SECONDS, Signed, Signer, SignerKey, message_hash,
        record_hash,
    },
};
use std::collections::BTreeMap;

/// Independently pinned starting home. A missing hash is allowed only for genesis bootstrap.
pub struct HomeTrust<'a> {
    pub account_anchor: &'a str,
    pub node_id: &'a str,
    pub node_key: &'a str,
    pub home_epoch: u64,
    pub home_hash: Option<&'a str>,
    /// Manager range of the cached home, never a later current-custody floor.
    pub cached_manager_range: u64,
    pub cached_manager_certificate_hash: Option<&'a str>,
}
/// Constructed only after the complete historical chain is authenticated.
#[derive(Clone, Debug)]
pub struct VerifiedHome {
    evidence: RecordEvidence,
    hash: String,
    ancestry: BTreeMap<u64, String>,
}
impl VerifiedHome {
    #[must_use]
    pub fn extends(&self, epoch: u64, hash: &str) -> bool {
        self.ancestry.get(&epoch).is_some_and(|known| known == hash)
    }
    #[must_use]
    pub fn evidence(&self) -> &RecordEvidence {
        &self.evidence
    }
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.evidence.record.epoch()
    }
    #[must_use]
    pub fn home(&self) -> (&str, &str) {
        self.evidence.record.home()
    }
}
fn certificates(
    e: &RecordEvidence,
    a: &Signed<Authorization>,
    at: u64,
    seen: &mut BTreeMap<u64, String>,
) -> Result<u64, CryptoError> {
    let mut previous: Option<&Envelope<MasterCertificate>> = None;
    for cert in &e.management_certificate_chain {
        crate::custody::verify_home_management_certificate(cert, &a.body.account_anchor)?;
        let hash = object_hash(cert)?;
        if seen.get(&cert.body.range_index).is_some_and(|known| known != &hash) {
            return Err(reject("migration management certificate fork"));
        }
        seen.insert(cert.body.range_index, hash);
        if let Some(old) = previous
            && (cert.body.range_index <= old.body.range_index
                || cert.body.previous_certificate_hash.as_deref()
                    != Some(object_hash(old)?.as_str()))
        {
            return Err(reject("migration management chain gap"));
        }
        previous = Some(cert);
    }
    let cert = previous.ok_or_else(|| reject("migration management evidence absent"))?;
    let actor =
        e.actor_certificate.as_ref().ok_or_else(|| reject("migration actor evidence absent"))?;
    let b = &actor.body;
    let manager_hash = object_hash(cert)?;
    if manager_hash != a.body.management_certificate_hash
        || b.master_certificate_hash != manager_hash
        || b.account_anchor != a.body.account_anchor
        || b.device_id != a.body.actor.device_id
        || b.device_epoch != a.body.actor.device_epoch
        || b.principal_kind != ramflux_protocol::PrincipalKind::Human
        || a.body.actor.account_anchor != a.body.account_anchor
        || b.not_before > at
        || at > b.expires_at
        || !b.capabilities.iter().any(|cap| cap == "register")
    {
        return Err(reject("migration historical actor authority mismatch"));
    }
    crate::custody::verify_home_branch_certificate(actor, &cert.body.self_signing_public_key)?;
    let expected = [
        Signer {
            role: Role::Management,
            key: SignerKey::MasterCertifiedCustody {
                account_anchor: a.body.account_anchor.clone(),
                master_certificate_hash: manager_hash.clone(),
                authority_record_hash: a.body.authority_record_hash.clone(),
                public_key: cert.body.self_signing_public_key.clone(),
            },
        },
        Signer {
            role: Role::Actor,
            key: SignerKey::BranchV3 {
                device_ref: a.body.actor.clone(),
                branch_certificate_hash: object_hash(actor)?,
                public_key: b.branch_signing_public_key.clone(),
            },
        },
    ];
    if a.signers.as_slice() != expected {
        return Err(reject("migration historical signer mismatch"));
    }
    // A attests that this exact publication was current at commit. Client master
    // issuance clocks never order historical home records against A's clock.
    // Verify its cryptographic structure at its own publication time, while the
    // actor's branch lease below remains checked at the node-signed commit time.
    let publication_time = e
        .authority
        .record
        .body
        .issued_at
        .max(e.authority.record.body.master_certificate.body.issued_at)
        .max(at);
    let authority = crate::custody::verify_record(
        &e.authority.record,
        publication_time,
        e.authority.compacted_ids.as_deref(),
        None,
    )?;
    if object_hash(authority.envelope())? != a.body.authority_record_hash
        || object_hash(&authority.envelope().body.master_certificate)? != manager_hash
        || authority.authorize(&a.body.actor, "register", at)? != b
    {
        return Err(reject("migration historical authority membership mismatch"));
    }
    verify_signatures(a)?;
    Ok(cert.body.range_index)
}
fn verify_genesis(
    e: &RecordEvidence,
    pin: (&str, &str),
    now: u64,
) -> Result<(u64, u64), CryptoError> {
    let HomeRecord::Genesis { genesis } = &e.record else {
        return Err(reject("migration genesis required"));
    };
    if genesis.body.home_epoch != 0
        || genesis.body.home_node != pin.0
        || genesis.body.home_node_key != pin.1
        || genesis.body.registered_at > now.saturating_add(SKEW_SECONDS)
        || !e.management_certificate_chain.is_empty()
        || e.actor_certificate.is_some()
    {
        return Err(reject("migration genesis base mismatch"));
    }
    let authority = crate::custody::verify_record(
        &e.authority.record,
        now,
        e.authority.compacted_ids.as_deref(),
        None,
    )?;
    if object_hash(authority.envelope())? != genesis.body.custody_record_hash
        || authority.envelope().body.account_anchor != genesis.body.account_anchor
    {
        return Err(reject("migration genesis authority mismatch"));
    }
    verify_node(genesis, pin.0, pin.1)?;
    Ok((genesis.body.registered_at, authority.envelope().body.master_certificate.body.range_index))
}
/// Authenticate every missed move with its own historical evidence and retained base pin.
/// # Errors
/// Rejects gaps/forks, missing certificates, invalid time/range, wrong A key and oversized pages.
pub fn verify_home_chain(
    result: &ResolveResult,
    trust: &HomeTrust<'_>,
    now: u64,
) -> Result<VerifiedHome, CryptoError> {
    if result.predecessors.len() + 1 > MAX_CHAIN_RECORDS
        || ramflux_protocol::canonical_json_bytes(result)?.len() > MAX_RESOLVE_BYTES
    {
        return Err(reject("migration chain budget exceeded"));
    }
    let mut hash = trust.home_hash.map(str::to_owned);
    let mut ancestry = BTreeMap::new();
    if let Some(hash) = trust.home_hash {
        ancestry.insert(trust.home_epoch, hash.to_owned());
    }
    let mut epoch = trust.home_epoch;
    let mut node_id = trust.node_id.to_owned();
    let mut node_key = trust.node_key.to_owned();
    let mut committed_at = 0;
    let mut seen = BTreeMap::new();
    if let Some(hash) = trust.cached_manager_certificate_hash {
        seen.insert(trust.cached_manager_range, hash.to_owned());
    }
    let mut manager_range = trust.cached_manager_range;
    for e in result.predecessors.iter().chain(std::iter::once(&result.home)) {
        let next_hash = record_hash(&e.record)?;
        if e.record.account_anchor() != trust.account_anchor {
            return Err(reject("migration chain account mismatch"));
        }
        if hash.as_deref() == Some(next_hash.as_str()) {
            if e.record.epoch() != epoch || e.record.home() != (&node_id, &node_key) {
                return Err(reject("migration cached base mismatch"));
            }
            if let HomeRecord::Committed { authorization, commit_proof } = &e.record {
                committed_at = commit_proof.body.committed_at;
                manager_range =
                    certificates(e, authorization, commit_proof.body.committed_at, &mut seen)?;
            }
            continue;
        }
        crate::custody::verify_node_identity_record(&e.node_record, &node_id, &node_key, now)?;
        match &e.record {
            HomeRecord::Genesis { .. } => {
                if hash.is_some() || epoch != 0 {
                    return Err(reject("migration genesis base mismatch"));
                }
                (committed_at, manager_range) = verify_genesis(e, (&node_id, &node_key), now)?;
            }
            HomeRecord::Committed { authorization, commit_proof } => {
                let a = &authorization.body;
                let c = &commit_proof.body;
                if hash.as_deref() != Some(a.previous_home_hash.as_str())
                    || epoch.checked_add(1) != Some(a.next_home_epoch)
                    || a.old_node != node_id
                    || c.old_node != node_id
                    || c.account_anchor != a.account_anchor
                    || c.migration_id != a.migration_id
                    || c.destination_node != a.destination_node
                    || c.destination_key != a.destination_key
                    || c.previous_home_hash != a.previous_home_hash
                    || c.next_home_epoch != a.next_home_epoch
                    || c.authority_record_hash != a.authority_record_hash
                    || c.authorization_hash != message_hash(authorization)?
                    || c.offer_hash != a.offer_hash
                    || c.committed_at < committed_at
                    || c.committed_at > now.saturating_add(SKEW_SECONDS)
                    || c.committed_at > c.commit_deadline
                    || c.committed_at > hard_deadline(a)?
                    || c.forward_until
                        != c.committed_at
                            .checked_add(FORWARD_SECONDS)
                            .ok_or_else(|| reject("migration forwarding overflow"))?
                {
                    return Err(reject("migration committed chain mismatch"));
                }
                authorization_bounds(a, c.committed_at)?;
                verify_node(commit_proof, &node_id, &node_key)?;
                let range = certificates(e, authorization, c.committed_at, &mut seen)?;
                if range < manager_range {
                    return Err(reject("migration management range decreased"));
                }
                manager_range = range;
                epoch = a.next_home_epoch;
                node_id.clone_from(&a.destination_node);
                node_key.clone_from(&a.destination_key);
                committed_at = c.committed_at;
            }
        }
        ancestry.insert(e.record.epoch(), next_hash.clone());
        hash = Some(next_hash);
    }
    let hash = hash.ok_or_else(|| reject("migration genesis missing"))?;
    if record_hash(&result.home.record)? != hash {
        return Err(reject("migration result head mismatch"));
    }
    Ok(VerifiedHome { evidence: result.home.clone(), hash, ancestry })
}
/// Binding from B's durable sealed operation, never from unverified request metadata.
pub struct SealedBinding<'a> {
    pub destination_node: &'a str,
    pub destination_key: &'a str,
    pub authorization_hash: &'a str,
    pub offer_hash: &'a str,
    pub seal_hash: &'a str,
    pub previous_home_hash: &'a str,
    pub next_home_epoch: u64,
    pub home_floor: Option<(u64, &'a str)>,
}
/// A proof activates only the exact destination's own sealed successor; a timer never does.
/// # Errors
/// Rejects another destination/seal/base, a stale/forked floor and unsupported genesis activation.
pub fn activation_allowed(
    home: &VerifiedHome,
    sealed: &SealedBinding<'_>,
) -> Result<(), CryptoError> {
    let HomeRecord::Committed { authorization, commit_proof } = &home.evidence.record else {
        return Err(reject("migration activation requires commit"));
    };
    let a = &authorization.body;
    let c = &commit_proof.body;
    if c.destination_node != sealed.destination_node
        || c.destination_key != sealed.destination_key
        || c.authorization_hash != sealed.authorization_hash
        || c.offer_hash != sealed.offer_hash
        || c.seal_hash != sealed.seal_hash
        || c.previous_home_hash != sealed.previous_home_hash
        || a.next_home_epoch != sealed.next_home_epoch
        || c.committed_at > c.commit_deadline
        || c.committed_at > hard_deadline(a)?
    {
        return Err(reject("migration activation sealed binding mismatch"));
    }
    if let Some((epoch, hash)) = sealed.home_floor
        && !home.extends(epoch, hash)
    {
        return Err(reject("migration activation stale or forked"));
    }
    Ok(())
}
