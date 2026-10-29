// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    InboxEntry, LifecycleMetadataSummary, NodeCoreError, SessionDescriptor, SessionLifecycle,
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod prekey_budgets;
pub(crate) mod registration;
use prekey_budgets::PrekeyBudgetTable;

pub const IDENTITY_BIND_AUDIENCE: &str = "ramflux-node";
pub const IDENTITY_BIND_CAPABILITY: &str = "device.delivery.bind";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityRegisterRequest {
    pub root_public_key: String,
    #[serde(default)]
    pub device_set: Option<ramflux_protocol::SignedDeviceSetRecord>,
    #[serde(default)]
    pub principal_commitment: String,
    pub branch_public_key: String,
    pub proof: ramflux_crypto::BranchProofDocument,
    pub target_delivery_id: String,
    pub gateway_id: String,
    pub session_id: String,
    pub push_alias_hash: Option<String>,
    pub now: i64,
    #[serde(default)]
    pub registration_pow: Option<RegistrationPowProof>,
    #[serde(default)]
    pub source_ip_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityRegistrationResponse {
    pub principal_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub target_delivery_id: String,
    pub session_bound: bool,
    pub registration_trust_tier: RegistrationTrustTier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationPowProof {
    pub nonce: u64,
    pub difficulty_bits: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationPolicy {
    pub challenge_policy: RegistrationChallengePolicy,
    pub pow_difficulty_bits: u8,
    pub per_source_ip_registration_limit: u32,
    pub registration_window_seconds: u64,
}

impl Default for RegistrationPolicy {
    fn default() -> Self {
        Self {
            challenge_policy: RegistrationChallengePolicy::None,
            pow_difficulty_bits: 0,
            per_source_ip_registration_limit: 120,
            registration_window_seconds: 60,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationChallengePolicy {
    #[default]
    None,
    Pow,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationTrustTier {
    #[default]
    New,
    Challenged,
    InviteTrusted,
    Attested,
    OperatorTrusted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FriendRequestBudgetRequest {
    pub source_principal_id: String,
    pub target_principal_id: String,
    pub now: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FriendRequestBudgetResponse {
    pub source_principal_id: String,
    pub target_principal_id: String,
    pub registration_trust_tier: RegistrationTrustTier,
    pub budget_limit: u32,
    pub used_in_window: u32,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevokeRequest {
    pub device_id: String,
    pub principal_commitment: String,
    pub root_public_key: String,
    pub revoked_at: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevokeResponse {
    pub device_id: String,
    pub revoked: bool,
}

#[derive(Serialize)]
struct DeviceRevokeSigningBody<'a> {
    device_id: &'a str,
    principal_commitment: &'a str,
    revoked_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrekeyPublishRequest {
    pub device_id: String,
    pub bundle: ramflux_crypto::PrekeyBundle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrekeyLeaseRequest {
    pub device_id: String,
    pub fetcher_root_commitment: String,
    pub fetcher_device_id: String,
    pub source_prefix: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrekeyResponse {
    pub device_id: String,
    pub bundle: Option<ramflux_crypto::PrekeyBundle>,
    pub principal_commitment: String,
    pub target_delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub one_time_prekey_exhausted: bool,
    #[serde(skip)]
    pub prekey_exhaustion_warning: bool,
    #[serde(default)]
    pub available_one_time_prekeys: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub one_time_prekey_leases: BTreeMap<String, ramflux_protocol::OneTimePrekeyLease>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrekeyLeaseState {
    pub storage_key: String,
    pub available: std::collections::VecDeque<String>,
    pub consumed: BTreeSet<String>,
    #[serde(default)]
    pub leased_at: BTreeMap<String, i64>,
    pub exhaustion_fallbacks: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceManifestEntry {
    pub principal_id: String,
    pub principal_commitment: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub branch_public_key: String,
    pub target_delivery_id: String,
    pub branch_proof: ramflux_crypto::BranchProofDocument,
    #[serde(serialize_with = "ramflux_crypto::serialize_signed_prekey_only")]
    pub prekey_bundle: ramflux_crypto::PrekeyBundle,
    pub branch_authorized_event_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceManifestResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_device_set: Option<ramflux_protocol::SignedDeviceSetRecord>,
    pub principal_id: String,
    pub principal_commitment: String,
    pub root_public_key: String,
    pub devices: Vec<DeviceManifestEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceAuthKeyResponse {
    #[serde(default)]
    pub root_public_key: Option<String>,
    #[serde(default)]
    pub signed_device_set: Option<ramflux_protocol::SignedDeviceSetRecord>,
    pub principal_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub branch_public_key: String,
    pub target_delivery_id: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InboxFetchResponse {
    pub target_delivery_id: String,
    pub entries: Vec<InboxEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp10OwnDeviceFanoutRequest {
    pub principal_id: String,
    pub source_device_id: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp10OwnDeviceFanoutDelivery {
    pub device_id: String,
    pub target_delivery_id: String,
    pub outcome: String,
    pub inbox_seq: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp10OwnDeviceFanoutResponse {
    pub principal_id: String,
    pub source_device_id: String,
    pub delivered: Vec<ItestMvp10OwnDeviceFanoutDelivery>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct IdentityDeviceRecord {
    pub(crate) principal_id: String,
    #[serde(default)]
    pub(crate) principal_commitment: String,
    pub(crate) device_id: String,
    pub(crate) device_epoch: u64,
    pub(crate) branch_public_key: String,
    pub(crate) target_delivery_id: String,
    pub(crate) branch_proof: ramflux_crypto::BranchProofDocument,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityRegistry {
    #[serde(default, skip_serializing_if = "crate::custody_authority::CustodyRegistry::is_empty")]
    pub(crate) custody: crate::custody_authority::CustodyRegistry,
    // A metadata purge is not a root-signed release of a registered principal name.
    #[serde(default)]
    principal_root_bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) identity_authority_fences:
        BTreeMap<String, crate::identity_authority::IdentityAuthorityFence>,
    #[serde(default)]
    pub(crate) signed_device_sets: BTreeMap<String, ramflux_protocol::SignedDeviceSetRecord>,
    pub(crate) root_public_keys: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) root_public_keys_by_commitment: BTreeMap<String, String>,
    pub(crate) devices: BTreeMap<String, IdentityDeviceRecord>,
    pub(crate) revoked_devices: BTreeSet<String>,
    #[serde(default)]
    device_root_bindings: BTreeMap<String, (String, String)>,
    #[serde(default)]
    delivery_root_bindings: BTreeMap<String, (String, String, String)>,
    // Historical unqualified proof ids are retained only for snapshot provenance.
    seen_proofs: BTreeSet<String>,
    #[serde(default, deserialize_with = "crate::registration_receipts::load_receipts")]
    root_seen_proofs: std::collections::VecDeque<crate::registration_receipts::RegistrationReceipt>,
    #[serde(default, skip_serializing)]
    pub(crate) foreign_device_heads: crate::foreign_device_heads::ForeignDeviceHeads,
    pub(crate) prekey_bundles: BTreeMap<String, ramflux_crypto::PrekeyBundle>,
    #[serde(default)]
    available_one_time_prekeys: BTreeMap<String, std::collections::VecDeque<String>>,
    #[serde(default)]
    consumed_one_time_prekeys: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    one_time_prekey_lease_times: BTreeMap<String, BTreeMap<String, i64>>,
    #[serde(skip)]
    prekey_fetch_times_by_source: PrekeyBudgetTable,
    #[serde(skip)]
    prekey_fetch_times_by_fetcher: PrekeyBudgetTable,
    #[serde(skip)]
    prekey_fetch_times_by_pair: PrekeyBudgetTable,
    #[serde(skip)]
    prekey_fetch_times_by_target: PrekeyBudgetTable,
    #[serde(default)]
    prekey_exhaustion_fallbacks: BTreeMap<String, u64>,
    #[serde(default, deserialize_with = "load_registration_policy")]
    registration_policy: RegistrationPolicy,
    #[serde(default)]
    registration_trust_tiers: BTreeMap<String, RegistrationTrustTier>,
    #[serde(default)]
    registration_times_by_source_ip: BTreeMap<String, Vec<i64>>,
    #[serde(default)]
    friend_request_times_by_principal: BTreeMap<String, Vec<i64>>,
}

fn load_registration_policy<'de, D>(deserializer: D) -> Result<RegistrationPolicy, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(normalize_registration_policy(RegistrationPolicy::deserialize(deserializer)?))
}

fn normalize_registration_policy(mut policy: RegistrationPolicy) -> RegistrationPolicy {
    let defaults = RegistrationPolicy::default();
    if matches!(policy.per_source_ip_registration_limit, 0 | u32::MAX) {
        policy.per_source_ip_registration_limit = defaults.per_source_ip_registration_limit;
    }
    if policy.registration_window_seconds == 0 {
        policy.registration_window_seconds = defaults.registration_window_seconds;
    }
    policy
}

impl IdentityRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Returns an error when the proof is invalid, replayed, expired, or revoked.
    pub fn register_identity(
        &mut self,
        request: &IdentityRegisterRequest,
    ) -> Result<(SessionDescriptor, RegistrationTrustTier), NodeCoreError> {
        let tier = self.validate_registration_policy(request)?;
        let prepared = self.prepare_registration(request, tier)?;
        prepared.apply_to(self).commit();
        Ok((prepared.session, prepared.tier))
    }
    pub(crate) fn register_admitted_identity(
        &mut self,
        request: &IdentityRegisterRequest,
        registration_trust_tier: RegistrationTrustTier,
    ) -> Result<(SessionDescriptor, RegistrationTrustTier), NodeCoreError> {
        if self.revoked_devices.contains(&Self::device_storage_key(
            &self
                .device_identity_for_root(&request.principal_commitment, &request.proof.device_id)
                .ok_or_else(|| NodeCoreError::ItestHttp("registration authority missing".into()))?,
        )) {
            return Err(NodeCoreError::ItestHttp(format!(
                "device revoked: {}",
                request.proof.device_id
            )));
        }
        let root_public_key =
            ramflux_crypto::verifying_key_from_base64url(&request.root_public_key)
                .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
        if !request.principal_commitment.is_empty() {
            let derived_commitment = ramflux_crypto::blake3_256_base64url(
                "ramflux.identity.root_public_key.commitment.v1",
                &root_public_key.to_bytes(),
            );
            if derived_commitment != request.principal_commitment {
                return Err(NodeCoreError::ItestHttp(
                    "principal commitment root mismatch".to_owned(),
                ));
            }
            if self
                .root_public_keys_by_commitment
                .get(&request.principal_commitment)
                .is_some_and(|existing| existing != &request.root_public_key)
            {
                return Err(NodeCoreError::ItestHttp(
                    "principal commitment already bound to different root".to_owned(),
                ));
            }
        }
        ramflux_crypto::verify_branch_proof(
            &root_public_key,
            &request.proof,
            IDENTITY_BIND_AUDIENCE,
            IDENTITY_BIND_CAPABILITY,
            request.now,
        )
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;

        self.check_registration_root_ownership(request)?;
        self.check_registration_ownership(request)?;
        let identity = self
            .device_identity_for_root(&request.principal_commitment, &request.proof.device_id)
            .ok_or_else(|| NodeCoreError::ItestHttp("registration authority missing".into()))?;
        self.admit_registration_proof(
            &identity,
            request.source_ip_hash.as_deref().unwrap_or("unknown-source-ip"),
            &request.proof.proof_id,
            request.proof.expires_at,
            request.now,
        )?;
        self.principal_root_bindings
            .insert(request.proof.principal_id.clone(), request.root_public_key.clone());
        self.root_public_keys
            .insert(request.proof.principal_id.clone(), request.root_public_key.clone());
        if !request.principal_commitment.is_empty() {
            self.root_public_keys_by_commitment
                .insert(request.principal_commitment.clone(), request.root_public_key.clone());
        }
        self.reserve_registration_ownership(request);
        self.registration_trust_tiers
            .insert(request.proof.principal_id.clone(), registration_trust_tier.clone());
        self.legacy_remove_device_metadata(&identity);
        self.devices.insert(
            Self::device_storage_key(
                &self
                    .device_identity_for_root(
                        &request.principal_commitment,
                        &request.proof.device_id,
                    )
                    .ok_or_else(|| {
                        NodeCoreError::ItestHttp("registration authority missing".into())
                    })?,
            ),
            IdentityDeviceRecord {
                principal_id: request.proof.principal_id.clone(),
                principal_commitment: request.principal_commitment.clone(),
                device_id: request.proof.device_id.clone(),
                device_epoch: request.proof.device_epoch,
                branch_public_key: request.branch_public_key.clone(),
                target_delivery_id: request.target_delivery_id.clone(),
                branch_proof: request.proof.clone(),
            },
        );
        Ok((
            SessionDescriptor {
                target_delivery_id: request.target_delivery_id.clone(),
                device_id: request.proof.device_id.clone(),
                gateway_id: request.gateway_id.clone(),
                session_id: request.session_id.clone(),
                device_epoch: request.proof.device_epoch,
                session_seq: 1,
                last_cursor: None,
                push_alias_hash: request.push_alias_hash.clone(),
                lifecycle: SessionLifecycle::Live,
            },
            registration_trust_tier,
        ))
    }

    fn admit_registration_proof(
        &mut self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        source_bucket: &str,
        proof: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<(), NodeCoreError> {
        let key = ramflux_crypto::blake3_256_base64url(
            "ramflux.node.registration_proof.v2",
            &ramflux_protocol::canonical_json_bytes(&(source.storage_key(), proof))
                .map_err(|error| NodeCoreError::ItestHttp(error.to_string()))?,
        );
        self.migrate_legacy_registration_receipts(now);
        self.root_seen_proofs
            .retain(|receipt| receipt.expires_at.is_none_or(|expires| expires >= now));
        if self.root_seen_proofs.iter().any(|receipt| receipt.key == key) {
            return Err(NodeCoreError::ItestHttp("branch proof replay".into()));
        }
        if self
            .root_seen_proofs
            .iter()
            .filter(|r| r.root.as_deref() == Some(source.root_commitment()))
            .count()
            >= crate::registration_receipts::REGISTRATION_ROOT_LIMIT
        {
            return Err(NodeCoreError::Capacity { resource: "registration_proofs_per_root" });
        }
        if self
            .root_seen_proofs
            .iter()
            .filter(|r| r.source.as_deref() == Some(source_bucket))
            .count()
            >= crate::registration_receipts::registration_source_limit()?
        {
            return Err(NodeCoreError::Capacity { resource: "registration_proofs_per_source" });
        }
        if self.root_seen_proofs.len() >= crate::registration_receipts::REGISTRATION_PROOF_LIMIT {
            return Err(NodeCoreError::Capacity { resource: "registration_proofs" });
        }
        self.root_seen_proofs.push_back(crate::registration_receipts::RegistrationReceipt {
            key,
            expires_at: Some(expires_at),
            root: Some(source.root_commitment().to_owned()),
            source: Some(source_bucket.to_owned()),
        });
        Ok(())
    }
    pub(crate) fn migrate_legacy_registration_receipts(&mut self, now: i64) -> bool {
        let deadline = now
            .saturating_add(ramflux_crypto::MAX_BRANCH_PROOF_LIFETIME_SECONDS)
            .saturating_add(ramflux_crypto::BRANCH_PROOF_CLOCK_SKEW_SECONDS);
        let mut changed = false;
        for receipt in &mut self.root_seen_proofs {
            if receipt.expires_at.is_none() {
                receipt.expires_at = Some(deadline);
                changed = true;
            }
        }
        changed
    }
    pub(crate) fn prune_registration_proofs(&mut self, now: i64) -> usize {
        self.migrate_legacy_registration_receipts(now);
        let before = self.root_seen_proofs.len() + self.seen_proofs.len();
        self.seen_proofs.clear();
        self.root_seen_proofs
            .retain(|receipt| receipt.expires_at.is_some_and(|expires| expires >= now));
        before - self.root_seen_proofs.len()
    }
    pub fn set_registration_policy(&mut self, policy: RegistrationPolicy) {
        self.registration_policy = normalize_registration_policy(policy);
    }

    #[must_use]
    pub const fn registration_policy(&self) -> &RegistrationPolicy {
        &self.registration_policy
    }

    #[must_use]
    pub fn registration_trust_tier(&self, principal_id: &str) -> RegistrationTrustTier {
        self.registration_trust_tiers
            .get(principal_id)
            .cloned()
            .unwrap_or(RegistrationTrustTier::New)
    }

    /// # Errors
    /// Returns an error when the source exceeds its tier-specific friend-request budget.
    pub fn record_friend_request(
        &mut self,
        request: &FriendRequestBudgetRequest,
    ) -> Result<FriendRequestBudgetResponse, NodeCoreError> {
        let tier = self.registration_trust_tier(&request.source_principal_id);
        let limit = friend_request_budget_limit(&tier);
        let window_start = request.now.saturating_sub(60);
        let entries = self
            .friend_request_times_by_principal
            .entry(request.source_principal_id.clone())
            .or_default();
        entries.retain(|timestamp| *timestamp >= window_start);
        if entries.len() >= limit as usize {
            return Err(NodeCoreError::ItestHttp(format!(
                "friend request budget exceeded for {}",
                request.source_principal_id
            )));
        }
        entries.push(request.now);
        Ok(FriendRequestBudgetResponse {
            source_principal_id: request.source_principal_id.clone(),
            target_principal_id: request.target_principal_id.clone(),
            registration_trust_tier: tier,
            budget_limit: limit,
            used_in_window: u32::try_from(entries.len()).unwrap_or(u32::MAX),
            accepted: true,
        })
    }

    pub(crate) fn validate_registration_policy(
        &mut self,
        request: &IdentityRegisterRequest,
    ) -> Result<RegistrationTrustTier, NodeCoreError> {
        self.migrate_legacy_registration_receipts(request.now);
        self.check_source_registration_budget(request)?;
        match self.registration_policy.challenge_policy {
            RegistrationChallengePolicy::None => Ok(RegistrationTrustTier::New),
            RegistrationChallengePolicy::Pow => {
                let Some(proof) = &request.registration_pow else {
                    return Err(NodeCoreError::ItestHttp("missing registration PoW".to_owned()));
                };
                if proof.difficulty_bits < self.registration_policy.pow_difficulty_bits
                    || !ramflux_crypto::registration_pow_meets_difficulty(
                        &request.proof.principal_id,
                        proof.nonce,
                        self.registration_policy.pow_difficulty_bits,
                    )
                {
                    return Err(NodeCoreError::ItestHttp("invalid registration PoW".to_owned()));
                }
                Ok(RegistrationTrustTier::Challenged)
            }
        }
    }

    fn check_source_registration_budget(
        &mut self,
        request: &IdentityRegisterRequest,
    ) -> Result<(), NodeCoreError> {
        let source = request.source_ip_hash.as_deref().unwrap_or("unknown-source-ip");
        if self.registration_times_by_source_ip.len() > 4096 {
            let mut order = self
                .registration_times_by_source_ip
                .iter()
                .map(|(key, times)| (times.last().copied().unwrap_or(0), key.clone()))
                .collect::<Vec<_>>();
            order.sort_unstable();
            for (_, key) in
                order.into_iter().take(self.registration_times_by_source_ip.len() - 4096)
            {
                self.registration_times_by_source_ip.remove(&key);
            }
        }
        while (self.registration_times_by_source_ip.len() > 4096
            || (self.registration_times_by_source_ip.len() == 4096
                && !self.registration_times_by_source_ip.contains_key(source)))
            && let Some(victim) = self
                .registration_times_by_source_ip
                .iter()
                .min_by_key(|(_, v)| v.last().copied().unwrap_or(0))
                .map(|(k, _)| k.clone())
        {
            self.registration_times_by_source_ip.remove(&victim);
        }
        let seconds =
            i64::try_from(self.registration_policy.registration_window_seconds).unwrap_or(i64::MAX);
        let entries = self.registration_times_by_source_ip.entry(source.into()).or_default();
        let effective_now = request.now.max(entries.last().copied().unwrap_or(request.now));
        entries.retain(|t| effective_now.saturating_sub(*t) < seconds);
        if entries.len() >= self.registration_policy.per_source_ip_registration_limit as usize {
            return Err(NodeCoreError::ItestHttp("registration source rate exceeded".into()));
        }
        entries.push(effective_now);
        Ok(())
    }

    fn reserve_registration_ownership(&mut self, request: &IdentityRegisterRequest) {
        self.delivery_root_bindings.insert(
            request.target_delivery_id.clone(),
            (
                request.proof.principal_id.clone(),
                request.root_public_key.clone(),
                request.proof.device_id.clone(),
            ),
        );
    }

    fn device_root_matches(device: &IdentityDeviceRecord, root: &str) -> bool {
        ramflux_crypto::verifying_key_from_base64url(root).is_ok_and(|key| {
            ramflux_crypto::verify_branch_proof(
                &key,
                &device.branch_proof,
                IDENTITY_BIND_AUDIENCE,
                IDENTITY_BIND_CAPABILITY,
                device.branch_proof.issued_at,
            )
            .is_ok()
        })
    }

    pub(crate) fn check_registration_root_ownership(
        &self,
        request: &IdentityRegisterRequest,
    ) -> Result<(), NodeCoreError> {
        if self
            .principal_root_bindings
            .get(&request.proof.principal_id)
            .or_else(|| self.root_public_keys.get(&request.proof.principal_id))
            .is_some_and(|root| root != &request.root_public_key)
        {
            return Err(NodeCoreError::PrincipalIdTaken);
        }
        Ok(())
    }
    fn check_registration_ownership(
        &self,
        request: &IdentityRegisterRequest,
    ) -> Result<(), NodeCoreError> {
        if self.delivery_root_bindings.get(&request.target_delivery_id).is_some_and(|(p, r, _)| {
            p != &request.proof.principal_id || r != &request.root_public_key
        }) || self.devices.values().any(|d| {
            d.target_delivery_id == request.target_delivery_id
                && (d.principal_id != request.proof.principal_id
                    || !Self::device_root_matches(d, &request.root_public_key))
        }) {
            return Err(NodeCoreError::DeviceIdTaken);
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when the revocation is not signed by the registered principal root.
    pub fn revoke_device(&mut self, request: &DeviceRevokeRequest) -> Result<bool, NodeCoreError> {
        if self.signed_device_sets.contains_key(&request.principal_commitment) {
            return Err(NodeCoreError::ItestHttp(
                "root-bound devices require a newer signed device-set revocation".into(),
            ));
        }
        let expected_root = self
            .root_public_keys_by_commitment
            .get(&request.principal_commitment)
            .ok_or_else(|| {
                NodeCoreError::ItestHttp(format!(
                    "unknown principal commitment: {}",
                    request.principal_commitment
                ))
            })?;
        if expected_root != &request.root_public_key {
            return Err(NodeCoreError::ItestHttp(
                "device revoke root public key mismatch".to_owned(),
            ));
        }
        let device = self
            .device_record_for_principal(
                self.signed_device_sets.get(&request.principal_commitment).map_or_else(
                    || {
                        self.root_public_keys
                            .iter()
                            .find(|(_, key)| *key == &request.root_public_key)
                            .map_or("", |(id, _)| id.as_str())
                    },
                    |s| s.principal_id.as_str(),
                ),
                &request.device_id,
            )
            .ok_or_else(|| {
                NodeCoreError::ItestHttp(format!("unknown device: {}", request.device_id))
            })?;
        if device.principal_commitment != request.principal_commitment {
            return Err(NodeCoreError::ItestHttp(
                "device revoke principal commitment mismatch".to_owned(),
            ));
        }
        let revoke_body = ramflux_protocol::canonical_json_bytes(&DeviceRevokeSigningBody {
            device_id: &request.device_id,
            principal_commitment: &request.principal_commitment,
            revoked_at: request.revoked_at,
        })
        .map_err(|source| {
            NodeCoreError::ItestHttp(format!("device revoke body invalid: {source}"))
        })?;
        ramflux_crypto::verify_canonical_signature(
            &revoke_body,
            &request.signature,
            &request.root_public_key,
        )
        .map_err(|source| NodeCoreError::ItestHttp(format!("device revoke invalid: {source}")))?;
        Ok(self.revoked_devices.insert(Self::device_storage_key(
            &self
                .device_identity_for_root(&request.principal_commitment, &request.device_id)
                .ok_or_else(|| NodeCoreError::ItestHttp("revocation authority missing".into()))?,
        )))
    }

    /// # Errors
    /// Returns an error when the device is unknown, revoked, or bundle verification fails.
    pub fn publish_prekey(&mut self, request: PrekeyPublishRequest) -> Result<(), NodeCoreError> {
        let device = self
            .device_record_for_principal(&request.bundle.identity_commitment, &request.device_id)
            .ok_or_else(|| NodeCoreError::ItestHttp("unknown scoped device".into()))?;
        if self.record_is_revoked(device) {
            return Err(NodeCoreError::ItestHttp("device revoked".into()));
        }
        let storage_key = self
            .storage_key_for_record(device)
            .ok_or_else(|| NodeCoreError::ItestHttp("verified device authority missing".into()))?;
        self.authorize_bound_prekey(device, &request.bundle)?;
        let branch_public_key = ramflux_crypto::verifying_key_from_base64url(
            &device.branch_public_key,
        )
        .map_err(|source| {
            NodeCoreError::ItestHttp(format!("prekey publication signature: {source}"))
        })?;
        ramflux_crypto::verify_prekey_bundle(&branch_public_key, &request.bundle).map_err(
            |source| NodeCoreError::ItestHttp(format!("prekey publication signature: {source}")),
        )?;
        let ids = if request.bundle.one_time_prekey_ids.is_empty() {
            request.bundle.one_time_prekey_id.clone().into_iter().collect::<Vec<_>>()
        } else {
            request.bundle.one_time_prekey_ids.clone()
        };
        let keys = if request.bundle.one_time_prekey_x25519_public.is_empty() {
            request.bundle.one_time_prekey.iter().copied().collect::<Vec<_>>()
        } else {
            request.bundle.one_time_prekey_x25519_public.clone()
        };
        if ids.len() != keys.len()
            || ids.len() > 200
            || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        {
            return Err(NodeCoreError::ItestHttp("invalid one-time prekey pool".into()));
        }
        if let Some(previous) = self.prekey_bundles.get(&storage_key) {
            if request.bundle.prekey_bundle_counter < previous.prekey_bundle_counter {
                return Err(NodeCoreError::ItestHttp("prekey bundle counter rollback".into()));
            }
            if request.bundle.prekey_bundle_counter == previous.prekey_bundle_counter
                && request.bundle != *previous
            {
                return Err(NodeCoreError::ItestHttp("prekey bundle counter conflict".into()));
            }
        }
        let consumed = self.consumed_one_time_prekeys.entry(storage_key.clone()).or_default();
        consumed.retain(|id| ids.contains(id));
        let leases = self.one_time_prekey_lease_times.entry(storage_key.clone()).or_default();
        leases.retain(|id, _| ids.contains(id));
        // Historical cursors had no clock. Start their grace now, never mislabel them unleased.
        let now = i64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        )
        .unwrap_or(i64::MAX);
        for id in consumed.iter() {
            leases.entry(id.clone()).or_insert(now);
        }
        let available = ids.into_iter().filter(|id| !consumed.contains(id)).collect();
        self.available_one_time_prekeys.insert(storage_key.clone(), available);
        self.prekey_bundles.insert(storage_key, request.bundle);
        Ok(())
    }

    /// Configures each in-memory lease budget's maximum number of tracked identities.
    /// A zero capacity is normalized to one; new identities evict the least recently used entry.
    pub fn set_prekey_budget_capacity(&mut self, capacity: usize) {
        self.prekey_fetch_times_by_source.set_capacity(capacity);
        self.prekey_fetch_times_by_fetcher.set_capacity(capacity);
        self.prekey_fetch_times_by_pair.set_capacity(capacity);
        self.prekey_fetch_times_by_target.set_capacity(capacity);
    }

    #[must_use]
    pub fn owner_prekey_leases(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> BTreeMap<String, ramflux_protocol::OneTimePrekeyLease> {
        let state = self.prekey_lease_state(identity);
        self.prekey_bundle(identity)
            .map(|bundle| {
                bundle
                    .one_time_prekey_ids
                    .iter()
                    .map(|id| {
                        let status = state
                            .leased_at
                            .get(id)
                            .map_or(ramflux_protocol::OneTimePrekeyLease::Unleased, |at| {
                                ramflux_protocol::OneTimePrekeyLease::LeasedAt(*at)
                            });
                        (id.clone(), status)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Atomically leases at most one public OPK from a root-qualified device bundle.
    /// # Errors
    /// Returns pool integrity errors; exhausted budgets yield signed-prekey-only fallbacks.
    pub fn take_prekey_bundle(
        &mut self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
        source: &str,
        now: i64,
    ) -> Result<Option<(ramflux_crypto::PrekeyBundle, bool, bool)>, NodeCoreError> {
        self.lease_prekey_bundle(identity, source, source, source, now)
    }

    /// Atomically leases at most one public OPK under independent requester, pair, and prefix
    /// budgets. The requester values have already been authenticated by the router registry.
    /// # Errors
    /// Returns pool integrity errors; exhausted budgets yield signed-prekey-only fallbacks.
    pub fn lease_prekey_bundle(
        &mut self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
        fetcher: &str,
        pair: &str,
        source_prefix: &str,
        now: i64,
    ) -> Result<Option<(ramflux_crypto::PrekeyBundle, bool, bool)>, NodeCoreError> {
        if !self.device_is_usable(identity) {
            return Ok(None);
        }
        let storage_key = Self::device_storage_key(identity);
        let fetcher_allowed = self.prekey_fetch_times_by_fetcher.available(fetcher, now, 60, 3600);
        let pair_allowed = self.prekey_fetch_times_by_pair.available(pair, now, 1, 86400);
        let source_allowed =
            self.prekey_fetch_times_by_source.available(source_prefix, now, 120, 3600);
        let target_allowed =
            self.prekey_fetch_times_by_target.available(&storage_key, now, 6, 3600);
        let allowed = fetcher_allowed && pair_allowed && source_allowed && target_allowed;
        let mut bundle = self
            .prekey_bundles
            .get(&storage_key)
            .or_else(|| self.legacy_prekey_bundle(identity))
            .cloned();
        let Some(bundle) = bundle.as_mut() else { return Ok(None) };
        let selected = if allowed {
            self.available_one_time_prekeys
                .get_mut(&storage_key)
                .and_then(std::collections::VecDeque::pop_front)
        } else {
            None
        };
        if let Some(id) = selected {
            self.prekey_fetch_times_by_fetcher.record(fetcher, now, 3600);
            self.prekey_fetch_times_by_pair.record(pair, now, 86400);
            self.prekey_fetch_times_by_source.record(source_prefix, now, 3600);
            self.prekey_fetch_times_by_target.record(&storage_key, now, 3600);
            self.one_time_prekey_lease_times
                .entry(storage_key.clone())
                .or_default()
                .insert(id.clone(), now);
            let index = bundle
                .one_time_prekey_ids
                .iter()
                .position(|candidate| candidate == &id)
                .ok_or_else(|| NodeCoreError::ItestHttp("one-time prekey pool mismatch".into()))?;
            bundle.one_time_prekey_id = Some(id.clone());
            bundle.one_time_prekey = bundle.one_time_prekey_x25519_public.get(index).copied();
            bundle.one_time_prekey_signature =
                bundle.one_time_prekey_signatures.get(index).cloned();
            bundle.one_time_prekey_ids.clear();
            bundle.one_time_prekey_x25519_public.clear();
            bundle.one_time_prekey_signatures.clear();
            self.consumed_one_time_prekeys.entry(storage_key).or_default().insert(id);
            return Ok(Some((bundle.clone(), false, false)));
        }
        bundle.one_time_prekey_id = None;
        bundle.one_time_prekey = None;
        bundle.one_time_prekey_signature = None;
        let exhausted = self
            .available_one_time_prekeys
            .get(&storage_key)
            .is_none_or(std::collections::VecDeque::is_empty)
            && !bundle.one_time_prekey_ids.is_empty();
        bundle.one_time_prekey_ids.clear();
        bundle.one_time_prekey_x25519_public.clear();
        bundle.one_time_prekey_signatures.clear();
        if exhausted {
            let count = self.prekey_exhaustion_fallbacks.entry(storage_key.clone()).or_default();
            *count = count.saturating_add(1);
        }
        let warn = exhausted
            && self
                .prekey_exhaustion_fallbacks
                .get(&storage_key)
                .is_some_and(|count| count.is_power_of_two());
        Ok(Some((bundle.clone(), exhausted, warn)))
    }

    #[must_use]
    pub fn prekey_exhaustion_fallbacks(&self) -> u64 {
        self.prekey_exhaustion_fallbacks.values().copied().sum()
    }

    #[must_use]
    pub fn available_one_time_prekeys(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> usize {
        self.available_one_time_prekeys
            .get(&Self::device_storage_key(identity))
            .map_or(0, std::collections::VecDeque::len)
    }

    #[must_use]
    pub fn prekey_lease_state(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> PrekeyLeaseState {
        let storage_key = Self::device_storage_key(identity);
        PrekeyLeaseState {
            available: self
                .available_one_time_prekeys
                .get(&storage_key)
                .cloned()
                .unwrap_or_default(),
            consumed: self.consumed_one_time_prekeys.get(&storage_key).cloned().unwrap_or_default(),
            leased_at: self
                .one_time_prekey_lease_times
                .get(&storage_key)
                .cloned()
                .unwrap_or_default(),
            exhaustion_fallbacks: self
                .prekey_exhaustion_fallbacks
                .get(&storage_key)
                .copied()
                .unwrap_or_default(),
            storage_key,
        }
    }

    pub(crate) fn restore_prekey_lease_state(&mut self, state: PrekeyLeaseState) {
        self.one_time_prekey_lease_times.insert(state.storage_key.clone(), state.leased_at);
        self.available_one_time_prekeys.insert(state.storage_key.clone(), state.available);
        self.consumed_one_time_prekeys.insert(state.storage_key.clone(), state.consumed);
        self.prekey_exhaustion_fallbacks.insert(state.storage_key, state.exhaustion_fallbacks);
    }

    #[must_use]
    pub fn public_prekey_bundle(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Option<ramflux_crypto::PrekeyBundle> {
        Some(ramflux_crypto::signed_prekey_only_bundle(self.prekey_bundle(identity)?))
    }

    #[must_use]
    pub fn prekey_bundle(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Option<&ramflux_crypto::PrekeyBundle> {
        if !self.device_is_usable(identity) {
            return None;
        }
        self.prekey_bundles
            .get(&Self::device_storage_key(identity))
            .or_else(|| self.legacy_prekey_bundle(identity))
    }

    #[must_use]
    pub fn principal_commitment_for_device(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Option<&str> {
        if !self.device_is_usable(identity) {
            return None;
        }
        self.device_record(identity).map(|device| device.principal_commitment.as_str())
    }

    #[must_use]
    pub fn identity_keys_for_target_delivery_id(&self, target_delivery_id: &str) -> Vec<String> {
        let Some(device) = self.devices.values().find(|device| {
            device.target_delivery_id == target_delivery_id && self.device_record_is_usable(device)
        }) else {
            return Vec::new();
        };
        let mut keys = Vec::with_capacity(2);
        if !device.principal_commitment.is_empty() {
            keys.push(device.principal_commitment.clone());
        }
        if !keys.iter().any(|key| key == &device.principal_id) {
            keys.push(device.principal_id.clone());
        }
        keys
    }

    /// Resolves one active root for a principal; ambiguous registrations fail closed.
    pub(crate) fn principal_manifest_ambiguous(&self, principal: &str) -> bool {
        self.devices
            .values()
            .filter(|device| device.principal_id == principal && !self.record_is_revoked(device))
            .map(|device| &device.principal_commitment)
            .collect::<BTreeSet<_>>()
            .len()
            > 1
    }
    #[must_use]
    pub fn principal_manifest(&self, principal_id: &str) -> Option<DeviceManifestResponse> {
        let roots = self
            .devices
            .values()
            .filter(|device| device.principal_id == principal_id && !self.record_is_revoked(device))
            .map(|device| &device.principal_commitment)
            .collect::<std::collections::BTreeSet<_>>();
        if roots.len() != 1 {
            return None;
        }
        self.device_manifest(roots.into_iter().next()?)
    }

    #[must_use]
    pub fn device_manifest(&self, principal_commitment: &str) -> Option<DeviceManifestResponse> {
        if !self.signed_device_sets.contains_key(principal_commitment) {
            return self.legacy_device_manifest(principal_commitment);
        }
        let root_public_key = self.root_public_keys_by_commitment.get(principal_commitment)?;
        let mut devices = self
            .devices
            .values()
            .filter(|device| {
                device.principal_commitment == principal_commitment
                    && self.device_record_is_usable(device)
                    && ramflux_crypto::branch_proof_material_is_ready(
                        device.branch_proof.issued_at,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |time| i64::try_from(time.as_secs()).unwrap_or(i64::MAX)),
                    )
            })
            .filter_map(|device| {
                let prekey_bundle =
                    self.public_prekey_bundle(&self.device_identity_for_root(
                        &device.principal_commitment,
                        &device.device_id,
                    )?)?;
                Some(DeviceManifestEntry {
                    principal_id: device.principal_id.clone(),
                    principal_commitment: device.principal_commitment.clone(),
                    device_id: device.device_id.clone(),
                    device_epoch: device.device_epoch,
                    branch_public_key: device.branch_public_key.clone(),
                    target_delivery_id: device.target_delivery_id.clone(),
                    branch_proof: device.branch_proof.clone(),
                    prekey_bundle: prekey_bundle.clone(),
                    branch_authorized_event_id: format!(
                        "device.branch_authorized:{}:{}",
                        device.device_id, device.device_epoch
                    ),
                })
            })
            .collect::<Vec<_>>();
        devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        let signed_device_set = self.signed_device_sets.get(principal_commitment).cloned();
        let principal_id = signed_device_set
            .as_ref()
            .map(|set| set.principal_id.clone())
            .or_else(|| devices.first().map(|device| device.principal_id.clone()))?;
        Some(DeviceManifestResponse {
            signed_device_set,
            principal_id,
            principal_commitment: principal_commitment.to_owned(),
            root_public_key: root_public_key.clone(),
            devices,
        })
    }

    /// A literal name cannot select device authority.
    /// ```compile_fail
    /// let registry = ramflux_node_core::IdentityRegistry::new();
    /// registry.device_auth_key("alice-device");
    /// ```
    #[must_use]
    pub fn device_auth_key(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Option<DeviceAuthKeyResponse> {
        let device = self.device_record(identity)?;
        if !self.record_is_revoked(device) && !self.device_is_usable(identity) {
            return None;
        }
        Some(DeviceAuthKeyResponse {
            root_public_key: self
                .root_public_keys_by_commitment
                .get(&device.principal_commitment)
                .cloned(),
            signed_device_set: self.signed_device_sets.get(&device.principal_commitment).cloned(),
            principal_id: device.principal_id.clone(),
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
            branch_public_key: device.branch_public_key.clone(),
            target_delivery_id: device.target_delivery_id.clone(),
            revoked: self.record_is_revoked(device),
        })
    }

    #[must_use]
    pub fn target_delivery_id_for_device(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Option<&str> {
        if !self.device_is_usable(identity) {
            return None;
        }
        self.device_record(identity).map(|device| device.target_delivery_id.as_str())
    }

    #[must_use]
    pub fn target_delivery_id_for_principal(&self, principal_id: &str) -> Option<&str> {
        self.devices
            .values()
            .find(|device| {
                device.principal_id == principal_id && self.device_record_is_usable(device)
            })
            .map(|device| device.target_delivery_id.as_str())
    }

    #[must_use]
    pub fn active_own_device_targets(
        &self,
        principal_id: &str,
        source_device_id: &str,
    ) -> Vec<(String, String)> {
        self.devices
            .values()
            .filter(|device| {
                device.principal_id == principal_id
                    && device.device_id != source_device_id
                    && self.device_record_is_usable(device)
            })
            .map(|device| (device.device_id.clone(), device.target_delivery_id.clone()))
            .collect()
    }

    #[must_use]
    pub fn metadata_summary(
        &self,
        principal_id: &str,
        session_bound: bool,
        pending_inbox_count: usize,
        tombstone_hash: Option<String>,
        deletion_proof_hash: Option<String>,
    ) -> LifecycleMetadataSummary {
        let device_ids: BTreeSet<String> = self
            .devices
            .iter()
            .filter(|(_, device)| device.principal_id == principal_id)
            .map(|(key, _)| key.clone())
            .collect();
        let prekey_count = device_ids
            .iter()
            .filter(|device_id| self.prekey_bundles.contains_key(*device_id))
            .count();
        let root_key_present = self.root_public_keys.contains_key(principal_id);
        LifecycleMetadataSummary {
            principal_id: principal_id.to_owned(),
            metadata_present: root_key_present || !device_ids.is_empty() || prekey_count > 0,
            root_key_present,
            device_count: device_ids.len(),
            prekey_count,
            session_bound,
            pending_inbox_count,
            tombstone_hash,
            deletion_proof_hash,
        }
    }

    pub(crate) fn remove_principal_metadata(&mut self, principal_id: &str) -> usize {
        if let Some(root) = self.root_public_keys.get(principal_id) {
            self.principal_root_bindings
                .entry(principal_id.to_owned())
                .or_insert_with(|| root.clone());
        }
        // Purging metadata never releases a delivery alias to a different root.
        for device in self.devices.values().filter(|device| device.principal_id == principal_id) {
            let root = self
                .root_public_keys_by_commitment
                .get(&device.principal_commitment)
                .or_else(|| self.root_public_keys.get(&device.principal_id))
                .cloned()
                .unwrap_or_default();
            self.delivery_root_bindings
                .entry(device.target_delivery_id.clone())
                .or_insert_with(|| (device.principal_id.clone(), root, device.device_id.clone()));
        }
        for set in self.signed_device_sets.values().filter(|set| set.principal_id == principal_id) {
            self.identity_authority_fences.insert(
                set.principal_commitment.clone(),
                crate::identity_authority::IdentityAuthorityFence {
                    principal_kind: set.principal_kind,
                    deleted: true,
                },
            );
        }
        self.signed_device_sets.retain(|_, record| record.principal_id != principal_id);
        let before_devices = self.devices.len();
        let before_prekeys = self.prekey_bundles.len();
        let before_trust = self.registration_trust_tiers.len();
        let device_ids: BTreeSet<String> = self
            .devices
            .iter()
            .filter(|(_, device)| device.principal_id == principal_id)
            .map(|(key, _)| key.clone())
            .collect();
        self.devices.retain(|_, device| device.principal_id != principal_id);
        self.prekey_bundles.retain(|device_id, _| !device_ids.contains(device_id));
        self.revoked_devices.retain(|device_id| !device_ids.contains(device_id));
        self.registration_trust_tiers.remove(principal_id);
        self.root_public_keys_by_commitment.retain(|_, root_public_key| {
            self.root_public_keys.get(principal_id) != Some(root_public_key)
        });
        let root_removed = usize::from(self.root_public_keys.remove(principal_id).is_some());
        root_removed
            .saturating_add(before_devices.saturating_sub(self.devices.len()))
            .saturating_add(before_prekeys.saturating_sub(self.prekey_bundles.len()))
            .saturating_add(before_trust.saturating_sub(self.registration_trust_tiers.len()))
    }
}

#[must_use]
pub const fn friend_request_budget_limit(tier: &RegistrationTrustTier) -> u32 {
    match tier {
        RegistrationTrustTier::New => 2,
        RegistrationTrustTier::Challenged => 4,
        RegistrationTrustTier::InviteTrusted
        | RegistrationTrustTier::Attested
        | RegistrationTrustTier::OperatorTrusted => 16,
    }
}

#[cfg(test)]
mod proof_retention_tests {
    use super::*;
    #[test]
    fn live_registration_receipts_refuse_capacity_and_only_expired_receipts_are_removed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = ramflux_crypto::create_identity_root("owner", [9; 32]);
        let source =
            ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "device")?;
        let mut registry = IdentityRegistry::new();
        for index in 0..crate::registration_receipts::REGISTRATION_ROOT_LIMIT {
            registry.admit_registration_proof(
                &source,
                "test-source",
                &index.to_string(),
                2000,
                1000,
            )?;
        }
        assert!(matches!(
            registry.admit_registration_proof(&source, "test-source", "overflow", 2000, 1000),
            Err(NodeCoreError::Capacity { resource: "registration_proofs_per_root" })
        ));
        assert!(
            registry.admit_registration_proof(&source, "test-source", "0", 2000, 1000).is_err()
        );
        let mut restored: IdentityRegistry =
            serde_json::from_slice(&serde_json::to_vec(&registry)?)?;
        assert!(
            restored.admit_registration_proof(&source, "test-source", "0", 2000, 2000).is_err()
        );
        restored.admit_registration_proof(&source, "test-source", "fresh", 3000, 2001)?;
        assert_eq!(restored.root_seen_proofs.len(), 1);
        Ok(())
    }
    #[test]
    fn registration_receipts_isolate_root_source_and_global_capacity_across_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = IdentityRegistry::new();
        let identity = |number: u64| {
            let root = ramflux_crypto::create_identity_root(
                &format!("root-{number}"),
                ramflux_crypto::blake3_256("ramflux.test.receipt-budget.v1", &number.to_be_bytes()),
            );
            ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "device")
        };
        for root in 0..2 {
            let source = identity(root)?;
            for proof in 0..crate::registration_receipts::REGISTRATION_ROOT_LIMIT {
                registry.admit_registration_proof(
                    &source,
                    "same-prefix",
                    &proof.to_string(),
                    2000,
                    1000,
                )?;
            }
        }
        let source = identity(2)?;
        assert!(matches!(
            registry.admit_registration_proof(&source, "same-prefix", "new", 2000, 1000),
            Err(NodeCoreError::Capacity { resource: "registration_proofs_per_source" })
        ));
        registry.admit_registration_proof(&source, "independent-prefix", "new", 2000, 1000)?;
        let mut registry: IdentityRegistry =
            serde_json::from_slice(&serde_json::to_vec(&registry)?)?;
        assert!(matches!(
            registry.admit_registration_proof(&source, "same-prefix", "another", 2000, 1000),
            Err(NodeCoreError::Capacity { resource: "registration_proofs_per_source" })
        ));
        for root in 2..32 {
            let source = identity(root)?;
            let bucket = format!("source-{root}");
            let start = usize::from(root == 2);
            for proof in start..crate::registration_receipts::REGISTRATION_ROOT_LIMIT {
                registry.admit_registration_proof(
                    &source,
                    &bucket,
                    &proof.to_string(),
                    2000,
                    1000,
                )?;
            }
        }
        assert_eq!(
            registry.root_seen_proofs.len(),
            crate::registration_receipts::REGISTRATION_PROOF_LIMIT
        );
        assert!(matches!(
            registry.admit_registration_proof(&identity(32)?, "fresh-source", "new", 2000, 1000),
            Err(NodeCoreError::Capacity { resource: "registration_proofs" })
        ));
        registry.admit_registration_proof(&identity(32)?, "fresh-source", "new", 3000, 2001)?;
        assert_eq!(registry.root_seen_proofs.len(), 1);
        Ok(())
    }
}
