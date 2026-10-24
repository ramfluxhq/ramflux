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
pub struct PrekeyResponse {
    pub device_id: String,
    pub bundle: Option<ramflux_crypto::PrekeyBundle>,
    pub principal_commitment: String,
    pub target_delivery_id: Option<String>,
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
    // A metadata purge is not a root-signed release of a registered principal name.
    #[serde(default)]
    principal_root_bindings: BTreeMap<String,String>,
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
    device_root_bindings: BTreeMap<String,(String,String)>,
    #[serde(default)]
    delivery_root_bindings: BTreeMap<String,(String,String,String)>,
    seen_proofs: BTreeSet<String>,
    pub(crate) prekey_bundles: BTreeMap<String,ramflux_crypto::PrekeyBundle>,
    #[serde(default, deserialize_with="load_registration_policy")]
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
    let mut policy = RegistrationPolicy::deserialize(deserializer)?;
    let defaults = RegistrationPolicy::default();
    if matches!(policy.per_source_ip_registration_limit, 0 | u32::MAX) {
        policy.per_source_ip_registration_limit = defaults.per_source_ip_registration_limit;
    }
    if policy.registration_window_seconds == 0 {
        policy.registration_window_seconds = defaults.registration_window_seconds;
    }
    Ok(policy)
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
        let mut candidate = self.clone();
        let result = candidate.register_identity_candidate(request)?;
        *self = candidate;
        Ok(result)
    }
    pub(crate) fn register_identity_candidate(
        &mut self,
        request: &IdentityRegisterRequest,
    ) -> Result<(SessionDescriptor, RegistrationTrustTier), NodeCoreError> {
        self.authorize_root_bound_registration(request)?;
        self.register_identity_inner(request)
    }
    fn register_identity_inner(
        &mut self,
        request: &IdentityRegisterRequest,
    ) -> Result<(SessionDescriptor, RegistrationTrustTier), NodeCoreError> {
        let registration_trust_tier = self.validate_registration_policy(request)?;
        self.register_admitted_identity(request,registration_trust_tier)
    }
    pub(crate) fn register_admitted_identity(&mut self, request: &IdentityRegisterRequest, registration_trust_tier: RegistrationTrustTier) -> Result<(SessionDescriptor,RegistrationTrustTier),NodeCoreError> {
        if self.revoked_devices.contains(&Self::device_storage_key(&request.principal_commitment,&request.proof.device_id)) {
            return Err(NodeCoreError::ItestHttp(format!("device revoked: {}",request.proof.device_id)));
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

        if self
            .principal_root_bindings
            .get(&request.proof.principal_id)
            .or_else(|| self.root_public_keys.get(&request.proof.principal_id))
            .is_some_and(|root| root != &request.root_public_key)
        {
            return Err(NodeCoreError::PrincipalIdTaken);
        }
        self.check_registration_ownership(request)?;
        if self.revoked_devices.contains(&request.proof.device_id) {
            return Err(NodeCoreError::ItestHttp(format!(
                "device revoked: {}",
                request.proof.device_id
            )));
        }
        if !self.seen_proofs.insert(request.proof.proof_id.clone()) {
            return Err(NodeCoreError::ItestHttp(format!(
                "branch proof replay: {}",
                request.proof.proof_id
            )));
        }
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
        if self
            .devices
            .get(&request.proof.device_id)
            .is_some_and(|old| old.principal_id == request.proof.principal_id)
        {
            self.devices.remove(&request.proof.device_id);
            self.prekey_bundles.remove(&request.proof.device_id);
        }
        self.devices.insert(
            Self::device_storage_key(&request.principal_commitment, &request.proof.device_id),
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

    pub fn set_registration_policy(&mut self, policy: RegistrationPolicy) {
        self.registration_policy = policy;
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
        self.device_root_bindings.insert(
            request.proof.device_id.clone(),
            (request.proof.principal_id.clone(), request.root_public_key.clone()),
        );
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

    fn check_registration_ownership(
        &self,
        request: &IdentityRegisterRequest,
    ) -> Result<(), NodeCoreError> {
        if self
            .device_root_bindings
            .get(&request.proof.device_id)
            .is_some_and(|(p, r)| p != &request.proof.principal_id || r != &request.root_public_key)
            || self.devices.get(&request.proof.device_id).is_some_and(|d| {
                d.principal_id != request.proof.principal_id
                    || !Self::device_root_matches(d, &request.root_public_key)
            })
            || self.delivery_root_bindings.get(&request.target_delivery_id).is_some_and(
                |(p, r, _)| p != &request.proof.principal_id || r != &request.root_public_key,
            )
            || self.devices.values().any(|d| {
                d.target_delivery_id == request.target_delivery_id
                    && (d.principal_id != request.proof.principal_id
                        || !Self::device_root_matches(d, &request.root_public_key))
            })
        {
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
        Ok(self
            .revoked_devices
            .insert(Self::device_storage_key(&request.principal_commitment, &request.device_id)))
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
        let storage_key = self.storage_key_for_record(device);
        self.authorize_bound_prekey(device, &request.bundle)?;
        let branch_public_key =
            ramflux_crypto::verifying_key_from_base64url(&device.branch_public_key)
                .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
        ramflux_crypto::verify_prekey_bundle(&branch_public_key, &request.bundle)
            .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
        self.prekey_bundles.insert(storage_key, request.bundle);
        Ok(())
    }

    #[must_use]
    pub fn prekey_bundle(&self, device_id: &str) -> Option<&ramflux_crypto::PrekeyBundle> {
        if !self.device_is_usable(device_id) {
            return None;
        }
        let device = self.device_record(device_id)?;
        self.prekey_bundles.get(&self.storage_key_for_record(device)).or_else(|| {
            self.prekey_bundles.get(&device.device_id).filter(|_| {
                self.devices
                    .get(&device.device_id)
                    .is_some_and(|legacy| legacy.principal_id == device.principal_id)
            })
        })
    }

    #[must_use]
    pub fn principal_commitment_for_device(&self, device_id: &str) -> Option<&str> {
        if !self.device_is_usable(device_id) {
            return None;
        }
        self.device_record(device_id).map(|device| device.principal_commitment.as_str())
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
            .filter(|device| {
                device.principal_id == principal
                    && !self.revoked_devices.contains(&device.device_id)
            })
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
            .filter(|device| {
                device.principal_id == principal_id
                    && !self.revoked_devices.contains(&device.device_id)
            })
            .map(|device| &device.principal_commitment)
            .collect::<std::collections::BTreeSet<_>>();
        if roots.len() != 1 {
            return None;
        }
        self.device_manifest(roots.into_iter().next()?)
    }

    #[must_use]
    pub fn device_manifest(&self, principal_commitment: &str) -> Option<DeviceManifestResponse> {
        let root_public_key = self.root_public_keys_by_commitment.get(principal_commitment)?;
        let mut devices = self
            .devices
            .values()
            .filter(|device| {
                device.principal_commitment == principal_commitment
                    && self.device_record_is_usable(device)
            })
            .filter_map(|device| {
                let prekey_bundle = self.prekey_bundle(&Self::principal_device_lookup(
                    &device.principal_id,
                    &device.device_id,
                ))?;
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

    #[must_use]
    pub fn device_auth_key(&self, device_id: &str) -> Option<DeviceAuthKeyResponse> {
        let device = self.device_record(device_id)?;
        if !self.record_is_revoked(device) && !self.device_is_usable(device_id) {
            return None;
        }
        Some(DeviceAuthKeyResponse {
            principal_id: device.principal_id.clone(),
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
            branch_public_key: device.branch_public_key.clone(),
            target_delivery_id: device.target_delivery_id.clone(),
            revoked: self.record_is_revoked(device),
        })
    }

    #[must_use]
    pub fn target_delivery_id_for_device(&self, device_id: &str) -> Option<&str> {
        if !self.device_is_usable(device_id) {
            return None;
        }
        self.device_record(device_id).map(|device| device.target_delivery_id.as_str())
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
        if let Some(root)=self.root_public_keys.get(principal_id) { self.principal_root_bindings.entry(principal_id.to_owned()).or_insert_with(||root.clone()); }
        for set in self.signed_device_sets.values().filter(|set|set.principal_id==principal_id) {
            self.identity_authority_fences.insert(set.principal_commitment.clone(),crate::identity_authority::IdentityAuthorityFence {principal_kind:set.principal_kind,deleted:true});
        }
        self.signed_device_sets.retain(|_,record|record.principal_id!=principal_id);
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
