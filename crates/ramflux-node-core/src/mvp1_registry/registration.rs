// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-sized registration candidates and reversible admission deltas.
use super::{IdentityDeviceRecord, RegistrationPolicy, RegistrationTrustTier};
use crate::registration_receipts::RegistrationReceipt;
use crate::{IdentityRegisterRequest, IdentityRegistry, NodeCoreError, SessionDescriptor};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};

type Changes<T> = BTreeMap<String, Option<T>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RegistrationDelta {
    principal_root_bindings: Changes<String>,
    identity_authority_fences: Changes<crate::identity_authority::IdentityAuthorityFence>,
    signed_device_sets: Changes<ramflux_protocol::SignedDeviceSetRecord>,
    root_public_keys: Changes<String>,
    root_public_keys_by_commitment: Changes<String>,
    devices: Changes<IdentityDeviceRecord>,
    prekey_bundles: Changes<ramflux_crypto::PrekeyBundle>,
    revoked_devices: BTreeMap<String, bool>,
    delivery_root_bindings: Changes<(String, String, String)>,
    registration_trust_tiers: Changes<RegistrationTrustTier>,
    removed_receipts: BTreeSet<String>,
    receipts: Vec<RegistrationReceipt>,
    // Include charges from previously refused attempts when the next admission commits.
    pub(crate) source_budgets: Changes<Vec<i64>>,
    registration_policy: Option<RegistrationPolicy>,
}
fn changes<T: Clone + PartialEq>(
    before: &BTreeMap<String, T>,
    after: &BTreeMap<String, T>,
) -> Changes<T> {
    before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .map(|key| (key.clone(), after.get(key).cloned()))
        .collect()
}
fn apply<T: Clone>(target: &mut BTreeMap<String, T>, changes: &Changes<T>) {
    for (key, value) in changes {
        if let Some(value) = value {
            target.insert(key.clone(), value.clone());
        } else {
            target.remove(key);
        }
    }
}
impl RegistrationDelta {
    fn between(before: &IdentityRegistry, after: &IdentityRegistry) -> Self {
        let old: BTreeMap<_, _> = before.root_seen_proofs.iter().map(|r| (&r.key, r)).collect();
        let next: BTreeSet<_> = after.root_seen_proofs.iter().map(|r| &r.key).collect();
        Self {
            principal_root_bindings: changes(
                &before.principal_root_bindings,
                &after.principal_root_bindings,
            ),
            identity_authority_fences: changes(
                &before.identity_authority_fences,
                &after.identity_authority_fences,
            ),
            signed_device_sets: changes(&before.signed_device_sets, &after.signed_device_sets),
            root_public_keys: changes(&before.root_public_keys, &after.root_public_keys),
            root_public_keys_by_commitment: changes(
                &before.root_public_keys_by_commitment,
                &after.root_public_keys_by_commitment,
            ),
            devices: changes(&before.devices, &after.devices),
            prekey_bundles: changes(&before.prekey_bundles, &after.prekey_bundles),
            revoked_devices: before
                .revoked_devices
                .union(&after.revoked_devices)
                .filter(|key| {
                    before.revoked_devices.contains(*key) != after.revoked_devices.contains(*key)
                })
                .map(|key| (key.clone(), after.revoked_devices.contains(key)))
                .collect(),
            delivery_root_bindings: changes(
                &before.delivery_root_bindings,
                &after.delivery_root_bindings,
            ),
            registration_trust_tiers: changes(
                &before.registration_trust_tiers,
                &after.registration_trust_tiers,
            ),
            removed_receipts: before
                .root_seen_proofs
                .iter()
                .filter(|r| !next.contains(&r.key))
                .map(|r| r.key.clone())
                .collect(),
            receipts: after
                .root_seen_proofs
                .iter()
                .filter(|r| old.get(&r.key).copied() != Some(*r))
                .cloned()
                .collect(),
            source_budgets: BTreeMap::new(),
            registration_policy: None,
        }
    }
    pub(crate) fn with_budget_changes(
        &self,
        before: &BTreeMap<String, Vec<i64>>,
        registry: &IdentityRegistry,
    ) -> Self {
        let mut delta = self.clone();
        delta.source_budgets = changes(before, registry.registration_budgets());
        delta
    }
    pub(crate) fn apply(&self, target: &mut IdentityRegistry) {
        apply(&mut target.principal_root_bindings, &self.principal_root_bindings);
        apply(&mut target.identity_authority_fences, &self.identity_authority_fences);
        apply(&mut target.signed_device_sets, &self.signed_device_sets);
        apply(&mut target.root_public_keys, &self.root_public_keys);
        apply(&mut target.root_public_keys_by_commitment, &self.root_public_keys_by_commitment);
        apply(&mut target.devices, &self.devices);
        apply(&mut target.prekey_bundles, &self.prekey_bundles);
        apply(&mut target.delivery_root_bindings, &self.delivery_root_bindings);
        apply(&mut target.registration_trust_tiers, &self.registration_trust_tiers);
        for (key, revoked) in &self.revoked_devices {
            if *revoked {
                target.revoked_devices.insert(key.clone());
            } else {
                target.revoked_devices.remove(key);
            }
        }
        let changed: BTreeSet<_> = self.receipts.iter().map(|r| &r.key).collect();
        target
            .root_seen_proofs
            .retain(|r| !self.removed_receipts.contains(&r.key) && !changed.contains(&r.key));
        target.root_seen_proofs.extend(self.receipts.iter().cloned());
        apply(&mut target.registration_times_by_source_ip, &self.source_budgets);
        if let Some(policy) = &self.registration_policy {
            target.registration_policy.clone_from(policy);
        }
    }
}
fn select<T: Clone>(map: &BTreeMap<String, T>, keys: &BTreeSet<String>) -> BTreeMap<String, T> {
    keys.iter().filter_map(|key| map.get(key).map(|value| (key.clone(), value.clone()))).collect()
}
impl IdentityRegistry {
    pub(crate) const fn registration_budgets(&self) -> &BTreeMap<String, Vec<i64>> {
        &self.registration_times_by_source_ip
    }
    /// Copy only authority that this admission can inspect or mutate. Global ownership
    /// checks retain conflicting delivery rows; unrelated roots' records are not cloned.
    fn registration_candidate(&self, request: &IdentityRegisterRequest) -> Self {
        let roots = BTreeSet::from([request.principal_commitment.clone()]);
        let principals = BTreeSet::from([request.proof.principal_id.clone()]);
        let devices: BTreeMap<_, _> = self
            .devices
            .iter()
            .filter(|(_, d)| {
                roots.contains(&d.principal_commitment)
                    || d.target_delivery_id == request.target_delivery_id
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut keys: BTreeSet<String> = devices.keys().cloned().collect();
        if let Some(set) = request
            .device_set
            .as_ref()
            .or_else(|| self.signed_device_sets.get(&request.principal_commitment))
            && let Ok(root) = ramflux_crypto::verifying_key_from_base64url(&request.root_public_key)
        {
            for device in &set.devices {
                if let Ok(identity) = ramflux_crypto::RootQualifiedDeviceRef::from_signed_device_set(
                    &root,
                    set,
                    &device.device_id,
                ) {
                    keys.insert(Self::device_storage_key(&identity));
                    keys.extend(Self::legacy_device_keys(&identity));
                }
            }
        }
        Self {
            principal_root_bindings: select(&self.principal_root_bindings, &principals),
            identity_authority_fences: select(&self.identity_authority_fences, &roots),
            signed_device_sets: select(&self.signed_device_sets, &roots),
            root_public_keys: select(&self.root_public_keys, &principals),
            root_public_keys_by_commitment: select(&self.root_public_keys_by_commitment, &roots),
            // Include aliases that collide with another root; legacy cleanup must see
            // their original owner and must leave those entries alone.
            devices: {
                let mut rows = select(&self.devices, &keys);
                rows.extend(devices);
                rows
            },
            prekey_bundles: select(&self.prekey_bundles, &keys),
            revoked_devices: self.revoked_devices.intersection(&keys).cloned().collect(),
            delivery_root_bindings: self
                .delivery_root_bindings
                .get(&request.target_delivery_id)
                .map(|value| BTreeMap::from([(request.target_delivery_id.clone(), value.clone())]))
                .unwrap_or_default(),
            registration_trust_tiers: select(&self.registration_trust_tiers, &principals),
            root_seen_proofs: self.root_seen_proofs.clone(),
            ..Self::default()
        }
    }
    pub(crate) fn prepare_registration(
        &self,
        request: &IdentityRegisterRequest,
        tier: RegistrationTrustTier,
    ) -> Result<PreparedRegistration, NodeCoreError> {
        // Reject mismatched supplied roots/principals before creating a scoped view.
        if let Some(set) = &request.device_set
            && (set.principal_commitment != request.principal_commitment
                || set.principal_id != request.proof.principal_id)
        {
            return Err(NodeCoreError::ItestHttp(
                "registration device set identity mismatch".into(),
            ));
        }
        let before = self.registration_candidate(request);
        let mut after = before.clone();
        after.authorize_root_bound_registration(request)?;
        let (session, tier) = after.register_admitted_identity(request, tier)?;
        let mut delta = RegistrationDelta::between(&before, &after);
        delta.registration_policy = Some(self.registration_policy.clone());
        Ok(PreparedRegistration {
            session,
            tier,
            delta,
            undo: RegistrationDelta::between(&after, &before),
            before_receipts: before.root_seen_proofs,
        })
    }
}
pub(crate) struct PreparedRegistration {
    pub(crate) session: SessionDescriptor,
    pub(crate) tier: RegistrationTrustTier,
    pub(crate) delta: RegistrationDelta,
    undo: RegistrationDelta,
    before_receipts: VecDeque<RegistrationReceipt>,
}
impl PreparedRegistration {
    pub(crate) fn apply_to<'a>(
        &'a self,
        registry: &'a mut IdentityRegistry,
    ) -> RegistrationGuard<'a> {
        let guard = RegistrationGuard { registry, undo: Some((&self.undo, &self.before_receipts)) };
        self.delta.apply(guard.registry);
        guard
    }
}
pub(crate) struct RegistrationGuard<'a> {
    pub(crate) registry: &'a mut IdentityRegistry,
    undo: Option<(&'a RegistrationDelta, &'a VecDeque<RegistrationReceipt>)>,
}
impl RegistrationGuard<'_> {
    pub(crate) fn commit(mut self) {
        self.undo = None;
    }
}
impl Drop for RegistrationGuard<'_> {
    fn drop(&mut self) {
        if let Some((undo, receipts)) = self.undo.take() {
            undo.apply(self.registry);
            self.registry.root_seen_proofs.clone_from(receipts);
        }
    }
}
