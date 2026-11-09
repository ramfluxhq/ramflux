// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate dm/group/own recipient target selection (S10a P05).
//!
//! Adapters call [`RamfluxClient::candidate_target_plan`] behind the existing
//! generation-0 schema gate. Live producers stay unfed until activation.
use crate::prekey::SdkDeviceManifestResponse;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::custody::{
    MAX_LAYER_DECLARATION_VALIDITY_SECONDS, MAX_MESSAGE_LAYER, MESSAGE_LAYER_FLOOR,
    SignedLayerDeclaration,
};
use ramflux_protocol::message::KindId;
use ramflux_protocol::message::registry::{COMPILED_LAYER, PROFILE_FLOOR, kind_binding};
use ramflux_protocol::schema_profile::{ACTIVE_STORAGE_GENERATION, MESSAGE_SCHEMA_V1_GENERATION};
use serde_json::json;
use std::collections::BTreeSet;

/// Send fan-out that applies the same fresh-cohort rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FanoutScope {
    Dm,
    Group,
    OwnCopy,
}

/// Verified declaration fields used for above-floor selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LayerView {
    pub max_layer: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl LayerView {
    fn from_signed(signed: &SignedLayerDeclaration) -> Self {
        Self {
            max_layer: signed.declaration.max_layer,
            issued_at: signed.declaration.issued_at,
            expires_at: signed.declaration.expires_at,
        }
    }

    /// Inclusive signed validity window from P04; `now == expires_at` is still fresh.
    #[must_use]
    pub(crate) fn is_fresh(self, now: u64) -> bool {
        self.max_layer >= MESSAGE_LAYER_FLOOR
            && self.max_layer <= MAX_MESSAGE_LAYER
            && self.issued_at != 0
            && self.expires_at != 0
            && self.issued_at <= now
            && now <= self.expires_at
            && self.expires_at.saturating_sub(self.issued_at)
                <= MAX_LAYER_DECLARATION_VALIDITY_SECONDS
    }
}

/// One recipient device plus an optional current verified declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetDevice {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub declaration: Option<LayerView>,
}

impl TargetDevice {
    fn key(&self) -> TargetKey {
        TargetKey {
            account_anchor: self.account_anchor.clone(),
            device_id: self.device_id.clone(),
            device_epoch: self.device_epoch,
        }
    }
}

/// Stable identity for one device in a representation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct TargetKey {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
}

/// Signed membership/epoch snapshot used for the pre-send recheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MembershipSnapshot {
    pub epoch: u64,
    pub devices: BTreeSet<TargetKey>,
}

/// Inputs for one logical event's candidate fan-out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectionRequest {
    pub scope: FanoutScope,
    pub kind: KindId,
    pub logical_event_id: String,
    pub now_unix: u64,
    pub source_compiled_support: u32,
    pub source: TargetDevice,
    pub targets: Vec<TargetDevice>,
    pub membership: MembershipSnapshot,
    pub variant_counter_high_water: u64,
}

/// How one representation is encoded. Structural kinds have no text arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Encoding {
    Typed { kind: KindId, layer: u32 },
    PeerUpgradeRequired,
}

/// One distinct plaintext/ciphertext variant of a logical event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Representation {
    pub variant_counter: u64,
    pub selected_layer: u32,
    pub encoding: Encoding,
    pub targets: BTreeSet<TargetKey>,
}

/// Candidate assignment: shared logical id, isolated stale-F variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectionPlan {
    pub logical_event_id: String,
    pub scope: FanoutScope,
    pub membership: MembershipSnapshot,
    pub fresh_cohort_layer: Option<u32>,
    pub representations: Vec<Representation>,
    pub variant_counter_high_water: u64,
}

/// True only after PR24 flips the live generation to message schema v1.
#[must_use]
pub(crate) const fn schema_v1_selected() -> bool {
    ACTIVE_STORAGE_GENERATION == MESSAGE_SCHEMA_V1_GENERATION
}

/// Map a kind onto an admitted layer. Never substitutes text for a control.
/// # Errors
/// Rejects the unspecified kind id.
pub(crate) fn encoding_for(kind: KindId, selected_layer: u32) -> Result<Encoding, SdkError> {
    if kind == KindId::KindUnspecified {
        return Err(invalid_kind());
    }
    let number = u32::try_from(i32::from(kind)).map_err(|_| invalid_kind())?;
    let Some(binding) = kind_binding(number) else {
        return Err(invalid_kind());
    };
    if selected_layer < PROFILE_FLOOR || selected_layer < binding.first_layer {
        return Ok(Encoding::PeerUpgradeRequired);
    }
    Ok(Encoding::Typed { kind, layer: selected_layer })
}

/// Partition fresh vs stale targets and assign distinct variant counters.
/// # Errors
/// Refuses a compiled maximum below the admitted floor, or an unspecified kind.
#[must_use = "selection must be retained until submit or rebuilt"]
pub(crate) fn select(request: &SelectionRequest) -> Result<SelectionPlan, SdkError> {
    if request.source_compiled_support < PROFILE_FLOOR {
        return Err(peer_upgrade());
    }
    encoding_for(request.kind, PROFILE_FLOOR)?;
    let compiled = request.source_compiled_support.min(COMPILED_LAYER);
    let source_cap = request
        .source
        .declaration
        .filter(|view| view.is_fresh(request.now_unix))
        .map_or(compiled, |view| compiled.min(view.max_layer).max(PROFILE_FLOOR));
    let (fresh, stale) = partition_targets(&request.targets, request.now_unix, source_cap);
    let fresh_cohort_layer = fresh.iter().map(|(_, layer)| *layer).min();
    let mut representations = Vec::new();
    let mut counter = request.variant_counter_high_water;
    if let Some(layer) = fresh_cohort_layer {
        let targets = fresh.into_iter().map(|(key, _)| key).collect();
        push_representation(&mut representations, &mut counter, request.kind, layer, targets)?;
    }
    if !stale.is_empty() {
        push_representation(
            &mut representations,
            &mut counter,
            request.kind,
            PROFILE_FLOOR,
            stale,
        )?;
    }
    Ok(SelectionPlan {
        logical_event_id: request.logical_event_id.clone(),
        scope: request.scope,
        membership: request.membership.clone(),
        fresh_cohort_layer,
        representations,
        variant_counter_high_water: counter,
    })
}

/// Rebuild unsubmitted variants when membership or declarations change.
/// # Errors
/// Propagates [`select`] failures after a membership or declaration change.
#[must_use = "rebuilt plans replace the unsubmitted assignment"]
pub(crate) fn recheck(
    plan: &SelectionPlan,
    request: &SelectionRequest,
) -> Result<SelectionPlan, SdkError> {
    let mut probe = request.clone();
    plan.logical_event_id.clone_into(&mut probe.logical_event_id);
    probe.variant_counter_high_water = 0;
    let probed = select(&probe)?;
    if assignment_equal(plan, &probed) {
        return Ok(plan.clone());
    }
    probe.variant_counter_high_water = plan.variant_counter_high_water;
    select(&probe)
}

fn partition_targets(
    targets: &[TargetDevice],
    now: u64,
    source_cap: u32,
) -> (Vec<(TargetKey, u32)>, BTreeSet<TargetKey>) {
    let mut fresh = Vec::new();
    let mut stale = BTreeSet::new();
    for target in targets {
        match target.declaration.filter(|view| view.is_fresh(now)) {
            Some(view) => {
                let layer = view.max_layer.min(source_cap).max(PROFILE_FLOOR);
                fresh.push((target.key(), layer));
            }
            None => {
                stale.insert(target.key());
            }
        }
    }
    (fresh, stale)
}

fn push_representation(
    representations: &mut Vec<Representation>,
    counter: &mut u64,
    kind: KindId,
    layer: u32,
    targets: BTreeSet<TargetKey>,
) -> Result<(), SdkError> {
    *counter = counter.checked_add(1).ok_or_else(invalid_kind)?;
    representations.push(Representation {
        variant_counter: *counter,
        selected_layer: layer,
        encoding: encoding_for(kind, layer)?,
        targets,
    });
    Ok(())
}

fn assignment_equal(left: &SelectionPlan, right: &SelectionPlan) -> bool {
    let fingerprint = |plan: &SelectionPlan| {
        plan.representations
            .iter()
            .map(|row| (row.selected_layer, row.encoding, row.targets.clone()))
            .collect::<Vec<_>>()
    };
    left.logical_event_id == right.logical_event_id
        && left.scope == right.scope
        && left.membership == right.membership
        && fingerprint(left) == fingerprint(right)
}

fn peer_upgrade() -> SdkError {
    SdkError::LocalBusRefused {
        code: "PeerUpgradeRequired".into(),
        message: "admitted clients must support the profile floor".into(),
        body: Box::new(json!({})),
    }
}

fn invalid_kind() -> SdkError {
    SdkError::LocalBusRefused {
        code: "ValidationFailed".into(),
        message: "message kind is not a supported constructor".into(),
        body: Box::new(json!({})),
    }
}

fn unix_now() -> Result<u64, SdkError> {
    u64::try_from(crate::time::now_unix_timestamp()).map_err(|_| SdkError::CustodySetupInvalid)
}

fn target_from_entry(
    root: &str,
    device_id: &str,
    entry: Option<&crate::prekey::SdkDeviceManifestEntry>,
) -> TargetDevice {
    TargetDevice {
        account_anchor: root.to_owned(),
        device_id: device_id.to_owned(),
        device_epoch: entry.map_or(0, |row| row.device_epoch),
        declaration: entry.and_then(|row| row.message_layer.as_ref()).map(LayerView::from_signed),
    }
}

impl RamfluxClient {
    /// Run candidate selection only when the live profile is message schema v1.
    ///
    /// The request closure is skipped while the gate is off so live send bytes
    /// stay unchanged. When the gate is on, the plan is rechecked against the
    /// same request before it is returned (keep counters if membership is
    /// unchanged; rebuild from `high_water` otherwise).
    /// # Errors
    /// Propagates request construction or [`select`] failures when the gate is on.
    pub(crate) fn candidate_target_plan(
        build: impl FnOnce() -> Result<SelectionRequest, SdkError>,
    ) -> Result<Option<SelectionPlan>, SdkError> {
        if !schema_v1_selected() {
            return Ok(None);
        }
        let request = build()?;
        let plan = select(&request)?;
        Ok(Some(recheck(&plan, &request)?))
    }

    pub(crate) fn dm_selection_request(
        &self,
        message: &crate::GatewayDirectMessage,
    ) -> Result<SelectionRequest, SdkError> {
        let local = self.owned_device_identity()?;
        let recipient = Self::qualified_recipient(message)?;
        let remote = self.device_identity(&recipient)?;
        self.pair_selection_request(
            FanoutScope::Dm,
            &message.message_id,
            (local.root_commitment(), local.device_id()),
            (remote.root_commitment(), remote.device_id()),
        )
    }

    pub(crate) fn own_copy_selection_request(
        logical_event_id: &str,
        source_device_id: &str,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<SelectionRequest, SdkError> {
        Ok(request_from_manifest(
            FanoutScope::OwnCopy,
            KindId::KindMessage,
            logical_event_id,
            unix_now()?,
            source_device_id,
            manifest,
        ))
    }

    pub(crate) fn group_selection_request(
        &self,
        group_id: &str,
        sender_id: &str,
    ) -> Result<SelectionRequest, SdkError> {
        if let Some(state) = self.account_db()?.shared_group_state(group_id)? {
            return self.shared_group_selection_request(group_id, sender_id, &state);
        }
        self.legacy_group_selection_request(group_id, sender_id)
    }

    fn pair_selection_request(
        &self,
        scope: FanoutScope,
        logical_event_id: &str,
        source: (&str, &str),
        target: (&str, &str),
    ) -> Result<SelectionRequest, SdkError> {
        let now = unix_now()?;
        let source = self.cached_target(source.0, source.1)?;
        let target = self.cached_target(target.0, target.1)?;
        let membership =
            MembershipSnapshot { epoch: 0, devices: BTreeSet::from([source.key(), target.key()]) };
        Ok(SelectionRequest {
            scope,
            kind: KindId::KindMessage,
            logical_event_id: logical_event_id.to_owned(),
            now_unix: now,
            source_compiled_support: COMPILED_LAYER,
            source,
            targets: vec![target],
            membership,
            variant_counter_high_water: 0,
        })
    }

    fn cached_target(&self, root: &str, device_id: &str) -> Result<TargetDevice, SdkError> {
        let manifest = self.account_db()?.load_actor_state::<SdkDeviceManifestResponse>(
            &format!("identity/manifest-root/{root}"),
        )?;
        let entry = manifest
            .as_ref()
            .and_then(|row| row.devices.iter().find(|device| device.device_id == device_id));
        Ok(target_from_entry(root, device_id, entry))
    }

    fn shared_group_selection_request(
        &self,
        group_id: &str,
        sender_id: &str,
        state: &ramflux_crypto::VerifiedGroupState,
    ) -> Result<SelectionRequest, SdkError> {
        let sender = self.local_device_identity(sender_id)?;
        let selected = self.shared_group_selected_devices(state)?;
        let mut targets = Vec::new();
        for (root, devices) in selected {
            let manifest = self.account_db()?.load_actor_state::<SdkDeviceManifestResponse>(
                &format!("identity/manifest-root/{root}"),
            )?;
            for device_id in devices {
                targets.push(target_from_entry(
                    &root,
                    &device_id,
                    manifest.as_ref().and_then(|row| {
                        row.devices.iter().find(|device| device.device_id == device_id)
                    }),
                ));
            }
        }
        let source = self.cached_target(sender.root_commitment(), sender.device_id())?;
        finish_group_request(group_id, state.snapshot().epoch, source, targets)
    }

    fn legacy_group_selection_request(
        &self,
        group_id: &str,
        sender_id: &str,
    ) -> Result<SelectionRequest, SdkError> {
        let group = self.group_state(group_id)?;
        let source = TargetDevice {
            account_anchor: String::new(),
            device_id: sender_id.to_owned(),
            device_epoch: 0,
            declaration: None,
        };
        let targets = group
            .members
            .into_iter()
            .filter(|member| member != sender_id)
            .map(|member| TargetDevice {
                account_anchor: String::new(),
                device_id: member,
                device_epoch: 0,
                declaration: None,
            })
            .collect();
        finish_group_request(group_id, group.group_epoch, source, targets)
    }
}

fn request_from_manifest(
    scope: FanoutScope,
    kind: KindId,
    logical_event_id: &str,
    now_unix: u64,
    source_device_id: &str,
    manifest: &SdkDeviceManifestResponse,
) -> SelectionRequest {
    let root = manifest.principal_commitment.as_str();
    let source = target_from_entry(
        root,
        source_device_id,
        manifest.devices.iter().find(|device| device.device_id == source_device_id),
    );
    let targets = manifest
        .devices
        .iter()
        .filter(|device| device.device_id != source_device_id)
        .map(|device| target_from_entry(root, &device.device_id, Some(device)))
        .collect::<Vec<_>>();
    let mut devices = BTreeSet::from([source.key()]);
    devices.extend(targets.iter().map(TargetDevice::key));
    SelectionRequest {
        scope,
        kind,
        logical_event_id: logical_event_id.to_owned(),
        now_unix,
        source_compiled_support: COMPILED_LAYER,
        source,
        targets,
        membership: MembershipSnapshot { epoch: 0, devices },
        variant_counter_high_water: 0,
    }
}

fn finish_group_request(
    group_id: &str,
    epoch: u64,
    source: TargetDevice,
    targets: Vec<TargetDevice>,
) -> Result<SelectionRequest, SdkError> {
    let mut devices = BTreeSet::from([source.key()]);
    devices.extend(targets.iter().map(TargetDevice::key));
    Ok(SelectionRequest {
        scope: FanoutScope::Group,
        kind: KindId::KindMessage,
        logical_event_id: group_id.to_owned(),
        now_unix: unix_now()?,
        source_compiled_support: COMPILED_LAYER,
        source,
        targets,
        membership: MembershipSnapshot { epoch, devices },
        variant_counter_high_water: 0,
    })
}

#[cfg(test)]
#[path = "target_selection_tests.rs"]
mod tests;
