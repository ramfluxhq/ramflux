// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate dm/group/own recipient target selection (S10a P05).
//!
//! Adapters call [`RamfluxClient::candidate_target_plan`] behind the existing
//! generation-0 schema gate. Live producers stay unfed until activation.
use crate::client::identity_authority::VerifiedLayerRoster;
use crate::prekey::SdkDeviceManifestResponse;
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::custody::SignedLayerDeclaration;
use ramflux_protocol::message::KindId;
use ramflux_protocol::message::registry::{COMPILED_LAYER, PROFILE_FLOOR, kind_binding};
use ramflux_protocol::schema_profile::schema_v1_live;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Send fan-out that applies the same fresh-cohort rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FanoutScope {
    Dm,
    Group,
    OwnCopy,
}

/// Verified declaration fields used for above-floor selection.
///
/// Fields stay private so a fresh view cannot be built from unverified bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LayerView {
    max_layer: u32,
    issued_at: u64,
    expires_at: u64,
}

impl LayerView {
    fn from_verified(signed: &SignedLayerDeclaration) -> Self {
        Self {
            max_layer: signed.declaration.max_layer,
            issued_at: signed.declaration.issued_at,
            expires_at: signed.declaration.expires_at,
        }
    }

    /// Inclusive selection window; P04 already enforced layer bounds and the 24 h cap.
    #[must_use]
    fn is_fresh(self, now: u64) -> bool {
        self.issued_at <= now && now <= self.expires_at
    }
}

/// One recipient device plus an optional current verified declaration.
///
/// A declaration is present only when the constructor received a [`VerifiedLayerRoster`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetDevice {
    account_anchor: String,
    device_id: String,
    device_epoch: u64,
    declaration: Option<LayerView>,
}

impl TargetDevice {
    /// Device without a verified declaration (legacy, missing, or refused authority).
    fn without_declaration(account_anchor: String, device_id: String, device_epoch: u64) -> Self {
        Self { account_anchor, device_id, device_epoch, declaration: None }
    }

    /// Layer and epoch come only from a P04-verified roster. Unverified bytes never enter.
    fn from_verified_roster(
        root: &str,
        device_id: &str,
        roster: Option<&VerifiedLayerRoster>,
    ) -> Self {
        let Some(roster) = roster else {
            return Self::without_declaration(root.to_owned(), device_id.to_owned(), 0);
        };
        let device = roster.device(device_id);
        Self {
            account_anchor: root.to_owned(),
            device_id: device_id.to_owned(),
            device_epoch: device.map_or(0, |row| row.device_epoch),
            declaration: device
                .and_then(|row| row.message_layer.as_ref())
                .map(LayerView::from_verified),
        }
    }

    fn key(&self) -> TargetKey {
        TargetKey {
            account_anchor: self.account_anchor.clone(),
            device_id: self.device_id().to_owned(),
            device_epoch: self.device_epoch(),
        }
    }

    #[must_use]
    pub(crate) fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub(crate) fn device_epoch(&self) -> u64 {
        self.device_epoch
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
pub(crate) fn schema_v1_selected() -> bool {
    schema_v1_live()
}

/// Refuse effectful generated entry points before any local allocation or write.
pub(crate) fn require_schema_v1() -> Result<(), SdkError> {
    if !schema_v1_selected() {
        return Err(SdkError::GeneratedRefused {
            code: crate::error::GeneratedRefusalCode::Content,
            reason: "generated profile is not selected".into(),
        });
    }
    Ok(())
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
    *counter = counter.checked_add(1).ok_or_else(counter_overflow)?;
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

fn counter_overflow() -> SdkError {
    SdkError::LocalBusRefused {
        code: "ValidationFailed".into(),
        message: "variant counter overflow".into(),
        body: Box::new(json!({})),
    }
}

fn unix_now() -> Result<u64, SdkError> {
    u64::try_from(crate::time::now_unix_timestamp()).map_err(|_| SdkError::CustodySetupInvalid)
}

/// Map a live send route onto the inner kind used for candidate encoding.
#[must_use]
pub(crate) fn kind_id_for_route(kind: &crate::client::routed::Kind) -> KindId {
    match kind {
        crate::client::routed::Kind::Control | crate::client::routed::Kind::GroupControl => {
            KindId::KindControl
        }
        crate::client::routed::Kind::Receipt => KindId::KindReceipt,
        crate::client::routed::Kind::Direct | crate::client::routed::Kind::GroupMessage => {
            KindId::KindMessage
        }
    }
}

/// Select, then re-read membership and recheck so a submit-time change rebuilds counters.
fn select_with_current_membership(
    build: impl Fn() -> Result<SelectionRequest, SdkError>,
) -> Result<SelectionPlan, SdkError> {
    let plan = select(&build()?)?;
    recheck(&plan, &build()?)
}

/// Source-qualified group event id (OV-P05-L1). Never `group_id`: that key collapses
/// every message in the group onto one fresh-cohort event.
pub(crate) fn group_logical_event_id(
    group_id: &str,
    message_id: Option<&str>,
) -> Result<String, SdkError> {
    let id = match message_id {
        Some(id) if !id.is_empty() => id.to_owned(),
        _ => crate::new_surface_message_id()?,
    };
    if id == group_id {
        return Err(SdkError::LocalBus(
            "group logical_event_id must be the message id, not group_id".into(),
        ));
    }
    Ok(id)
}

impl RamfluxClient {
    /// Run candidate selection only when the live profile is message schema v1.
    ///
    /// The request closure is skipped while the gate is off so live send bytes
    /// stay unchanged. When the gate is on, membership is read twice: once to
    /// select, then again so [`recheck`] sees the current roster.
    /// # Errors
    /// Propagates request construction or [`select`] failures when the gate is on.
    pub(crate) fn candidate_target_plan(
        build: impl Fn() -> Result<SelectionRequest, SdkError>,
    ) -> Result<Option<SelectionPlan>, SdkError> {
        if !schema_v1_selected() {
            return Ok(None);
        }
        Ok(Some(select_with_current_membership(build)?))
    }

    pub(crate) fn dm_selection_request(
        &self,
        message: &crate::GatewayDirectMessage,
        kind: KindId,
    ) -> Result<SelectionRequest, SdkError> {
        let local = self.owned_device_identity()?;
        let recipient = Self::qualified_recipient(message)?;
        let (root, device) =
            ramflux_protocol::parse_qualified_device_id(&recipient)?.ok_or_else(|| {
                crate::client::identity_authority::invalid("recipient device required")
            })?;
        self.pair_selection_request(
            FanoutScope::Dm,
            kind,
            &message.message_id,
            (local.root_commitment(), local.device_id()),
            (&root, &device),
        )
    }

    pub(crate) fn own_copy_selection_request(
        logical_event_id: &str,
        source_device_id: &str,
        manifest: &SdkDeviceManifestResponse,
        kind: KindId,
    ) -> Result<SelectionRequest, SdkError> {
        let now = unix_now()?;
        let roster = VerifiedLayerRoster::verify(manifest, now).ok();
        let root = manifest.principal_commitment.as_str();
        let source = TargetDevice::from_verified_roster(root, source_device_id, roster.as_ref());
        let targets = manifest
            .devices
            .iter()
            .filter(|device| device.device_id != source_device_id)
            .map(|device| {
                TargetDevice::from_verified_roster(root, &device.device_id, roster.as_ref())
            })
            .collect::<Vec<_>>();
        let mut devices = BTreeSet::from([source.key()]);
        devices.extend(targets.iter().map(TargetDevice::key));
        Ok(SelectionRequest {
            scope: FanoutScope::OwnCopy,
            kind,
            logical_event_id: logical_event_id.to_owned(),
            now_unix: now,
            source_compiled_support: COMPILED_LAYER,
            source,
            targets,
            membership: MembershipSnapshot { epoch: 0, devices },
            variant_counter_high_water: 0,
        })
    }

    pub(crate) fn group_selection_request(
        &self,
        group_id: &str,
        sender_id: &str,
        logical_event_id: &str,
        kind: KindId,
    ) -> Result<SelectionRequest, SdkError> {
        if let Some(state) = self.account_db()?.shared_group_state(group_id)? {
            return self.shared_group_selection_request(
                group_id,
                sender_id,
                logical_event_id,
                kind,
                &state,
            );
        }
        self.legacy_group_selection_request(group_id, sender_id, logical_event_id, kind)
    }

    fn pair_selection_request(
        &self,
        scope: FanoutScope,
        kind: KindId,
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
            kind,
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
        Ok(TargetDevice::from_verified_roster(root, device_id, self.cached_roster(root)?.as_ref()))
    }

    /// A refused cache is stale for that member's layer plan.
    fn cached_roster(&self, root: &str) -> Result<Option<VerifiedLayerRoster>, SdkError> {
        roster_from_authority_result(self.current_custody_authority(root, unix_now()?))
    }

    fn shared_group_selection_request(
        &self,
        _group_id: &str,
        sender_id: &str,
        logical_event_id: &str,
        kind: KindId,
        state: &ramflux_crypto::VerifiedGroupState,
    ) -> Result<SelectionRequest, SdkError> {
        let sender = self.local_device_identity(sender_id)?;
        let now = unix_now()?;
        let mut rosters = BTreeMap::new();
        let mut manifests = BTreeMap::new();
        for root in state
            .view()
            .members
            .iter()
            .map(|member| member.identity.root_commitment.as_str())
            .collect::<BTreeSet<_>>()
        {
            let roster = self.cached_roster(root)?;
            if let Some(roster) = roster.as_ref() {
                manifests.insert(root.to_owned(), roster.group_devices(now));
            } else if !self.custody_mode_observed(root)?
                && let Some(legacy) = self.observed_device_set(root)?
            {
                manifests.insert(
                    root.to_owned(),
                    legacy
                        .devices
                        .iter()
                        .filter(|device| device.status == ramflux_protocol::DeviceSetStatus::Active)
                        .map(|device| device.device_id.clone())
                        .collect(),
                );
            }
            rosters.insert(root.to_owned(), roster);
        }
        // A refused cache retains only explicit signed members as stale layer targets.
        // Native routing and sealing keep their independent current-authority checks.
        let selected = crate::client::shared_group::select_layer_devices(state.view(), &manifests);
        let mut targets = Vec::new();
        for (root, devices) in selected {
            let roster = rosters.get(&root).and_then(Option::as_ref);
            for device_id in devices {
                if root == sender.root_commitment() && device_id == sender.device_id() {
                    continue;
                }
                targets.push(TargetDevice::from_verified_roster(&root, &device_id, roster));
            }
        }
        let source = self.cached_target(sender.root_commitment(), sender.device_id())?;
        finish_group_request(logical_event_id, kind, state.snapshot().epoch, source, targets)
    }

    fn legacy_group_selection_request(
        &self,
        group_id: &str,
        sender_id: &str,
        logical_event_id: &str,
        kind: KindId,
    ) -> Result<SelectionRequest, SdkError> {
        let group = self.group_state(group_id)?;
        let source = TargetDevice::without_declaration(String::new(), sender_id.to_owned(), 0);
        let targets = group
            .members
            .into_iter()
            .filter(|member| member != sender_id)
            .map(|member| TargetDevice::without_declaration(String::new(), member, 0))
            .collect();
        finish_group_request(logical_event_id, kind, group.group_epoch, source, targets)
    }
}

fn finish_group_request(
    logical_event_id: &str,
    kind: KindId,
    epoch: u64,
    source: TargetDevice,
    mut targets: Vec<TargetDevice>,
) -> Result<SelectionRequest, SdkError> {
    let source_key = source.key();
    targets.retain(|target| target.key() != source_key);
    let mut devices = BTreeSet::from([source_key]);
    devices.extend(targets.iter().map(TargetDevice::key));
    Ok(SelectionRequest {
        scope: FanoutScope::Group,
        kind,
        logical_event_id: logical_event_id.to_owned(),
        now_unix: unix_now()?,
        source_compiled_support: COMPILED_LAYER,
        source,
        targets,
        membership: MembershipSnapshot { epoch, devices },
        variant_counter_high_water: 0,
    })
}

fn is_storage_or_io(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::Storage(_)
            | SdkError::Io(_)
            | SdkError::AccountDbNotUnlocked
            | SdkError::AccountNotOpen(_)
            | SdkError::AccountIndexNotOpen
            | SdkError::AccountManifestUnreadable
    )
}

pub(crate) fn roster_from_authority_result(
    result: Result<Option<VerifiedRecord>, SdkError>,
) -> Result<Option<VerifiedLayerRoster>, SdkError> {
    match result {
        Ok(record) => Ok(record.map(VerifiedLayerRoster::from_verified)),
        Err(error) if is_storage_or_io(&error) || matches!(error, SdkError::CustodyForkFenced) => {
            Err(error)
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
#[path = "target_selection_tests.rs"]
mod tests;
