// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::custody::{MAX_LAYER_DECLARATION_VALIDITY_SECONDS, MESSAGE_LAYER_FLOOR};
use ramflux_protocol::message::KindId;
use ramflux_protocol::message::registry::{COMPILED_LAYER, PROFILE_FLOOR};
use ramflux_protocol::schema_profile::{ACTIVE_STORAGE_GENERATION, MESSAGE_SCHEMA_V1_GENERATION};

const NOW: u64 = 2_000_000;
const ISSUE: u64 = NOW - 1_000;
const FRESH_EXPIRY: u64 = NOW + 1_000;
const STALE_EXPIRY: u64 = NOW - 1;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn view(max_layer: u32, issued_at: u64, expires_at: u64) -> LayerView {
    LayerView { max_layer, issued_at, expires_at }
}

fn device(id: &str, declaration: Option<LayerView>) -> TargetDevice {
    TargetDevice {
        account_anchor: "anchor".into(),
        device_id: id.into(),
        device_epoch: 1,
        declaration,
    }
}

fn membership(epoch: u64, devices: &[TargetDevice]) -> MembershipSnapshot {
    MembershipSnapshot { epoch, devices: devices.iter().map(TargetDevice::key).collect() }
}

fn request(
    scope: FanoutScope,
    kind: KindId,
    source: TargetDevice,
    targets: Vec<TargetDevice>,
    now: u64,
) -> SelectionRequest {
    let mut members = vec![source.clone()];
    members.extend(targets.iter().cloned());
    SelectionRequest {
        scope,
        kind,
        logical_event_id: "event-1".into(),
        now_unix: now,
        source_compiled_support: COMPILED_LAYER,
        membership: membership(7, &members),
        source,
        targets,
        variant_counter_high_water: 0,
    }
}

fn fresh_device(id: &str) -> TargetDevice {
    device(id, Some(view(MESSAGE_LAYER_FLOOR, ISSUE, FRESH_EXPIRY)))
}

fn stale_device(id: &str) -> TargetDevice {
    device(id, Some(view(MESSAGE_LAYER_FLOOR, ISSUE, STALE_EXPIRY)))
}

fn missing_device(id: &str) -> TargetDevice {
    device(id, None)
}

fn representation<'a>(
    plan: &'a SelectionPlan,
    contains: &str,
) -> Result<&'a Representation, Box<dyn std::error::Error>> {
    plan.representations
        .iter()
        .find(|row| row.targets.iter().any(|target| target.device_id == contains))
        .ok_or_else(|| "missing representation".into())
}

fn assert_typed(encoding: Encoding, kind: KindId, layer: u32) {
    assert_eq!(encoding, Encoding::Typed { kind, layer });
}

fn assert_peer_upgrade(error: &SdkError) -> TestResult {
    match error {
        SdkError::LocalBusRefused { code, .. } if code == "PeerUpgradeRequired" => Ok(()),
        other => Err(format!("expected PeerUpgradeRequired, got {other}").into()),
    }
}

fn assert_not_layer_unavailable(error: &SdkError) {
    let text = error.to_string();
    assert!(!text.contains("LayerUnavailable"), "{text}");
}

#[test]
fn group_fresh_cohort_minimum() -> TestResult {
    let alice = fresh_device("alice");
    let bob = fresh_device("bob");
    let carol = stale_device("carol");
    let plan = select(&request(
        FanoutScope::Group,
        KindId::KindMessage,
        alice.clone(),
        vec![alice.clone(), bob.clone(), carol.clone()],
        NOW,
    ))?;
    assert_eq!(plan.logical_event_id, "event-1");
    assert_eq!(plan.fresh_cohort_layer, Some(PROFILE_FLOOR));
    assert_eq!(plan.representations.len(), 2);
    let fresh = representation(&plan, "alice")?;
    let floor = representation(&plan, "carol")?;
    assert_eq!(fresh.selected_layer, PROFILE_FLOOR);
    assert_eq!(floor.selected_layer, PROFILE_FLOOR);
    assert_ne!(fresh.variant_counter, floor.variant_counter);
    assert!(fresh.targets.iter().any(|target| target.device_id == "bob"));
    assert!(!fresh.targets.iter().any(|target| target.device_id == "carol"));
    assert_eq!(floor.targets.len(), 1);
    assert_typed(fresh.encoding, KindId::KindMessage, PROFILE_FLOOR);
    assert_typed(floor.encoding, KindId::KindMessage, PROFILE_FLOOR);
    Ok(())
}

#[test]
fn own_and_dm_fresh_minimum() -> TestResult {
    let source = fresh_device("phone");
    let sibling = stale_device("laptop");
    let own = select(&request(
        FanoutScope::OwnCopy,
        KindId::KindMessage,
        source.clone(),
        vec![fresh_device("watch"), sibling.clone()],
        NOW,
    ))?;
    let dm = select(&request(
        FanoutScope::Dm,
        KindId::KindMessage,
        source,
        vec![fresh_device("peer-phone"), sibling],
        NOW,
    ))?;
    assert_eq!(own.scope, FanoutScope::OwnCopy);
    assert_eq!(dm.scope, FanoutScope::Dm);
    assert_eq!(own.logical_event_id, dm.logical_event_id);
    assert_eq!(own.fresh_cohort_layer, Some(PROFILE_FLOOR));
    assert_eq!(dm.fresh_cohort_layer, Some(PROFILE_FLOOR));
    let own_fresh = representation(&own, "watch")?;
    let own_floor = representation(&own, "laptop")?;
    let dm_fresh = representation(&dm, "peer-phone")?;
    let dm_floor = representation(&dm, "laptop")?;
    assert_ne!(own_fresh.variant_counter, own_floor.variant_counter);
    assert_ne!(dm_fresh.variant_counter, dm_floor.variant_counter);
    assert!(!own_fresh.targets.iter().any(|target| target.device_id == "laptop"));
    assert!(!dm_fresh.targets.iter().any(|target| target.device_id == "laptop"));
    let at_expiry = select(&request(
        FanoutScope::Dm,
        KindId::KindMessage,
        fresh_device("phone"),
        vec![device("peer", Some(view(PROFILE_FLOOR, ISSUE, NOW)))],
        NOW,
    ))?;
    assert!(representation(&at_expiry, "peer").is_ok());
    assert_eq!(at_expiry.representations.len(), 1);
    Ok(())
}

#[test]
fn membership_change_rebuilds_unsubmitted_representation() -> TestResult {
    let source = fresh_device("owner");
    let first = request(
        FanoutScope::Group,
        KindId::KindMessage,
        source.clone(),
        vec![fresh_device("alice"), fresh_device("bob")],
        NOW,
    );
    let plan = select(&first)?;
    let unchanged = recheck(&plan, &first)?;
    assert_eq!(unchanged.variant_counter_high_water, plan.variant_counter_high_water);
    let original = plan.representations.first().ok_or("fresh variant")?;
    let kept = unchanged.representations.first().ok_or("unchanged variant")?;
    assert_eq!(kept.variant_counter, original.variant_counter);
    let mut changed = first.clone();
    changed.targets.pop();
    changed.membership = membership(8, &[source.clone(), fresh_device("alice")]);
    let rebuilt = recheck(&plan, &changed)?;
    assert_eq!(rebuilt.logical_event_id, plan.logical_event_id);
    assert_ne!(rebuilt.variant_counter_high_water, plan.variant_counter_high_water);
    assert!(rebuilt.variant_counter_high_water > plan.variant_counter_high_water);
    assert!(
        !rebuilt
            .representations
            .iter()
            .any(|row| { row.targets.iter().any(|target| target.device_id == "bob") })
    );
    assert!(rebuilt.representations.iter().all(|row| {
        !plan.representations.iter().any(|old| old.variant_counter == row.variant_counter)
    }));
    Ok(())
}

#[test]
fn downgrade_does_not_execute_structural_control() -> TestResult {
    for kind in [KindId::KindDelete, KindId::KindEdit, KindId::KindReaction, KindId::KindControl] {
        assert_typed(encoding_for(kind, PROFILE_FLOOR)?, kind, PROFILE_FLOOR);
        assert_eq!(encoding_for(kind, PROFILE_FLOOR - 1)?, Encoding::PeerUpgradeRequired);
        let plan = select(&request(
            FanoutScope::Group,
            kind,
            fresh_device("owner"),
            vec![fresh_device("alice"), stale_device("bob"), missing_device("carol")],
            NOW,
        ))?;
        for row in &plan.representations {
            assert_typed(row.encoding, kind, PROFILE_FLOOR);
        }
    }
    let refused = select(&SelectionRequest {
        source_compiled_support: PROFILE_FLOOR - 1,
        ..request(
            FanoutScope::Dm,
            KindId::KindDelete,
            fresh_device("phone"),
            vec![fresh_device("peer")],
            NOW,
        )
    });
    match refused {
        Err(error) => {
            assert_peer_upgrade(&error)?;
            assert_not_layer_unavailable(&error);
        }
        Ok(_) => return Err("layer-1-only client must fail admission".into()),
    }
    Ok(())
}

#[test]
fn offline_over_24h_still_receives_floor_in_dm_group_and_own_copy() -> TestResult {
    let issued = NOW.saturating_sub(MAX_LAYER_DECLARATION_VALIDITY_SECONDS + 5);
    let expired = issued + MAX_LAYER_DECLARATION_VALIDITY_SECONDS;
    assert!(NOW > expired);
    let stale = device("stale", Some(view(PROFILE_FLOOR, issued, expired)));
    let fresh = fresh_device("fresh");
    for scope in [FanoutScope::Dm, FanoutScope::Group, FanoutScope::OwnCopy] {
        let plan = select(&request(
            scope,
            KindId::KindDelete,
            fresh_device("source"),
            vec![fresh.clone(), stale.clone()],
            NOW,
        ))?;
        assert_eq!(plan.scope, scope);
        assert_eq!(plan.logical_event_id, "event-1");
        let fresh_row = representation(&plan, "fresh")?;
        let floor_row = representation(&plan, "stale")?;
        assert_eq!(fresh_row.selected_layer, PROFILE_FLOOR);
        assert_eq!(floor_row.selected_layer, PROFILE_FLOOR);
        assert_ne!(fresh_row.variant_counter, floor_row.variant_counter);
        assert!(!fresh_row.targets.iter().any(|target| target.device_id == "stale"));
        assert_typed(floor_row.encoding, KindId::KindDelete, PROFILE_FLOOR);
        assert_eq!(plan.representations.len(), 2);
    }
    Ok(())
}

#[test]
fn schema_gate_off_skips_candidate_plan() -> TestResult {
    assert!(!schema_v1_selected());
    assert_eq!(ACTIVE_STORAGE_GENERATION, 0);
    assert_eq!(MESSAGE_SCHEMA_V1_GENERATION, 1);
    let mut built = false;
    let plan = RamfluxClient::candidate_target_plan(|| {
        built = true;
        Ok(request(
            FanoutScope::Dm,
            KindId::KindMessage,
            fresh_device("phone"),
            vec![fresh_device("peer")],
            NOW,
        ))
    })?;
    assert!(plan.is_none());
    assert!(!built, "gate-off adapters must not construct a selection request");
    Ok(())
}
