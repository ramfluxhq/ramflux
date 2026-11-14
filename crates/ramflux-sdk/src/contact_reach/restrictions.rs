// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent denials and signed clearances survive canonical mirror replacement.
use super::{group_restrictions, refused};
use crate::SdkError;
use ramflux_protocol::contact_reach::{Decision, MAX_STATE_BYTES, Reason, StateRecord};
use std::collections::BTreeMap;

fn denial_revision(record: &StateRecord) -> Result<Option<(String, u64)>, SdkError> {
    Ok(match record {
        StateRecord::Block { subject, update } => Some((
            subject.key()?,
            update
                .body
                .expected_revision
                .checked_add(1)
                .ok_or_else(|| refused(Reason::ForeignSnapshotInvalid))?,
        )),
        StateRecord::Floor { subject, revision, denied: true, .. } => {
            Some((subject.key()?, *revision))
        }
        _ => None,
    })
}
pub(super) fn merge_restrictions(
    mut retained: BTreeMap<String, StateRecord>,
    records: &[StateRecord],
) -> Result<BTreeMap<String, StateRecord>, SdkError> {
    let mut denial_floors: BTreeMap<String, u64> = BTreeMap::new();
    for record in retained.values().chain(records.iter()) {
        if let Some((key, revision)) = denial_revision(record)? {
            denial_floors
                .entry(key)
                .and_modify(|old| *old = (*old).max(revision))
                .or_insert(revision);
        }
    }
    for record in records {
        retain_clearance(&mut retained, record)?;
        if !matches!(
            record,
            StateRecord::Block { .. }
                | StateRecord::Decline { .. }
                | StateRecord::Floor { .. }
                | StateRecord::Conflict { .. }
                | StateRecord::Retirement { .. }
        ) {
            continue;
        }
        let key = serde_json::to_string(&record.order_key()?)?;
        if matches!(record, StateRecord::Retirement { group_floor: Some(_), .. }) {
            let merged = group_restrictions::merge(retained.get(&key), record)?;
            retained.insert(key, merged);
            continue;
        }
        let merged = match (retained.get(&key), record) {
            (
                Some(StateRecord::Retirement { revision: old, update: old_update, .. }),
                StateRecord::Retirement { revision: next, update: next_update, .. },
            ) => {
                if old == next && old_update != next_update {
                    return Err(refused(Reason::HomeFork));
                }
                if old > next {
                    retained
                        .get(&key)
                        .ok_or_else(|| refused(Reason::ForeignSnapshotInvalid))?
                        .clone()
                } else {
                    record.clone()
                }
            }
            (
                Some(StateRecord::Floor { subject, revision, denied, erase_generation, erased }),
                StateRecord::Floor {
                    revision: next_revision,
                    denied: next_denied,
                    erase_generation: next_generation,
                    erased: next_erased,
                    ..
                },
            ) => StateRecord::Floor {
                subject: subject.clone(),
                revision: (*revision).max(*next_revision),
                denied: *denied || *next_denied,
                erase_generation: (*erase_generation).max(*next_generation),
                erased: *erased || *next_erased,
            },
            (
                Some(StateRecord::Block { update: old, .. }),
                StateRecord::Block { update: next, .. },
            ) if old.body.expected_revision > next.body.expected_revision => {
                retained.get(&key).ok_or_else(|| refused(Reason::ForeignSnapshotInvalid))?.clone()
            }
            (
                Some(StateRecord::Decline { until: old, .. }),
                StateRecord::Decline { until: next, .. },
            ) if old > next => {
                retained.get(&key).ok_or_else(|| refused(Reason::ForeignSnapshotInvalid))?.clone()
            }
            (Some(StateRecord::Conflict { .. }), StateRecord::Conflict { .. }) => {
                retained.get(&key).ok_or_else(|| refused(Reason::ForeignSnapshotInvalid))?.clone()
            }
            _ => record.clone(),
        };
        retained.insert(key, merged);
    }
    apply_clearances(&mut retained, records, &denial_floors)?;
    if retained.len() > 8192
        || ramflux_protocol::canonical_json_bytes(&retained)?.len() > MAX_STATE_BYTES
    {
        return Err(refused(Reason::ForeignCapacity));
    }
    group_restrictions::verify_bindings(
        records
            .iter()
            .filter(|record| !matches!(record, StateRecord::Retirement { .. }))
            .chain(retained.values()),
    )?;
    Ok(retained)
}

/// Old backup witnesses may precede local floors; keep the strongest F and newest signed control.
pub(super) fn merge_restored(
    retained: BTreeMap<String, StateRecord>,
    records: &[StateRecord],
) -> Result<BTreeMap<String, StateRecord>, SdkError> {
    let mut groups = BTreeMap::new();
    for record in retained.values().chain(records.iter()) {
        let StateRecord::Retirement { group_floor: Some(next), revision: next_revision, .. } =
            record
        else {
            continue;
        };
        let key = record.order_key()?;
        let merged = match groups.get(&key) {
            Some(
                previous @ StateRecord::Retirement {
                    group_floor: Some(old),
                    revision: old_revision,
                    ..
                },
            ) if old.floor_epoch > next.floor_epoch
                || old.floor_epoch == next.floor_epoch && old_revision > next_revision =>
            {
                group_restrictions::merge(Some(record), previous)?
            }
            previous => group_restrictions::merge(previous, record)?,
        };
        groups.insert(key, merged);
    }
    let normalized: Vec<_> = records
        .iter()
        .filter(|record| !matches!(record, StateRecord::Retirement { group_floor: Some(_), .. }))
        .cloned()
        .chain(groups.into_values())
        .collect();
    merge_restrictions(retained, &normalized)
}

fn retain_clearance(
    retained: &mut BTreeMap<String, StateRecord>,
    next: &StateRecord,
) -> Result<(), SdkError> {
    let StateRecord::Retirement { subject, update, group_floor: None, .. } = next else {
        return Ok(());
    };
    if update.body.decision != Decision::Unblock {
        return Ok(());
    }
    let key = serde_json::to_string(&("clearance", subject.key()?))?;
    if let Some(StateRecord::Retirement { update: old, .. }) = retained.get(&key) {
        if old.body.expected_revision > update.body.expected_revision {
            return Ok(());
        }
        if old.body.expected_revision == update.body.expected_revision && old != update {
            return Err(refused(Reason::HomeFork));
        }
    }
    retained.insert(key, next.clone());
    Ok(())
}
fn apply_clearances(
    retained: &mut BTreeMap<String, StateRecord>,
    records: &[StateRecord],
    denial_floors: &BTreeMap<String, u64>,
) -> Result<(), SdkError> {
    // Keep only selectors here; mutation below cannot retain borrowed map entries.
    let mut clearances = BTreeMap::new();
    for record in records.iter().chain(retained.values()) {
        if let StateRecord::Retirement { subject, revision, update, .. } = record
            && update.body.decision == Decision::Unblock
        {
            clearances
                .entry(subject.key()?)
                .and_modify(|old: &mut u64| *old = (*old).max(*revision))
                .or_insert(*revision);
        }
    }
    for (subject, revision) in clearances {
        if revision <= denial_floors.get(&subject).copied().unwrap_or(0) {
            continue;
        }
        retained.remove(&serde_json::to_string(&("block", &subject))?);
        let floor_key = serde_json::to_string(&("floor", subject))?;
        if let Some(StateRecord::Floor { revision: floor_revision, denied, .. }) =
            retained.get_mut(&floor_key)
            && *floor_revision <= revision
        {
            *denied = false;
        }
    }
    Ok(())
}
