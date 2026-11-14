// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent local group floors survive omission and clear blocks only from newer signed control.
use super::refused;
use crate::SdkError;
use ramflux_protocol::contact_reach::{Reason, StateRecord, same_group_binding};
pub(super) fn merge(
    previous: Option<&StateRecord>,
    next: &StateRecord,
) -> Result<StateRecord, SdkError> {
    let StateRecord::Retirement { subject, revision, update, group_floor: Some(next_floor) } = next
    else {
        return Err(refused(Reason::ForeignSnapshotInvalid));
    };
    let Some(StateRecord::Retirement {
        subject: old_subject, group_floor: Some(old_floor), ..
    }) = previous
    else {
        return Ok(next.clone());
    };
    if !same_group_binding(subject, old_subject) {
        return Err(refused(Reason::ReachRouteInvalid));
    }
    if next_floor.floor_epoch < old_floor.floor_epoch {
        return Err(refused(Reason::HomeRollback));
    }
    let mut floor = next_floor.clone();
    match (&old_floor.block_control, &next_floor.block_control) {
        (Some(old), Some(new))
            if old.body.expected_revision == new.body.expected_revision && old != new =>
        {
            return Err(refused(Reason::HomeFork));
        }
        (Some(old), Some(new)) if old.body.expected_revision > new.body.expected_revision => {
            floor.block_control = Some(old.clone());
        }
        (Some(old), None) => floor.block_control = Some(old.clone()),
        _ => {}
    }
    // This is a local restrictive proof merge, separate from the canonical mirrored records/hash.
    let revision = if let Some(control) = &floor.block_control {
        control
            .body
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| refused(Reason::ForeignSnapshotInvalid))?
            .max(*revision)
    } else {
        *revision
    };
    floor.validate(update)?;
    Ok(StateRecord::Retirement {
        subject: subject.clone(),
        revision,
        update: update.clone(),
        group_floor: Some(floor),
    })
}

#[cfg(test)]
mod tests;
