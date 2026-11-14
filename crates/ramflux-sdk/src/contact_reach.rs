// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified recipient state. A home signature cannot manufacture friendship or positive grants.
mod delivery;
mod group_binding;
mod group_join;
mod group_kick;
mod group_profile;
mod group_restrictions;
mod group_roster;
#[cfg(test)]
mod group_test_support;
mod inner;
mod projection;
mod verification;
use crate::SdkError;
pub use projection::{ConversationPermission, ConversationReach};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::{
    contact_reach::{
        Decision, MAX_STATE_BYTES, Reason, STATE_DOMAIN, StateManifest, StatePage, StateRecord,
        check_submission_time, verify_pages,
    },
    custody::{self, Envelope as Signed},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn refused(reason: Reason) -> SdkError {
    SdkError::ReachRefused(reason)
}
pub(crate) fn remote_result(
    result: ramflux_protocol::contact_reach::OperationResult,
) -> Result<ramflux_protocol::contact_reach::OperationResult, SdkError> {
    if let ramflux_protocol::contact_reach::OperationResult::Error {
        reason,
        retry_after_ms,
        current_revision,
    } = result
    {
        return Err(SdkError::ReachRemote { reason, retry_after_ms, current_revision });
    }
    Ok(result)
}
/// A completely verified home mirror, suitable for one atomic local projection.
pub struct VerifiedReachState {
    pub(crate) manifest: StateManifest,
    pub(crate) records: Vec<StateRecord>,
}
/// Independently pinned state-read context; none of these facts comes from the manifest itself.
#[derive(Clone, Copy)]
pub struct ReachReadContext<'a> {
    pub authority: &'a VerifiedRecord,
    pub device: &'a custody::DeviceRef,
    pub home_head_hash: &'a str,
    pub home_node_key: &'a str,
    pub minimum_revision: u64,
    pub now: u64,
}
impl VerifiedReachState {
    /// Verify all pages, audience, lease and every embedded original account signature.
    /// # Errors
    /// Refuses partial state, rollback, home-forged grants, mismatched placements and unsafe records.
    pub fn verify(
        manifest: &Signed<StateManifest>,
        pages: &[StatePage],
        context: ReachReadContext<'_>,
    ) -> Result<Self, SdkError> {
        let b = &manifest.body;
        let root = &context.authority.envelope().body.account_anchor;
        b.validate()?;
        check_submission_time(b.issued_at, b.expires_at, context.now)?;
        if &b.account_anchor != root
            || &b.requesting_device != context.device
            || b.home_head_hash != context.home_head_hash
            || b.revision < context.minimum_revision
            || b.authority_head_hash != custody::object_hash(context.authority.envelope())?
        {
            return Err(refused(Reason::HomeRollback));
        }
        if context.device.account_anchor == *root {
            context.authority.authorize(context.device, "sync", context.now)?;
        } else {
            context.authority.authorize_primary_management(
                context.device,
                "contact_consent",
                context.now,
            )?;
        }
        ramflux_crypto::verify_canonical_signature(
            &custody::signing_bytes(STATE_DOMAIN, b)?,
            &manifest.signature,
            context.home_node_key,
        )?;
        let records = verify_pages(b, pages)?;
        let bases = verification::verify_records(&records, b, &context)?;
        verification::verify_placements(&records, b, &bases)?;
        Ok(Self { manifest: b.clone(), records })
    }
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.manifest.revision
    }
    #[must_use]
    pub fn state_hash(&self) -> &str {
        &self.manifest.state_hash
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedReachState {
    root: String,
    revision: u64,
    admission_revision: u64,
    home_head_hash: String,
    state_hash: String,
    records: Vec<StateRecord>,
    restrictions: BTreeMap<String, StateRecord>,
    conflict: bool,
}
impl crate::RamfluxClient {
    /// Install verified state and independent restrictive floors in one account writer commit.
    /// This read does not bootstrap message/SelfSync erase floors or authorize new-device publication.
    /// # Errors
    /// Refuses account mismatch and rollback; an equal-revision content conflict is durably fenced.
    pub fn install_reach_state(&self, verified: VerifiedReachState) -> Result<(), SdkError> {
        let own = self.owned_device_identity()?;
        if own.root_commitment() != verified.manifest.account_anchor {
            return Err(refused(Reason::AnchorMismatch));
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            let previous: Option<SavedReachState> =
                db.client_record("reach", "state")?.map(serde_json::from_value).transpose()?;
            if let Some(saved) = &previous {
                if saved.root != verified.manifest.account_anchor
                    || saved.conflict
                    || verified.manifest.revision < saved.revision
                {
                    return Err(refused(Reason::HomeRollback));
                }
                if verified.manifest.revision == saved.revision {
                    if verified.manifest.state_hash == saved.state_hash {
                        return Ok(());
                    }
                    let mut fenced = saved.clone();
                    fenced.conflict = true;
                    db.persist_client_record("reach", "state", &serde_json::to_value(fenced)?)?;
                    // Return after commit below; a callback error would roll the restrictive fence back.
                    return Ok(());
                }
            }
            let restrictions = match merge_restrictions(
                previous.as_ref().map_or_else(BTreeMap::new, |p| p.restrictions.clone()),
                &verified.records,
            ) {
                Ok(restrictions) => restrictions,
                Err(SdkError::ReachRefused(Reason::HomeFork)) => {
                    let mut fenced = previous.ok_or_else(|| refused(Reason::HomeFork))?;
                    fenced.conflict = true;
                    db.persist_client_record("reach", "state", &serde_json::to_value(fenced)?)?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let saved = SavedReachState {
                root: verified.manifest.account_anchor,
                revision: verified.manifest.revision,
                admission_revision: verified.manifest.admission_revision,
                home_head_hash: verified.manifest.home_head_hash,
                state_hash: verified.manifest.state_hash,
                records: verified.records,
                restrictions,
                conflict: false,
            };
            db.persist_client_record("reach", "state", &serde_json::to_value(saved)?)?;
            Ok::<_, SdkError>(())
        })?;
        let saved: SavedReachState = serde_json::from_value(
            db.client_record("reach", "state")?
                .ok_or_else(|| refused(Reason::ForeignSnapshotInvalid))?,
        )?;
        if saved.conflict {
            return Err(refused(Reason::HomeFork));
        }
        self.stage_reach_group_repairs()?;
        Ok(())
    }
}

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
fn merge_restrictions(
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
        if !matches!(
            record,
            StateRecord::Block { .. }
                | StateRecord::Decline { .. }
                | StateRecord::Floor { .. }
                | StateRecord::Conflict { .. }
                | StateRecord::Retirement { group_floor: Some(_), .. }
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
    for record in records {
        let StateRecord::Retirement { subject, revision, update, .. } = record else {
            continue;
        };
        if update.body.decision != Decision::Unblock
            || *revision <= denial_floors.get(&subject.key()?).copied().unwrap_or(0)
        {
            continue;
        }
        retained.remove(&serde_json::to_string(&("block", subject.key()?))?);
        let floor_key = serde_json::to_string(&("floor", subject.key()?))?;
        if let Some(StateRecord::Floor { revision: floor_revision, denied, .. }) =
            retained.get_mut(&floor_key)
            && *floor_revision <= *revision
        {
            *denied = false;
        }
    }
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
