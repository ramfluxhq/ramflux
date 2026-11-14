// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One recipient-owned group grant, bounded roster and canonical retained-denial record.
use super::{AccountReach, ReachClass};
use crate::contact_reach::{ReachError, Result, refuse, storage};
use ramflux_protocol::contact_reach::{
    GROUP_DENIAL_RESERVATION, GroupFloor, GroupRoster, Permissions, same_group_binding,
};
use ramflux_protocol::{
    contact_reach::{
        Admission, Decision, MAX_STATE_BYTES, MAX_SUBJECTS, OPERATION_HASH_DOMAIN, Placement,
        Reason, Route, StateRecord, Subject,
    },
    custody::{Envelope as Signed, framed_hash},
};
use std::collections::{BTreeMap, BTreeSet};
impl AccountReach {
    fn group_binding(&self, subject: &Subject) -> Result<()> {
        let Subject::Group { group_id, conversation_id, genesis_hash, .. } = subject else {
            return Err(refuse(Reason::ReachRouteInvalid));
        };
        for record in self.grants.values().chain(self.retirements.values()) {
            let (StateRecord::Grant { subject: existing, .. }
            | StateRecord::Retirement { subject: existing, .. }) = record
            else {
                continue;
            };
            if let Subject::Group {
                group_id: old,
                conversation_id: conversation,
                genesis_hash: genesis,
                ..
            } = existing
                && ((old == group_id && !same_group_binding(existing, subject))
                    || old != group_id
                        && (conversation == conversation_id || genesis == genesis_hash))
            {
                return Err(refuse(Reason::ReachRouteInvalid));
            }
        }
        Ok(())
    }
    fn group_floor(&self, key: &str) -> Result<Option<&GroupFloor>> {
        match self.retirements.get(key) {
            Some(StateRecord::Retirement { group_floor: Some(floor), .. }) => Ok(Some(floor)),
            None => Ok(None),
            Some(_) => Err(storage("invalid canonical group retirement")),
        }
    }
    pub(in crate::contact_reach) fn check_group_reservations(&self, positive: bool) -> Result<()> {
        let mut groups = BTreeSet::new();
        for record in self.grants.values().chain(self.retirements.values()) {
            let (StateRecord::Grant { subject, .. } | StateRecord::Retirement { subject, .. }) =
                record
            else {
                continue;
            };
            if matches!(subject, Subject::Group { .. }) {
                groups.insert(subject.key()?);
            }
        }
        let mut slots = self.retirements.keys().cloned().collect::<BTreeSet<_>>();
        slots.extend(groups.iter().cloned());
        if slots.len() > MAX_SUBJECTS
            || self.rosters.len() > MAX_SUBJECTS
            || ramflux_protocol::canonical_json_bytes(&self.rosters)?.len() > MAX_STATE_BYTES
        {
            return Err(refuse(Reason::ForeignCapacity));
        }
        let mut reserved = 0_usize;
        for key in groups {
            let mut actual = 0_usize;
            for row in [self.grants.get(&key), self.retirements.get(&key)].into_iter().flatten() {
                let entry = BTreeMap::from([(key.as_str(), row)]);
                actual = actual
                    .checked_add(ramflux_protocol::canonical_json_bytes(&entry)?.len())
                    .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
            }
            // The reservation includes every existing group byte and is a per-group ceiling.
            if actual > GROUP_DENIAL_RESERVATION {
                return Err(refuse(Reason::ForeignCapacity));
            }
            reserved = reserved
                .checked_add(GROUP_DENIAL_RESERVATION)
                .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        }
        if positive {
            let mut base = self.clone();
            base.grants.retain(|_, record| {
                !matches!(record, StateRecord::Grant { subject: Subject::Group { .. }, .. })
            });
            base.retirements.retain(|_, record| {
                !matches!(record, StateRecord::Retirement { subject: Subject::Group { .. }, .. })
            });
            let charged = ramflux_protocol::canonical_json_bytes(&base)?
                .len()
                .checked_add(reserved)
                .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
            if charged > MAX_STATE_BYTES || self.records()?.len() > 8192 {
                return Err(refuse(Reason::ForeignCapacity));
            }
        }
        Ok(())
    }
    pub(in crate::contact_reach) fn duplicate_group_allow(
        &self,
        update: &Signed<Admission>,
    ) -> Result<bool> {
        let Subject::Group { group_epoch, .. } = update.body.subject else {
            return Ok(false);
        };
        if update.body.decision != Decision::Allow {
            return Ok(false);
        }
        self.group_binding(&update.body.subject)?;
        let key = update.body.subject.key()?;
        if self
            .group_floor(&key)?
            .is_some_and(|floor| floor.blocked() || group_epoch <= floor.floor_epoch)
        {
            return Ok(false);
        }
        Ok(self.grants.get(&key).is_some_and(
            |record| matches!(record,StateRecord::Grant {update:old,..} if old==update),
        ))
    }
    pub(super) fn group_admission(&mut self, update: &Signed<Admission>) -> Result<()> {
        update.body.validate()?;
        self.group_binding(&update.body.subject)?;
        let key = update.body.subject.key()?;
        if self.duplicate_group_allow(update)? {
            return Ok(());
        }
        if update.body.expected_revision != self.admission_revision {
            return Err(ReachError::Revision(self.admission_revision));
        }
        let mut next = self.clone();
        let changed = next.group_transition(&key, update)?;
        if !changed {
            return Ok(());
        }
        next.admission_revision = next
            .admission_revision
            .checked_add(1)
            .filter(|value| *value <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        next.last_update = Some(update.clone());
        next.advance()?;
        next.check_group_reservations(update.body.decision == Decision::Allow)?;
        *self = next;
        Ok(())
    }
    fn group_transition(&mut self, key: &str, update: &Signed<Admission>) -> Result<bool> {
        let Subject::Group { group_epoch, .. } = update.body.subject else {
            return Err(refuse(Reason::ReachRouteInvalid));
        };
        match update.body.decision {
            Decision::Allow => {
                if self.group_floor(key)?.is_some_and(GroupFloor::blocked) {
                    return Err(refuse(Reason::ForeignReadRefused));
                }
                if self.grants.contains_key(key) {
                    return Err(refuse(Reason::ReachRouteInvalid));
                }
                if self.group_floor(key)?.is_some_and(|floor| group_epoch <= floor.floor_epoch) {
                    return Err(refuse(Reason::GroupEpochStale));
                }
                self.grants.insert(
                    key.into(),
                    StateRecord::Grant {
                        subject: update.body.subject.clone(),
                        permissions: Permissions::UNACCEPTED,
                        grant_until: 0,
                        update: update.clone(),
                    },
                );
                self.rosters.remove(key);
            }
            Decision::Revoke | Decision::Block => {
                return self.retire_group(key, update, group_epoch);
            }
            Decision::Unblock => {
                let Some(StateRecord::Retirement {
                    update: retired,
                    group_floor: Some(mut floor),
                    ..
                }) = self.retirements.get(key).cloned()
                else {
                    return Ok(false);
                };
                if !floor.blocked() {
                    return Ok(false);
                }
                if floor
                    .block_control
                    .as_ref()
                    .is_some_and(|old| old.body.expected_revision >= update.body.expected_revision)
                {
                    return Err(refuse(Reason::ReachRouteInvalid));
                }
                floor.block_control = Some(Box::new(update.clone()));
                self.save_group_retirement(key, &retired, update, *floor)?;
            }
            Decision::Decline => return Err(refuse(Reason::ReachRouteInvalid)),
        }
        Ok(true)
    }
    fn retire_group(
        &mut self,
        key: &str,
        update: &Signed<Admission>,
        group_epoch: u64,
    ) -> Result<bool> {
        if let Some(StateRecord::Grant { update: grant, .. }) = self.grants.remove(key) {
            let previous = self.group_floor(key)?.cloned();
            let roster_header = self.rosters.remove(key).map(|roster| Box::new(roster.header));
            let mut floor = GroupFloor {
                floor_epoch: group_epoch,
                grant: Some(Box::new(grant)),
                roster_header,
                block_control: if update.body.decision == Decision::Block {
                    Some(Box::new(update.clone()))
                } else {
                    previous.as_ref().and_then(|floor| floor.block_control.clone())
                },
            };
            floor.floor_epoch = floor
                .floor_epoch
                .max(
                    floor
                        .grant
                        .as_ref()
                        .and_then(|grant| {
                            if let Subject::Group { group_epoch, .. } = grant.body.subject {
                                Some(group_epoch)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0),
                )
                .max(floor.roster_header.as_ref().map_or(0, |header| header.body.group_epoch));
            if previous.as_ref().is_some_and(|old| floor.floor_epoch < old.floor_epoch) {
                return Err(storage("group retirement would lower a retained floor"));
            }
            self.save_group_retirement(key, update, update, floor)?;
        } else if update.body.decision == Decision::Block {
            let previous = self.retirements.get(key).cloned();
            if let Some(StateRecord::Retirement {
                update: retired,
                group_floor: Some(mut floor),
                ..
            }) = previous
            {
                if floor.blocked() {
                    return Ok(false);
                }
                if floor
                    .block_control
                    .as_ref()
                    .is_some_and(|old| old.body.expected_revision >= update.body.expected_revision)
                {
                    return Err(refuse(Reason::ReachRouteInvalid));
                }
                floor.block_control = Some(Box::new(update.clone()));
                self.save_group_retirement(key, &retired, update, *floor)?;
            } else {
                let floor = GroupFloor {
                    floor_epoch: group_epoch,
                    grant: None,
                    roster_header: None,
                    block_control: Some(Box::new(update.clone())),
                };
                self.save_group_retirement(key, update, update, floor)?;
                self.check_group_reservations(true)?;
            }
        } else {
            return Ok(false);
        }
        Ok(true)
    }
    fn save_group_retirement(
        &mut self,
        key: &str,
        retired: &Signed<Admission>,
        control: &Signed<Admission>,
        floor: GroupFloor,
    ) -> Result<()> {
        floor.validate(retired)?;
        let record = StateRecord::Retirement {
            subject: retired.body.subject.clone(),
            revision: control
                .body
                .expected_revision
                .checked_add(1)
                .ok_or_else(|| refuse(Reason::ForeignCapacity))?,
            update: retired.clone(),
            group_floor: Some(Box::new(floor)),
        };
        if ramflux_protocol::canonical_json_bytes(&record)?.len() > GROUP_DENIAL_RESERVATION {
            return Err(storage("group retirement exceeded its JOIN reservation"));
        }
        self.retirements.insert(key.into(), record);
        Ok(())
    }
    pub(in crate::contact_reach) fn group_roster(&mut self, roster: GroupRoster) -> Result<bool> {
        let key = serde_json::to_string(&serde_json::json!(["group", roster.header.body.group_id]))
            .map_err(storage)?;
        let Some(StateRecord::Grant { update: grant, .. }) = self.grants.get(&key) else {
            return Err(refuse(Reason::ReachRouteInvalid));
        };
        roster.validate(grant)?;
        if let Some(old) = self.rosters.get(&key) {
            if roster.header.body.group_epoch < old.header.body.group_epoch {
                return Err(refuse(Reason::GroupEpochStale));
            }
            if roster.header.body.group_epoch == old.header.body.group_epoch {
                if roster.header.body.membership_hash == old.header.body.membership_hash
                    && roster.header.body.members_hash == old.header.body.members_hash
                {
                    return Ok(false);
                }
                return Err(refuse(Reason::ReachRouteInvalid));
            }
        }
        let mut next = self.clone();
        next.rosters.insert(key, roster);
        next.check_group_reservations(true)?;
        // Rosters are deliberately absent from the authenticated reach mirror and revision.
        *self = next;
        Ok(true)
    }
    pub(super) fn classify_group(&self, route: &Route) -> Result<(ReachClass, Placement)> {
        let group = route.group.as_ref().ok_or_else(|| refuse(Reason::ReachRouteInvalid))?;
        let key = serde_json::to_string(&serde_json::json!(["group", group.group_id]))
            .map_err(storage)?;
        if self.group_floor(&key)?.is_some_and(GroupFloor::blocked) {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        let Some(StateRecord::Grant {
            subject: Subject::Group { conversation_id, group_epoch, .. },
            update: grant,
            ..
        }) = self.grants.get(&key)
        else {
            return Err(refuse(Reason::ForeignReadRefused));
        };
        if self.group_floor(&key)?.is_some_and(|floor| *group_epoch <= floor.floor_epoch) {
            return Err(refuse(Reason::GroupEpochStale));
        }
        let roster = self.rosters.get(&key).ok_or_else(|| refuse(Reason::ForeignReadRefused))?;
        if roster.header.body.grant_hash != framed_hash(OPERATION_HASH_DOMAIN, grant)? {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        let member = roster
            .members
            .iter()
            .find(|member| member.root == route.source.account_anchor)
            .ok_or_else(|| refuse(Reason::ForeignReadRefused))?;
        if conversation_id != &route.conversation_id
            || roster.header.body.conversation_id != route.conversation_id
        {
            return Err(refuse(Reason::ReachRouteInvalid));
        }
        roster.validate(grant).map_err(|_| refuse(Reason::ReachRouteInvalid))?;
        if group.group_epoch < member.since_epoch.max(*group_epoch) {
            return Err(refuse(Reason::GroupEpochStale));
        }
        if group.group_epoch == roster.header.body.group_epoch
            && group.membership_hash != roster.header.body.membership_hash
        {
            return Err(refuse(Reason::ReachRouteInvalid));
        }
        Ok((ReachClass::Accepted, Placement::Direct))
    }
}

#[cfg(test)]
mod tests;
