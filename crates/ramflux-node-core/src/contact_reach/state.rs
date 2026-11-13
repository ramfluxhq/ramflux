// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recipient-owned authorization and canonical state transitions; no network or trust writes.
use super::{ReachError, Result, refuse, storage};
use ramflux_protocol::{
    contact_reach::{
        Admission, DECLINE_COOLDOWN, Decision, MAX_STATE_BYTES, MAX_SUBJECTS,
        OPERATION_HASH_DOMAIN, Placement, ReachMode, ReachPolicy, Reason, Relationship, Route,
        StateRecord, Subject, Traffic,
    },
    custody::{Envelope as Signed, framed_hash},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountReach {
    pub revision: u64,
    pub policy: Option<Signed<ReachPolicy>>,
    pub admission_revision: u64,
    pub last_update: Option<Signed<Admission>>,
    pub grants: BTreeMap<String, StateRecord>,
    pub blocks: BTreeMap<String, StateRecord>,
    pub declines: BTreeMap<String, StateRecord>,
    pub retirements: BTreeMap<String, StateRecord>,
    pub placements: BTreeMap<String, StateRecord>,
    pub floors: BTreeMap<String, StateRecord>,
    pub conflicts: BTreeMap<String, StateRecord>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachClass {
    Unsolicited,
    Replied,
    Accepted,
}

impl AccountReach {
    #[must_use]
    pub fn policy_revision(&self) -> u64 {
        self.policy.as_ref().map_or(0, |p| p.body.revision)
    }

    pub(super) fn advance(&mut self) -> Result<()> {
        self.revision = self
            .revision
            .checked_add(1)
            .filter(|n| *n <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        for map in [
            &self.grants,
            &self.blocks,
            &self.declines,
            &self.retirements,
            &self.placements,
            &self.floors,
        ] {
            if map.len() > MAX_SUBJECTS {
                return Err(refuse(Reason::ForeignCapacity));
            }
        }
        if self.conflicts.len() > 2
            || ramflux_protocol::canonical_json_bytes(self)?.len() > MAX_STATE_BYTES
        {
            return Err(refuse(Reason::ForeignCapacity));
        }
        Ok(())
    }

    pub(super) fn policy(&mut self, update: Signed<ReachPolicy>) -> Result<()> {
        let current = self.policy_revision();
        if update.body.expected_revision != current {
            return Err(ReachError::Revision(current));
        }
        if current == 0 && update.body.mode != ReachMode::ContactsOnly {
            return Err(refuse(Reason::ReachPolicyRequired));
        }
        if update.body.mode == ReachMode::ContactsOnly {
            let basis = framed_hash(OPERATION_HASH_DOMAIN, &update)?;
            let revision =
                self.revision.checked_add(1).ok_or_else(|| refuse(Reason::ForeignCapacity))?;
            for record in self.placements.values_mut() {
                if let StateRecord::Placement {
                    conversation_id,
                    placement,
                    relationship,
                    revision: row_revision,
                    basis: row_basis,
                    ..
                } = record
                {
                    let granted = self.grants.values().any(|g| matches!(g,StateRecord::Grant {
                        subject:Subject::Conversation { conversation_id:id,.. },.. } if id==conversation_id));
                    if *relationship == Relationship::Unaccepted
                        && *placement == Placement::Direct
                        && !granted
                    {
                        *placement = Placement::Strangers;
                        *row_revision = revision;
                        *row_basis = vec![basis.clone()];
                    }
                }
            }
        }
        self.policy = Some(update);
        self.advance()
    }

    pub(super) fn admission(
        &mut self,
        update: Signed<Admission>,
        conversation: Option<&str>,
        now: u64,
    ) -> Result<()> {
        let b = &update.body;
        if b.expected_revision != self.admission_revision {
            return Err(ReachError::Revision(self.admission_revision));
        }
        let next = self
            .admission_revision
            .checked_add(1)
            .filter(|n| *n <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        let key = b.subject.key()?;
        match b.decision {
            Decision::Allow => self.apply_allow(&update, conversation)?,
            Decision::Block | Decision::Decline => {
                if let Some(root) = b.subject.root() {
                    self.grants.retain(|_,r| !matches!(r,StateRecord::Grant { subject,.. } if subject.root() == Some(root)));
                }
                if b.decision == Decision::Block {
                    self.blocks.insert(
                        key.clone(),
                        StateRecord::Block { subject: b.subject.clone(), update: update.clone() },
                    );
                } else {
                    let root =
                        b.subject.root().ok_or_else(|| refuse(Reason::ForeignInvalidFrame))?;
                    self.declines.insert(
                        root.into(),
                        StateRecord::Decline {
                            root: root.into(),
                            until: now
                                .checked_add(DECLINE_COOLDOWN)
                                .ok_or_else(|| refuse(Reason::ForeignCapacity))?,
                            update: update.clone(),
                        },
                    );
                }
                self.floors.insert(
                    key.clone(),
                    StateRecord::Floor {
                        subject: b.subject.clone(),
                        revision: next,
                        denied: true,
                        erase_generation: next,
                        erased: true,
                    },
                );
            }
            Decision::Unblock => {
                self.blocks.remove(&key);
                // Unblock restores no positive grant, and retains the erase generation.
                self.floors.insert(
                    key.clone(),
                    StateRecord::Floor {
                        subject: b.subject.clone(),
                        revision: next,
                        denied: false,
                        erase_generation: next,
                        erased: true,
                    },
                );
            }
            Decision::Revoke => {
                self.grants.remove(&key);
            }
        }
        if b.decision != Decision::Allow {
            self.retirements.insert(
                key,
                StateRecord::Retirement {
                    subject: b.subject.clone(),
                    revision: next,
                    update: update.clone(),
                },
            );
        }
        self.reconcile_placement(&update, conversation)?;
        self.admission_revision = next;
        self.last_update = Some(update);
        self.advance()
    }

    fn reconcile_placement(
        &mut self,
        update: &Signed<Admission>,
        conversation: Option<&str>,
    ) -> Result<()> {
        let b = &update.body;
        if b.decision != Decision::Allow
            && b.decision != Decision::Unblock
            && let Some(id) = conversation
        {
            let friendship = b
                .subject
                .root()
                .map(|root| Subject::Friendship { root: root.into() }.key())
                .transpose()?;
            let accepted = friendship.as_ref().and_then(|key| self.grants.get(key));
            let basis = if let Some(StateRecord::Grant { update, .. }) = accepted {
                vec![framed_hash(OPERATION_HASH_DOMAIN, update)?]
            } else {
                vec![framed_hash(OPERATION_HASH_DOMAIN, &update)?]
            };
            if let Some(StateRecord::Placement {
                placement,
                relationship,
                revision,
                basis: old_basis,
                ..
            }) = self.placements.get_mut(id)
            {
                *placement =
                    if accepted.is_some() { Placement::Direct } else { Placement::Strangers };
                *relationship = if accepted.is_some() {
                    Relationship::Accepted
                } else {
                    Relationship::Unaccepted
                };
                *revision =
                    self.revision.checked_add(1).ok_or_else(|| refuse(Reason::ForeignCapacity))?;
                *old_basis = basis;
            }
        }
        Ok(())
    }

    fn apply_allow(
        &mut self,
        update: &Signed<Admission>,
        conversation: Option<&str>,
    ) -> Result<()> {
        let b = &update.body;
        let key = b.subject.key()?;

        let permissions = b.permissions.ok_or_else(|| refuse(Reason::ForeignInvalidFrame))?;
        let grant_until = b.grant_until.ok_or_else(|| refuse(Reason::ForeignInvalidFrame))?;
        self.grants.insert(
            key.clone(),
            StateRecord::Grant {
                subject: b.subject.clone(),
                permissions,
                grant_until,
                update: update.clone(),
            },
        );
        self.retirements.remove(&key);
        if let Some(id) = conversation {
            let accepted = matches!(b.subject, Subject::Friendship { .. });
            let friendship = b
                .subject
                .root()
                .map(|root| Subject::Friendship { root: root.into() }.key())
                .transpose()?;
            let accepted_grant = friendship.as_ref().and_then(|key| self.grants.get(key));
            let previous_accepted = accepted_grant.is_some();
            let mut basis = vec![framed_hash(OPERATION_HASH_DOMAIN, &update)?];
            if !accepted && let Some(StateRecord::Grant { update, .. }) = accepted_grant {
                basis.push(framed_hash(OPERATION_HASH_DOMAIN, update)?);
            }
            // Reply never moves a stranger thread or downgrades an accepted relationship.
            let (placement, relationship) = if accepted || previous_accepted {
                (Placement::Direct, Relationship::Accepted)
            } else {
                (Placement::Strangers, Relationship::Unaccepted)
            };
            self.placements.insert(
                id.into(),
                StateRecord::Placement {
                    conversation_id: id.into(),
                    revision: self
                        .revision
                        .checked_add(1)
                        .ok_or_else(|| refuse(Reason::ForeignCapacity))?,
                    placement,
                    relationship,
                    tombstone: false,
                    basis,
                },
            );
        }
        Ok(())
    }

    /// Evaluate recipient-owned denial state before any positive authority.
    /// # Errors
    /// Returns only generic remote refusal; no block/decline decision is disclosed.
    pub fn check_denials(&self, root: &str, node: &str, now: u64) -> Result<()> {
        if self.blocks.values().any(|r| match r {
            StateRecord::Block { subject: Subject::Friendship { root: r }, .. } => r == root,
            StateRecord::Block { subject: Subject::Node { node_id }, .. } => node_id == node,
            _ => false,
        }) || self
            .declines
            .get(root)
            .is_some_and(|r| matches!(r,StateRecord::Decline { until,.. } if *until > now))
        {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        Ok(())
    }

    /// Classify from saved recipient grants, never from a sender's DM/group label alone.
    /// Callers verify source/target/current grant signer and group epoch before publication.
    /// # Errors
    /// Refuses denied, missing-policy or unauthorized group/receipt/typing traffic.
    pub fn classify(&self, route: &Route, peer: &str, now: u64) -> Result<(ReachClass, Placement)> {
        self.check_denials(&route.source.account_anchor, peer, now)?;
        let policy = self.policy.as_ref().ok_or_else(|| refuse(Reason::ReachPolicyRequired))?;
        if matches!(route.traffic, Traffic::SelfSync | Traffic::OwnCopy) {
            if route.source.account_anchor != route.recipient_root {
                return Err(refuse(Reason::ForeignReadRefused));
            }
            return Ok((ReachClass::Accepted, Placement::Direct));
        }
        let friendship = Subject::Friendship { root: route.source.account_anchor.clone() }.key()?;
        let conversation = Subject::Conversation {
            root: route.source.account_anchor.clone(),
            conversation_id: route.conversation_id.clone(),
        }
        .key()?;
        if self.blocks.contains_key(&conversation) {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        let grant = [&friendship, &conversation].into_iter().filter_map(|key| self.grants.get(key)).find(|record| {
            matches!(record, StateRecord::Grant { grant_until, .. } if *grant_until == 0 || *grant_until > now)
        });
        if let Some(StateRecord::Grant { permissions, grant_until, subject, .. }) = grant
            && (*grant_until == 0 || *grant_until > now)
        {
            let allowed = match route.traffic {
                Traffic::Dm | Traffic::GroupInvite => true,
                Traffic::Receipt => permissions.user_delivered || permissions.read,
                Traffic::Typing => permissions.typing,
                _ => false,
            };
            if allowed {
                return Ok(if matches!(subject, Subject::Friendship { .. }) {
                    (ReachClass::Accepted, Placement::Direct)
                } else {
                    (ReachClass::Replied, Placement::Strangers)
                });
            }
        }
        if route.traffic == Traffic::Group {
            let group = self.grants.values().any(|r| {
                matches!(r,StateRecord::Grant {
                subject: Subject::GroupSender { root,group_id,.. },grant_until:0,.. }
                if root == &route.source.account_anchor && group_id == &route.conversation_id)
            });
            if group {
                return Ok((ReachClass::Accepted, Placement::Direct));
            }
            return Err(refuse(Reason::ForeignReadRefused));
        }
        if matches!(route.traffic, Traffic::Receipt | Traffic::Typing) {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        Ok((
            ReachClass::Unsolicited,
            if policy.body.mode == ReachMode::Open && route.traffic == Traffic::Dm {
                Placement::Direct
            } else {
                Placement::Strangers
            },
        ))
    }

    /// Complete canonical state mirror; no time-dependent record rewriting occurs on read.
    /// # Errors
    /// Refuses uninitialized policy and inconsistent canonical keys.
    pub fn records(&self) -> Result<Vec<StateRecord>> {
        let policy = self.policy.clone().ok_or_else(|| refuse(Reason::ReachPolicyRequired))?;
        let mut records = vec![
            StateRecord::Policy { revision: self.policy_revision(), update: policy },
            StateRecord::AdmissionMeta {
                revision: self.admission_revision,
                last_update: self.last_update.clone(),
            },
        ];
        for map in [
            &self.grants,
            &self.blocks,
            &self.declines,
            &self.retirements,
            &self.placements,
            &self.floors,
            &self.conflicts,
        ] {
            records.extend(map.values().cloned());
        }
        let mut keyed =
            records.into_iter().map(|r| Ok((r.order_key()?, r))).collect::<Result<Vec<_>>>()?;
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        if keyed.windows(2).any(|p| p.first().zip(p.get(1)).is_some_and(|(a, b)| a.0 == b.0)) {
            return Err(storage("duplicate canonical reach record"));
        }
        Ok(keyed.into_iter().map(|(_, r)| r).collect())
    }
}
