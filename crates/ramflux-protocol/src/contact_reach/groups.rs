// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! FINAL r4f group consent, derived roster and reproducible retained-denial proofs.
use super::{Admission, Decision, Subject, digest, invalid, safe};
use crate::{
    ProtocolError,
    custody::{Envelope as Signed, framed_hash},
};
use serde::{Deserialize, Serialize};
pub const GROUP_JOIN_NOTICE_DOMAIN: &str = "ramflux.contact.group_join_notice.v1";
pub const GROUP_ROSTER_DOMAIN: &str = "ramflux.contact.group_roster.v1";
pub const GROUP_ROSTER_MEMBERS_DOMAIN: &str = "ramflux.contact.group_roster_members.v1";
pub const GROUP_DENIAL_RESERVATION: usize = 15 * 1024;
pub const MAX_GROUP_ROSTER_MEMBERS: usize = 199;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupJoinNotice {
    pub version: u32,
    pub recipient_root: String,
    pub group_id: String,
    pub conversation_id: String,
    pub genesis_hash: String,
    pub epoch: u64,
    pub membership_hash: String,
    pub inviter_root: String,
    pub member_root_count: u64,
}
impl GroupJoinNotice {
    /// # Errors
    /// Refuses noncanonical group bindings, roots, hashes, epoch or member count.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let subject = Subject::Group {
            group_id: self.group_id.clone(),
            conversation_id: self.conversation_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            group_epoch: self.epoch,
            membership_hash: self.membership_hash.clone(),
        };
        subject.validate()?;
        digest(&self.recipient_root)?;
        digest(&self.inviter_root)?;
        if self.version != 1 || !(1..=200).contains(&self.member_root_count) {
            return Err(invalid("group JOIN Notice bounds"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRosterHeader {
    pub version: u32,
    pub recipient_root: String,
    pub group_id: String,
    pub conversation_id: String,
    pub grant_hash: String,
    pub group_epoch: u64,
    pub membership_hash: String,
    pub members_hash: String,
    pub member_count: u64,
    pub issued_at: u64,
}
impl GroupRosterHeader {
    /// # Errors
    /// Refuses malformed bindings, noncanonical hashes and the independent 2-KiB header cap.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        super::group_profile::validate_group_id(&self.group_id)?;
        crate::message::dm_scope::validate_group(&self.conversation_id)
            .map_err(|_| invalid("group roster conversation"))?;
        for value in
            [&self.recipient_root, &self.grant_hash, &self.membership_hash, &self.members_hash]
        {
            digest(value)?;
        }
        safe(self.group_epoch)?;
        safe(self.issued_at)?;
        if self.version != 1
            || self.group_epoch == 0
            || self.member_count > 199
            || crate::canonical_json_bytes(self)?.len() > 2048
        {
            return Err(invalid("group roster header bounds"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRosterMember {
    pub root: String,
    pub since_epoch: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRoster {
    pub header: Signed<GroupRosterHeader>,
    pub members: Vec<GroupRosterMember>,
}
impl GroupRoster {
    /// Check a roster against the exact live grant; this performs no signature or consent inference.
    /// # Errors
    /// Refuses stale/bad bindings, member hashes, order, admission floors or 16-KiB overflow.
    pub fn validate(&self, grant: &Signed<Admission>) -> Result<(), ProtocolError> {
        grant.body.validate()?;
        self.header.body.validate()?;
        if crate::canonical_json_bytes(&self.header)?.len() > 2048
            || crate::canonical_json_bytes(self)?.len() > 16 * 1024
        {
            return Err(invalid("group roster byte cap"));
        }
        let Subject::Group { group_id, conversation_id, group_epoch, .. } = &grant.body.subject
        else {
            return Err(invalid("roster requires a group grant"));
        };
        let header = &self.header.body;
        if grant.body.decision != Decision::Allow
            || header.recipient_root != grant.body.recipient_root
            || header.group_id != *group_id
            || header.conversation_id != *conversation_id
            || header.grant_hash != framed_hash(super::OPERATION_HASH_DOMAIN, grant)?
            || header.group_epoch < *group_epoch
            || self.members.len() > MAX_GROUP_ROSTER_MEMBERS
            || header.member_count
                != u64::try_from(self.members.len()).map_err(|_| invalid("roster count"))?
            || header.members_hash != framed_hash(GROUP_ROSTER_MEMBERS_DOMAIN, &self.members)?
        {
            return Err(invalid("roster/live grant correlation"));
        }
        let mut previous: Option<&str> = None;
        for member in &self.members {
            digest(&member.root)?;
            safe(member.since_epoch)?;
            if member.root == header.recipient_root
                || previous.is_some_and(|root| root >= member.root.as_str())
                || member.since_epoch < *group_epoch
                || member.since_epoch > header.group_epoch
            {
                return Err(invalid("roster root order or admission floor"));
            }
            previous = Some(&member.root);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupFloor {
    pub floor_epoch: u64,
    pub grant: Option<Box<Signed<Admission>>>,
    pub roster_header: Option<Box<Signed<GroupRosterHeader>>>,
    pub block_control: Option<Box<Signed<Admission>>>,
}
/// Compare the immutable group-to-conversation/genesis binding, without conflating epoch/hash.
#[must_use]
pub fn same_group_binding(left: &Subject, right: &Subject) -> bool {
    matches!((left,right),(Subject::Group{group_id:left_group,conversation_id:left_conversation,genesis_hash:left_genesis,..},
        Subject::Group{group_id:right_group,conversation_id:right_conversation,genesis_hash:right_genesis,..})
        if left_group==right_group && left_conversation==right_conversation && left_genesis==right_genesis)
}
impl GroupFloor {
    /// Recompute FINAL r4f's single floor formula from its complete original signed witnesses.
    /// # Errors
    /// Refuses fabricated floors, conflicting bindings, invalid witness roles or header/grant links.
    pub fn validate(&self, update: &Signed<Admission>) -> Result<(), ProtocolError> {
        let Subject::Group { group_id, conversation_id, group_epoch, .. } = &update.body.subject
        else {
            return Err(invalid("group floor requires group subject"));
        };
        update.body.validate()?;
        if !matches!(update.body.decision, Decision::Revoke | Decision::Block) {
            return Err(invalid("group floor needs a retirement decision"));
        }
        if update.body.decision == Decision::Block {
            let control = self
                .block_control
                .as_ref()
                .ok_or_else(|| invalid("signed group block clearance is missing"))?;
            if control.body.expected_revision < update.body.expected_revision
                || control.body.expected_revision == update.body.expected_revision
                    && control.as_ref() != update
            {
                return Err(invalid("retained block control predates its block"));
            }
        }
        let mut floor = *group_epoch;
        if let Some(grant) = &self.grant {
            grant.body.validate()?;
            if grant.body.decision != Decision::Allow
                || !same_group_binding(&grant.body.subject, &update.body.subject)
                || grant.body.recipient_root != update.body.recipient_root
            {
                return Err(invalid("retired group grant binding"));
            }
            if let Subject::Group { group_epoch, .. } = grant.body.subject {
                floor = floor.max(group_epoch);
            }
        }
        if let Some(header) = &self.roster_header {
            header.body.validate()?;
            let grant =
                self.grant.as_ref().ok_or_else(|| invalid("roster witness without grant"))?;
            let body = &header.body;
            if crate::canonical_json_bytes(header)?.len() > 2048
                || body.group_id != *group_id
                || body.conversation_id != *conversation_id
                || body.recipient_root != update.body.recipient_root
                || body.grant_hash != framed_hash(super::OPERATION_HASH_DOMAIN, grant.as_ref())?
            {
                return Err(invalid("retired roster header binding"));
            }
            floor = floor.max(body.group_epoch);
        }
        if let Some(control) = &self.block_control {
            control.body.validate()?;
            if !matches!(control.body.decision, Decision::Block | Decision::Unblock)
                || !same_group_binding(&control.body.subject, &update.body.subject)
                || control.body.recipient_root != update.body.recipient_root
            {
                return Err(invalid("retained group block control binding"));
            }
        }
        if self.floor_epoch != floor {
            return Err(invalid("group floor is not reproducible"));
        }
        Ok(())
    }
    #[must_use]
    pub fn blocked(&self) -> bool {
        self.block_control.as_ref().is_some_and(|control| control.body.decision == Decision::Block)
    }
}
