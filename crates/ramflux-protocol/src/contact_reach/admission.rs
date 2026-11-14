// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Friendship, conversation and group grants are independent signed authorities.
use super::{
    COMMAND_LIFETIME, CONVERSATION_LIFETIME, actor, digest, invalid, lifetime, node, safe, text,
};
use crate::{ProtocolError, custody::DeviceRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Subject {
    Friendship {
        root: String,
    },
    Conversation {
        root: String,
        conversation_id: String,
    },
    Node {
        node_id: String,
    },
    Group {
        group_id: String,
        conversation_id: String,
        genesis_hash: String,
        group_epoch: u64,
        membership_hash: String,
    },
}
impl Subject {
    /// Validate a subject without granting the claimed membership.
    /// # Errors
    /// Refuses malformed roots, group/conversation ids and node names.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Friendship { root } => digest(root),
            Self::Conversation { root, conversation_id } => {
                digest(root)?;
                text(conversation_id)
            }
            Self::Node { node_id } => node(node_id),
            Self::Group {
                group_id,
                conversation_id,
                genesis_hash,
                group_epoch,
                membership_hash,
            } => {
                super::group_profile::validate_group_id(group_id)?;
                crate::message::dm_scope::validate_group(conversation_id)
                    .map_err(|_| invalid("invalid group conversation"))?;
                digest(genesis_hash)?;
                digest(membership_hash)?;
                safe(*group_epoch)?;
                if *group_epoch == 0 {
                    return Err(invalid("zero group epoch"));
                }
                Ok(())
            }
        }
    }
    #[must_use]
    pub fn root(&self) -> Option<&str> {
        match self {
            Self::Friendship { root } | Self::Conversation { root, .. } => Some(root),
            Self::Node { .. } | Self::Group { .. } => None,
        }
    }
    /// Stable subject identity, deliberately excluding mutable group membership hashes.
    /// # Errors
    /// Propagates canonical serialization errors.
    pub fn key(&self) -> Result<String, ProtocolError> {
        let key = match self {
            Self::Friendship { root } => serde_json::json!(["friendship", root]),
            Self::Conversation { root, conversation_id } => {
                serde_json::json!(["conversation", root, conversation_id])
            }
            Self::Node { node_id } => serde_json::json!(["node", node_id]),
            Self::Group { group_id, .. } => serde_json::json!(["group", group_id]),
        };
        String::from_utf8(crate::canonical_json_bytes(&key)?)
            .map_err(|_| invalid("subject key encoding"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub user_delivered: bool,
    pub read: bool,
    pub typing: bool,
}
impl Permissions {
    pub const UNACCEPTED: Self = Self { user_delivered: false, read: false, typing: false };
    pub const ACCEPTED: Self = Self { user_delivered: true, read: true, typing: true };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Revoke,
    Block,
    Unblock,
    Decline,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub version: u32,
    pub operation_id: String,
    pub recipient_root: String,
    pub home_head_hash: String,
    pub expected_revision: u64,
    pub subject: Subject,
    pub decision: Decision,
    pub permissions: Option<Permissions>,
    pub grant_until: Option<u64>,
    pub authority_head_hash: String,
    pub master_certificate_hash: String,
    pub actor: DeviceRef,
    pub notice_hash: Option<String>,
    pub evidence_hash: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl Admission {
    /// Validate exact decision/subject/null/lifetime rules, without authorizing the command.
    /// # Errors
    /// Refuses invalid ids, unsafe integers and contradictory decision fields.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for v in [
            &self.operation_id,
            &self.recipient_root,
            &self.home_head_hash,
            &self.authority_head_hash,
            &self.master_certificate_hash,
        ] {
            digest(v)?;
        }
        actor(&self.actor)?;
        self.subject.validate()?;
        if self.subject.root() == Some(self.recipient_root.as_str()) {
            return Err(invalid("reach peer must be a different root"));
        }
        if let Subject::Conversation { root, conversation_id } = &self.subject {
            let expected = crate::message::dm_scope::derive(&self.recipient_root, root)
                .map_err(|_| invalid("invalid reach DM root pair"))?;
            if conversation_id != &expected {
                return Err(invalid("reach conversation must use the deterministic v3 DM id"));
            }
        }
        safe(self.expected_revision)?;
        if self.version != 2 || self.expected_revision == crate::MAX_SAFE_JSON_INTEGER {
            return Err(invalid("admission version or exhausted revision"));
        }
        lifetime(self.issued_at, self.expires_at, COMMAND_LIFETIME)?;
        if matches!(self.subject, Subject::Node { .. })
            && !matches!(self.decision, Decision::Block | Decision::Unblock)
            || self.decision == Decision::Decline
                && !matches!(self.subject, Subject::Friendship { .. })
        {
            return Err(invalid("admission decision not valid for subject"));
        }
        if self.decision == Decision::Allow {
            digest(self.notice_hash.as_deref().ok_or_else(|| invalid("allow needs notice"))?)?;
            digest(self.evidence_hash.as_deref().ok_or_else(|| invalid("allow needs evidence"))?)?;
            if let Subject::Group { membership_hash, .. } = &self.subject
                && self.evidence_hash.as_deref() != Some(membership_hash.as_str())
            {
                return Err(invalid("group allow evidence must equal its adopted membership hash"));
            }
            let until = self.grant_until.ok_or_else(|| invalid("allow needs deadline"))?;
            safe(until)?;
            let expected = if matches!(self.subject, Subject::Conversation { .. }) {
                self.issued_at
                    .checked_add(CONVERSATION_LIFETIME)
                    .ok_or_else(|| invalid("conversation expiry overflow"))?
            } else {
                0
            };
            if self.permissions.is_none()
                || until != expected
                || matches!(self.subject, Subject::Group { .. })
                    && self.permissions != Some(Permissions::UNACCEPTED)
            {
                return Err(invalid("allow permissions or deadline"));
            }
        } else if self.permissions.is_some()
            || self.grant_until.is_some()
            || self.notice_hash.is_some()
            || self.evidence_hash.is_some()
        {
            return Err(invalid("non-allow fields must be null"));
        }
        Ok(())
    }
}
