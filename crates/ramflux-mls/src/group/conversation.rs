// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The `rf_conversation` group context extension (`0xF0C1`) and the expected-principal check.
//!
//! A `dm` or `self` group is bound to one conversation by an immutable extension set at create
//! (group context extension proposals are refused, so it never changes):
//! `{v = 1, role u8, conversation_id<V>}`. A joiner compares it with what it expects before it
//! joins: the role must match the group kind, the id must be the conversation it was invited to,
//! and every member must belong to the expected principals.

use std::collections::BTreeSet;

use openmls::prelude::{Extension, ExtensionType, Extensions, GroupContext, UnknownExtension};
use ramflux_protocol::domain::MLS_SELF_SCOPE_V1;
use ramflux_protocol::message::dm_scope;

use crate::credential::{GroupKind, MemberIdentity};
use crate::{EXTENSION_TYPE_RF_CONVERSATION, MlsError};

/// Version of the extension payload.
const EXTENSION_VERSION: u8 = 1;
/// Largest accepted extension payload (a `dm:` id is 47 bytes).
const MAX_EXTENSION_BYTES: usize = 128;

/// Role of a bound conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationRole {
    /// Two principals.
    Dm,
    /// One principal (own-device sync).
    Own,
}

impl ConversationRole {
    fn code(self) -> u8 {
        match self {
            Self::Dm => 1,
            Self::Own => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Dm),
            2 => Some(Self::Own),
            _ => None,
        }
    }

    /// The group kind that carries this role.
    #[must_use]
    pub fn kind(self) -> GroupKind {
        match self {
            Self::Dm => GroupKind::Dm,
            Self::Own => GroupKind::Own,
        }
    }
}

/// The conversation binding of a `dm` or `self` group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfConversation {
    /// Role of the conversation.
    pub role: ConversationRole,
    /// `dm`: the UTF-8 `dm_scope::derive` id. `own`: [`self_conversation_id`].
    pub conversation_id: Vec<u8>,
}

fn reject(what: &str) -> MlsError {
    MlsError::PolicyRejected(format!("rf_conversation: {what}"))
}

/// The conversation id of the own-device group of `anchor`: `blake3(MLS_SELF_SCOPE_V1 || anchor)`.
#[must_use]
pub fn self_conversation_id(anchor: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MLS_SELF_SCOPE_V1.as_bytes());
    hasher.update(anchor.as_bytes());
    *hasher.finalize().as_bytes()
}

impl RfConversation {
    /// The binding of the `dm` between two anchors.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] for malformed or equal anchors.
    pub fn dm(first: &str, second: &str) -> Result<Self, MlsError> {
        let id = dm_scope::derive(first, second).map_err(|_| reject("dm anchors"))?;
        Ok(Self { role: ConversationRole::Dm, conversation_id: id.into_bytes() })
    }

    /// The binding of the own-device group of `anchor`.
    #[must_use]
    pub fn own(anchor: &str) -> Self {
        Self { role: ConversationRole::Own, conversation_id: self_conversation_id(anchor).to_vec() }
    }

    /// A binding with a random id, for debug-created groups that have no real conversation.
    #[must_use]
    pub fn synthetic(role: ConversationRole, id: [u8; 32]) -> Self {
        Self { role, conversation_id: id.to_vec() }
    }

    /// Extension payload bytes.
    ///
    /// # Errors
    /// The id is empty or longer than the bound.
    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        let id_len = u8::try_from(self.conversation_id.len())
            .ok()
            .filter(|len| *len > 0 && usize::from(*len) <= MAX_EXTENSION_BYTES - 3)
            .ok_or_else(|| reject("conversation id length"))?;
        let mut out = vec![EXTENSION_VERSION, self.role.code(), id_len];
        out.extend_from_slice(&self.conversation_id);
        Ok(out)
    }

    /// Strict decode: exact version, known role, no trailing bytes.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] for any malformed payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        if bytes.len() > MAX_EXTENSION_BYTES {
            return Err(reject("payload too large"));
        }
        let [version, role, id_len, rest @ ..] = bytes else {
            return Err(reject("truncated payload"));
        };
        if *version != EXTENSION_VERSION {
            return Err(reject("version"));
        }
        let role = ConversationRole::from_code(*role).ok_or_else(|| reject("role"))?;
        if *id_len == 0 || rest.len() != usize::from(*id_len) {
            return Err(reject("id length"));
        }
        Ok(Self { role, conversation_id: rest.to_vec() })
    }

    /// The group context extension.
    ///
    /// # Errors
    /// See [`Self::encode`].
    pub fn extension(&self) -> Result<Extension, MlsError> {
        Ok(Extension::Unknown(EXTENSION_TYPE_RF_CONVERSATION, UnknownExtension(self.encode()?)))
    }

    /// The extension type to list in `required_capabilities` and leaf capabilities.
    #[must_use]
    pub fn extension_type() -> ExtensionType {
        ExtensionType::Unknown(EXTENSION_TYPE_RF_CONVERSATION)
    }

    /// Read the binding from a group context, if it carries one.
    ///
    /// # Errors
    /// The extension is present but malformed.
    pub fn from_extensions(
        extensions: &Extensions<GroupContext>,
    ) -> Result<Option<Self>, MlsError> {
        extensions
            .unknown(EXTENSION_TYPE_RF_CONVERSATION)
            .map(|unknown| Self::decode(&unknown.0))
            .transpose()
    }
}

/// The principals a conversation may contain, and the binding they derive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPrincipals {
    principals: BTreeSet<String>,
    binding: RfConversation,
}

impl ExpectedPrincipals {
    /// Expected set of a `dm`: `{own, peer}` with `derive(own, peer) == conversation_id`.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] for malformed or equal anchors.
    pub fn dm(own: &str, peer: &str) -> Result<Self, MlsError> {
        Ok(Self {
            principals: BTreeSet::from([own.to_owned(), peer.to_owned()]),
            binding: RfConversation::dm(own, peer)?,
        })
    }

    /// Expected set of the own-device group: `{own}`.
    #[must_use]
    pub fn own(own: &str) -> Self {
        Self { principals: BTreeSet::from([own.to_owned()]), binding: RfConversation::own(own) }
    }

    /// The binding a group of this conversation must carry.
    #[must_use]
    pub fn binding(&self) -> &RfConversation {
        &self.binding
    }

    /// True when `anchor` is one of the expected principals.
    #[must_use]
    pub fn contains(&self, anchor: &str) -> bool {
        self.principals.contains(anchor)
    }

    /// The group must carry exactly the expected binding.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] when the extension is missing, its role does not match the kind
    /// or its id is another conversation's.
    pub fn check_binding(
        &self,
        kind: GroupKind,
        found: Option<&RfConversation>,
    ) -> Result<(), MlsError> {
        let found = found.ok_or_else(|| reject("missing"))?;
        if found.role.kind() != kind || found.role != self.binding.role {
            return Err(reject("role does not match the group kind"));
        }
        if found.conversation_id != self.binding.conversation_id {
            return Err(reject("conversation id is not the expected one"));
        }
        Ok(())
    }

    /// Every device member belongs to an expected principal; no other credential type is allowed.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] for a member outside the set.
    pub fn check_members(&self, members: &[MemberIdentity]) -> Result<(), MlsError> {
        for member in members {
            match member {
                MemberIdentity::Device(device) if self.contains(&device.root_commitment) => {}
                // Debug builds pin Basic credentials; they never carry an account anchor.
                MemberIdentity::PinnedBasic { .. } => {}
                _ => return Err(MlsError::PolicyRejected("principal is not expected".to_owned())),
            }
        }
        Ok(())
    }

    /// One added member must belong to an expected principal (`may_add`).
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] for a member outside the set.
    pub fn check_member(&self, member: &MemberIdentity) -> Result<(), MlsError> {
        self.check_members(std::slice::from_ref(member))
    }
}
