// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable reach CAS and operation dedup, independent of username mutation epochs.
use super::super::{CheckpointError, HomeDirectory, Result, canonical, storage};
use ramflux_protocol::{
    account_reach::{ReachPolicy, ReachState},
    custody::{DeviceSet, Envelope},
    home_migration::ResolveResult,
};
use redb::{ReadableDatabase, ReadableTable};

pub use ramflux_protocol::account_reach::ReachRecord as ReachCommit;

/// Reply permissions one owner may hold at once; a new one beyond this is refused.
pub const MAX_REPLY_PERMISSIONS_PER_OWNER: usize = 4096;
/// Validity of one stored reply permission, in seconds.
pub const REPLY_PERMISSION_TTL_SECONDS: u64 = 86_400;

impl HomeDirectory {
    /// Commit one authenticated owner's conversation permission before its reply is queued.
    /// The conversation must be the shared DM scope of the owner and peer, and an owner holds
    /// at most `MAX_REPLY_PERMISSIONS_PER_OWNER` live permissions.
    /// # Errors
    /// Refuses invalid roots, operation substitution, foreign conversation ids, the per-owner
    /// cap and unavailable durable storage.
    pub fn authorize_reply(
        &self,
        owner: &str,
        peer: &str,
        conversation: &str,
        operation: &str,
        now: u64,
    ) -> Result<ramflux_protocol::account_reach::ReplyPermission> {
        super::super::fixed(owner)?;
        super::super::fixed(peer)?;
        let expected = ramflux_protocol::message::dm_scope::derive(peer, owner)
            .map_err(|_| CheckpointError::Refused("reply_conversation"))?;
        super::super::require(expected == conversation, "reply_conversation")?;
        let _guard = self.publication_guard()?;
        let tx = self.db.begin_write().map_err(storage)?;
        let mut table = tx.open_table(super::META).map_err(storage)?;
        let prefix = format!("reply-permission:{owner}:");
        let key = format!("{prefix}{}", super::super::transport::digest(&(peer, conversation))?);
        let existing: Option<ramflux_protocol::account_reach::ReplyPermission> =
            match table.get(key.as_str()).map_err(storage)? {
                Some(old) => Some(serde_json::from_slice(old.value())?),
                None => None,
            };
        if let Some(old) = existing.as_ref()
            && old.expires_at > now
        {
            return Ok(old.clone());
        }
        if existing.is_none() {
            let mut live = 0_usize;
            for row in table.range(prefix.as_str()..).map_err(storage)? {
                let (row_key, _) = row.map_err(storage)?;
                if !row_key.value().starts_with(prefix.as_str()) {
                    break;
                }
                live = live.saturating_add(1);
                if live >= MAX_REPLY_PERMISSIONS_PER_OWNER {
                    return Err(CheckpointError::Refused("reply_permission_cap"));
                }
            }
        }
        let permission = ramflux_protocol::account_reach::ReplyPermission {
            owner_root: owner.into(),
            peer_root: peer.into(),
            conversation_id: conversation.into(),
            operation_id: operation.into(),
            revision: 1,
            expires_at: now.saturating_add(REPLY_PERMISSION_TTL_SECONDS),
        };
        table.insert(key.as_str(), canonical(&permission)?.as_slice()).map_err(storage)?;
        drop(table);
        tx.commit().map_err(storage)?;
        Ok(permission)
    }

    /// # Errors
    /// Refuses unavailable storage and malformed retained policy bytes.
    pub fn reach_commit(&self, root: &str) -> Result<Option<ReachCommit>> {
        super::super::fixed(root)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(super::META).map_err(storage)?;
        table
            .get(format!("reach:{root}").as_str())
            .map_err(storage)?
            .map(|v| decode(v.value()))
            .transpose()
    }

    /// Commit a current-primary policy, or return the current state on a stale CAS.
    /// An identical operation can never allocate a second revision, including after restart.
    /// # Errors
    /// Refuses invalid authority, operation reuse with other bytes and corrupt storage.
    pub fn commit_reach(
        &self,
        policy: ReachPolicy,
        authority: &Envelope<DeviceSet>,
        history: &ResolveResult,
        now: u64,
    ) -> Result<ReachState> {
        let _guard = self.publication_guard()?;
        ramflux_crypto::account_reach::verify_reach_policy(&policy, authority)
            .map_err(|_| CheckpointError::Refused("reach_signature"))?;
        let first = history.predecessors.first().unwrap_or(&history.home);
        let home = ramflux_crypto::home_migration::verify_home_chain(history, first, now)
            .map_err(|_| CheckpointError::Refused("reach_home"))?;
        super::super::require(
            home.hash() == policy.body.home_head_hash
                && home.evidence().record.account_anchor() == policy.body.account_anchor
                && home.home().0 == self.home,
            "reach_home",
        )?;
        let root = &policy.body.account_anchor;
        let tx = self.db.begin_write().map_err(storage)?;
        let mut table = tx.open_table(super::META).map_err(storage)?;
        let key = format!("reach:{root}");
        let old =
            table.get(key.as_str()).map_err(storage)?.map(|v| decode(v.value())).transpose()?;
        let op_key = format!("reach-operation:{root}:{}", policy.body.operation_id);
        let seen = table.get(op_key.as_str()).map_err(storage)?.map(|v| v.value().to_vec());
        let hash = super::super::transport::digest(&policy)?;
        if let Some(seen) = seen {
            super::super::require(seen == hash.as_bytes(), "reach_operation_reuse")?;
            return Ok(state(old, authority, history, false));
        }
        let revision = old.as_ref().map_or(0, |row: &ReachCommit| row.policy.body.revision);
        if policy.body.expected_revision != revision {
            return Ok(state(old, authority, history, true));
        }
        super::super::require(
            revision != 0
                || policy.body.mode == ramflux_protocol::account_reach::ReachMode::ContactsOnly,
            "reach_initial_contacts_only",
        )?;
        let commit = ReachCommit { policy, authority: authority.clone() };
        table.insert(key.as_str(), canonical(&commit)?.as_slice()).map_err(storage)?;
        table.insert(op_key.as_str(), hash.as_bytes()).map_err(storage)?;
        drop(table);
        tx.commit().map_err(storage)?;
        Ok(state(Some(commit), authority, history, false))
    }
}

pub(super) fn state(
    commit: Option<ReachCommit>,
    current: &Envelope<DeviceSet>,
    history: &ResolveResult,
    conflict: bool,
) -> ReachState {
    let (policy, authority) =
        commit.map_or((None, current.clone()), |row| (Some(row.policy), row.authority));
    ReachState {
        policy,
        authority: Box::new(authority),
        history: Box::new(history.clone()),
        conflict,
    }
}

fn decode(bytes: &[u8]) -> Result<ReachCommit> {
    super::super::require(
        bytes.len() <= ramflux_protocol::custody::MAX_RECORD_BYTES + 2048,
        "reach_record_size",
    )?;
    let commit: ReachCommit = serde_json::from_slice(bytes)?;
    ramflux_crypto::account_reach::verify_reach_policy(&commit.policy, &commit.authority)
        .map_err(|_| CheckpointError::Refused("reach_signature"))?;
    Ok(commit)
}
