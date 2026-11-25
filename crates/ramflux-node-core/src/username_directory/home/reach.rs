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

/// Live reply permissions one owner may hold at once; a new one beyond this is refused.
#[cfg(not(feature = "itest-reply-permission-limits"))]
pub const MAX_REPLY_PERMISSIONS_PER_OWNER: usize = 4096;
/// Real-run knob: one live permission, so the cap is reachable with two peers.
#[cfg(feature = "itest-reply-permission-limits")]
pub const MAX_REPLY_PERMISSIONS_PER_OWNER: usize = 1;
/// Validity of one stored reply permission, in seconds.
#[cfg(not(feature = "itest-reply-permission-limits"))]
pub const REPLY_PERMISSION_TTL_SECONDS: u64 = 86_400;
/// Real-run knob: a short lifetime, so the expiry sweep is observable in one run.
#[cfg(feature = "itest-reply-permission-limits")]
pub const REPLY_PERMISSION_TTL_SECONDS: u64 = 20;

impl HomeDirectory {
    /// Commit one authenticated owner's conversation permission before its reply is queued.
    /// The conversation must be the shared DM scope of the owner and peer, and an owner holds
    /// at most `MAX_REPLY_PERMISSIONS_PER_OWNER` live permissions. Expired permissions of the
    /// owner are deleted on every write, so they never count toward the cap.
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
        let (live, expired) = reply_permission_rows(&table, &prefix, &key, now)?;
        for row_key in &expired {
            table.remove(row_key.as_str()).map_err(storage)?;
        }
        if live >= MAX_REPLY_PERMISSIONS_PER_OWNER {
            drop(table);
            // Keep the expiry sweep even when this permission is refused.
            tx.commit().map_err(storage)?;
            return Err(CheckpointError::Refused("reply_permission_cap"));
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
    /// The operation lookup runs before the signature and head checks, so a retry of the exact
    /// bytes of an already committed operation returns the stored state even after the
    /// authority or home head moved on.
    /// # Errors
    /// Refuses a policy for another account than the session `root`, invalid authority,
    /// operation reuse with other bytes and corrupt storage.
    pub fn commit_reach(
        &self,
        root: &str,
        policy: ReachPolicy,
        authority: &Envelope<DeviceSet>,
        history: &ResolveResult,
        now: u64,
    ) -> Result<ReachState> {
        super::super::fixed(root)?;
        super::super::require(policy.body.account_anchor == root, "reach_owner")?;
        let _guard = self.publication_guard()?;
        let key = format!("reach:{root}");
        let op_key = format!("reach-operation:{root}:{}", policy.body.operation_id);
        let hash = super::super::transport::digest(&policy)?;
        let tx = self.db.begin_write().map_err(storage)?;
        let mut table = tx.open_table(super::META).map_err(storage)?;
        let seen = table.get(op_key.as_str()).map_err(storage)?.map(|v| v.value().to_vec());
        if let Some(seen) = seen {
            super::super::require(seen == hash.as_bytes(), "reach_operation_reuse")?;
            let old =
                table.get(key.as_str()).map_err(storage)?.map(|v| decode(v.value())).transpose()?;
            return Ok(state(old, authority, history, false));
        }
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
        let old =
            table.get(key.as_str()).map_err(storage)?.map(|v| decode(v.value())).transpose()?;
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

/// Count the owner's live reply permissions other than `own_key`, and collect the keys of
/// expired ones (`expires_at <= now`) for removal once the range borrow has ended.
fn reply_permission_rows(
    table: &redb::Table<'_, &str, &[u8]>,
    prefix: &str,
    own_key: &str,
    now: u64,
) -> Result<(usize, Vec<String>)> {
    let mut live = 0_usize;
    let mut expired = Vec::new();
    for row in table.range(prefix..).map_err(storage)? {
        let (row_key, row_value) = row.map_err(storage)?;
        let row_key = row_key.value();
        if !row_key.starts_with(prefix) {
            break;
        }
        let permission: ramflux_protocol::account_reach::ReplyPermission =
            serde_json::from_slice(row_value.value())?;
        if permission.expires_at <= now {
            expired.push(row_key.to_owned());
        } else if row_key != own_key {
            live = live.saturating_add(1);
        }
    }
    Ok((live, expired))
}
