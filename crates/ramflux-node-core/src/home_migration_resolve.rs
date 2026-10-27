// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only successor resolution preserves the caller's ancestry floor without importing live state.
use crate::{HomeMigrationService, MigrationPeerReply, NodeCoreError, RouterRedbStore};
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::home_migration::{
    HomeRecord, MAX_CHAIN_RECORDS, MAX_RESOLVE_BYTES, Refusal, ResolvePayload, ResolveResult,
    record_hash,
};
fn failure(reason: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(reason)
}
fn wire(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
impl HomeMigrationService {
    pub(crate) fn latest_migration_home(
        &self,
        store: &RouterRedbStore,
        payload: &ResolvePayload,
        id: &str,
        now: u64,
    ) -> Result<ResolveResult, NodeCoreError> {
        if payload.limit == 0 || payload.limit > MAX_CHAIN_RECORDS as u64 {
            return Err(failure(Refusal::HomeCheckpointRequired));
        }
        let known = store.migration_home(&payload.target_anchor)?;
        if let Some(known) = &known
            && known.record.home() == (self.node.node_id(), self.node.public_key())
        {
            return store.resolve_migration_home(
                &payload.target_anchor,
                payload.after_home_hash.as_deref(),
                usize::try_from(payload.limit)
                    .map_err(|_| failure(Refusal::HomeCheckpointRequired))?,
            );
        }
        let peer = known
            .as_ref()
            .map(|k| k.record.home().0)
            .or(payload.old_node_hint.as_deref())
            .ok_or_else(|| failure(Refusal::HomeGenesisRequired))?;
        if peer == self.node.node_id() {
            return Err(failure(Refusal::HomeGenesisRequired));
        }
        let pin = self.mesh.peer_key(peer)?;
        if known.as_ref().is_some_and(|k| k.record.home().1 != pin) {
            return Err(failure(Refusal::PinMismatch));
        }
        let remote = ResolvePayload {
            target_anchor: payload.target_anchor.clone(),
            after_home_hash: known
                .as_ref()
                .map(|k| record_hash(&k.record))
                .transpose()
                .map_err(wire)?,
            limit: MAX_CHAIN_RECORDS as u64,
            old_node_hint: None,
        };
        let call = self.node.peer_resolve_call(peer, remote, id, now)?;
        let suffix = match self.mesh.exchange(peer, &call)? {
            MigrationPeerReply::Resolved(result) => *result,
            MigrationPeerReply::Refused(reason) => return Err(failure(reason)),
            _ => return Err(failure(Refusal::EvidenceRequired)),
        };
        let mut result = if let Some(known) = known {
            crypto::verify_home_chain(&suffix, &known, now)
                .map_err(|_| failure(Refusal::HomeFork))?;
            let mut prefix =
                store.resolve_migration_home(&payload.target_anchor, None, MAX_CHAIN_RECORDS)?;
            if record_hash(&suffix.home.record).map_err(wire)?
                != record_hash(&known.record).map_err(wire)?
            {
                prefix.predecessors.push(prefix.home);
                for entry in &suffix.predecessors {
                    if record_hash(&entry.record).map_err(wire)?
                        != record_hash(&known.record).map_err(wire)?
                    {
                        prefix.predecessors.push(entry.clone());
                    }
                }
                prefix.home = suffix.home;
            }
            prefix
        } else {
            // An authenticated caller's hint selects a proxy destination, never a new stored
            // home pin. Clients must still match genesis against their existing contact binding.
            let first = suffix.predecessors.first().unwrap_or(&suffix.home);
            if !matches!(first.record, HomeRecord::Genesis { .. })
                || first.record.home() != (peer, pin.as_str())
            {
                return Err(failure(Refusal::HomeGenesisRequired));
            }
            crypto::verify_home_chain(&suffix, first, now)
                .map_err(|_| failure(Refusal::HomeFork))?;
            suffix
        };
        if result.home.record.account_anchor() != payload.target_anchor {
            return Err(failure(Refusal::HomeFork));
        }
        if let Some(after) = &payload.after_home_hash {
            if record_hash(&result.home.record).map_err(wire)? == *after {
                result.predecessors.clear();
            } else {
                let position = result
                    .predecessors
                    .iter()
                    .position(|r| record_hash(&r.record).is_ok_and(|h| h == *after))
                    .ok_or_else(|| failure(Refusal::BaseMismatch))?;
                result.predecessors.drain(..=position);
            }
        }
        if result.predecessors.len() + 1
            > usize::try_from(payload.limit)
                .map_err(|_| failure(Refusal::HomeCheckpointRequired))?
            || ramflux_protocol::canonical_json_bytes(&result).map_err(wire)?.len()
                > MAX_RESOLVE_BYTES
        {
            return Err(failure(Refusal::HomeCheckpointRequired));
        }
        Ok(result)
    }
}
