// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live derived rosters have a separate bounded compartment and never enter state-read pages.
use super::{
    AccountReach, Applied, OPERATION_HASH_DOMAIN, OPERATIONS, OperationResult, OperationRow,
    ReachOwner, Reason, Result, RouterRedbStore, authority, custody, encoded, key, refuse,
    retain_operation, row, storage,
};
use redb::{ReadableTable, TableDefinition};
#[cfg(test)]
pub(super) mod fault;
const ROSTERS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_group_rosters_v1");
pub(super) fn load(
    tx: &redb::WriteTransaction,
    root: &str,
    state: &mut AccountReach,
) -> Result<()> {
    let prefix = format!("[{},", serde_json::to_string(root).map_err(storage)?);
    let table = tx.open_table(ROSTERS).map_err(storage)?;
    let mut bytes = 0_usize;
    for item in table.range(prefix.as_str()..).map_err(storage)?.take(1025) {
        let (key, value) = item.map_err(storage)?;
        if !key.value().starts_with(&prefix) {
            break;
        }
        let (owner, subject): (String, String) =
            serde_json::from_str(key.value()).map_err(storage)?;
        bytes = bytes
            .checked_add(value.value().len())
            .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
        if owner != root || state.rosters.len() >= 1024 || bytes > 16 * 1024 * 1024 {
            return Err(storage("invalid bounded group roster compartment"));
        }
        state.rosters.insert(subject, row(value.value())?);
    }
    Ok(())
}
pub(super) fn save(tx: &redb::WriteTransaction, root: &str, state: &AccountReach) -> Result<()> {
    state.check_group_reservations(false)?;
    let prefix = format!("[{},", serde_json::to_string(root).map_err(storage)?);
    let mut table = tx.open_table(ROSTERS).map_err(storage)?;
    let old = table
        .range(prefix.as_str()..)
        .map_err(storage)?
        .take(1025)
        .map(|item| {
            let (key, _) = item.map_err(storage)?;
            Ok(key.value().to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    for old in old {
        if !old.starts_with(&prefix) {
            break;
        }
        let (_, subject): (String, String) = serde_json::from_str(&old).map_err(storage)?;
        if !state.rosters.contains_key(&subject) {
            table.remove(old.as_str()).map_err(storage)?;
        }
    }
    for (subject, roster) in &state.rosters {
        table.insert(key(root, subject)?.as_str(), encoded(roster)?.as_slice()).map_err(storage)?;
    }
    Ok(())
}
impl RouterRedbStore {
    /// Apply one primary-signed roster only while its exact group grant is live.
    /// # Errors
    /// Refuses current-primary, hash/epoch, capacity and exact operation retry conflicts.
    pub fn reach_group_roster(
        &self,
        owner: ReachOwner<'_>,
        operation_id: &str,
        roster: &ramflux_protocol::contact_reach::GroupRoster,
        now: u64,
    ) -> Result<OperationResult> {
        let id = ramflux_protocol::decode_base64url(operation_id)
            .map_err(|_| refuse(Reason::ForeignInvalidFrame))?;
        if id.len() != 32 || ramflux_protocol::encode_base64url(&id) != operation_id {
            return Err(refuse(Reason::ForeignInvalidFrame));
        }
        let _home_gate = self.acquire_home_operation(owner.recipient_root)?;
        let (tx, now) = self.begin_reach_write(now)?;
        let authority = authority(&tx, owner.recipient_root, now)?;
        authority.authorize_primary_management(owner.actor, "contact_consent", now)?;
        let operation_key = key(owner.recipient_root, operation_id)?;
        let operation = ramflux_protocol::contact_reach::Operation::GroupRoster {
            operation_id: operation_id.to_owned(),
            roster: Box::new(roster.clone()),
        };
        let hash = custody::framed_hash(OPERATION_HASH_DOMAIN, &operation)?;
        if let Some(old) = tx
            .open_table(OPERATIONS)
            .map_err(storage)?
            .get(operation_key.as_str())
            .map_err(storage)?
            .map(|v| row::<OperationRow>(v.value()))
            .transpose()?
            && old.expires_at > now
        {
            if old.hash != hash {
                return Err(refuse(Reason::IdempotencyConflict));
            }
            return Ok(old.result);
        }
        let expires = roster
            .header
            .body
            .issued_at
            .checked_add(300)
            .ok_or_else(|| refuse(Reason::ReachRouteInvalid))?;
        if now >= expires {
            return Err(refuse(Reason::ReachCommandExpired));
        }
        let mut state = super::load(&tx, owner.recipient_root)?;
        let subject_key =
            serde_json::to_string(&serde_json::json!(["group", roster.header.body.group_id]))
                .map_err(storage)?;
        let Some(ramflux_protocol::contact_reach::StateRecord::Grant { update: grant, .. }) =
            state.grants.get(&subject_key)
        else {
            return Err(refuse(Reason::ForeignReadRefused));
        };
        ramflux_crypto::contact_reach::verify_group_roster_command(roster, grant, &authority, now)?;
        let changed = state.group_roster(roster.clone())?;
        let result = OperationResult::GroupRoster {
            group_epoch: roster.header.body.group_epoch,
            outcome: if changed { Applied::Applied } else { Applied::Duplicate },
        };
        // Roster intent retry identity is kept separately from consent and survives reconnect.
        retain_operation(&tx, &operation_key, expires, &hash, &result, now)?;
        super::provenance::retain(&tx, owner.recipient_root, &state, now)?;
        super::save(&tx, owner.recipient_root, &state)?;
        #[cfg(test)]
        fault::checkpoint(fault::Point::BeforeCommit)?;
        tx.commit()?;
        #[cfg(test)]
        fault::checkpoint(fault::Point::AfterCommit)?;
        Ok(result)
    }
}
