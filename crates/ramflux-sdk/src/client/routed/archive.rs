// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-device session record: one sending state plus bounded receive-only previous states.
use super::{RamfluxClient, SdkError, now_unix_timestamp};
/// Eight previous ratchets limit encrypted client storage while tolerating several overlapping
/// bootstraps. Eviction, unlike archiving, destroys the old private state.
pub(super) const MAX_PAIR_ARCHIVE: usize = 8;
impl RamfluxClient {
    pub(super) fn archived_pairs(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Vec<String>, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<Vec<String>>(&format!(
                "{}/archive",
                RamfluxClient::pair_key(local, remote)?
            ))?
            .unwrap_or_default())
    }
    pub(super) fn archive_pair(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        id: &str,
    ) -> Result<(), SdkError> {
        let mut archive = self.archived_pairs(local, remote)?;
        if archive.iter().any(|old| old == id) {
            return Ok(());
        }
        archive.insert(0, id.to_owned());
        while archive.len() > MAX_PAIR_ARCHIVE {
            if let Some(evicted) = archive.pop() {
                self.retire_pair(local, remote, &evicted)?;
            }
        }
        self.account_db()?.persist_actor_state(
            &format!("{}/archive", RamfluxClient::pair_key(local, remote)?),
            &archive,
        )?;
        Ok(())
    }
    pub(super) fn promote_pair(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        id: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let key = RamfluxClient::pair_key(local, remote)?;
        if let Some(old) = db.load_actor_state::<String>(&key)?
            && old != id
        {
            self.archive_pair(local, remote, &old)?;
        }
        let mut archive = self.archived_pairs(local, remote)?;
        archive.retain(|old| old != id);
        db.persist_actor_state(&format!("{key}/archive"), &archive)?;
        db.persist_actor_state(&key, &id)?;
        db.supersede_pair_tombstones(&key, id)?;
        db.prune_pair_metadata()?;
        Ok(())
    }
    pub(super) fn confirm_pair_record(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        session: &ramflux_crypto::DmSession,
        reset: bool,
        bootstrap: bool,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let id = &session.session_id;
        let archived = self.archived_pairs(local, remote)?.contains(id);
        let fresh =
            !db.load_actor_state::<bool>(&format!("dm-pair/confirmed/{id}"))?.unwrap_or(false);
        let key = RamfluxClient::pair_key(local, remote)?;
        let current = db.load_actor_state::<String>(&key)?;
        let current_confirmed = current
            .as_ref()
            .map(|old| db.load_actor_state::<bool>(&format!("dm-pair/confirmed/{old}")))
            .transpose()?
            .flatten()
            .unwrap_or(false);
        let current_local = current
            .as_ref()
            .map(|old| db.load_actor_state::<bool>(&format!("dm-pair/local/{old}")))
            .transpose()?
            .flatten()
            .unwrap_or(false);
        db.persist_actor_state(&format!("dm-pair/confirmed/{id}"), &true)?;
        db.remove_actor_state(&format!("dm-pair/bootstrap/{id}"))?;
        let simultaneous = current_local && !current_confirmed;
        let promote = match current.as_deref() {
            None => !archived,
            Some(old) if old == id => false,
            Some(old) => !archived && fresh && bootstrap && (!simultaneous || id.as_str() < old),
        };
        if promote {
            self.promote_pair(local, remote, id)?;
            db.append_journal(
                &format!("pair-promoted:{id}"),
                "session.reset",
                &serde_json::json!({"device_id": remote.storage_key(), "reason": if reset {"verified_reset_archived_previous"} else {"verified_bootstrap_archived_previous"}}),
                now_unix_timestamp(),
                None,
            )?;
        } else if current.as_deref() != Some(id) && !archived {
            self.archive_pair(local, remote, id)?;
        }
        // An archived hit is ordinary receive progress, not confirmation of the current reset.
        if db.load_actor_state::<String>(&key)?.as_deref() == Some(id) {
            if db.actor_state_exists(&format!("{key}/manual"))? {
                db.remove_actor_state(&format!("{key}/manual"))?;
                db.append_journal(
                    &format!("pair-manual-restored:{id}"),
                    "session.reset",
                    &serde_json::json!({"device_id":remote.storage_key(),"state":"healthy"}),
                    now_unix_timestamp(),
                    None,
                )?;
            }
            db.remove_actor_state(&format!("{key}/reset-pending"))?;
            db.remove_actor_state(&format!(
                "dm-pair/reset-work/{}",
                RamfluxClient::pair_key(local, remote)?
            ))?;
        }
        Ok(())
    }
}
