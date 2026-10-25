// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded state anti-entropy and own-device activation backfill.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
const PROGRESS: &str = "group-state/recovery-progress";
const GROUPS_PER_TICK: u32 = 4;
#[derive(Default, Deserialize, Serialize)]
struct Progress {
    device_set_epoch: u64,
    after: String,
    complete: bool,
}

pub(in crate::bus) fn stage(account: &LocalBusAccountState) -> Result<usize, SdkError> {
    let client = &account.client;
    let db = client.account_db()?;
    db.prune_shared_group_boundaries(now_unix_timestamp())?;
    let own = client.owned_device_identity()?;
    let Some(set) = client.observed_device_set(own.root_commitment())? else {
        return Ok(0);
    };
    let mut progress = db.load_actor_state::<Progress>(PROGRESS)?.unwrap_or_default();
    if progress.device_set_epoch != set.device_set_epoch {
        progress = Progress { device_set_epoch: set.device_set_epoch, ..Progress::default() };
    }
    if progress.complete {
        return Ok(0);
    }
    let groups = db.client_directory_ids("group", &progress.after, GROUPS_PER_TICK)?;
    let mut staged = 0;
    for group in &groups {
        db.write_transaction(|| -> Result<(), SdkError> {
            if let Some(state) = db.shared_group_state(group)?
                && state.view().effective_role(own.root_commitment(), own.device_id()).is_some()
            {
                let state = ramflux_crypto::resign_group_state_snapshot(
                    client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                    &client.owned_group_actor(&account.gateway_config.target_delivery_id)?,
                    &state,
                )?;
                // An authenticated own-device-set change restages state for newly enrolled
                // siblings. Completion is durable; idle time never restarts this scan.
                if !super::outbox::enqueue_recovery(client, &state)? {
                    return Ok(());
                }
                staged += 1;
            }
            progress.after.clone_from(group);
            db.persist_actor_state(PROGRESS, &progress)?;
            Ok(())
        })?;
    }
    if groups.len() < GROUPS_PER_TICK as usize {
        progress.complete = true;
        db.persist_actor_state(PROGRESS, &progress)?;
    }
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::identity_authority::test_support;
    use std::sync::{Arc, atomic::AtomicBool};
    #[test]
    fn shared_group_recovery_runs_only_for_authenticated_device_set_changes() -> Result<(), SdkError>
    {
        let root = crate::bus::runtime_tests::root("group-recovery");
        let account = crate::bus::runtime_tests::account(
            &root,
            "alice",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let mut manifest = test_support::public_manifest(&account.client)?;
        account.client.persist_identity_directory(&manifest)?;
        account.client.shared_group_create("group", "thread", Some("Name".into()), "target")?;
        assert_eq!(stage(&account)?, 1);
        assert_eq!(stage(&account)?, 0, "same state cannot create an echo broadcast");
        // An authenticated own-set epoch change invalidates the completed scan.
        test_support::sign_manifest(
            account.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &mut manifest,
            2,
        )?;
        account.client.persist_identity_directory(&manifest)?;
        assert_eq!(stage(&account)?, 1);
        assert_eq!(stage(&account)?, 0);
        let db = account.client.account_db()?;
        let progress: Progress =
            db.load_actor_state(PROGRESS)?.ok_or(StorageError::GroupPermissionDenied)?;
        assert!(progress.complete);
        for _ in 0..4 {
            assert_eq!(stage(&account)?, 0, "idle ticks must never replay full state");
        }
        assert_eq!(db.list_actor_states::<serde_json::Value>("group-state/send/")?.len(), 1);
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
