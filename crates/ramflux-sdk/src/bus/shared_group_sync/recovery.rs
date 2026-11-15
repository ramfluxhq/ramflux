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
    // The authenticated device-set epoch is the native custody authority's; the legacy
    // observed record is never written for a native account.
    let Some(authority) =
        client.current_custody_authority(own.root_commitment(), crate::custody::network_now()?)?
    else {
        return Ok(0);
    };
    let device_set_epoch = authority.envelope().body.device_set_epoch;
    let mut progress = db.load_actor_state::<Progress>(PROGRESS)?.unwrap_or_default();
    if progress.device_set_epoch != device_set_epoch {
        progress = Progress { device_set_epoch, ..Progress::default() };
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
                client.stage_group_device_beacon(
                    group,
                    &account.gateway_config.target_delivery_id,
                    device_set_epoch,
                )?;
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
    use crate::client::native_test_support::{Fixture as Native, TestResult, bus as native_bus};
    use std::future::Future;
    fn native_block_on<T>(future: impl Future<Output = TestResult<T>>) -> Result<T, SdkError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(future)
            .map_err(|error| SdkError::LocalBus(error.to_string()))
    }
    #[test]
    fn shared_group_recovery_runs_only_for_authenticated_device_set_changes() -> Result<(), SdkError>
    {
        let mut account =
            native_block_on(async { Ok(Native::with_device("alice", "phone").await?.into_bus()) })?;
        account.client.fixture_group_create("group", "thread", Some("Name".into()), "phone")?;
        assert_eq!(stage(&account)?, 1);
        assert_eq!(stage(&account)?, 0, "same state cannot create an echo broadcast");
        // An authenticated own-set epoch change (a native sibling joining) invalidates the scan.
        let laptop =
            native_block_on(Box::pin(native_bus::sibling(&mut account, "alice-laptop", "laptop")))?;
        drop(laptop);
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
        Ok(())
    }
}
