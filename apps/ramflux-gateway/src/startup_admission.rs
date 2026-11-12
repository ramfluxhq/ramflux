// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A crash reservation delays listening; graceful shutdown releases it at the exact floor.
use ramflux_node_core::{GatewayRedbStore, GatewayState, NodeCoreError};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

pub(crate) fn wait(state: &mut GatewayState) -> anyhow::Result<u64> {
    let started = Instant::now();
    let maximum = Duration::from_secs(ramflux_node_core::PRE_AUTH_CHECKPOINT_SECONDS);
    wait_with(state, SystemTime::now, |delay| {
        let remaining = maximum.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(NodeCoreError::PreAuthClockRollback);
        }
        std::thread::sleep(delay.min(remaining));
        Ok(())
    })
}
fn wait_with(
    state: &mut GatewayState,
    mut clock: impl FnMut() -> SystemTime,
    mut wait: impl FnMut(Duration) -> Result<(), NodeCoreError>,
) -> anyhow::Result<u64> {
    let mut logged = false;
    loop {
        let time = clock();
        let delay = state.admission_startup_delay(time)?;
        if delay.is_zero() {
            return Ok(state.observe_pre_auth_time(time)?);
        }
        if !logged {
            tracing::info!(
                wait_seconds = delay.as_secs_f64(),
                "gateway waiting for committed crash reservation"
            );
            logged = true;
        }
        wait(delay)?;
    }
}

pub(crate) fn final_checkpoint(
    state: &Arc<Mutex<GatewayState>>,
    store: &GatewayRedbStore,
) -> Result<(), NodeCoreError> {
    let writer = store.write_guard()?;
    let (checkpoint, now) = {
        let mut state =
            state.lock().map_err(|_| NodeCoreError::Redb("gateway state poisoned".into()))?;
        let now = state.observe_pre_auth_time(SystemTime::now())?;
        (state.final_admission_checkpoint(now), now)
    };
    writer.prune_replay(i64::try_from(now).map_err(|_| NodeCoreError::PreAuthClockInvalid)?)?;
    writer.save_admission_checkpoint(&checkpoint)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, time::UNIX_EPOCH};
    #[test]
    fn clean_restart_is_immediate_crash_waits_and_true_rollback_is_typed() -> anyhow::Result<()> {
        for enabled in [false, true] {
            let path = std::env::temp_dir().join(format!(
                "gateway-startup-{}.redb",
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
            ));
            let store = GatewayRedbStore::open(&path)?;
            let mut state = GatewayState::new();
            state.set_pre_auth_policy(ramflux_node_core::GatewayPreAuthPolicy {
                enabled,
                per_source_ip_handshake_rate: 1,
                ..Default::default()
            })?;
            state.observe_pre_auth_time(UNIX_EPOCH + Duration::from_secs(100))?;
            store.save_admission_checkpoint(&state.admission_checkpoint(100))?;
            let mut crashed =
                store.load_state()?.ok_or_else(|| anyhow::anyhow!("missing crash checkpoint"))?;
            let clock = Cell::new(100);
            let waits = Cell::new(0);
            let now = wait_with(
                &mut crashed,
                || UNIX_EPOCH + Duration::from_secs(clock.get()),
                |duration| {
                    waits.set(waits.get() + 1);
                    clock.set(clock.get() + duration.as_secs());
                    Ok(())
                },
            )?;
            assert_eq!(now, 130, "crash must wait through committed endpoint");
            assert_eq!(waits.get(), 1);
            let mut rolled = store
                .load_state()?
                .ok_or_else(|| anyhow::anyhow!("missing rollback checkpoint"))?;
            let result = wait_with(
                &mut rolled,
                || UNIX_EPOCH + Duration::from_secs(99),
                |_| Err(NodeCoreError::PreAuthSnapshotInvalid),
            );
            assert!(matches!(
                result.as_ref().err().and_then(|error| error.downcast_ref::<NodeCoreError>()),
                Some(NodeCoreError::PreAuthClockRollback)
            ));
            store.save_admission_checkpoint(&state.final_admission_checkpoint(100))?;
            let mut clean =
                store.load_state()?.ok_or_else(|| anyhow::anyhow!("missing clean checkpoint"))?;
            assert_eq!(
                wait_with(
                    &mut clean,
                    || UNIX_EPOCH + Duration::from_secs(100),
                    |_| Err(NodeCoreError::PreAuthSnapshotInvalid)
                )?,
                100
            );
            drop(store);
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}
