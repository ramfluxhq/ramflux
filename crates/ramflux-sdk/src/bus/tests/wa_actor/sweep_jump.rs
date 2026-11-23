// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Virtual-time jump from 899s to the 900s safety sweep.

use super::*;

pub(super) async fn jump_sweep(
    runtime: &mut super::super::super::AccountRuntime,
    handle: &crate::bus::connection_manager::ConnectionHandle,
    gateway: &Arc<std::sync::Mutex<super::super::fixture::Gateway>>,
) -> Case {
    tokio::time::advance(Duration::from_secs(899)).await;
    stays_until(
        runtime,
        Duration::from_millis(200),
        "session left Live before the 900s sweep",
        |_| Ok(handle.snapshot().state != NetworkingState::Live),
    )
    .await?;
    assert_eq!(
        handle.snapshot().state,
        NetworkingState::Live,
        "session must stay Live through 899s snap={:?} err={:?}",
        handle.snapshot(),
        handle.test_receive_last_error()
    );
    assert_eq!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len(),
        1,
        "no Resume until 900s snap={:?}",
        handle.snapshot()
    );
    tokio::time::advance(Duration::from_millis(1_000)).await;
    pump_until(runtime, PHASE_WALL, "Sweep Resume at 900s", |_| {
        Ok(gateway.lock().map_or(0, |g| g.resumes.len()) >= 2
            || handle.snapshot().state != NetworkingState::Live)
    })
    .await?;
    let resumes = gateway.lock().map_err(|_| "gateway")?.resumes.len();
    assert!(
        resumes >= 2,
        "Sweep Resume at 900s: resumes={resumes} trace={:?} err={:?} snap={:?}",
        handle.test_receive_trace(),
        handle.test_receive_last_error(),
        handle.snapshot()
    );
    Ok(())
}
