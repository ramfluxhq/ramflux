// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keep live sinks while expiring disconnected session metadata and resume checkpoints.
pub(crate) fn checkpoint_once_at(
    context: &crate::serve::GatewayListenerContext,
    clock: impl FnOnce() -> std::time::SystemTime,
) -> anyhow::Result<()> {
    // Writer ordering precedes state capture; a blocked writer never owns the state mutex.
    let writer = context.store.write_guard()?;
    let active = context.hub.retention_snapshot();
    let (checkpoint, now) = {
        let mut state = crate::gateway_state(&context.state)?;
        let now = state.observe_pre_auth_time(clock())?;
        state.prune_retained_sessions_bounded(
            now,
            crate::session::gateway_resume_window_seconds(),
            |session| {
                active
                    .get(&session.target_delivery_id)
                    .is_some_and(|entry| entry.session_id == session.session_id)
            },
        );
        (state.admission_checkpoint(now), now)
    };
    writer.prune_replay(i64::try_from(now)?)?;
    writer.save_admission_checkpoint(&checkpoint)?;
    crate::gateway_state(&context.state)?.install_admission_checkpoint(&checkpoint);
    writer.prune_session_rows(now, crate::session::gateway_resume_window_seconds())?;
    Ok(())
}

pub(crate) fn start(context: crate::serve::GatewayListenerContext) -> anyhow::Result<()> {
    let observer = context.clone();
    ramflux_node_core::spawn_service_worker("gateway-admission-health", move |_| {
        let mut was_unavailable = false;
        while ramflux_node_core::service_shutdown_sleep(std::time::Duration::from_secs(10)) {
            if let Ok(mut state) = crate::gateway_state(&observer.state) {
                let unavailable = state
                    .observe_admission_checkpoint_health(ramflux_node_core::now_unix_seconds());
                if unavailable {
                    tracing::warn!(
                        checkpoint_outages = state.pre_auth_metrics().checkpoint_outages,
                        checkpoint_failures = state.pre_auth_metrics().checkpoint_failures,
                        "gateway admission checkpoint unavailable"
                    );
                } else if was_unavailable {
                    tracing::info!("gateway admission checkpoint recovered");
                }
                was_unavailable = unavailable;
            }
        }
    })?;
    ramflux_node_core::spawn_service_worker("gateway-retention", move |_| {
        while ramflux_node_core::service_shutdown_sleep(std::time::Duration::from_secs(10)) {
            if checkpoint_once_at(&context, std::time::SystemTime::now).is_err()
                && let Ok(mut state) = crate::gateway_state(&context.state)
            {
                state.record_admission_checkpoint_failure();
            }
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ramflux_node_core::{GatewaySession, GatewaySessionLifecycle, GatewayState};

    #[test]
    fn checkpoint_samples_clock_after_writer_wait_and_preserves_real_rollback() -> anyhow::Result<()>
    {
        use std::{
            sync::{
                Arc,
                atomic::{AtomicU64, Ordering},
                mpsc,
            },
            time::{Duration, UNIX_EPOCH},
        };
        let (_fixture_directory_0, fixture_value_0) =
            crate::session::tests::test_gateway_context()?;
        let context = fixture_value_0;
        let listener = crate::pre_auth_transport_tests::support::listener_context(&context);
        let checkpoint = crate::gateway_state(&context.state)?.admission_checkpoint(100);
        context.store.save_admission_checkpoint(&checkpoint)?;
        crate::gateway_state(&context.state)?.install_admission_checkpoint(&checkpoint);
        let writer = context.store.write_guard()?;
        let (attempted, observed) = mpsc::channel();
        context.store.observe_next_writer_attempt(attempted)?;
        let clock = Arc::new(AtomicU64::new(120));
        let worker_clock = Arc::clone(&clock);
        let worker = std::thread::spawn(move || {
            super::checkpoint_once_at(&listener, || {
                UNIX_EPOCH + Duration::from_secs(worker_clock.load(Ordering::SeqCst))
            })
            .map_err(|error| error.to_string())
        });
        observed.recv_timeout(Duration::from_secs(10))?;
        assert!(
            crate::pre_auth::admit_with_clock("source", None, &context.state, || UNIX_EPOCH
                + Duration::from_secs(121))?
            .is_none()
        );
        clock.store(122, Ordering::SeqCst);
        drop(writer);
        let committed = worker.join().map_err(|_| anyhow::anyhow!("checkpoint worker panicked"))?;
        assert!(
            committed.is_ok(),
            "checkpoint sampled before waiting for the writer: {committed:?}"
        );
        assert_eq!(
            crate::gateway_state(&context.state)?
                .observe_pre_auth_time(UNIX_EPOCH + Duration::from_secs(122))?,
            122
        );
        assert!(matches!(
            crate::gateway_state(&context.state)?
                .observe_pre_auth_time(UNIX_EPOCH + Duration::from_secs(121)),
            Err(ramflux_node_core::NodeCoreError::PreAuthClockRollback)
        ));
        Ok(())
    }

    #[test]
    fn slow_checkpoint_commit_does_not_block_authenticated_activity_and_recovers()
    -> anyhow::Result<()> {
        use std::{
            sync::mpsc,
            time::{Duration, UNIX_EPOCH},
        };
        let (_fixture_directory_1, fixture_value_1) =
            crate::session::tests::test_gateway_context()?;
        let context = fixture_value_1;
        let listener = crate::pre_auth_transport_tests::support::listener_context(&context);
        let checkpoint = crate::gateway_state(&context.state)?.admission_checkpoint(100);
        context.store.save_admission_checkpoint(&checkpoint)?;
        crate::gateway_state(&context.state)?.install_admission_checkpoint(&checkpoint);
        crate::gateway_state(&context.state)?.open_session(GatewaySession {
            session_id: "active".into(),
            target_delivery_id: "target".into(),
            device_id: "device".into(),
            opened_at: 100,
            last_heartbeat_at: 100,
            lifecycle: GatewaySessionLifecycle::Live,
        });
        let root = ramflux_crypto::create_identity_root("principal", [51; 32]);
        let branch = ramflux_crypto::create_device_branch("principal", "device", 1, [52; 32]);
        let runtime = crate::GatewaySessionRuntime {
            call_session_generation: None,
            session_push: None,
            ephemeral: false,
            push_limit: 256,
            source_identity: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
                &root, &branch,
            )?,
            session_id: "active".into(),
            resume_token: "token".into(),
            principal_id: "principal".into(),
            device_id: "device".into(),
            target_delivery_id: "target".into(),
            device_epoch: 1,
            branch_public_key: ramflux_crypto::public_key_base64url_from_seed([52; 32]),
            supports_forward_ack: false,
            ephemeral_rate: std::sync::Arc::default(),
        };
        let (entered, observed) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        context.store.pause_next_admission_commit(entered, waiting)?;
        let worker = std::thread::spawn(move || {
            super::checkpoint_once_at(&listener, || UNIX_EPOCH + Duration::from_secs(120))
                .map_err(|error| error.to_string())
        });
        // A semantic write-transaction barrier; timeout is only a deadlock watchdog.
        observed.recv_timeout(Duration::from_secs(10))?;
        assert!(context.state.try_lock().is_ok(), "checkpoint fsync held the gateway state mutex");
        crate::session::refresh_session_activity(&context, &runtime)?;
        assert!(crate::gateway_state(&context.state)?.observe_admission_checkpoint_health(131));
        assert_eq!(crate::gateway_state(&context.state)?.pre_auth_metrics().checkpoint_outages, 1);
        let error = crate::pre_auth::admit_with_clock("source", None, &context.state, || {
            UNIX_EPOCH + Duration::from_secs(131)
        })
        .err()
        .map(|error| error.to_string());
        assert_eq!(error.as_deref(), Some("checkpoint_unavailable"));
        release.send(())?;
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("checkpoint worker panicked"))?
            .map_err(anyhow::Error::msg)?;
        assert!(!crate::gateway_state(&context.state)?.observe_admission_checkpoint_health(132));
        assert!(
            crate::pre_auth::admit_with_clock("source", None, &context.state, || UNIX_EPOCH
                + Duration::from_secs(132))?
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn retention_keeps_disconnected_sessions_for_the_configured_resume_window() {
        let window = crate::session::resume_window_from(Some("900"));
        assert_eq!(window, 900);
        assert_eq!(crate::session::resume_window_from(Some("0")), 300);
        let mut state = GatewayState::new();
        state.open_session(GatewaySession {
            session_id: "idle".into(),
            target_delivery_id: "idle".into(),
            device_id: "phone".into(),
            opened_at: 1_000,
            last_heartbeat_at: 1_000,
            lifecycle: GatewaySessionLifecycle::Live,
        });
        let none = std::collections::BTreeSet::new();
        assert_eq!(state.prune_retained_sessions(1_600, window, &none), 0);
        assert!(state.session("idle").is_some());
        assert_eq!(state.prune_retained_sessions(1_901, window, &none), 1);
    }
}
