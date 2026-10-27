// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keep live sinks while expiring disconnected session metadata and resume checkpoints.
pub(crate) fn start(context: crate::serve::GatewayListenerContext) -> anyhow::Result<()> {
    ramflux_node_core::spawn_service_worker("gateway-retention", move |_| {
        while ramflux_node_core::service_shutdown_sleep(std::time::Duration::from_secs(30)) {
            let active = context.hub.active_session_ids();
            let result = (|| -> anyhow::Result<()> {
                let mut state = crate::gateway_state(&context.state)?;
                state.prune_retained_sessions(
                    ramflux_node_core::now_unix_seconds(),
                    crate::session::gateway_resume_window_seconds(),
                    &active,
                );
                context.store.save_state(&state)?;
                Ok(())
            })();
            if let Err(error) = result {
                tracing::warn!(%error,"gateway retention deferred");
            }
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ramflux_node_core::{GatewaySession, GatewaySessionLifecycle, GatewayState};

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
