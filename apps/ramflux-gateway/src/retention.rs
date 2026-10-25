// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keep live sinks while expiring disconnected session metadata and resume checkpoints.
pub(crate) fn start(context: crate::serve::GatewayListenerContext) -> anyhow::Result<()> {
    std::thread::Builder::new().name("gateway-retention".into()).spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            let active = context.hub.active_session_ids();
            let result = (|| -> anyhow::Result<()> {
                let mut state = crate::gateway_state(&context.state)?;
                state.prune_retained_sessions(ramflux_node_core::now_unix_seconds(), 300, &active);
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
