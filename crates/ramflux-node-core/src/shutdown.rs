// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Common bounded process shutdown for the seven node services.

use crate::NodeCoreError;
use std::time::Duration;

const SHUTDOWN_GRACE_SECONDS_ENV: &str = "RAMFLUX_SHUTDOWN_GRACE_SECONDS";
const DEFAULT_SHUTDOWN_GRACE_SECONDS: u64 = 1;
const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 4;

/// Wait for SIGTERM or SIGINT, allow detached request workers a bounded drain window, then return.
///
/// Service stores commit synchronously. Returning from the caller drops its store handles before
/// `main` exits, while the process boundary closes listener sockets and any remaining worker clones.
///
/// # Errors
/// Returns an error when the configured grace period is invalid or signal registration fails.
pub fn wait_for_service_shutdown(service: &'static str) -> Result<(), NodeCoreError> {
    let grace = shutdown_grace_period()?;
    #[cfg(unix)]
    {
        use signal_hook::consts::signal::{SIGINT, SIGTERM};
        use signal_hook::iterator::Signals;

        let mut signals = Signals::new([SIGTERM, SIGINT])
            .map_err(|error| NodeCoreError::ServiceShutdown(error.to_string()))?;
        let signal = signals
            .forever()
            .next()
            .ok_or_else(|| NodeCoreError::ServiceShutdown("signal stream ended".to_owned()))?;
        std::thread::sleep(grace);
        tracing::info!(service, signal, "graceful shutdown complete");
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (service, grace);
        Err(NodeCoreError::ServiceShutdown("SIGTERM shutdown is supported only on Unix".to_owned()))
    }
}

fn shutdown_grace_period() -> Result<Duration, NodeCoreError> {
    let seconds = match crate::environment::var(SHUTDOWN_GRACE_SECONDS_ENV) {
        Ok(value) => parse_shutdown_grace_seconds(&value)?,
        Err(std::env::VarError::NotPresent) => DEFAULT_SHUTDOWN_GRACE_SECONDS,
        Err(error) => return Err(NodeCoreError::ServiceShutdown(error.to_string())),
    };
    Ok(Duration::from_secs(seconds))
}

fn parse_shutdown_grace_seconds(value: &str) -> Result<u64, NodeCoreError> {
    let seconds = value.parse::<u64>().map_err(|_| {
        NodeCoreError::ServiceShutdown(format!(
            "{SHUTDOWN_GRACE_SECONDS_ENV} must be an integer from 0 to {MAX_SHUTDOWN_GRACE_SECONDS}"
        ))
    })?;
    if seconds > MAX_SHUTDOWN_GRACE_SECONDS {
        return Err(NodeCoreError::ServiceShutdown(format!(
            "{SHUTDOWN_GRACE_SECONDS_ENV} must be an integer from 0 to {MAX_SHUTDOWN_GRACE_SECONDS}"
        )));
    }
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_grace_is_bounded_below_container_timeout() -> Result<(), NodeCoreError> {
        assert_eq!(parse_shutdown_grace_seconds("0")?, 0);
        assert_eq!(parse_shutdown_grace_seconds("4")?, 4);
        assert!(parse_shutdown_grace_seconds("5").is_err());
        assert!(parse_shutdown_grace_seconds("invalid").is_err());
        Ok(())
    }
}
