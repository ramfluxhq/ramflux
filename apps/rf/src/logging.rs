// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Daemon diagnostics are opt-in and always kept off the CLI's JSON output stream.
use crate::RfError;
use tracing_subscriber::EnvFilter;

pub(crate) fn init() -> Result<(), RfError> {
    let filter = match EnvFilter::try_from_env("RUST_LOG") {
        Ok(filter) => filter,
        Err(error) => {
            if std::env::var_os("RUST_LOG").is_some() {
                eprintln!("warning: invalid RUST_LOG; daemon logging disabled: {error}");
            }
            EnvFilter::new("off")
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init()
        .map_err(|error| RfError::Message(format!("could not initialize daemon logging: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn daemon_rust_log_filter_writes_sdk_info_only_to_stderr()
    -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os("RF_LOGGING_TEST_CHILD").is_some() {
            init()?;
            tracing::info!(target: "ramflux_sdk", inbox_seq = 42, kind = "InboundPending",
                reason = "group root unavailable", "held-entry-filter-probe");
            tracing::debug!(target: "ramflux_sdk", "debug-filter-probe");
            return Ok(());
        }
        for setting in [Some("ramflux_sdk=info"), Some("ramflux_sdk=["), Some("non-utf8"), None] {
            let mut child = Command::new(std::env::current_exe()?);
            child
                .args([
                    "--exact",
                    "logging::tests::daemon_rust_log_filter_writes_sdk_info_only_to_stderr",
                    "--nocapture",
                ])
                .env("RF_LOGGING_TEST_CHILD", "1")
                .env_remove("RUST_LOG");
            if let Some(value) = setting {
                if value == "non-utf8" {
                    use std::os::unix::ffi::OsStringExt;
                    child.env("RUST_LOG", std::ffi::OsString::from_vec(vec![0xff]));
                } else {
                    child.env("RUST_LOG", value);
                }
            }
            let output = child.output()?;
            assert!(output.status.success());
            let stderr = String::from_utf8(output.stderr)?;
            assert!(!String::from_utf8(output.stdout)?.contains("held-entry-filter-probe"));
            assert_eq!(
                stderr.matches("held-entry-filter-probe").count(),
                usize::from(setting == Some("ramflux_sdk=info"))
            );
            assert!(!stderr.contains("debug-filter-probe"));
            if matches!(setting, Some("ramflux_sdk=[" | "non-utf8")) {
                assert_eq!(stderr.matches("warning: invalid RUST_LOG").count(), 1);
            }
            if setting == Some("ramflux_sdk=info") {
                for expected in ["INFO", "inbox_seq=42", "InboundPending", "group root unavailable"]
                {
                    assert!(stderr.contains(expected), "missing {expected}: {stderr}");
                }
            }
        }
        Ok(())
    }
}
