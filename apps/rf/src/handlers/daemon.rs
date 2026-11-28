// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_daemon(socket: PathBuf, command: DaemonCommand) -> Result<(), RfError> {
    match command.action {
        DaemonAction::Start(start) => {
            crate::logging::init()?;
            eprintln!("{}", ramflux_core::version::BANNER);
            #[cfg(target_os = "linux")]
            {
                let state = crate::linux_paths::state_dir()?;
                crate::linux_paths::ensure_state_dir(&state)?;
                eprintln!("ramflux state directory: {}", state.display());
            }
            #[cfg(feature = "itest-memory-vault")]
            let itest_vault_path =
                start.itest_memory_vault.then(|| start.data_root.join("itest-memory-vault.json"));
            if start.prx_base_url.is_some() != start.prx_token_file.is_some() {
                return Err(RfError::Message(
                    "--prx-base-url and --prx-token-file are set together".into(),
                ));
            }
            if start.prx_state_dir.is_some()
                && (start.prx_base_url.is_some() || start.prx_token_file.is_some())
            {
                return Err(RfError::Message(
                    "--prx-state-dir is not combined with --prx-base-url".into(),
                ));
            }
            let mut config = LocalBusConfig::new(socket, start.data_root);
            // Environment provisioning is a CLI concern; native clients pass their own pin.
            config.username_directory = ramflux_sdk::username_directory::configured_center().ok();
            if let (Some(url), Some(path)) = (&start.prx_base_url, &start.prx_token_file) {
                config = config.with_prx(url, path)?;
            }
            if let Some(dir) = &start.prx_state_dir {
                #[cfg(unix)]
                {
                    let (url, path) = crate::prx::adopt(dir).await?;
                    config = config.with_prx(&url, &path)?;
                }
                #[cfg(not(unix))]
                {
                    let _ = dir;
                    return Err(RfError::UnsupportedPlatform { command: "prx" });
                }
            }
            #[cfg(feature = "itest-memory-vault")]
            if let Some(path) = itest_vault_path {
                config.custody_vault = Some(std::sync::Arc::new(
                    ramflux_sdk::custody::MemoryPrimaryVault::persist_at(path)?,
                ));
            }
            // Pairing trust, including RAMFLUX_ITEST_PAIRING_CA_FILE on integration builds, is
            // PairingConfig::from_env. The in-process C ABI client starts with pairing unset and
            // the supervisor applies that same reader. Nothing else about TLS changes.
            config.pairing = Some(ramflux_sdk::custody::pairing::PairingConfig::from_env()?);
            if let Some(path) = start.builtin_nodes {
                config.builtin_nodes = serde_json::from_slice(&std::fs::read(path)?)?;
            }
            // The process exits explicitly: lingering blocking work must not keep it alive.
            let code = match ramflux_sdk::serve_local_bus(config).await {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            };
            {
                use std::io::Write;
                let _ = std::io::stdout().flush();
                let _ = std::io::stderr().flush();
            }
            std::process::exit(code)
        }
        DaemonAction::Status => {
            let mut bus = LocalBusClient::connect(socket).await?;
            print_json(&bus.request(None, "daemon", "daemon.status", serde_json::json!({})).await?)
        }
        DaemonAction::Stop => daemon_stop(socket).await,
    }
}

/// Total client-side limit for `rf daemon stop`, from the start of the command.
const STOP_LIMIT: std::time::Duration = std::time::Duration::from_millis(5000);
#[cfg(unix)]
const EXIT_POLL: std::time::Duration = std::time::Duration::from_millis(20);

async fn daemon_stop(socket: PathBuf) -> Result<(), RfError> {
    let deadline = tokio::time::Instant::now() + STOP_LIMIT;
    let reply = tokio::time::timeout_at(deadline, async {
        let mut bus = LocalBusClient::connect(socket).await?;
        bus.request(None, "daemon", "daemon.stop", serde_json::json!({})).await
    })
    .await
    .map_err(|_| RfError::Message("daemon did not answer daemon.stop within 5 s".into()))??;
    print_json(&reply)?;
    #[cfg(unix)]
    if let Some(pid) = reply.get("pid").and_then(serde_json::Value::as_u64) {
        let gone = tokio::time::timeout_at(deadline, async {
            while !process_gone(pid) {
                tokio::time::sleep(EXIT_POLL).await;
            }
        })
        .await;
        if gone.is_err() {
            return Err(RfError::Message(format!("daemon process {pid} still running after 5 s")));
        }
    }
    Ok(())
}

/// True when the process no longer exists (a zombie that nobody reaped counts as exited).
#[cfg(unix)]
fn process_gone(pid: u64) -> bool {
    let Some(target) = i32::try_from(pid).ok().and_then(rustix::process::Pid::from_raw) else {
        return true;
    };
    match rustix::process::test_kill_process(target) {
        Ok(()) => process_is_zombie(pid),
        Err(error) => error == rustix::io::Errno::SRCH,
    }
}

#[cfg(target_os = "linux")]
fn process_is_zombie(pid: u64) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')').is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_zombie(_pid: u64) -> bool {
    false
}
