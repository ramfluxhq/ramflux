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
            ramflux_sdk::serve_local_bus(config).await?;
            Ok(())
        }
        DaemonAction::Status => {
            let mut bus = LocalBusClient::connect(socket).await?;
            print_json(&bus.request(None, "daemon", "daemon.status", serde_json::json!({})).await?)
        }
        DaemonAction::Stop => {
            let mut bus = LocalBusClient::connect(socket).await?;
            print_json(&bus.request(None, "daemon", "daemon.stop", serde_json::json!({})).await?)
        }
    }
}
