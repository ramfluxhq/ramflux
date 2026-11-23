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
            let mut config = LocalBusConfig::new(socket, start.data_root);
            if let (Some(url), Some(path)) = (&start.prx_base_url, &start.prx_token_file) {
                config = config.with_prx(url, path)?;
            }
            #[cfg(feature = "itest-memory-vault")]
            if let Some(path) = itest_vault_path {
                config.custody_vault = Some(std::sync::Arc::new(
                    ramflux_sdk::custody::MemoryPrimaryVault::persist_at(path)?,
                ));
            }
            // Integration builds only (the same gate as the memory vault): a node under test serves
            // pairing over HTTPS with its own test CA, which the SDK's fixed trust roots do not
            // contain. The CA file is the one the test stack created; nothing else changes.
            #[cfg(feature = "itest-memory-vault")]
            if let Some(path) = std::env::var_os("RAMFLUX_ITEST_PAIRING_CA_FILE") {
                use std::io::Read as _;
                let mut pem = String::new();
                std::fs::File::open(path)?.take(65_537).read_to_string(&mut pem)?;
                if pem.len() > 65_536 {
                    return Err(RfError::Message("the pairing test CA file is too large".into()));
                }
                config.pairing = Some(ramflux_sdk::custody::pairing::PairingConfig {
                    enabled: true,
                    extra_root_ca_pem: Some(pem),
                });
            }
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
