// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_daemon(socket: PathBuf, command: DaemonCommand) -> Result<(), RfError> {
    match command.action {
        DaemonAction::Start(start) => {
            let mut config = LocalBusConfig::new(socket, start.data_root);
            config.itest_legacy_accounts = start.itest_legacy_accounts;
            #[cfg(feature = "itest-memory-vault")]
            if start.itest_memory_vault {
                config.custody_vault =
                    Some(std::sync::Arc::new(ramflux_sdk::custody::MemoryPrimaryVault::default()));
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
