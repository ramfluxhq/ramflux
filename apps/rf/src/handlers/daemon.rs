// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_daemon(socket: PathBuf, command: DaemonCommand) -> Result<(), RfError> {
    match command.action {
        DaemonAction::Start(start) => {
            let config = LocalBusConfig::new(socket, start.data_root);
            ramflux_sdk::serve_local_bus(config).await?;
            Ok(())
        }
        DaemonAction::Status => {
            let mut bus = LocalBusClient::connect(socket).await?;
            print_json(
                &bus.request::<serde_json::Value>(
                    None,
                    "daemon",
                    "daemon.status",
                    &serde_json::json!({}),
                )
                .await?,
            )
        }
        DaemonAction::Stop => {
            let mut bus = LocalBusClient::connect(socket).await?;
            print_json(
                &bus.request::<serde_json::Value>(
                    None,
                    "daemon",
                    "daemon.stop",
                    &serde_json::json!({}),
                )
                .await?,
            )
        }
    }
}
