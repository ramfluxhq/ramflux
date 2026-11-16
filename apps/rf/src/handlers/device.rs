// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_device(socket: PathBuf, command: DeviceCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        DeviceAction::Authorize(selector) => print_json(
            &bus.request(
                Some(selector.account),
                "device",
                "device.authorize",
                serde_json::json!({}),
            )
            .await?,
        ),
        DeviceAction::Migrate(migrate) => {
            let mut proofs = Vec::new();
            for file in migrate.authorizations {
                let bytes = std::fs::read(file)?;
                if bytes.len() > 512 * 1024 {
                    return Err(RfError::Message("authorization file exceeds budget".into()));
                }
                proofs.push(serde_json::from_slice::<serde_json::Value>(&bytes)?);
            }
            print_json(
                &bus.request(
                    Some(migrate.account),
                    "device",
                    "device.migrate",
                    serde_json::json!({"authorizations":proofs}),
                )
                .await?,
            )
        }
        DeviceAction::Refresh(refresh) => print_json(
            &bus.request(
                Some(refresh.account),
                "device",
                "device.refresh",
                serde_json::json!({"principal_commitment":refresh.principal_commitment}),
            )
            .await?,
        ),
        DeviceAction::Revoke(revoke) => {
            let request = LocalBusDeviceRevokeRequest { device_id: revoke.device };
            print_json(
                &bus.request(
                    Some(revoke.account),
                    "device",
                    "device.revoke",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
        DeviceAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "device", "device.list", serde_json::json!({}))
                .await?,
        ),
        DeviceAction::Sync(sync) => handle_device_sync(&mut bus, sync).await,
    }
}

async fn handle_device_sync(
    bus: &mut LocalBusClient,
    command: DeviceSyncCommand,
) -> Result<(), RfError> {
    match command.action {
        DeviceSyncAction::Export(export) => {
            let request = ramflux_sdk::LocalBusDeviceSyncExportRequest {
                target_device_id: export.target_device,
                relay_endpoint: export.relay_endpoint,
                relay_service_key_base64: None,
                chunk_size: export.chunk_size,
            };
            print_json(
                &bus.request(
                    Some(export.account),
                    "device",
                    "device.sync.export",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
    }
}
