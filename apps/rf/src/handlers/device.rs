// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_device(socket: PathBuf, command: DeviceCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        DeviceAction::Activate(activate) => {
            let request = ramflux_sdk::LocalBusDeviceActivateRequest {
                device_id: activate.device,
                target_delivery_id: activate.target,
                device_seed: resolve_seed(activate.device_seed_byte_hex.as_deref())?,
                device_epoch: activate.device_epoch,
            };
            print_json(
                &bus.request(Some(activate.account), "device", "device.activate", &request).await?,
            )
        }
        DeviceAction::Revoke(revoke) => {
            let request = LocalBusDeviceRevokeRequest { device_id: revoke.device };
            print_json(
                &bus.request(Some(revoke.account), "device", "device.revoke", &request).await?,
            )
        }
        DeviceAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "device", "device.list", &serde_json::json!({}))
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
                &bus.request(Some(export.account), "device", "device.sync.export", &request)
                    .await?,
            )
        }
        DeviceSyncAction::Import(import) => {
            let envelope = if let Some(envelope_json) = import.envelope_json {
                serde_json::from_str(&envelope_json)?
            } else if let Some(envelope_file) = import.envelope_file {
                let body = std::fs::read_to_string(envelope_file)?;
                serde_json::from_str(&body)?
            } else {
                return Err(RfError::Message(
                    "device sync import requires --envelope-json or --envelope-file".to_owned(),
                ));
            };
            let request = ramflux_sdk::LocalBusDeviceSyncImportRequest {
                envelope,
                relay_service_key_base64: None,
            };
            print_json(
                &bus.request(Some(import.account), "device", "device.sync.import", &request)
                    .await?,
            )
        }
    }
}
