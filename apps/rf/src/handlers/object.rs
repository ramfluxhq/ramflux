// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_object(socket: PathBuf, command: ObjectCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        ObjectAction::Put(put) => {
            let bytes = std::fs::read(&put.file)?;
            let request = LocalBusObjectPutRequest {
                object_id: put.object,
                plaintext_base64: ramflux_protocol::encode_base64url(&bytes),
                chunk_size: put.chunk_size,
            };
            print_json(&bus.request(Some(put.account), "object", "object.put", &request).await?)
        }
        ObjectAction::Get(get) => {
            let request = LocalBusObjectGetRequest { object_id: get.object };
            let response = bus.request(Some(get.account), "object", "object.get", &request).await?;
            let plaintext = response
                .get("plaintext_base64")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| RfError::Message("object.get response missing plaintext".to_owned()))
                .and_then(|value| {
                    ramflux_protocol::decode_base64url(value)
                        .map_err(|error| RfError::Message(format!("invalid object body: {error}")))
                })?;
            std::fs::write(&get.out, plaintext)?;
            print_json(&response)
        }
        ObjectAction::Import(import) => {
            let package = serde_json::from_slice(&std::fs::read(&import.package)?)?;
            let request = LocalBusObjectImportRequest { package };
            print_json(
                &bus.request(Some(import.account), "object", "object.import", &request).await?,
            )
        }
        ObjectAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "object", "object.list", &serde_json::json!({}))
                .await?,
        ),
        ObjectAction::Share(share) => {
            let request = LocalBusObjectShareRequest {
                object_id: share.object,
                conversation_id: share.to,
                sender_id: share.sender,
                recipient_device_id: share.recipient_device,
                target_delivery_id: share.target,
            };
            let response =
                bus.request(Some(share.account), "object", "object.share", &request).await?;
            if let Some(out_package) = share.out_package {
                let package = response
                    .get("package")
                    .ok_or_else(|| RfError::Message("object.share missing package".to_owned()))?;
                std::fs::write(out_package, serde_json::to_vec_pretty(package)?)?;
            }
            print_json(&response)
        }
        ObjectAction::Delete(delete) => {
            let request = LocalBusObjectDeleteRequest { object_id: delete.object };
            print_json(
                &bus.request(Some(delete.account), "object", "object.delete", &request).await?,
            )
        }
    }
}
