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
                relay_endpoint: put.relay_url,
                relay_service_key_base64: put.relay_service_key,
                relay_interrupt_after_chunks: put.relay_interrupt_after_chunks,
            };
            print_json(&bus.request(Some(put.account), "object", "object.put", &request).await?)
        }
        ObjectAction::Get(get) => {
            let request = LocalBusObjectGetRequest {
                object_id: get.object,
                relay_endpoint: get.relay_url,
                relay_service_key_base64: get.relay_service_key,
                relay_ack: get.relay_ack,
                relay_interrupt_after_chunks: get.relay_interrupt_after_chunks,
            };
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
        ObjectAction::Status(status) => {
            let request = LocalBusObjectTransferStatusRequest {
                object_id: status.object,
                direction: status.direction,
            };
            print_json(
                &bus.request(Some(status.account), "object", "object.transfer.status", &request)
                    .await?,
            )
        }
        ObjectAction::Resume(resume) => {
            let request = LocalBusObjectTransferResumeRequest {
                object_id: resume.object,
                direction: resume.direction,
                relay_endpoint: Some(resume.relay_url),
                relay_service_key_base64: resume.relay_service_key,
                relay_interrupt_after_chunks: resume.relay_interrupt_after_chunks,
            };
            print_json(
                &bus.request(Some(resume.account), "object", "object.transfer.resume", &request)
                    .await?,
            )
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
                recipient_principal_commitment: share.recipient_principal_commitment,
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
