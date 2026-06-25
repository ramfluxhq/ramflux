// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub fn send_plaintext_federated_direct_message(
        &self,
        engine: &GatewaySessionEngine,
        mut message: GatewayDirectMessage,
        plaintext: &[u8],
        federation: &LocalBusFederationRoute,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let conversation_id = message.conversation_id.clone();
        let prekey_url =
            federation.recipient_prekey_url.as_deref().or(engine.config.prekey_http_url.as_deref());
        let (mut session, x3dh) = self.load_or_create_send_dm_session_with_prekey_url(
            &message,
            prekey_url,
            &engine.config.device_id,
        )?;
        let ciphertext = session.encrypt(plaintext, dm_associated_data(&conversation_id))?;
        message.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
            schema: "ramflux.sdk.dm_x3dh_envelope.v1".to_owned(),
            version: 1,
            x3dh,
            ciphertext,
        })?;
        self.send_direct_message(
            &message.conversation_id,
            &message.message_id,
            &message.sender_id,
            &message.encrypted_body,
        )?;
        let envelope = gateway_direct_message_envelope(&engine.config, &message)?;
        tracing::info!(
            source_node_id = %federation.source_node_id,
            target_node_id = %federation.target_node_id,
            federation_url = %federation.federation_url,
            envelope_id = %envelope.envelope_id,
            target_delivery_id = %envelope.target_delivery_id,
            route_decision = "remote_federation_forward",
            "submitting federated direct message to source node federation surface"
        );
        let response = post_federated_envelope_forward(federation, envelope)?;
        self.persist_dm_session(&conversation_id, &message.envelope_id, "send", &session)?;
        Ok(response)
    }

    /// # Errors
    /// Returns an error when envelope construction or the federation forward request fails.
    pub fn forward_federated_gateway_message(
        &self,
        engine: &GatewaySessionEngine,
        message: &GatewayDirectMessage,
        federation: &LocalBusFederationRoute,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let envelope = gateway_direct_message_envelope(&engine.config, message)?;
        tracing::info!(
            source_node_id = %federation.source_node_id,
            target_node_id = %federation.target_node_id,
            federation_url = %federation.federation_url,
            envelope_id = %envelope.envelope_id,
            target_delivery_id = %envelope.target_delivery_id,
            route_decision = "remote_federation_forward",
            "submitting federated gateway message to source node federation surface"
        );
        post_federated_envelope_forward(federation, envelope)
    }

    /// # Errors
    /// Returns an error when the contact event cannot be encrypted or forwarded.
    pub fn send_plaintext_federated_contact_event(
        &self,
        engine: &GatewaySessionEngine,
        event_type: &str,
        request: &LocalBusContactFederatedRequest,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "type": event_type,
            "link_id": request.link_id,
            "requester": request.requester_id,
            "target": request.target_id,
        }))?;
        self.send_plaintext_federated_direct_message(
            engine,
            GatewayDirectMessage {
                conversation_id: request.conversation_id.clone(),
                message_id: request.message_id.clone(),
                envelope_id: request.envelope_id.clone(),
                source_principal_id: request.source_principal_id.clone(),
                sender_id: request.sender_id.clone(),
                recipient_device_id: Some(request.recipient_device_id.clone()),
                target_delivery_id: request.target_delivery_id.clone(),
                encrypted_body: Vec::new(),
                created_at: now_unix_timestamp(),
                ttl: 300,
            },
            &body,
            &request.federation,
        )
    }

    /// # Errors
    pub fn register_node(&mut self, node_id: &str, endpoint: &str) -> ramflux_sync::FederationNode {
        self.federation_mesh.register_node(node_id, endpoint)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn establish_trusted_link(&mut self, left: &str, right: &str) -> Result<(), SdkError> {
        Ok(self.federation_mesh.establish_trusted_link(left, right)?)
    }

    /// # Errors
    /// Returns an error when the node is not active or cannot be bound.
    pub fn bind_identity_home(&mut self, identity: &str, node_id: &str) -> Result<(), SdkError> {
        Ok(self.federation_mesh.bind_identity_home(identity, node_id)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn send_cross_node_message(
        &mut self,
        from_identity: &str,
        to_identity: &str,
        body_ciphertext: &[u8],
    ) -> Result<FederationMessage, SdkError> {
        Ok(self.federation_mesh.send_cross_node_message(
            from_identity,
            to_identity,
            body_ciphertext,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn migrate_home_node(
        &mut self,
        migration: HomeNodeMigration,
    ) -> Result<HomeNodeMigration, SdkError> {
        Ok(self.federation_mesh.migrate_home_node(migration)?)
    }
}

fn post_federated_envelope_forward(
    federation: &LocalBusFederationRoute,
    envelope: ramflux_protocol::Envelope,
) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
    sdk_http_post_json(
        &federation.federation_url,
        "/s8/federation/forward",
        &SdkFederatedEnvelopeForwardRequest {
            signed: ramflux_protocol::SignedFields {
                signing_key_id: format!("{}#federation", federation.source_node_id),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: String::new(),
            },
            admin_token: federation.admin_token.clone(),
            source_node_id: federation.source_node_id.clone(),
            target_node_id: federation.target_node_id.clone(),
            delivery_class: "opaque_event".to_owned(),
            required_capability: federation.required_capability.clone(),
            envelope,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn federation_forward_client_reads_content_length_without_waiting_for_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let (response_written_tx, response_written_rx) = mpsc::channel();
        let (release_server_tx, release_server_rx) = mpsc::channel();
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|source| source.to_string())?;
            let request = read_stub_request(&mut stream)?;
            if request.path != "/s8/federation/forward" {
                return Err(format!("unexpected path: {}", request.path));
            }
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).map_err(|source| source.to_string())?;
            if body.get("source_node_id").and_then(serde_json::Value::as_str) != Some("node-a") {
                return Err("unexpected source_node_id".to_owned());
            }
            if body.get("target_node_id").and_then(serde_json::Value::as_str) != Some("node-b") {
                return Err("unexpected target_node_id".to_owned());
            }
            if body.get("signing_key_id").and_then(serde_json::Value::as_str)
                != Some("node-a#federation")
            {
                return Err("missing federation forward signing_key_id".to_owned());
            }
            if body.get("signature_alg").and_then(serde_json::Value::as_str) != Some("ed25519") {
                return Err("missing federation forward signature_alg".to_owned());
            }
            if body.get("signature").and_then(serde_json::Value::as_str) != Some("") {
                return Err("missing federation forward signature field".to_owned());
            }
            let response_body = serde_json::to_vec(&SdkFederatedEnvelopeForwardResponse {
                accepted: true,
                source_node_id: "node-a".to_owned(),
                target_node_id: "node-b".to_owned(),
                delivery: SdkFederatedSubmitResponse {
                    outcome: "forwarded".to_owned(),
                    target_delivery_id: "delivery-b".to_owned(),
                    inbox_seq: Some(7),
                    cursor: None,
                },
            })
            .map_err(|source| source.to_string())?;
            let response_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream.write_all(response_head.as_bytes()).map_err(|source| source.to_string())?;
            stream.write_all(&response_body).map_err(|source| source.to_string())?;
            stream.flush().map_err(|source| source.to_string())?;
            response_written_tx.send(()).map_err(|source| source.to_string())?;
            let _ = release_server_rx.recv_timeout(Duration::from_secs(2));
            Ok(())
        });

        let route = LocalBusFederationRoute {
            federation_url: endpoint,
            source_node_id: "node-a".to_owned(),
            target_node_id: "node-b".to_owned(),
            required_capability: "ramflux.federation.envelope_forward".to_owned(),
            admin_token: None,
            recipient_prekey_url: None,
        };
        let envelope = test_forward_envelope();
        let (client_tx, client_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = post_federated_envelope_forward(&route, envelope)
                .map_err(|source| source.to_string());
            let _ = client_tx.send(result);
        });

        response_written_rx.recv_timeout(Duration::from_secs(2))?;
        let response = if let Ok(result) = client_rx.recv_timeout(Duration::from_millis(500)) {
            result.map_err(|source| -> Box<dyn std::error::Error> { source.into() })?
        } else {
            let _ = release_server_tx.send(());
            let _ = join_stub_server(server);
            return Err("federation forward client waited for EOF after Content-Length".into());
        };
        release_server_tx.send(())?;
        join_stub_server(server)?;
        assert!(response.accepted);
        assert_eq!(response.delivery.outcome, "forwarded");
        Ok(())
    }

    struct StubRequest {
        path: String,
        body: Vec<u8>,
    }

    fn read_stub_request(stream: &mut TcpStream) -> Result<StubRequest, String> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).map_err(|source| source.to_string())?;
        let parts = request_line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 || parts[0] != "POST" {
            return Err(format!("unexpected request line: {request_line}"));
        }
        let mut content_length = None;
        loop {
            let mut header = String::new();
            let bytes = reader.read_line(&mut header).map_err(|source| source.to_string())?;
            if bytes == 0 {
                return Err("request ended before headers complete".to_owned());
            }
            let trimmed = header.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some(value) = trimmed.strip_prefix("Content-Length:") {
                content_length =
                    Some(value.trim().parse::<usize>().map_err(|source| source.to_string())?);
            }
        }
        let content_length =
            content_length.ok_or_else(|| "request missing Content-Length".to_owned())?;
        let mut body = vec![0_u8; content_length];
        reader.read_exact(&mut body).map_err(|source| source.to_string())?;
        Ok(StubRequest { path: parts[1].to_owned(), body })
    }

    fn test_forward_envelope() -> ramflux_protocol::Envelope {
        ramflux_protocol::Envelope {
            schema: "ramflux.envelope.v1".to_owned(),
            version: 1,
            domain: "ramflux.message".to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "test-key".to_owned(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "test-signature".to_owned(),
            },
            envelope_id: "env-forward-test".to_owned(),
            source_principal_id: "principal-a".to_owned(),
            source_device_id: "device-a".to_owned(),
            target_delivery_id: "delivery-b".to_owned(),
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 300,
            created_at: now_unix_timestamp(),
            encrypted_payload: "payload".to_owned(),
            payload_hash: "hash".to_owned(),
        }
    }

    fn join_stub_server(
        server: thread::JoinHandle<Result<(), String>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match server.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(source.into()),
            Err(_) => Err("stub server panicked".into()),
        }
    }
}
