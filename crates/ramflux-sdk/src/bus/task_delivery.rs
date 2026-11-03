// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary gateway submission and bounded executor-confirmation retries.
use crate::prelude::*;
pub(super) struct Destination {
    pub route: LocalBusFederationRoute,
    pub conversation_id: String,
    pub message_id: String,
    pub device_id: String,
    pub recipient_root: String,
}
pub(super) struct Delivery {
    pub envelope: ramflux_protocol::Envelope,
    pub federation: Option<Destination>,
}
pub(super) async fn submit_all(
    account: &mut LocalBusAccountState,
    deliveries: Vec<Delivery>,
) -> Result<usize, SdkError> {
    submit_until(account, deliveries, tokio::time::Instant::now() + Duration::from_secs(15)).await
}
pub(super) async fn submit_until(
    account: &mut LocalBusAccountState,
    deliveries: Vec<Delivery>,
    deadline: tokio::time::Instant,
) -> Result<usize, SdkError> {
    let count = deliveries.len();
    for delivery in deliveries {
        submit(account, &delivery, deadline).await?;
    }
    Ok(count)
}
async fn submit(
    account: &mut LocalBusAccountState,
    delivery: &Delivery,
    deadline: tokio::time::Instant,
) -> Result<(), SdkError> {
    let mut engine = match tokio::time::timeout_at(deadline, account.take_live_engine()).await {
        Ok(result) => result?,
        Err(_) => {
            if let Some(engine) = account.engine.take() {
                account.retire_engine(engine)?;
            }
            return Err(if delivery.federation.is_some() {
                SdkError::TaskDeliveryTimeout
            } else {
                SdkError::InboundPending("task delivery tick budget exhausted".into())
            });
        }
    };
    let result = if let Some(destination) = &delivery.federation {
        match federated_envelope(&engine, delivery, destination) {
            Ok(envelope) => RamfluxClient::forward_task_envelope_until(
                destination.route.clone(),
                envelope,
                deadline,
            )
            .await
            .map(|_| ()),
            Err(error) => Err(error),
        }
    } else if let Ok(result) =
        tokio::time::timeout_at(deadline, engine.submit_envelope(delivery.envelope.clone())).await
    {
        result.map(|_| ())
    } else {
        account.retire_engine(engine)?;
        return Err(SdkError::InboundPending("task delivery tick budget exhausted".into()));
    };
    account.put_engine(engine);
    result
}

fn federated_envelope(
    engine: &GatewaySessionEngine,
    delivery: &Delivery,
    destination: &Destination,
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let envelope = &delivery.envelope;
    let encrypted_body = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
        .map_err(|_| SdkError::LocalBus("invalid retained task ciphertext".into()))?;
    gateway_direct_message_envelope(
        &engine.config,
        &GatewayDirectMessage {
            conversation_id: destination.conversation_id.clone(),
            message_id: destination.message_id.clone(),
            envelope_id: envelope.envelope_id.clone(),
            source_principal_id: envelope.source_principal_id.clone(),
            sender_id: envelope.source_device_id.clone(),
            recipient_device_id: Some(destination.device_id.clone()),
            recipient_principal_commitment: Some(destination.recipient_root.clone()),
            target_delivery_id: envelope.target_delivery_id.clone(),
            encrypted_body,
            created_at: envelope.created_at,
            ttl: envelope.ttl,
        },
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    type FrameFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

    struct HangingLegacyGateway {
        last: Option<GatewayClientFrame>,
        stall_heartbeat: bool,
    }

    impl GatewaySessionFrameSink for HangingLegacyGateway {
        fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> FrameFuture<'a, ()> {
            Box::pin(async move {
                self.last = Some(
                    serde_json::from_slice(frame)
                        .map_err(|error| TransportError::Quic(error.to_string()))?,
                );
                Ok(())
            })
        }

        fn finish(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    impl GatewaySessionFrameSource for HangingLegacyGateway {
        fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
            let last = self.last.take();
            let stall = self.stall_heartbeat;
            Box::pin(async move {
                if let Some(GatewayClientFrame::Heartbeat { now }) = last
                    && !stall
                {
                    return serde_json::to_vec(&GatewayServerFrame::Heartbeat { now })
                        .map_err(|error| TransportError::Quic(error.to_string()));
                }
                std::future::pending().await
            })
        }
    }

    #[tokio::test]
    async fn federated_submit_respects_the_shared_deadline_and_returns_the_actor_engine()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut buffer = [0; 4096];
            let _ = socket.read(&mut buffer)?;
            std::thread::sleep(Duration::from_millis(600));
            let _ = socket.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n");
            Ok(())
        });
        let root = super::super::runtime_tests::root("federated-submit-deadline");
        let mut account = super::super::runtime_tests::account(
            &root,
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let live = account.take_live_engine().await?;
        account.put_engine(GatewaySessionEngine::with_test_transport(
            live.config.clone(),
            Box::new(HangingLegacyGateway { last: None, stall_heartbeat: false }),
        ));
        let message = GatewayDirectMessage {
            conversation_id: "task".into(),
            message_id: "deadline-message".into(),
            envelope_id: "deadline-envelope".into(),
            source_principal_id: "sender".into(),
            sender_id: "device-sender".into(),
            recipient_device_id: Some("remote-device".into()),
            recipient_principal_commitment: None,
            target_delivery_id: "remote-target".into(),
            encrypted_body: b"opaque retained control".to_vec(),
            created_at: now_unix_timestamp(),
            ttl: 600,
        };
        let envelope = gateway_direct_message_envelope(&account.gateway_config, &message, None)?;
        let destination = Destination {
            route: LocalBusFederationRoute {
                federation_url: url,
                source_node_id: "a".into(),
                target_node_id: "b".into(),
                required_capability: "task".into(),
                admin_token: None,
                recipient_prekey_url: None,
            },
            conversation_id: message.conversation_id,
            message_id: message.message_id,
            device_id: "remote-device".into(),
            recipient_root: "remote-root".into(),
        };
        let started = tokio::time::Instant::now();
        let result = submit_until(
            &mut account,
            vec![Delivery { envelope, federation: Some(destination) }],
            started + Duration::from_millis(100),
        )
        .await;
        assert!(matches!(result, Err(SdkError::TaskDeliveryTimeout)), "{result:?}");
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(
            account.has_pooled_engine(),
            "HTTP timeout must not discard the unrelated gateway session"
        );
        tokio::task::spawn_blocking(move || {
            server.join().map_err(|_| std::io::Error::other("stub panicked"))?
        })
        .await??;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn federated_deadline_also_covers_gateway_acquisition_and_preserves_resume()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::runtime_tests::root("federated-acquire-deadline");
        let mut account = super::super::runtime_tests::account(
            &root,
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let mut config = account.take_live_engine().await?.config.clone();
        config.previous_session_id = Some("acquire-session".into());
        config.resume_token = Some("acquire-resume".into());
        config.last_seen_inbox_seq = 41;
        account.put_engine(GatewaySessionEngine::with_test_transport(
            config,
            Box::new(HangingLegacyGateway { last: None, stall_heartbeat: true }),
        ));
        let envelope = serde_json::from_value(serde_json::json!({
            "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
            "signing_key_id":"device-sender","signature_alg":"ed25519","signature":"fixture",
            "envelope_id":"acquire-deadline","source_principal_id":"sender",
            "source_device_id":"device-sender","target_delivery_id":"remote-target",
            "delivery_class":"opaque_event","priority":"normal","ttl":600,
            "created_at":1,"encrypted_payload":"b3BhcXVl","payload_hash":"opaque-hash"
        }))?;
        let destination = Destination {
            route: LocalBusFederationRoute {
                federation_url: "http://127.0.0.1:1".into(),
                source_node_id: "a".into(),
                target_node_id: "b".into(),
                required_capability: "task".into(),
                admin_token: None,
                recipient_prekey_url: None,
            },
            conversation_id: "task".into(),
            message_id: "message".into(),
            device_id: "remote".into(),
            recipient_root: "remote-root".into(),
        };
        let started = tokio::time::Instant::now();
        let result = submit_until(
            &mut account,
            vec![Delivery { envelope, federation: Some(destination) }],
            started + Duration::from_millis(100),
        )
        .await;
        assert!(matches!(result, Err(SdkError::TaskDeliveryTimeout)), "{result:?}");
        assert_eq!(started.elapsed(), Duration::from_millis(100));
        assert!(!account.has_pooled_engine());
        let saved = account
            .client
            .projection_checkpoint(LocalBusAccountState::GATEWAY_RESUME_CHECKPOINT)?
            .ok_or("checkpoint")?;
        let saved: serde_json::Value = serde_json::from_str(&saved)?;
        assert_eq!(saved["previous_session_id"], "acquire-session");
        assert_eq!(saved["resume_token"], "acquire-resume");
        assert_eq!(saved["last_seen_inbox_seq"], 41);
        Ok(())
    }

    #[tokio::test]
    async fn timed_out_submit_discards_engine_before_a_legacy_nack_can_be_reused()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::runtime_tests::root("submit-timeout-discards-engine");
        let mut account = super::super::runtime_tests::account(
            &root,
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let live = account.take_live_engine().await?;
        let mut config = live.config.clone();
        config.previous_session_id = Some("resume-session-before-timeout".to_owned());
        config.resume_token = Some("resume-token-before-timeout".to_owned());
        config.last_seen_inbox_seq = 41;
        account.put_engine(GatewaySessionEngine::with_test_transport(
            config,
            Box::new(HangingLegacyGateway { last: None, stall_heartbeat: false }),
        ));
        let envelope: ramflux_protocol::Envelope = serde_json::from_value(serde_json::json!({
            "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
            "signing_key_id":"device-sender","signature_alg":"ed25519","signature":"fixture",
            "envelope_id":"timed-out-envelope","source_principal_id":"sender",
            "source_device_id":"device-sender","target_delivery_id":"remote-target",
            "delivery_class":"opaque_event","priority":"normal","ttl":600,
            "created_at":now_unix_timestamp(),"encrypted_payload":"opaque",
            "payload_hash":"opaque-hash"
        }))?;
        let error = submit_until(
            &mut account,
            vec![Delivery { envelope, federation: None }],
            tokio::time::Instant::now() + Duration::from_millis(1),
        )
        .await
        .err()
        .ok_or("expected submit timeout")?;
        assert!(matches!(error, SdkError::InboundPending(_)), "unexpected error: {error:?}");
        assert!(!account.has_pooled_engine());
        let persisted = account
            .client
            .projection_checkpoint(LocalBusAccountState::GATEWAY_RESUME_CHECKPOINT)?
            .ok_or("missing gateway resume checkpoint")?;
        let persisted: serde_json::Value = serde_json::from_str(&persisted)?;
        assert_eq!(persisted["previous_session_id"], "resume-session-before-timeout");
        assert_eq!(persisted["resume_token"], "resume-token-before-timeout");
        assert_eq!(persisted["last_seen_inbox_seq"], 41);
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
