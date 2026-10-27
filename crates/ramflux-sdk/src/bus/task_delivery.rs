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
    let mut engine = account.take_live_engine().await?;
    let mut reusable = true;
    let result = if let Some(destination) = &delivery.federation {
        let envelope = &delivery.envelope;
        let body = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
            .map_err(|_| SdkError::LocalBus("invalid retained task ciphertext".into()));
        match body {
            Ok(encrypted_body) => account
                .client
                .forward_federated_gateway_message(
                    &engine,
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
                    &destination.route,
                )
                .map(|_| ()),
            Err(error) => Err(error),
        }
    } else if let Ok(result) =
        tokio::time::timeout_at(deadline, engine.submit_envelope(delivery.envelope.clone())).await
    {
        result.map(|_| ())
    } else {
        reusable = false;
        Err(SdkError::InboundPending("task delivery tick budget exhausted".into()))
    };
    if reusable {
        account.put_engine(engine);
    }
    result
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
            Box::pin(async move {
                if let Some(GatewayClientFrame::Heartbeat { now }) = last {
                    return serde_json::to_vec(&GatewayServerFrame::Heartbeat { now })
                        .map_err(|error| TransportError::Quic(error.to_string()));
                }
                std::future::pending().await
            })
        }
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
        let config = live.config.clone();
        account.put_engine(GatewaySessionEngine::with_test_transport(
            config,
            Box::new(HangingLegacyGateway { last: None }),
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
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
