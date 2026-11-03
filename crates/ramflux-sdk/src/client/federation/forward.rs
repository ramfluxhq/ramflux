// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deadline-bound task forwarding; detached resolver work retains its bounded permit.

use super::{forward_request, *};
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

fn slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(4)))
}

impl RamfluxClient {
    pub(crate) async fn forward_task_envelope_until(
        federation: LocalBusFederationRoute,
        envelope: ramflux_protocol::Envelope,
        deadline: tokio::time::Instant,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        forward_until(federation, envelope, deadline, slots().clone()).await
    }
}

async fn forward_until(
    federation: LocalBusFederationRoute,
    envelope: ramflux_protocol::Envelope,
    deadline: tokio::time::Instant,
    capacity: Arc<Semaphore>,
) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(SdkError::TaskDeliveryTimeout);
    }
    let permit = capacity.try_acquire_owned().map_err(|_| SdkError::TaskForwardWorkerCapacity)?;
    let wall_deadline = std::time::Instant::now() + remaining;
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        crate::prekey::sdk_http_post_json_with_deadline(
            &federation.federation_url,
            "/s8/federation/forward",
            &forward_request(&federation, envelope),
            wall_deadline,
        )
    });
    match tokio::time::timeout_at(deadline, worker).await {
        Ok(Ok(Err(SdkError::Io(error))))
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Err(SdkError::TaskDeliveryTimeout)
        }
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(SdkError::LocalBus(format!("task forward worker failed: {error}"))),
        Err(_) => Err(SdkError::TaskDeliveryTimeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn envelope() -> Result<ramflux_protocol::Envelope, SdkError> {
        Ok(serde_json::from_value(serde_json::json!({
            "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
            "signing_key_id":"device-sender","signature_alg":"ed25519","signature":"fixture",
            "envelope_id":"forward-deadline","source_principal_id":"sender",
            "source_device_id":"device-sender","target_delivery_id":"remote-target",
            "delivery_class":"opaque_event","priority":"normal","ttl":600,
            "created_at":1,"encrypted_payload":"b3BhcXVl","payload_hash":"opaque-hash"
        }))?)
    }

    fn route(url: String) -> LocalBusFederationRoute {
        LocalBusFederationRoute {
            federation_url: url,
            source_node_id: "a".into(),
            target_node_id: "b".into(),
            admin_token: Some("fixture".into()),
            required_capability: "dm".into(),
            recipient_prekey_url: None,
        }
    }

    #[tokio::test]
    async fn stalled_forward_returns_typed_timeout_without_blocking_runtime_or_leaking_slot()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let target = route(format!("http://{}", listener.local_addr()?));
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut buffer = [0; 4096];
            let _ = socket.read(&mut buffer)?;
            // Longer than both the caller deadline and the permit-release assertion.
            std::thread::sleep(Duration::from_millis(800));
            let _ = socket.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n");
            Ok(())
        });
        let capacity = Arc::new(Semaphore::new(1));
        let started = tokio::time::Instant::now();
        let mut heartbeat = false;
        let (result, ()) = tokio::join!(
            forward_until(
                target,
                envelope()?,
                started + Duration::from_millis(100),
                capacity.clone()
            ),
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                heartbeat = true;
            },
        );
        assert!(matches!(result, Err(SdkError::TaskDeliveryTimeout)), "{result:?}");
        assert!(heartbeat && started.elapsed() < Duration::from_millis(500));
        tokio::time::timeout(Duration::from_millis(250), async {
            while capacity.available_permits() != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| "deadline did not release the worker slot")?;
        tokio::task::spawn_blocking(move || {
            server.join().map_err(|_| std::io::Error::other("stub panicked"))?
        })
        .await??;
        Ok(())
    }

    #[tokio::test]
    async fn expired_forward_and_full_worker_pool_refuse_without_starting_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let capacity = Arc::new(Semaphore::new(1));
        let held = capacity.clone().acquire_owned().await?;
        let target = route("http://127.0.0.1:1".into());
        assert!(matches!(
            forward_until(
                target.clone(),
                envelope()?,
                tokio::time::Instant::now(),
                capacity.clone()
            )
            .await,
            Err(SdkError::TaskDeliveryTimeout)
        ));
        assert!(matches!(
            forward_until(
                target,
                envelope()?,
                tokio::time::Instant::now() + Duration::from_secs(1),
                capacity.clone()
            )
            .await,
            Err(SdkError::TaskForwardWorkerCapacity)
        ));
        drop(held);
        assert_eq!(capacity.available_permits(), 1);
        Ok(())
    }
}
