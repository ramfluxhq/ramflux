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

#[cfg(test)]
thread_local! {
    static OVERRIDE: std::cell::RefCell<Option<(std::time::Instant, Arc<Semaphore>)>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
#[must_use]
pub(crate) struct ForwardOverride;
#[cfg(test)]
impl ForwardOverride {
    pub(crate) fn install(wall: std::time::Instant, capacity: Arc<Semaphore>) -> Self {
        OVERRIDE.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some((wall, capacity));
        });
        Self
    }
}
#[cfg(test)]
impl Drop for ForwardOverride {
    fn drop(&mut self) {
        OVERRIDE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
impl RamfluxClient {
    pub(crate) async fn forward_task_envelope_until(
        federation: LocalBusFederationRoute,
        envelope: ramflux_protocol::Envelope,
        deadline: tokio::time::Instant,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (wall, capacity) = (std::time::Instant::now() + remaining, slots().clone());
        #[cfg(test)]
        let (wall, capacity) =
            OVERRIDE.with(|slot| slot.borrow().clone()).unwrap_or((wall, capacity));
        forward_until(federation, envelope, deadline, wall, capacity).await
    }
}

async fn forward_until(
    federation: LocalBusFederationRoute,
    envelope: ramflux_protocol::Envelope,
    deadline: tokio::time::Instant,
    wall_deadline: std::time::Instant,
    capacity: Arc<Semaphore>,
) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(SdkError::TaskDeliveryTimeout);
    }
    let permit = capacity.try_acquire_owned().map_err(|_| SdkError::TaskForwardWorkerCapacity)?;
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
    use crate::test_peers::{Peers, wait_for};

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

    #[tokio::test(start_paused = true)]
    async fn stalled_forward_returns_typed_timeout_without_blocking_runtime_or_leaking_slot()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut peers = Peers::default();
        let target = route(peers.spawn(true)?);
        let capacity = Arc::new(Semaphore::new(1));
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(forward_until(
            target,
            envelope()?,
            started + Duration::from_secs(1),
            std::time::Instant::now() + Duration::from_secs(60),
            capacity.clone(),
        ));
        wait_for(|| peers.accepted() == 1 || task.is_finished(), 10).await;
        assert!(!task.is_finished(), "the forward ended before entering its held HTTP request");
        assert_eq!(started.elapsed(), Duration::ZERO);
        let heartbeat = tokio::spawn(async {
            tokio::task::yield_now().await;
            true
        });
        tokio::time::advance(Duration::from_secs(1)).await;
        let result = task.await?;
        assert!(matches!(result, Err(SdkError::TaskDeliveryTimeout)), "{result:?}");
        assert!(heartbeat.await?);
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert!(capacity.try_acquire().is_err(), "held peer must retain its isolated permit");
        assert!(peers.finish()? < Duration::from_secs(2));
        wait_for(|| capacity.available_permits() == 1, 10).await;
        Ok(())
    }

    #[tokio::test]
    async fn forward_socket_deadline_releases_the_permit_before_the_peer_guard()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut peers = Peers::default();
        let target = route(peers.spawn(false)?);
        let capacity = Arc::new(Semaphore::new(1));
        let task = tokio::spawn(forward_until(
            target,
            envelope()?,
            tokio::time::Instant::now() + Duration::from_secs(30),
            std::time::Instant::now() + Duration::from_millis(500),
            capacity.clone(),
        ));
        let result = task.await?;
        assert!(matches!(result, Err(SdkError::TaskDeliveryTimeout)), "{result:?}");
        assert_eq!(peers.accepted(), 1);
        assert!(!peers.guard_expired());
        assert!(capacity.try_acquire().is_ok());
        assert!(peers.finish()? < Duration::from_secs(2));
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
                std::time::Instant::now() + Duration::from_secs(60),
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
                std::time::Instant::now() + Duration::from_secs(60),
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
