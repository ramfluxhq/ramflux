// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use serde_json::Value;
struct StepSink {
    events: tokio::sync::mpsc::Sender<Value>,
    release: Arc<tokio::sync::Semaphore>,
}
impl GatewaySessionFrameSink for StepSink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.events
                .send(serde_json::from_slice(bytes)?)
                .await
                .map_err(|_| TransportError::Quic("event channel closed".into()))?;
            let permit = self
                .release
                .acquire()
                .await
                .map_err(|_| TransportError::Quic("permit closed".into()))?;
            permit.forget();
            Ok(())
        })
    }
}
async fn next(events: &mut tokio::sync::mpsc::Receiver<Value>) -> anyhow::Result<Value> {
    tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("writer ended"))
}
#[tokio::test]
async fn queued_incarnation_and_detached_resync() -> anyhow::Result<()> {
    const ID: &str = "0123456789abcdef0123456789abcdef";
    let hub = Arc::new(crate::GatewaySessionHub::default());
    let (send, mut events) = tokio::sync::mpsc::channel(32);
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let sink: GatewaySendHandle = Arc::new(tokio::sync::Mutex::new(Box::new(StepSink {
        events: send,
        release: release.clone(),
    })));
    hub.register_with_limit("target".into(), "session".into(), sink, Some(ID.into()), 16).await?;
    let frame = |seq| {
        let mut envelope = crate::session::tests::test_envelope();
        envelope.target_delivery_id = "target".into();
        ramflux_node_core::GatewayServerFrame::Deliver {
            entry: ramflux_node_core::InboxEntry {
                target_delivery_id: "target".into(),
                inbox_seq: seq,
                envelope,
            },
        }
    };
    assert!(hub.send_delivery("target", &frame(1), Some((ID, 12345))).await);
    let first = next(&mut events).await?;
    assert_eq!(first["incarnation_id"], ID);
    assert_eq!(first["retain_until"], 12345);
    for seq in 2..=20 {
        assert!(hub.send_delivery("target", &frame(seq), Some((ID, 12345))).await);
    }
    for seq in 2..=8 {
        release.add_permits(1);
        let wire = next(&mut events).await?;
        assert_eq!(wire["frame_type"], "deliver");
        assert_eq!(wire["entry"]["inbox_seq"], seq);
    }
    release.add_permits(1);
    let hint = next(&mut events).await?;
    assert_eq!(hint["frame_type"], "resync");
    assert_eq!(hint["after_inbox_seq"], 16);
    assert_eq!(hint["incarnation_id"], ID);
    assert!(hub.send_delivery("target", &frame(25), Some((ID, 12345))).await);
    release.add_permits(1);
    let fresh = next(&mut events).await?;
    assert_eq!(fresh["frame_type"], "resync");
    assert_eq!(fresh["after_inbox_seq"], 24);
    release.add_permits(1);
    for seq in 9..=16 {
        let wire = next(&mut events).await?;
        assert_eq!(wire["entry"]["inbox_seq"], seq);
        assert_eq!(wire["incarnation_id"], ID);
        assert_eq!(wire["retain_until"], 12345);
        release.add_permits(1);
    }
    hub.flushed("target").await?;
    Ok(())
}

#[tokio::test]
async fn frame_atomic_sink_yields_between_deliveries() -> anyhow::Result<()> {
    let hub = Arc::new(crate::GatewaySessionHub::default());
    let (events, mut received) = tokio::sync::mpsc::channel(8);
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let sender: GatewaySendHandle =
        Arc::new(tokio::sync::Mutex::new(Box::new(StepSink { events, release: release.clone() })));
    hub.register("target".into(), "session".into(), sender.clone()).await?;
    let frame = ramflux_node_core::GatewayServerFrame::Heartbeat { now: 1 };
    assert!(hub.send_to("target", &frame).await);
    assert_eq!(next(&mut received).await?["now"], 1);
    assert!(hub.send_to("target", &frame).await);
    let control = tokio::spawn(async move {
        crate::session::write_gateway_handle(
            &sender,
            &ramflux_node_core::GatewayServerFrame::Heartbeat { now: 7 },
        )
        .await
    });
    tokio::task::yield_now().await;
    assert!(received.try_recv().is_err());
    release.add_permits(1);
    assert_eq!(next(&mut received).await?["now"], 7);
    release.add_permits(1);
    control.await??;
    assert_eq!(next(&mut received).await?["now"], 1);
    release.add_permits(1);
    hub.flushed("target").await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn queue_wait_does_not_consume_write_deadline() -> anyhow::Result<()> {
    let hub = Arc::new(crate::GatewaySessionHub::default());
    let (events, mut received) = tokio::sync::mpsc::channel(8);
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let sender: GatewaySendHandle =
        Arc::new(tokio::sync::Mutex::new(Box::new(StepSink { events, release: release.clone() })));
    let mut registration = hub.register("target".into(), "session".into(), sender.clone()).await?;
    let control = tokio::spawn(async move {
        crate::session::write_gateway_handle(
            &sender,
            &ramflux_node_core::GatewayServerFrame::Heartbeat { now: 7 },
        )
        .await
    });
    assert_eq!(next(&mut received).await?["now"], 7);
    assert!(
        hub.send_to("target", &ramflux_node_core::GatewayServerFrame::Heartbeat { now: 1 }).await
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(14)).await;
    release.add_permits(1);
    control.await??;
    assert_eq!(next(&mut received).await?["now"], 1);
    tokio::time::advance(Duration::from_secs(14)).await;
    assert!(!*registration.closed.borrow());
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::time::timeout(Duration::from_secs(1), registration.closed.changed()).await??;
    assert!(*registration.closed.borrow());
    Ok(())
}
