// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use std::future::Future;
const ID: &str = "0123456789abcdef0123456789abcdef";
async fn queue()
-> anyhow::Result<(PushQueue, GatewaySendHandle, Arc<Mutex<Vec<serde_json::Value>>>)> {
    let (closed, _) = tokio::sync::watch::channel(false);
    let q = PushQueue::new(16, closed);
    let (send, frames) = crate::session_push::tests::support::sink();
    q.install(&send, Some(ID.into())).await?;
    Ok((q, send, frames))
}
#[tokio::test]
async fn retirement_before_sink_authority_refuses_dequeued_frame() -> anyhow::Result<()> {
    let (q, send, frames) = queue().await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    *q.inner.before_write.lock().map_err(|_| anyhow::anyhow!("barrier poisoned"))? =
        Some((entered.clone(), release.clone()));
    let mut envelope = crate::session::tests::test_envelope();
    envelope.target_delivery_id = "target".into();
    let bytes = serde_json::to_vec(&ramflux_node_core::SessionPushServerFrame::Deliver {
        entry: ramflux_node_core::InboxEntry {
            target_delivery_id: "target".into(),
            inbox_seq: 1,
            envelope,
        },
        incarnation_id: ID.into(),
        retain_until: 12345,
    })?;
    assert_eq!(q.try_push_versioned(bytes, 1, Some(ID.into())), Admission::Queued);
    let Next::Frame(frame) = q.next() else {
        anyhow::bail!("frame not dequeued");
    };
    let writer = q.clone();
    let sink = send.clone();
    let writing = tokio::spawn(async move {
        writer.write(&sink, &frame.bytes, frame.incarnation.as_deref()).await
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    q.retire_with_sink(&send).await;
    assert!(q.is_closed());
    release.add_permits(1);
    let wrote = tokio::time::timeout(Duration::from_secs(2), writing).await??;
    let wire = frames.lock().map_err(|_| anyhow::anyhow!("frames poisoned"))?;
    assert!(wire.is_empty(), "retired incarnation reached the wire: {wire:?}");
    assert!(!wrote);
    Ok(())
}
struct Held {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl GatewaySessionFrameSink for Held {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            let p = self.release.acquire().await.map_err(|_| TransportError::LockPoisoned)?;
            p.forget();
            Ok(())
        })
    }
}
#[tokio::test]
async fn admitted_write_finishes_once_before_retirement() -> anyhow::Result<()> {
    let (closed, _) = tokio::sync::watch::channel(false);
    let q = PushQueue::new(16, closed);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let send: GatewaySendHandle = Arc::new(tokio::sync::Mutex::new(Box::new(Held {
        entered: entered.clone(),
        release: release.clone(),
        calls: calls.clone(),
    })));
    q.install(&send, Some(ID.into())).await?;
    let writer = q.clone();
    let sink = send.clone();
    let task = tokio::spawn(async move { writer.write(&sink, b"frame", Some(ID)).await });
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    let retirement = q.retire_with_sink(&send);
    tokio::pin!(retirement);
    std::future::poll_fn(|cx| {
        assert!(retirement.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(!q.is_closed());
    release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), retirement).await?;
    assert!(task.await?);
    assert!(q.is_closed());
    assert!(!q.write(&send, b"later", Some(ID)).await);
    assert!(write_frame(&send, b"control reply").await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn queued_wrong_incarnation_retires_without_write() -> anyhow::Result<()> {
    let (q, send, frames) = queue().await?;
    assert!(!q.write(&send, b"frame", Some("fedcba9876543210fedcba9876543210")).await);
    assert!(q.is_closed());
    assert!(frames.lock().map_err(|_| anyhow::anyhow!("poison"))?.is_empty());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn direct_control_sink_write_has_the_same_deadline() -> anyhow::Result<()> {
    let (closed, _) = tokio::sync::watch::channel(false);
    let q = PushQueue::new(16, closed);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let send: GatewaySendHandle = Arc::new(tokio::sync::Mutex::new(Box::new(Held {
        entered: entered.clone(),
        release,
        calls,
    })));
    q.install(&send, Some(ID.into())).await?;
    let task = tokio::spawn(async move { send.lock().await.send_frame(b"control").await });
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    tokio::time::advance(Duration::from_secs(15)).await;
    assert!(tokio::time::timeout(Duration::from_secs(1), task).await??.is_err());
    assert!(q.is_closed());
    Ok(())
}
