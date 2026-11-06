// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production submit/fanout/forward calls finish independently of recipient output.
use crate::session_push::tests::support::{Fixture, ID, sink};
use ramflux_transport::{GatewaySessionFrameSink, TransportError};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
struct Held {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
    finished: Arc<AtomicUsize>,
    frames: Arc<Mutex<Vec<Value>>>,
}
impl GatewaySessionFrameSink for Held {
    fn finish(&mut self) -> Result<(), TransportError> {
        self.finished.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.entered.notify_one();
            let permit = self
                .release
                .acquire()
                .await
                .map_err(|_| TransportError::Quic("test release closed".into()))?;
            permit.forget();
            self.frames
                .lock()
                .map_err(|_| TransportError::LockPoisoned)?
                .push(serde_json::from_slice(bytes)?);
            Ok(())
        })
    }
}
fn submit(
    runtime: &crate::GatewaySessionRuntime,
    seq: u64,
) -> anyhow::Result<ramflux_node_core::GatewaySubmitFrame> {
    let mut submit = crate::session::submit_ack_tests::signed_submit(
        runtime,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    )?;
    submit.envelope.envelope_id = format!("queue-{seq}");
    submit.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&submit.envelope)?,
        [4; 32],
    );
    submit.signed_request.request_id = format!("queue-request-{seq}");
    submit.signed_request.nonce = format!("queue-nonce-{seq}");
    submit.signed_request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(&submit.envelope)?,
    );
    submit.signed_request.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(&submit.signed_request)?,
        [4; 32],
    );
    Ok(submit)
}
async fn produce(
    fixture: &mut Fixture,
    runtime: &crate::GatewaySessionRuntime,
    send: &crate::GatewaySendHandle,
    kind: u8,
    seq: u64,
) -> anyhow::Result<()> {
    let submit = submit(runtime, seq)?;
    if kind == 2 {
        let result = crate::serve::handle_gateway_forward_deliver(
            &fixture.context.hub,
            crate::GatewayForwardDeliverRequest {
                source_gateway_id: "source".into(),
                target_delivery_id: "alice-target".into(),
                forwarded: true,
                incarnation_id: None,
                retain_until: None,
                frame: ramflux_node_core::GatewayServerFrame::Deliver {
                    entry: ramflux_node_core::InboxEntry {
                        inbox_seq: seq,
                        target_delivery_id: "alice-target".into(),
                        envelope: submit.envelope,
                    },
                },
            },
        )
        .await?;
        assert!(result.delivered);
        return Ok(());
    }
    let context = fixture.context.clone();
    let sender_runtime = runtime.clone();
    let send = send.clone();
    let task = tokio::spawn(async move {
        if kind == 0 {
            crate::session::handle_gateway_submit(&send, &context, &sender_runtime, &submit).await
        } else {
            let fanout = ramflux_node_core::GatewayOwnDeviceFanoutFrame {
                principal_id: sender_runtime.principal_id.clone(),
                source_device_id: sender_runtime.device_id.clone(),
                signed_request: submit.signed_request,
                envelope: submit.envelope,
            };
            crate::session::handle_gateway_own_device_fanout(
                &send,
                &context,
                &sender_runtime,
                &fanout,
            )
            .await
        }
    });
    let request = fixture.next().await?;
    let response = if kind == 0 {
        assert_eq!(request.path, "/mvp0/envelope");
        json!({"outcome":"online","target_delivery_id":"alice-target","inbox_seq":seq,"cursor":null,"incarnation_id":ID,"retain_until":12345})
    } else {
        assert_eq!(request.path, "/mvp10/own-devices/fanout");
        json!({"principal_id":runtime.principal_id,"source_device_id":runtime.device_id,"delivered":[{"device_id":"alice-device","target_delivery_id":"alice-target","inbox_seq":seq,"outcome":"online","incarnation_id":ID,"retain_until":12345}]})
    };
    request.respond.send((200, response)).map_err(|_| anyhow::anyhow!("sender cancelled"))?;
    tokio::time::timeout(std::time::Duration::from_secs(2), task).await???;
    Ok(())
}
#[tokio::test]
async fn sender_isolation() -> anyhow::Result<()> {
    same_sender_loop().await?;
    for kind in 1..3 {
        case(kind, false).await?;
    }
    Ok(())
}
#[tokio::test]
async fn stalled_writer() -> anyhow::Result<()> {
    for kind in 0..3 {
        case(kind, true).await?;
    }
    Ok(())
}
async fn case(kind: u8, stalled: bool) -> anyhow::Result<()> {
    let mut fixture = Fixture::new(&format!("queue-caller-{kind}-{stalled}"))?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let frames = Arc::new(Mutex::new(Vec::new()));
    let peer: crate::GatewaySendHandle = Arc::new(tokio::sync::Mutex::new(Box::new(Held {
        entered: entered.clone(),
        release: release.clone(),
        finished: finished.clone(),
        frames: frames.clone(),
    })));
    let mut registration = fixture
        .context
        .hub
        .register_with_limit("alice-target".into(), "recipient".into(), peer, None, 16)
        .await?;
    let runtime = crate::session::submit_ack_tests::test_runtime()?;
    let (send, replies) = sink();
    produce(&mut fixture, &runtime, &send, kind, 1).await?;
    tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified()).await?;
    if stalled {
        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(14)).await;
        assert!(!*registration.closed.borrow());
        assert_eq!(finished.load(Ordering::SeqCst), 0);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::time::timeout(std::time::Duration::from_secs(1), registration.closed.changed())
            .await??;
        assert!(*registration.closed.borrow());
        assert_eq!(finished.load(Ordering::SeqCst), 1);
        tokio::time::resume();
        let (replacement, received) = sink();
        fixture
            .context
            .hub
            .register("alice-target".into(), "replacement".into(), replacement)
            .await?;
        produce(&mut fixture, &runtime, &send, kind, 2).await?;
        fixture.context.hub.flushed("alice-target").await?;
        assert_eq!(received.lock().map_err(|_| anyhow::anyhow!("received"))?.len(), 1);
    } else {
        produce(&mut fixture, &runtime, &send, kind, 2).await?;
        if kind != 2 {
            assert_eq!(replies.lock().map_err(|_| anyhow::anyhow!("replies"))?.len(), 2);
        }
        assert_eq!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 0);
        release.add_permits(2);
        fixture.context.hub.flushed("alice-target").await?;
        assert_eq!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 2);
    }
    Ok(())
}

struct Requests(tokio::sync::mpsc::Receiver<Vec<u8>>);
impl ramflux_transport::GatewaySessionFrameSource for Requests {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>,
    > {
        Box::pin(async move {
            self.0.recv().await.ok_or_else(|| {
                TransportError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            })
        })
    }
}
async fn same_sender_loop() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("queue-same-sender-loop")?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let received = Arc::new(Mutex::new(Vec::new()));
    let finished = Arc::new(AtomicUsize::new(0));
    let peer: crate::GatewaySendHandle = Arc::new(tokio::sync::Mutex::new(Box::new(Held {
        entered: entered.clone(),
        release: release.clone(),
        finished,
        frames: received.clone(),
    })));
    fixture
        .context
        .hub
        .register_with_limit("alice-target".into(), "recipient".into(), peer, None, 16)
        .await?;
    let runtime = crate::session::submit_ack_tests::test_runtime()?;
    let (send, replies) = sink();
    let (requests, source) = tokio::sync::mpsc::channel(2);
    let first = ramflux_node_core::GatewayClientFrame::Submit { submit: submit(&runtime, 1)? };
    let second = ramflux_node_core::GatewayClientFrame::Submit { submit: submit(&runtime, 2)? };
    let context = fixture.context.clone();
    let loop_task = tokio::spawn(crate::session::run_gateway_session_loop(
        send,
        Box::new(Requests(source)),
        context,
        runtime,
    ));
    requests.send(serde_json::to_vec(&first)?).await?;
    let request = fixture.next().await?;
    request.respond.send((200,json!({"outcome":"online","target_delivery_id":"alice-target","inbox_seq":1,"cursor":null,"incarnation_id":ID,"retain_until":12345}))).map_err(|_|anyhow::anyhow!("first cancelled"))?;
    tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified()).await?;
    assert_eq!(replies.lock().map_err(|_| anyhow::anyhow!("replies"))?.len(), 1);
    requests.send(serde_json::to_vec(&second)?).await?;
    let second = tokio::time::timeout(std::time::Duration::from_secs(2), fixture.next()).await??;
    second.respond.send((200,json!({"outcome":"online","target_delivery_id":"alice-target","inbox_seq":2,"cursor":null,"incarnation_id":ID,"retain_until":12345}))).map_err(|_|anyhow::anyhow!("second cancelled"))?;
    drop(requests);
    tokio::time::timeout(std::time::Duration::from_secs(2), loop_task).await???;
    assert_eq!(replies.lock().map_err(|_| anyhow::anyhow!("replies"))?.len(), 2);
    assert_eq!(received.lock().map_err(|_| anyhow::anyhow!("received"))?.len(), 0);
    release.add_permits(2);
    fixture.context.hub.flushed("alice-target").await?;
    Ok(())
}
