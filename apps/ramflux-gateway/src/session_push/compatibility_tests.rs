// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Raw compatibility bytes, establishment rollback and authority-first diagnostics.
use super::*;
use ramflux_transport::{GatewaySessionFrameSink, TransportError};
struct RawSink(Arc<std::sync::Mutex<Vec<Vec<u8>>>>);
impl GatewaySessionFrameSink for RawSink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.0.lock().map_err(|_| TransportError::LockPoisoned)?.push(bytes.to_vec());
            Ok(())
        })
    }
}
fn session() -> ramflux_node_core::GatewaySessionEstablishedFrame {
    ramflux_node_core::GatewaySessionEstablishedFrame {
        session_id: "session".into(),
        gateway_id: "gateway".into(),
        accepted_cursor: None,
        resume_token: "resume".into(),
        resume_window_seconds: 300,
    }
}
#[tokio::test]
async fn legacy_established_raw_bytes() -> anyhow::Result<()> {
    let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut sink = RawSink(frames.clone());
    established(&mut sink, session(), None).await?;
    assert_eq!(frames.lock().map_err(|_|Retired)?[0],br#"{"frame_type":"session_established","session":{"session_id":"session","gateway_id":"gateway","accepted_cursor":null,"resume_token":"resume","resume_window_seconds":300}}"#);
    Ok(())
}
struct Broken;
impl GatewaySessionFrameSink for Broken {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async { Err(TransportError::Quic("fixture write failure".into())) })
    }
}
#[tokio::test]
async fn establishment_write_errors_keep_client_mapping() -> anyhow::Result<()> {
    for id in [None, Some(ID)] {
        let error = established(&mut Broken, session(), id).await.err().ok_or(Retired)?;
        assert!(error.downcast_ref::<crate::session_response::ClientWriteFailure>().is_some());
    }
    Ok(())
}
#[tokio::test]
async fn initial_registration_readiness_scope() -> anyhow::Result<()> {
    for (label, status, response) in [
        ("refused", 400, json!({"reason":"busy","incarnation_id":ID})),
        (
            "bad-id",
            200,
            json!({"incarnation_id":"invalid","target_delivery_id":"target","session_id":"session"}),
        ),
        (
            "wrong-target",
            200,
            json!({"incarnation_id":ID,"target_delivery_id":"other","session_id":"session"}),
        ),
        (
            "wrong-session",
            200,
            json!({"incarnation_id":ID,"target_delivery_id":"target","session_id":"other"}),
        ),
        ("removed", 404, json!({})),
        ("method-removed", 405, json!({})),
        ("gone", 410, json!({})),
        ("transient", 500, json!({})),
        ("timeout", 0, json!({})),
    ] {
        let mut fixture = Fixture::new(&format!("capable-fallback-{label}"))?;
        fixture.context.hub.readiness.started.store(true, Ordering::Release);
        fixture.context.hub.readiness.ready.store(true, Ordering::Release);
        let context = fixture.context.clone();
        let auth = super::negotiation::auth(true)?;
        let descriptor = super::negotiation::descriptor();
        let task = tokio::spawn(async move { negotiate(&context, &auth, &descriptor).await });
        let capable = fixture.next().await?;
        assert_eq!(capable.path, "/s1/session");
        if status == 0 {
            tokio::time::pause();
            tokio::time::advance(REQUEST_TIMEOUT).await;
            tokio::time::resume();
        } else {
            capable.respond.send((status, response)).map_err(|_| Retired)?;
        }
        let legacy = fixture.next().await?;
        assert_eq!(legacy.path, "/s1/session/upsert");
        assert_eq!(fixture.context.hub.readiness.supports(), !matches!(status, 404 | 405 | 410));
        legacy
            .respond
            .send((200, serde_json::to_value(super::negotiation::descriptor())?))
            .map_err(|_| Retired)?;
        let mode = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .map_err(|_| anyhow::anyhow!("negotiation guard elapsed"))???;
        assert_eq!(mode, None);
        let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        established(&mut RawSink(frames.clone()), session(), mode.as_deref()).await?;
        let value: Value = serde_json::from_slice(&frames.lock().map_err(|_| Retired)?[0])?;
        assert!(value["session"].get("capabilities").is_none());
        assert!(value["session"].get("inbox_incarnation_id").is_none());
    }
    Ok(())
}
#[tokio::test]
async fn transient_active_session_failure_keeps_global_readiness() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("capable-transient-readiness")?;
    fixture.context.hub.readiness.started.store(true, Ordering::Release);
    fixture.context.hub.readiness.ready.store(true, Ordering::Release);
    let context = fixture.context.clone();
    let task = tokio::spawn(async move {
        let (send, _) = sink();
        handle(
            &send,
            &context,
            &runtime()?,
            &serde_json::to_vec(
                &json!({"frame_type":"fetch_entry","incarnation_id":ID,"inbox_seq":1}),
            )?,
        )
        .await
    });
    let request = fixture.next().await?;
    request.respond.send((503, json!({}))).map_err(|_| Retired)?;
    assert!(task.await?.is_err_and(|error| error.downcast_ref::<Retired>().is_some()));
    assert!(fixture.context.hub.readiness.supports());
    Ok(())
}
#[tokio::test]
async fn native_authority_precedes_input_diagnostics() -> anyhow::Result<()> {
    for frame in [
        json!({"frame_type":"fetch_entry","incarnation_id":"ffffffffffffffffffffffffffffffff","inbox_seq":1}),
        json!({"frame_type":"ack_batch","incarnation_id":ID,"inbox_seqs":[]}),
    ] {
        let mut fixture = Fixture::new("native-first-diagnostics")?;
        let context = fixture.context.clone();
        let (send, frames) = sink();
        let grant = crate::custody::GatewayGrant::from_test_session(
            ramflux_protocol::custody::CustodySession {
                session_id: "native".into(),
                device_ref: ramflux_protocol::custody::DeviceRef {
                    account_anchor: "anchor".into(),
                    device_id: "device".into(),
                    device_epoch: 1,
                },
                target_delivery_id: "target".into(),
                record_hash: "record".into(),
                proof_hash: "proof".into(),
                binding_mode: ramflux_protocol::custody::BindingMode::HomeRelayReceipt,
                expires_at: ramflux_node_core::now_unix_seconds() + 60,
            },
        );
        let task = tokio::spawn(async move {
            handle_authorized(
                &send,
                &context,
                &runtime()?,
                &serde_json::to_vec(&frame)?,
                Some(&grant),
            )
            .await
        });
        let authority = fixture.next().await?;
        assert!(authority.path.starts_with("/mvp1/device-auth-key/"));
        authority.respond.send((200, Value::Null)).map_err(|_| Retired)?;
        assert!(task.await?.is_err_and(|error| error.downcast_ref::<Retired>().is_some()));
        assert_eq!(
            frames.lock().map_err(|_| Retired)?[0],
            json!({"frame_type":"nack","reason":"native_session_authority_refused"})
        );
        assert!(fixture.requests.try_recv().is_err());
    }
    Ok(())
}

struct MeasuredSink(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl GatewaySessionFrameSink for MeasuredSink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.0.store(bytes.as_ptr() as usize, Ordering::Release);
            Ok(())
        })
    }
}
#[tokio::test]
async fn measured_page_and_point_buffers_are_reused() -> anyhow::Result<()> {
    let point = json!({"frame_type":"entry_gone","incarnation_id":ID,"inbox_seq":1,"observed_issued_inbox_seq":1,"reason":"expired"});
    let page = json!({"frame_type":"resume_page","target_delivery_id":"target","incarnation_id":ID,"after_inbox_seq":0,"covered_through_seq":1,"issued_inbox_seq":1,"settled_through_seq":0,"entries":[],"known_losses":[],"oversize_next":null,"more":false});
    for (value, bytes) in [
        (&point, validation::point(&point, "target", 1)?),
        (&page, validation::page(&page, "target", 0, 1)?),
    ] {
        assert_eq!(bytes, serde_json::to_vec(value)?);
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink: GatewaySendHandle =
            Arc::new(tokio::sync::Mutex::new(Box::new(MeasuredSink(observed.clone()))));
        write_bytes(&sink, &bytes).await?;
        assert_eq!(
            observed.load(Ordering::Acquire),
            bytes.as_ptr() as usize,
            "write must borrow the measured buffer"
        );
    }
    Ok(())
}
