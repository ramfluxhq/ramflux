// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Raw requests prove negotiation, input fences and recipient wire behavior.
#[path = "negotiation_tests.rs"]
mod negotiation;
#[cfg(feature = "itest-local-mint")]
#[path = "submit_tests.rs"]
mod submit;
#[path = "test_support.rs"]
mod support;
use super::*;
use support::{Fixture, ID, cursor, runtime, sink};

async fn call(
    fixture: &mut Fixture,
    runtime: GatewaySessionRuntime,
    request: Value,
    replies: Vec<Value>,
) -> anyhow::Result<Value> {
    let (send, frames) = sink();
    let context = fixture.context.clone();
    let task = tokio::spawn(async move {
        handle(&send, &context, &runtime, &serde_json::to_vec(&request)?).await
    });
    for reply in replies {
        let req = fixture.next().await?;
        req.respond.send((200, reply)).map_err(|_| anyhow::anyhow!("request cancelled"))?;
    }
    tokio::time::timeout(Duration::from_secs(10), task).await???;
    let frames = frames.lock().map_err(|_| anyhow::anyhow!("frame mutex"))?;
    anyhow::ensure!(frames.len() == 1, "one reply per request");
    Ok(frames[0].clone())
}
fn issued() -> Value {
    json!({"issued":[{"target_delivery_id":"target","incarnation_id":ID,"inbox_seq":10}]})
}
#[tokio::test(flavor = "current_thread")]
async fn async_ack_nack_and_input_caps() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("push-ack-caps")?;
    let runtime = runtime()?;
    let mut inputs = vec![
        json!([]),
        json!([0]),
        json!([2, 1]),
        json!([1, 1]),
        json!((1..=65).collect::<Vec<_>>()),
    ];
    for seqs in inputs.drain(..) {
        let reply = call(
            &mut fixture,
            runtime.clone(),
            json!({"frame_type":"ack_batch","incarnation_id":ID,"inbox_seqs":seqs}),
            vec![],
        )
        .await?;
        assert_eq!(reply["reason"], "invalid_seq");
        assert!(fixture.requests.try_recv().is_err());
    }
    let (send, frames) = sink();
    let context = fixture.context.clone();
    let worker_runtime = runtime.clone();
    let bytes = serde_json::to_vec(
        &json!({"frame_type":"ack_batch","incarnation_id":ID,"inbox_seqs":(1..=64).collect::<Vec<_>>()}),
    )?;
    let task = tokio::spawn(async move { handle(&send, &context, &worker_runtime, &bytes).await });
    let probe = fixture.next().await?;
    assert_eq!(probe.path, "/mvp0/issued-seqs");
    heartbeat(&fixture.context).await?;
    probe
        .respond
        .send((
            200,
            json!({"issued":[{"target_delivery_id":"target","incarnation_id":ID,"inbox_seq":64}]}),
        ))
        .map_err(|_| Retired)?;
    let batch = fixture.next().await?;
    assert_eq!(batch.path, "/mvp0/ack-bound-batch");
    assert_eq!(batch.body["inbox_seqs"].as_array().map(Vec::len), Some(64));
    heartbeat(&fixture.context).await?;
    batch.respond.send((200,json!({"incarnation_id":ID,"cursor":cursor(),"results":(1..=64).map(|s|json!({"inbox_seq":s,"outcome":"acked","reason":null})).collect::<Vec<_>>()}))).map_err(|_|Retired)?;
    tokio::time::timeout(Duration::from_secs(10), task).await???;
    assert_eq!(frames.lock().map_err(|_| Retired)?[0]["frame_type"], "ack_batch");
    assert_eq!(frames.lock().map_err(|_| Retired)?[0]["incarnation_id"], ID);
    assert_eq!(frames.lock().map_err(|_| Retired)?[0]["cursor"], cursor());
    assert_eq!(
        frames.lock().map_err(|_| Retired)?[0]["results"].as_array().map(Vec::len),
        Some(64)
    );
    legacy_ack_nack(&mut fixture, &runtime).await?;
    let (send, frames) = sink();
    handle(
        &send,
        &fixture.context,
        &runtime,
        &vec![b' '; ramflux_node_core::ENTRY_FRAME_BYTE_CAP + 1],
    )
    .await?;
    assert_eq!(frames.lock().map_err(|_| Retired)?[0]["reason"], "payload_too_large");
    assert!(fixture.requests.try_recv().is_err());
    Ok(())
}
async fn heartbeat(context: &GatewayQuicContext) -> anyhow::Result<()> {
    let (send, frames) = sink();
    context.hub.register("heartbeat".into(), "heartbeat".into(), send).await?;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            context
                .hub
                .send_to("heartbeat", &ramflux_node_core::GatewayServerFrame::Heartbeat { now: 7 })
        )
        .await?
    );
    assert_eq!(frames.lock().map_err(|_| Retired)?[0], json!({"frame_type":"heartbeat","now":7}));
    Ok(())
}
async fn legacy_ack_nack(
    fixture: &mut Fixture,
    runtime: &GatewaySessionRuntime,
) -> anyhow::Result<()> {
    for is_ack in [true, false] {
        let (send, frames) = sink();
        let context = fixture.context.clone();
        let mut runtime = runtime.clone();
        runtime.session_push = None;
        let task = tokio::spawn(async move {
            if is_ack {
                crate::session::handle_gateway_ack(
                    &send,
                    &context,
                    &runtime,
                    &serde_json::from_value(support::ack(1))?,
                )
                .await
            } else {
                crate::session::handle_gateway_nack(
                    &send,
                    &context,
                    &runtime,
                    &serde_json::from_value(support::nack(1))?,
                )
                .await
            }
        });
        let req = fixture.next().await?;
        assert_eq!(req.path, if is_ack { "/mvp0/ack-bound" } else { "/mvp0/nack-bound" });
        heartbeat(&fixture.context).await?;
        req.respond.send((200, cursor())).map_err(|_| Retired)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        let rows = frames.lock().map_err(|_| Retired)?.clone();
        assert_eq!(rows.len(), if is_ack { 2 } else { 1 });
        assert_eq!(rows.last(), Some(&json!({"frame_type":"cursor","cursor":cursor()})));
        if is_ack {
            assert_eq!(rows[0], json!({"frame_type":"ack","cursor":cursor()}));
        }
    }
    Ok(())
}
#[tokio::test]
async fn invalid_seq_terminal() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("push-point-inputs")?;
    let zero = call(
        &mut fixture,
        runtime()?,
        json!({"frame_type":"fetch_entry","incarnation_id":ID,"inbox_seq":0}),
        vec![],
    )
    .await?;
    assert_eq!(zero["reason"], "invalid_seq");
    assert!(fixture.requests.try_recv().is_err());
    let future = call(
        &mut fixture,
        runtime()?,
        json!({"frame_type":"fetch_entry","incarnation_id":ID,"inbox_seq":11}),
        vec![issued()],
    )
    .await?;
    assert_eq!(future["reason"], "invalid_seq");
    assert!(fixture.requests.try_recv().is_err());
    let stale=call(&mut fixture,runtime()?,json!({"frame_type":"fetch_entry","incarnation_id":"ffffffffffffffffffffffffffffffff","inbox_seq":11}),vec![]).await?;
    assert_eq!(stale["reason"], "incarnation_mismatch");
    assert!(fixture.requests.try_recv().is_err());
    Ok(())
}
#[tokio::test]
async fn inbox_incarnation_lifecycle() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("push-wire-metadata")?;
    let record = json!({"entry":{"target_delivery_id":"target","inbox_seq":1,"envelope":crate::session::tests::test_envelope()},"retain_until":12345});
    let page = json!({"target_delivery_id":"target","incarnation_id":ID,"after_inbox_seq":0,"covered_through_seq":3,"issued_inbox_seq":3,"settled_through_seq":0,"entries":[record.clone()],"known_losses":[{"from_seq":2,"to_seq":3,"reason":"expired"}],"oversize_next":null,"more":false});
    let reply=call(&mut fixture,runtime()?,json!({"frame_type":"resume","incarnation_id":ID,"resume":{"target_delivery_id":"target","after_inbox_seq":0,"limit":999,"resume_token":"resume"}}),vec![page.clone()]).await?;
    let mut expected = page;
    expected["frame_type"] = json!("resume_page");
    assert_eq!(reply, expected);
    for (seq, response) in [
        (1, json!({"frame_type":"entry","incarnation_id":ID,"record":record})),
        (
            2,
            json!({"frame_type":"entry_too_large","incarnation_id":ID,"inbox_seq":2,"retain_until":12346}),
        ),
        (
            3,
            json!({"frame_type":"entry_gone","incarnation_id":ID,"inbox_seq":3,"observed_issued_inbox_seq":10,"reason":"expired"}),
        ),
    ] {
        let reply = call(
            &mut fixture,
            runtime()?,
            json!({"frame_type":"fetch_entry","incarnation_id":ID,"inbox_seq":seq}),
            vec![issued(), response.clone()],
        )
        .await?;
        assert_eq!(reply, response);
    }
    for (tag, body) in [("ack", support::ack(1)), ("nack", support::nack(1))] {
        let mut request = json!({"frame_type":tag,"incarnation_id":ID});
        request[tag] = body;
        let response = if tag == "ack" {
            json!({"incarnation_id":ID,"cursor":cursor(),"results":[{"inbox_seq":1,"outcome":"acked","reason":null}]})
        } else {
            json!({"incarnation_id":ID,"cursor":cursor()})
        };
        let reply = call(&mut fixture, runtime()?, request, vec![issued(), response]).await?;
        assert_eq!(
            reply,
            json!({"frame_type":if tag=="ack"{"ack"}else{"cursor"},"incarnation_id":ID,"cursor":cursor()})
        );
    }
    Ok(())
}
#[tokio::test]
async fn legacy_wire_unchanged() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("push-legacy-wire")?;
    let mut runtime = runtime()?;
    runtime.session_push = None;
    for tag in ["fetch_entry", "ack_batch", "resume"] {
        let response = call(
            &mut fixture,
            runtime.clone(),
            json!({"frame_type":tag,"incarnation_id":ID}),
            vec![],
        )
        .await?;
        assert_eq!(response, json!({"frame_type":"nack","reason":"gateway_request_invalid"}));
        assert!(fixture.requests.try_recv().is_err());
    }
    let (send, frames) = sink();
    let context = fixture.context.clone();
    let copy = runtime.clone();
    let task = tokio::spawn(async move {
        crate::session::handle_gateway_resume(
            &send,
            &context,
            &copy,
            &ramflux_node_core::GatewayResumeFrame {
                target_delivery_id: "target".into(),
                after_inbox_seq: 0,
                limit: 1,
                resume_token: "resume".into(),
            },
        )
        .await
    });
    let req = fixture.next().await?;
    assert!(req.path.starts_with("/mvp1/inbox/target?"));
    req.respond
        .send((200, json!({"target_delivery_id":"target","entries":[]})))
        .map_err(|_| Retired)?;
    task.await??;
    assert_eq!(frames.lock().map_err(|_| Retired)?[0], json!({"frame_type":"resume","entries":[]}));
    legacy_ack_nack(&mut fixture, &runtime).await?;
    Ok(())
}

#[tokio::test]
async fn unnegotiated_dispatch_and_legacy_establishment() -> anyhow::Result<()> {
    let fixture = Fixture::new("push-legacy-dispatch")?;
    let mut runtime = runtime()?;
    runtime.session_push = None;
    let (send, frames) = sink();
    crate::session::run_gateway_session_loop(
        send,
        Box::new(support::Source(std::collections::VecDeque::from([
            serde_json::to_vec(
                &json!({"frame_type":"ack_batch","incarnation_id":ID,"inbox_seqs":[1]}),
            )?,
            serde_json::to_vec(&json!({"frame_type":"heartbeat","now":7}))?,
        ]))),
        fixture.context.clone(),
        runtime,
    )
    .await?;
    let rows = frames.lock().map_err(|_| Retired)?.clone();
    assert_eq!(rows[0], json!({"frame_type":"nack","reason":"gateway_request_invalid"}));
    assert_eq!(rows[1], json!({"frame_type":"heartbeat","now":7}));
    drop(rows);
    let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut wire = support::Sink(frames.clone());
    established(
        &mut wire,
        ramflux_node_core::GatewaySessionEstablishedFrame {
            session_id: "session".into(),
            gateway_id: "gateway".into(),
            accepted_cursor: None,
            resume_token: "resume".into(),
            resume_window_seconds: 300,
        },
        None,
    )
    .await?;
    assert_eq!(
        frames.lock().map_err(|_| Retired)?[0],
        json!({"frame_type":"session_established","session":{"session_id":"session","gateway_id":"gateway","accepted_cursor":null,"resume_token":"resume","resume_window_seconds":300}})
    );
    Ok(())
}

#[tokio::test]
async fn scoped_resume_and_router_refusal() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("push-resume-scope")?;
    for (target, token, limit, reason) in [
        ("forged", "resume", 1, "invalid_resume_token"),
        ("target", "forged", 1, "invalid_resume_token"),
        ("target", "resume", 0, "invalid_limit"),
    ] {
        let reply=call(&mut fixture,runtime()?,json!({"frame_type":"resume","incarnation_id":ID,"resume":{"target_delivery_id":target,"after_inbox_seq":0,"limit":limit,"resume_token":token}}),vec![]).await?;
        assert_eq!(reply["reason"], reason);
        assert!(fixture.requests.try_recv().is_err());
    }
    let (send, frames) = sink();
    let context = fixture.context.clone();
    let task = tokio::spawn(async move {
        handle(&send,&context,&runtime()?,&serde_json::to_vec(&json!({"frame_type":"resume","incarnation_id":ID,"resume":{"target_delivery_id":"target","after_inbox_seq":11,"limit":999,"resume_token":"resume"}}))?).await
    });
    let req = fixture.next().await?;
    assert!(req.path.contains("limit=256"));
    req.respond
        .send((400, json!({"reason":"cursor_ahead","incarnation_id":ID})))
        .map_err(|_| Retired)?;
    task.await??;
    assert_eq!(
        frames.lock().map_err(|_| Retired)?[0],
        json!({"frame_type":"nack","reason":"cursor_ahead","incarnation_id":ID})
    );
    Ok(())
}
