// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Socket-driven pacing across rollover, close and recovery of deferred packets.
use super::*;
use ramflux_protocol::A2uiConversationCommand as C;

fn saved(host: &Host) -> TestResult<Value> {
    Ok(serde_json::from_slice(&std::fs::read(&host.config.state_file)?)?)
}

fn spaced(data: &Data) {
    assert!(
        data.surface_write_times.windows(2).all(|pair| pair[1] >= pair[0] + 100),
        "every surface write, including rollover and close, needs its own interval: {:?}",
        data.surface_write_times
    );
}

#[tokio::test]
async fn bridge_surface_writes_are_paced_across_rollover_and_close_on_the_bus_clock() -> TestResult
{
    let (_root, server, mut host) = fixture().await?;
    // The bus clock deliberately trails wall time. Eligibility and wakeups must agree.
    let base = crate::bus::now_ms().saturating_sub(60_000);
    host.data.lock().map_err(|_| "data")?.clock = base;
    let input = host.input(&server, "paced-stream").await?;
    let text = "x".repeat(20_000);
    let mut p = params(&input, "paced-delta");
    p["op"] = json!("stream_append");
    p["version"] = json!(1);
    p["text_delta"] = json!(text);
    server.call("reply.surface", p).await?;
    assert_eq!(host.data.lock().map_err(|_| "data")?.surface_write_times, [base]);
    assert!(
        !saved(&host)?["engine"]["packet"]["outputs"]
            .as_array()
            .ok_or("pending outputs")?
            .is_empty(),
        "the early RPC ACK must follow a durable pending packet"
    );
    let mut p = params(&input, "paced-close");
    p["op"] = json!("close");
    p["version"] = json!(2);
    p["fallback_text"] = json!(text);
    let mut wire = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":"prx-paced-close","method":"reply.surface","params":p}),
    )?;
    wire.push(b'\n');
    server.raw(wire).await?;
    let mut closed = false;
    for interval in 1..=64 {
        let before = host.data.lock().map_err(|_| "data")?.surface_write_times.len();
        host.data.lock().map_err(|_| "data")?.clock = base + interval * 100;
        host.poll_clock().await?;
        host.event("message.updated", json!({"message":{"deleted":false}})).await?;
        host.applied().await?;
        let data = host.data.lock().map_err(|_| "data")?;
        assert!(data.surface_write_times.len() <= before + 1, "a tick spent multiple write slots");
        spaced(&data);
        closed = data.surface_states.len() == 2
            && data.surface_states.values().all(ramflux_protocol::SurfaceState::is_closed);
        if closed {
            break;
        }
    }
    assert!(closed, "bounded manual clock steps must drain rollover and close");
    finish(&server, &input, &text).await?;
    {
        let data = host.data.lock().map_err(|_| "data")?;
        spaced(&data);
        assert_eq!(
            data.surfaces.iter().filter(|e| matches!(e.command(), C::CreateSurface(_))).count(),
            2
        );
        assert_eq!(texts(&data)?.concat(), text);
    }
    host.stop().await?;
    Ok(())
}

#[tokio::test]
async fn bridge_deferred_surface_packet_survives_restart_and_bounds_restored_deadline() -> TestResult
{
    let (_root, server, mut host) = fixture().await?;
    let base = crate::bus::now_ms();
    host.data.lock().map_err(|_| "data")?.clock = base;
    let input = host.input(&server, "paced-restart").await?;
    let text = "y".repeat(20_000);
    let mut p = params(&input, "restart-delta");
    p["op"] = json!("stream_append");
    p["version"] = json!(1);
    p["text_delta"] = json!(text);
    server.call("reply.surface", p).await?;
    assert_eq!(host.data.lock().map_err(|_| "data")?.surface_write_times.len(), 1);
    let data = Arc::clone(&host.data);
    let stopped = host.stop().await?;
    let path = stopped.host.config.state_file.clone();
    let mut checkpoint: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let turn = input["params"]["turn_id"].as_str().ok_or("turn")?;
    checkpoint["engine"]["turns"][turn]["next_surface_write_at"] = json!(u64::MAX);
    std::fs::write(&path, serde_json::to_vec(&checkpoint)?)?;
    data.lock().map_err(|_| "data")?.clock = 0;
    let after = server.calls.lock().map_err(|_| "calls")?.len();
    let mut host = Host::resume(stopped, Arc::clone(&data)).await?;
    server.wait_method("bridge.hello", after).await?;
    host.event("message.updated", json!({"message":{"deleted":false}})).await?;
    host.applied().await?;
    assert!(
        saved(&host)?["engine"]["turns"][turn]["next_surface_write_at"]
            .as_u64()
            .ok_or("restored write deadline")?
            <= crate::bus::now_ms() + 100,
        "a restored deadline may reserve at most one write interval"
    );
    let mut p = params(&input, "restart-close");
    p["op"] = json!("close");
    p["version"] = json!(2);
    p["fallback_text"] = json!(text);
    server.call("reply.surface", p).await?;
    finish(&server, &input, &text).await?;
    {
        let data = data.lock().map_err(|_| "data")?;
        spaced(&data);
        assert_eq!(data.surface_states.len(), 2);
        assert!(data.surface_states.values().all(ramflux_protocol::SurfaceState::is_closed));
        assert_eq!(texts(&data)?.concat(), text);
    }
    host.stop().await?;
    Ok(())
}

#[tokio::test]
async fn bridge_deferred_packet_wake_waits_for_the_next_bus_clock_poll() -> TestResult {
    use crate::EngineProvider;
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let (_root, server, mut host) = fixture().await?;
    let base = crate::bus::now_ms().saturating_sub(60_000);
    host.data.lock().map_err(|_| "data")?.clock = base;
    let input = host.input(&server, "paced-wake").await?;
    let mut p = params(&input, "wake-delta");
    p["op"] = json!("stream_append");
    p["version"] = json!(1);
    p["text_delta"] = json!("z".repeat(20_000));
    server.call("reply.surface", p).await?;
    let stopped = host.stop().await?;
    assert!(!stopped.host.engine.output_ready(base));
    assert!(stopped.host.engine.packet().is_some());
    // Drain any previously stored Notify permit without yielding or advancing a clock.
    // A future that always compares with wall time remains ready on every poll.
    let mut pending = false;
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..4 {
        let wake = stopped.host.engine.wake();
        tokio::pin!(wake);
        pending |= wake.as_mut().poll(&mut context).is_pending();
    }
    assert!(pending, "a deferred packet must sleep until the bus clock is polled again");
    Ok(())
}
