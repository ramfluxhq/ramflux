// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Courier priority and task-only federation capacity regressions over real host exchanges.

use crate::bus::connection_manager::ConnectionHandle;
use crate::bus::connection_manager::tests::{config, entry, fixture, send, watchdog};
use crate::{GatewayClientFrame, GatewayServerFrame};
use std::time::Duration;
use tokio::time::Instant;

type Case = Result<(), Box<dyn std::error::Error>>;

fn cursor(
    handle: ConnectionHandle,
    deadline: Instant,
) -> tokio::task::JoinHandle<Result<Option<crate::GatewayCursor>, crate::SdkError>> {
    tokio::spawn(async move { handle.call(|engine| Box::pin(engine.cursor()), deadline).await })
}
async fn wait_for_queued(handle: &ConnectionHandle, count: usize) {
    while handle.queued_calls() != count {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn receipt_prekey_fetch_not_starved_by_bulk() -> Case {
    watchdog(async {
        let (handle, mut io) = fixture().await?;
        let first = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        let mut bulk = Vec::new();
        for _ in 0..crate::bus::runtime_limits::CALL_QUEUE {
            bulk.push(cursor(handle.clone(), Instant::now() + Duration::from_secs(600)));
        }
        wait_for_queued(&handle, crate::bus::runtime_limits::CALL_QUEUE).await;
        let receipt = {
            let context = handle.test_context();
            let config = config()?;
            tokio::spawn(async move {
                crate::bus::delivery_receipts::background::test_fetch_material(&context, config).await
            })
        };
        wait_for_queued(&handle, crate::bus::runtime_limits::CALL_QUEUE + 1).await;
        assert_eq!(handle.queued_calls(), crate::bus::runtime_limits::CALL_QUEUE + 1);
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        first.await??;
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::PrekeyFetch { device_id }) if device_id == "receipt-peer"));
        // No bundle is needed to prove scheduling: a missing prekey completes this exchange.
        send(&io, &GatewayServerFrame::Prekey { response: crate::prekey::SdkPrekeyResponse {
            device_id: "receipt-peer".into(), bundle: None, principal_commitment: String::new(), target_delivery_id: None,
        } })?;
        assert!(matches!(receipt.await?, Err(crate::SdkError::InboundPending(_) | crate::SdkError::SenderManifestRequired { .. } | crate::SdkError::FreshHeadRequired { .. })));
        assert!(bulk.iter().all(|call| !call.is_finished()));
        for call in bulk { call.abort(); let _ = call.await; }
        handle.stop().await;
        Ok(())
    }).await
}

#[tokio::test]
async fn group_and_call_control_bypass_saturated_task_limiter() -> Case {
    let limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    super::federation::TEST_LIMITER
        .scope(
            limiter.clone(),
            watchdog(async move {
                let capacity = limiter;
                let _permits = capacity.acquire_many(4).await?;
                let (handle, mut io) = fixture().await?;
                let server = tokio::spawn(async move {
                    for _ in 0..2 {
                        let Some(GatewayClientFrame::Submit { submit }) = io.output.recv().await
                        else {
                            return Err("test: expected gateway Submit");
                        };
                        assert_eq!(
                            submit.target_node.as_deref(),
                            Some("b"),
                            "federated target lost"
                        );
                        let mut accepted = entry("bypass", 1).map_err(|_| "test: entry")?;
                        accepted.envelope = submit.envelope;
                        send(&io, &GatewayServerFrame::Deliver { entry: accepted })
                            .map_err(|_| "test: reply")?;
                    }
                    Ok::<_, &'static str>(())
                });
                let context = handle.test_context();
                let route = crate::LocalBusFederationRoute {
                    source_node_id: "a".into(),
                    target_node_id: "b".into(),
                    required_capability: "group".into(),
                };
                let envelope = entry("bypass", 1)?.envelope;
                assert!(matches!(
                    crate::bus::couriers::federation::submit_until(
                        &context,
                        envelope.clone(),
                        Some(route.clone()),
                        context.call_deadline(),
                        false
                    )
                    .await,
                    Err(crate::SdkError::TaskForwardWorkerCapacity)
                ));
                crate::bus::couriers::federation::submit(
                    &context,
                    envelope.clone(),
                    Some(route.clone()),
                )
                .await?;
                crate::bus::couriers::federation::submit_until(
                    &context,
                    envelope,
                    Some(route),
                    context.call_deadline(),
                    true,
                )
                .await?;
                server.await??;
                handle.stop().await;
                Ok(())
            }),
        )
        .await
}
