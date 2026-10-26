// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A background-confirmed deregistration also clears the persisted pending marker.
use super::*;

#[tokio::test]
async fn confirmed_background_deregistration_clears_the_persisted_marker() -> Result<(), SdkError> {
    let root = root("push-clear-confirmed");
    let mut account = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    let checkpoint = crate::bus::dispatch::device::PUSH_ROUTE_CHECKPOINT;
    account.client.set_projection_checkpoint(checkpoint, "{\"deregister_pending\":true}")?;
    account.gateway_config.push_route = None;
    account.gateway_config.push_route_clear_pending = true;
    let mut engine = account.engine.take().ok_or(SdkError::GatewaySessionNotEstablished)?;
    // The engine's background retry was confirmed by the node.
    engine.config.push_route = None;
    engine.config.push_route_clear_pending = false;
    account.put_engine(engine);
    assert_eq!(account.client.projection_checkpoint(checkpoint)?.as_deref(), Some(""));
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn the_push_route_sequence_is_persisted_and_never_reused() -> Result<(), SdkError> {
    let root = root("push-seq-persisted");
    let mut account = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    let mut engine = account.engine.take().ok_or(SdkError::GatewaySessionNotEstablished)?;
    // A control was signed while the device clock was far ahead.
    let ahead = 4_000_000_000_000_u64;
    engine.config.push_route_last_seq = ahead;
    account.put_engine(engine);
    let saved = account
        .client
        .projection_checkpoint(crate::bus::dispatch::device::PUSH_ROUTE_SEQ_CHECKPOINT)?;
    assert_eq!(saved.as_deref(), Some("4000000000000"));
    assert_eq!(crate::bus::dispatch::device::stored_push_route_seq(&account.client)?, ahead);
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
