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
