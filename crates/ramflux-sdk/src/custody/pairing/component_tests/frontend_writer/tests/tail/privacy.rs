// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native J6 persistence and node-bound AEAD packet/log privacy through the actual driver.
use super::*;
#[tokio::test(start_paused = true)]
async fn primary_transfer_full_node_sees_sizes_only() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let (mut rig, mut source, client, mut target, request) =
        Box::pin(setup_with_source(|client, evidence| {
            let db = client.account_db()?;
            db.seed_full_transfer_supported_state_for_test()?;
            let mut source = db.prepare_full_transfer_source()?;
            let snapshot = ramflux_protocol::encode_base64url([92; 32]);
            source.capture_base_cut(&snapshot)?;
            let (_, encoded) = source.encode_fixed_base_source(&snapshot, std::io::sink())?;
            evidence.reject_roots(encoded.chunks_root, encoded.schema.census_hash)?;
            Ok(())
        }))
        .await?;
    Box::pin(merge(&mut rig, &mut source, &client, &mut target, &request)).await?;
    assert!(
        rig.node.persist_calls.load(std::sync::atomic::Ordering::Acquire) >= 2,
        "test: privacy fixture never persisted the native handoff"
    );
    rig.wire_evidence.check_persistence(&rig._node_root.path().join("authority.redb"))?;
    rig.wire_evidence.assert_private();
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}
