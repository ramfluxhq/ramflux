// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Two own devices: a sibling that independently accepts a peer must not break own copies.
use super::*;

#[tokio::test]
async fn sibling_acceptance_copy_does_not_block_the_authors_surface_copies() -> TestResult {
    let root = runtime_tests::root("surface-own-sibling-consent");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (mut sibling, config, receiver, directory, peer) =
        sibling_fixture_with_peer(&root, &mut source, false).await?;
    let peer_root = peer.client.owned_device_identity()?.root_commitment().to_owned();
    let own_root = source.client.owned_device_identity()?.root_commitment().to_owned();
    let gateway = fresh_sibling_gateway(&source.client, &sibling.client)?;
    let source_own = Arc::clone(&gateway.own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config.clone(), Box::new(gateway)));
    // The author's first own copy bootstraps the pair towards the sibling.
    let create = super::super::dm_tests::create_carrier(&source.client)?;
    assert_eq!(send(&mut source, &create).await?["own_device_copy_state"], "submitted");
    let first = source_own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    // Before it arrives, the sibling accepts the same peer on its own and replicates that consent.
    let manifest: crate::prekey::SdkDeviceManifestResponse = sibling
        .client
        .account_db()?
        .load_actor_state(&format!("identity/manifest-root/{peer_root}"))?
        .ok_or("peer manifest")?;
    sibling.client.establish_friend_link("sibling-accepted", &peer_root, &own_root)?;
    sibling.client.stage_own_contact(&manifest, "sibling-accepted")?;
    let back = fresh_sibling_gateway(&sibling.client, &source.client)?;
    let sibling_own = Arc::clone(&back.own);
    sibling.put_engine(GatewaySessionEngine::with_test_transport(receiver.clone(), Box::new(back)));
    assert_eq!(
        crate::bus::own_device_copy::flush(&mut sibling)
            .await
            .map_err(|e| format!("sibling acceptance copy: {e:?}"))?,
        1
    );
    let crossed = sibling_own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    // Select delivery by the real session ordering, forcing both branches on every run.
    let winner =
        converge(&source.client, &sibling.client, &config, &receiver, first, crossed).await?;
    let next = append(&source.client, &create, 2)?;
    assert_eq!(
        send(&mut source, &next).await.map_err(|e| format!("author next copy: {e:?}"))?["own_device_copy_state"],
        "submitted"
    );
    let second = source_own
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .last()
        .cloned()
        .ok_or("second own copy")?;
    assert!(
        sibling
            .client
            .receive_own_device_message(&receiver, &entry(second, 2))
            .await
            .map_err(|e| format!("author next copy at sibling: {e:?}"))?
    );
    assert_eq!(sibling.client.surface_get("surface", 0, None)?["version"], 2);
    // A distinct consent copy tests the reverse ratchet direction after convergence.
    sibling.client.establish_friend_link("reverse-confirmed", &peer_root, &own_root)?;
    sibling.client.stage_own_contact(&manifest, "reverse-confirmed")?;
    assert_eq!(crate::bus::own_device_copy::flush(&mut sibling).await?, 1);
    let reverse = sibling_own
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .last()
        .cloned()
        .ok_or("reverse own copy")?;
    receive_copy(&source.client, &config, reverse, 2).await?;
    assert_eq!(active(&source.client, &sibling.client.owned_device_identity()?)?, winner);
    assert_eq!(active(&sibling.client, &source.client.owned_device_identity()?)?, winner);
    directory.abort();
    drop((source, sibling, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn active(
    client: &RamfluxClient,
    remote: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<String, SdkError> {
    let (session, _) = client
        .active_pair(&client.owned_device_identity()?, remote)?
        .ok_or_else(|| SdkError::LocalBus("missing own-device active pair".into()))?;
    Ok(session.session_id.clone())
}
async fn receive_copy(
    client: &RamfluxClient,
    config: &GatewaySessionConfig,
    envelope: ramflux_protocol::Envelope,
    sequence: u64,
) -> TestResult {
    let mut incoming = entry(envelope, sequence);
    incoming.target_delivery_id.clone_from(&config.target_delivery_id);
    incoming.envelope.target_delivery_id.clone_from(&config.target_delivery_id);
    assert!(
        client.receive_own_device_message(config, &incoming).await?,
        "own copy must be authenticated and applied"
    );
    Ok(())
}
async fn converge(
    source: &RamfluxClient,
    sibling: &RamfluxClient,
    config: &GatewaySessionConfig,
    receiver: &GatewaySessionConfig,
    first: ramflux_protocol::Envelope,
    crossed: ramflux_protocol::Envelope,
) -> Result<String, Box<dyn std::error::Error>> {
    let source_ref = source.owned_device_identity()?;
    let sibling_ref = sibling.owned_device_identity()?;
    let left = active(source, &sibling_ref)?;
    let right = active(sibling, &source_ref)?;
    assert_ne!(left, right, "independent crossed bootstraps must have distinct sessions");
    let winner = std::cmp::min(&left, &right).clone();
    if left < right {
        // The larger local session receives the smaller candidate: incoming must win.
        receive_copy(sibling, receiver, first, 1).await?;
        assert_eq!(
            active(sibling, &source_ref)?,
            winner,
            "incoming lower session must be promoted"
        );
        // The smaller local session receives the larger candidate: local must stay active.
        receive_copy(source, config, crossed, 1).await?;
        assert_eq!(active(source, &sibling_ref)?, winner, "lower local session must remain active");
    } else {
        receive_copy(source, config, crossed, 1).await?;
        assert_eq!(
            active(source, &sibling_ref)?,
            winner,
            "incoming lower session must be promoted"
        );
        receive_copy(sibling, receiver, first, 1).await?;
        assert_eq!(active(sibling, &source_ref)?, winner, "lower local session must remain active");
    }
    assert_eq!(active(source, &sibling_ref)?, active(sibling, &source_ref)?);
    Ok(winner)
}
