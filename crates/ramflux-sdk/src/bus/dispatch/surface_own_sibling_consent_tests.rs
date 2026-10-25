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
    // Both crossed bootstraps are delivered, then the author streams its next version.
    assert!(
        sibling
            .client
            .receive_own_device_message(&receiver, &entry(first, 1))
            .await
            .map_err(|e| format!("author bootstrap at sibling: {e:?}"))?
    );
    let mut back_entry = entry(crossed, 1);
    back_entry.target_delivery_id.clone_from(&config.target_delivery_id);
    back_entry.envelope.target_delivery_id.clone_from(&config.target_delivery_id);
    source
        .client
        .receive_own_device_message(&config, &back_entry)
        .await
        .map_err(|e| format!("sibling bootstrap at author: {e:?}"))?;
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
    directory.abort();
    drop((source, sibling, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
