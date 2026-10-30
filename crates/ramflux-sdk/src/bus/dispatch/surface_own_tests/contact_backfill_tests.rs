// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Slow peer directory fetches survive cancellation budgets and parked contacts reach siblings.
use super::*;

#[tokio::test]
async fn slow_contact_manifest_persists_and_is_delivered_to_sibling() -> TestResult {
    Box::pin(slow_contact(false)).await
}

#[tokio::test]
async fn parked_contact_is_retried_after_schedule_and_delivered_from_slow_gateway() -> TestResult {
    Box::pin(slow_contact(true)).await
}

async fn slow_contact(park: bool) -> TestResult {
    let root = runtime_tests::root(if park { "parked-slow-contact" } else { "slow-contact" });
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory, peer) =
        sibling_fixture_with_peer(&root, &mut source, false).await?;
    let peer_identity = peer.client.owned_device_identity()?;
    let manifest: crate::prekey::SdkDeviceManifestResponse = source
        .client
        .account_db()?
        .load_actor_state(&format!("identity/manifest-root/{}", peer_identity.root_commitment()))?
        .ok_or("fixture manifest")?;
    let peer_root = &manifest.principal_commitment;
    let key = format!("identity/manifest-root/{peer_root}");
    source.client.account_db()?.remove_actor_state(&key)?;
    sibling.client.account_db()?.remove_actor_state(&key)?;
    source.client.establish_friend_link(
        "slow-contact",
        source.client.owned_device_identity()?.root_commitment(),
        peer_root,
    )?;
    let now = now_unix_timestamp();
    source.client.account_db()?.persist_actor_state("own-contact/last-refresh", &now)?;
    let (slow_config, server) = crate::bus::own_contact_backfill::tests::slow_directory(
        &root,
        config.clone(),
        manifest.clone(),
    )
    .await?;
    source.engine = None;
    source.gateway_config = slow_config;
    assert_eq!(crate::bus::own_contact_backfill::drive(&source).await?, 0);
    assert_eq!(crate::bus::own_contact_backfill::drive(&source).await?, 0);
    if park {
        // Consume the normal five exponentially spaced attempts without publishing a manifest.
        for at in [now, now + 5, now + 15, now + 35, now + 75] {
            assert_eq!(source.client.claim_contact_backfill_refresh(at)?, Some(peer_root.clone()));
        }
        assert_eq!(crate::bus::own_contact_backfill::drive(&source).await?, 0);
        assert_eq!(source.client.account_db()?.actor_state_usage("own-contact/parked/")?.0, 1);
        assert_eq!(crate::bus::own_contact_backfill::drive(&source).await?, 0);
        assert_eq!(source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
        // Advance the durable retry deadline, without changing roster or directory state.
        let mut progress: serde_json::Value = source
            .client
            .account_db()?
            .load_actor_state("own-contact/backfill")?
            .ok_or("progress")?;
        progress["retry_at"] = serde_json::json!(now - 1);
        source.client.account_db()?.persist_actor_state("own-contact/backfill", &progress)?;
        assert_eq!(crate::bus::own_contact_backfill::drive(&source).await?, 0);
        assert_eq!(crate::bus::own_contact_backfill::drive(&source).await?, 0);
    }
    let result = crate::bus::own_contact_backfill::drive(&source).await;
    if result.is_err() {
        server.abort();
    }
    assert_eq!(result?, 1);
    server.await??;
    let persisted: crate::prekey::SdkDeviceManifestResponse =
        source.client.account_db()?.load_actor_state(&key)?.ok_or("slow manifest missing")?;
    assert_eq!(persisted.principal_commitment, *peer_root);
    assert_eq!(source.client.account_db()?.actor_state_usage("own-contact/parked/")?.0, 0);
    let gateway = fresh_sibling_gateway(&source.client, &sibling.client)?;
    let own = Arc::clone(&gateway.own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 1);
    let packet = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(packet, 1)).await?);
    assert_eq!(sibling.client.account_db()?.friend_link("slow-contact")?.state, "accepted");
    assert!(sibling.client.account_db()?.actor_state_exists(&key)?);
    directory.abort();
    drop((source, sibling, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
