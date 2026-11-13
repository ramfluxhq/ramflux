// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real queue retries at due time and both independent terminal retry budgets.
use super::*;

pub(super) async fn exhaust_parked_target(
    source: &mut LocalBusAccountState,
    key: &str,
    own: &Arc<Mutex<Vec<ramflux_protocol::Envelope>>>,
) -> TestResult {
    let before = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
    let mut previous: Value = source.client.account_db()?.load_actor_state(key)?.ok_or("parked")?;
    let live_attempts = previous["targets"][0]["attempts"].clone();
    for attempts in 3..=10 {
        due(&source.client)?;
        assert_eq!(crate::bus::own_device_copy::flush(source).await?, 0);
        let work: Value = source.client.account_db()?.load_actor_state(key)?.ok_or("retry")?;
        assert_eq!(
            work["targets"][0]["attempts"], live_attempts,
            "ACKed sibling must not spend another attempt"
        );
        let dead = work["targets"]
            .as_array()
            .ok_or("targets")?
            .iter()
            .find(|t| t["device"] == "dead-sibling")
            .ok_or("dead")?;
        assert_eq!(dead["attempts"], attempts, "parked target must retry when due");
        assert_eq!(work["packet"], previous["packet"], "retry ciphertext stays immutable");
        previous = work;
    }
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), before + 8);
    assert_eq!(crate::bus::own_device_copy::flush(source).await?, 0);
    assert!(!source.client.account_db()?.actor_state_exists(key)?, "ten attempts exhaust the copy");
    let copy = previous["intent"]["copy_id"].as_str().ok_or("copy")?;
    let status: Value = source
        .client
        .account_db()?
        .load_actor_state(&format!("own-device/status/{copy}"))?
        .ok_or("status")?;
    assert_eq!(status["state"], "failed");
    assert_eq!(
        source.client.account_db()?.actor_state_usage("own-device/context-delivered/")?.0,
        0
    );
    Ok(())
}

#[tokio::test]
async fn parked_copy_is_indexed_when_due_and_fails_at_the_configured_lifetime() -> TestResult {
    let root = runtime_tests::root("own-copy-lifetime");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    source.client.set_offline_retention_secs(3_600)?;
    let (sibling, config, _, directory) = sibling_fixture(&root, &mut source).await?;
    let mut gateway = super::super::super::fixture::RecordingGateway::new(Arc::default());
    gateway.fail_own_ack = true;
    let own = Arc::clone(&gateway.own);
    source
        .install_test_session(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let create = super::super::super::dm_tests::create_carrier(&source.client)?;
    assert_eq!(send(&mut source, &create).await?["own_device_copy_state"], "pending");
    let db = source.client.account_db()?;
    let key = db.actor_state_key_page("own-device/send/", 1)?.remove(0);
    let mut work: Value = db.load_actor_state(&key)?.ok_or("copy")?;
    let now = now_unix_timestamp();
    work["intent"]["created_at"] = json!(now - 3_600);
    work["intent"]["expires_at"] = json!(now);
    work["targets"][0]["next_at"] = json!(now + 60);
    db.persist_actor_state(&key, &work)?;
    assert_eq!(db.due_own_copy_keys(now - 1, 256)?, Vec::<String>::new());
    assert_eq!(db.due_own_copy_keys(now, 256)?, vec![key.clone()]);
    let captures = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 0);
    assert!(!source.client.account_db()?.actor_state_exists(&key)?);
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), captures);
    let status: Value = source
        .client
        .account_db()?
        .load_actor_state(&format!(
            "own-device/status/{}",
            work["intent"]["copy_id"].as_str().ok_or("id")?
        ))?
        .ok_or("status")?;
    assert_eq!(status["state"], "failed");
    directory.abort();
    drop((source, sibling));
    Ok(())
}
