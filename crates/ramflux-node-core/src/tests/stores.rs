// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

fn current_envelope(
    envelope_id: &str,
    target_delivery_id: &str,
    delivery_class: DeliveryClass,
) -> Envelope {
    let mut envelope = envelope(envelope_id, target_delivery_id, delivery_class);
    envelope.created_at = i64::try_from(now_unix_seconds()).unwrap_or(i64::MAX - 3_600);
    envelope
}

#[test]
fn router_redb_store_restores_router_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("router_redb_store_restores_router_snapshot")?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    router.upsert_session(session("target_live", SessionLifecycle::Live, 1, 1))?;
    router.submit_envelope(envelope("env_pending", "target_offline", DeliveryClass::OpaqueEvent));
    router.submit_envelope(envelope("env_acked", "target_ack", DeliveryClass::OpaqueEvent));
    router.apply_ack(&ack("env_acked"))?;
    store.save_router(&router)?;
    drop(store);

    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_snapshot".to_owned()))?;
    assert!(matches!(
        restored.submit_envelope(envelope("env_online", "target_live", DeliveryClass::OpaqueEvent)),
        RouterSubmitOutcome::Online(_)
    ));
    assert_eq!(restored.resume("target_offline", 0, 10).len(), 1);
    assert_eq!(
        restored.cursor_state("target_ack").and_then(|cursor| cursor.last_envelope_id),
        Some("env_acked".to_owned())
    );
    Ok(())
}

#[test]
fn router_redb_store_restores_home_node_migration_state() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_store_path("router_redb_store_restores_home_node_migration_state")?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    let request = registration_request(
        "principal_migrate_store",
        "device_migrate_store",
        831,
        None,
        "ip_store",
    )?;
    router.mvp1_register_identity(&request)?;
    let proof = migration_proof_for_registration(
        &request,
        831,
        "mig_store",
        request.now,
        request.now + 1,
        "node_new_store.example",
    )?;
    let migration = router.apply_home_node_migration(&proof, &request.proof, request.now + 1)?;
    store.save_router(&router)?;
    drop(store);

    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_migration".to_owned()))?;
    assert_eq!(
        restored
            .home_node_migration(&request.proof.principal_id)
            .map(|record| record.migration_proof_hash.clone()),
        Some(migration.migration_proof_hash.clone())
    );

    let mut envelope = envelope(
        "env_home_node_migrated_after_restore",
        &request.target_delivery_id,
        DeliveryClass::OpaqueEvent,
    );
    envelope.created_at = request.now + 2;
    let rejected = restored.submit_envelope_at(envelope, request.now + 2);
    let RouterSubmitOutcome::RejectedHomeNodeMigrated(delivery) = rejected else {
        return Err(format!("expected restored migrated nack, got {rejected:?}").into());
    };
    assert_eq!(delivery.proof_hash, migration.migration_proof_hash);
    assert_eq!(delivery.new_home_node_hint, "node_new_store.example");
    assert_eq!(delivery.nack.reason, NackReason::HomeNodeMigrated);
    Ok(())
}

#[test]
fn router_redb_store_restores_home_node_route_state() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("router_redb_store_restores_home_node_route_state")?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    let request = registration_request(
        "principal_route_store",
        "device_route_store",
        842,
        None,
        "ip_route_store",
    )?;
    router.mvp1_register_identity(&request)?;
    let signer = NodeServiceSigningKey::from_seed([0x93; 32]);
    let (migration_proof, route_update) = route_update_fixture(
        &request,
        842,
        "mig_route_store",
        "node_new_route_store.example",
        "node-new-route-store.example:7443",
        &signer,
    )?;
    router.apply_home_node_migration(&migration_proof, &request.proof, request.now + 1)?;
    let route = router.apply_home_node_route_update_proof(&route_update, request.now + 2)?;
    store.save_router(&router)?;
    drop(store);

    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_home_node_route".to_owned()))?;
    assert_eq!(restored.resolve_home_node_route(&request.proof.principal_id), Some(route));
    Ok(())
}

#[test]
fn router_redb_incremental_replay_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("router_redb_incremental_replay_survives_restart")?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let submitted =
        current_envelope("env_replay_incremental", "target_replay", DeliveryClass::OpaqueEvent);
    let replay_key = envelope_replay_tuple_key(&submitted);
    let replay_expires_at = submitted.created_at + i64::from(submitted.ttl);
    let accepted = router.submit_envelope_at(submitted.clone(), submitted.created_at + 1);
    let entry = match accepted {
        RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
        other => return Err(format!("expected offline queue, got {other:?}").into()),
    };
    store.record_submission_increment(&replay_key, replay_expires_at, Some(&entry))?;
    drop(store);

    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_incremental".to_owned()))?;
    let replay = restored.submit_envelope_at(submitted.clone(), submitted.created_at + 2);
    assert!(matches!(replay, RouterSubmitOutcome::RejectedSecurity { .. }));
    Ok(())
}

#[test]
fn router_wal_submission_restores_replay_and_inbox_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("router_wal_submission_restores_replay_and_inbox_atomically")?;
    let wal_root = path.with_extension("submission.wal");
    let store = RouterRedbStore::open_with_wal(&path, &wal_root)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let submitted = current_envelope(
        "env_router_wal_submission",
        "target_router_wal",
        DeliveryClass::OpaqueEvent,
    );
    let replay_key = envelope_replay_tuple_key(&submitted);
    let replay_expires_at = submitted.created_at + i64::from(submitted.ttl);
    let accepted = router.submit_envelope_at(submitted.clone(), submitted.created_at + 1);
    let entry = match accepted {
        RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
        other => return Err(format!("expected offline queue, got {other:?}").into()),
    };
    store.record_submission_increment(&replay_key, replay_expires_at, Some(&entry))?;
    drop(store);

    let redb_only = RouterRedbStore::open_without_wal(&path)?;
    assert!(redb_only.load_router()?.is_none());
    drop(redb_only);

    let reopened = RouterRedbStore::open_with_wal(&path, &wal_root)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_wal_submission".to_owned()))?;
    assert_eq!(restored.resume("target_router_wal", 0, 10).len(), 1);
    let replay = restored.submit_envelope_at(submitted, replay_expires_at - 1);
    assert!(matches!(replay, RouterSubmitOutcome::RejectedSecurity { .. }));
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn router_wal_async_submission_restores_replay_and_inbox_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("router_wal_async_submission_restores_replay_and_inbox_atomically")?;
    let wal_root = path.with_extension("async_submission.wal");
    let store = RouterRedbStore::open_with_wal(&path, &wal_root)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let submitted = current_envelope(
        "env_router_wal_async_submission",
        "target_router_wal_async",
        DeliveryClass::OpaqueEvent,
    );
    let replay_key = envelope_replay_tuple_key(&submitted);
    let replay_expires_at = submitted.created_at + i64::from(submitted.ttl);
    let accepted = router.submit_envelope_at(submitted.clone(), submitted.created_at + 1);
    let entry = match accepted {
        RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
        other => return Err(format!("expected offline queue, got {other:?}").into()),
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(store.record_submission_increment_async(
        &replay_key,
        replay_expires_at,
        Some(&entry),
    ))?;
    drop(store);

    let redb_only = RouterRedbStore::open_without_wal(&path)?;
    assert!(redb_only.load_router()?.is_none());
    drop(redb_only);

    let reopened = RouterRedbStore::open_with_wal(&path, &wal_root)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_wal_async_submission".to_owned()))?;
    assert_eq!(restored.resume("target_router_wal_async", 0, 10).len(), 1);
    let replay = restored.submit_envelope_at(submitted, replay_expires_at - 1);
    assert!(matches!(replay, RouterSubmitOutcome::RejectedSecurity { .. }));
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn router_wal_submission_respects_redb_ack_cursor_on_restore()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("router_wal_submission_respects_redb_ack_cursor_on_restore")?;
    let wal_root = path.with_extension("ack.wal");
    let store = RouterRedbStore::open_with_wal(&path, &wal_root)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let submitted = current_envelope(
        "env_router_wal_acked",
        "target_router_wal_ack",
        DeliveryClass::OpaqueEvent,
    );
    let replay_key = envelope_replay_tuple_key(&submitted);
    let replay_expires_at = submitted.created_at + i64::from(submitted.ttl);
    let accepted = router.submit_envelope_at(submitted.clone(), submitted.created_at + 1);
    let entry = match accepted {
        RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
        other => return Err(format!("expected offline queue, got {other:?}").into()),
    };
    store.record_submission_increment(&replay_key, replay_expires_at, Some(&entry))?;
    let cursor = router.apply_ack(&ack("env_router_wal_acked"))?;
    store.record_ack_increment(&cursor, "env_router_wal_acked")?;
    drop(store);

    let reopened = RouterRedbStore::open_with_wal(&path, &wal_root)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_wal_ack".to_owned()))?;
    assert!(restored.resume("target_router_wal_ack", 0, 10).is_empty());
    assert_eq!(
        restored.cursor_state("target_router_wal_ack").and_then(|cursor| cursor.last_envelope_id),
        Some("env_router_wal_acked".to_owned())
    );
    let replay = restored.submit_envelope_at(submitted, replay_expires_at - 1);
    assert!(matches!(replay, RouterSubmitOutcome::RejectedSecurity { .. }));
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn router_redb_expired_replay_tuple_is_purged_on_load() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("router_redb_expired_replay_tuple_is_purged_on_load")?;
    let store = RouterRedbStore::open(&path)?;
    let mut expired =
        current_envelope("env_replay_expired_on_disk", "target_replay", DeliveryClass::OpaqueEvent);
    let now = i64::try_from(now_unix_seconds())?;
    expired.ttl = 60;
    expired.created_at = now - 120;
    let replay_key = envelope_replay_tuple_key(&expired);
    let replay_expires_at = expired.created_at + i64::from(expired.ttl);
    store.record_submission_increment(&replay_key, replay_expires_at, None)?;
    drop(store);

    let reopened = RouterRedbStore::open(&path)?;
    assert!(reopened.load_router()?.is_none());
    drop(reopened);

    let reopened_again = RouterRedbStore::open(&path)?;
    assert!(reopened_again.load_router()?.is_none());
    Ok(())
}

#[test]
fn router_redb_fanout_replay_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("router_redb_fanout_replay_survives_restart")?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    router.mvp1_register_identity(&registration_request(
        "principal_fanout",
        "device_source",
        601,
        None,
        "ip_fanout_source",
    )?)?;
    router.mvp1_register_identity(&registration_request(
        "principal_fanout",
        "device_peer",
        602,
        None,
        "ip_fanout_peer",
    )?)?;
    store.record_identity_registry(&router.mvp1_identities_snapshot())?;
    let fanout_envelope =
        current_envelope("env_fanout_replay", "target_unused", DeliveryClass::SelfDeviceControl);
    let request = ItestMvp10OwnDeviceFanoutRequest {
        principal_id: "principal_fanout".to_owned(),
        source_device_id: "device_source".to_owned(),
        envelope: fanout_envelope.clone(),
    };
    let response = router.mvp10_own_device_fanout(request.clone())?;
    assert_eq!(response.delivered.len(), 1);
    let replay_key = envelope_replay_tuple_key(&request.envelope);
    let replay_expires_at = request.envelope.created_at + i64::from(request.envelope.ttl);
    let entries = response
        .delivered
        .iter()
        .filter_map(|delivery| {
            delivery.inbox_seq.map(|inbox_seq| {
                let mut envelope = request.envelope.clone();
                envelope.target_delivery_id.clone_from(&delivery.target_delivery_id);
                envelope.envelope_id =
                    mvp10_fanout_envelope_id(&request.envelope.envelope_id, &delivery.device_id);
                InboxEntry {
                    inbox_seq,
                    target_delivery_id: delivery.target_delivery_id.clone(),
                    envelope,
                }
            })
        })
        .collect::<Vec<_>>();
    store.record_fanout_increment(&replay_key, replay_expires_at, &entries)?;
    drop(store);

    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_fanout".to_owned()))?;
    assert_eq!(restored.resume("target_principal_fanout", 0, 10).len(), 1);
    let replay = restored.mvp10_own_device_fanout(request);
    assert!(matches!(replay, Err(NodeCoreError::ReplayGuard(_))));
    Ok(())
}

#[test]
fn router_redb_incremental_ack_survives_restart_without_duplicate_delivery()
-> Result<(), Box<dyn std::error::Error>> {
    let path =
        temp_store_path("router_redb_incremental_ack_survives_restart_without_duplicate_delivery")?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let submitted = current_envelope(
        "env_ack_incremental",
        "target_ack_incremental",
        DeliveryClass::OpaqueEvent,
    );
    let replay_key = envelope_replay_tuple_key(&submitted);
    let replay_expires_at = submitted.created_at + i64::from(submitted.ttl);
    let accepted = router.submit_envelope_at(submitted.clone(), submitted.created_at + 1);
    let entry = match accepted {
        RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
        other => return Err(format!("expected offline queue, got {other:?}").into()),
    };
    store.record_submission_increment(&replay_key, replay_expires_at, Some(&entry))?;
    let cursor = router.apply_ack(&ack("env_ack_incremental"))?;
    store.record_ack_increment(&cursor, "env_ack_incremental")?;
    drop(store);

    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_incremental".to_owned()))?;
    assert!(restored.resume("target_ack_incremental", 0, 10).is_empty());
    assert_eq!(
        restored.cursor_state("target_ack_incremental").and_then(|cursor| cursor.last_envelope_id),
        Some("env_ack_incremental".to_owned())
    );
    Ok(())
}

#[test]
fn router_redb_per_key_state_round_trip_restores_router() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_store_path("router_redb_per_key_state_round_trip_restores_router")?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();

    router.upsert_session(session("target_online_keyed", SessionLifecycle::Live, 1, 1))?;
    store.record_session_entry(
        &router.session("target_online_keyed").ok_or("missing keyed session after upsert")?,
    )?;

    let register = registration_request("principal_keyed", "device_delete", 501, None, "ip_keyed")?;
    router.mvp1_register_identity(&register)?;
    store.record_identity_registry(&router.mvp1_identities_snapshot())?;
    store.record_session_entry(
        &router.session("target_principal_keyed").ok_or("missing keyed identity session")?,
    )?;

    let submitted =
        current_envelope("env_keyed_pending", "target_pending_keyed", DeliveryClass::OpaqueEvent);
    let replay_key = envelope_replay_tuple_key(&submitted);
    let replay_expires_at = submitted.created_at + i64::from(submitted.ttl);
    let queued = match router.submit_envelope_at(submitted.clone(), submitted.created_at + 1) {
        RouterSubmitOutcome::OfflineQueued(queued) => queued,
        other => return Err(format!("expected offline queue, got {other:?}").into()),
    };
    store.record_submission_increment(&replay_key, replay_expires_at, Some(&queued.entry))?;

    let acked = current_envelope("env_keyed_ack", "target_ack_keyed", DeliveryClass::OpaqueEvent);
    let acked_key = envelope_replay_tuple_key(&acked);
    let acked_expires_at = acked.created_at + i64::from(acked.ttl);
    let acked_entry = match router.submit_envelope_at(acked.clone(), acked.created_at + 1) {
        RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
        other => return Err(format!("expected ack queue, got {other:?}").into()),
    };
    store.record_submission_increment(&acked_key, acked_expires_at, Some(&acked_entry))?;
    let cursor = router.apply_ack(&ack("env_keyed_ack"))?;
    store.record_ack_increment(&cursor, "env_keyed_ack")?;

    let lifecycle = router.mvp7_apply_lifecycle_event(&lifecycle_request(
        "principal_keyed",
        "evt_keyed_deactivated",
        "identity.deactivated",
        1,
        1_760_000_100,
        None,
    ))?;
    let tombstone_hash =
        lifecycle.record.tombstone_hash.clone().ok_or("missing keyed tombstone hash")?;
    store.record_lifecycle_record(&lifecycle.record)?;
    store.record_federated_lifecycle_tombstone(
        lifecycle.tombstone.as_ref(),
        "target_fed_keyed",
        &AccountLifecycleState::Deactivated,
    )?;

    let abuse = router.mvp7_submit_abuse_report(&abuse_report("report_keyed"))?;
    store.record_abuse_report(&abuse.report)?;
    drop(store);

    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened
        .load_router()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("router_keyed".to_owned()))?;
    assert!(matches!(
        restored.submit_envelope(envelope(
            "env_online_keyed_after_restart",
            "target_online_keyed",
            DeliveryClass::OpaqueEvent,
        )),
        RouterSubmitOutcome::Online(_)
    ));
    assert_eq!(restored.resume("target_pending_keyed", 0, 10).len(), 1);
    assert_eq!(
        restored.cursor_state("target_ack_keyed").and_then(|cursor| cursor.last_envelope_id),
        Some("env_keyed_ack".to_owned())
    );
    assert!(matches!(
        restored.submit_envelope(envelope(
            "env_after_fed_deactivate",
            "target_fed_keyed",
            DeliveryClass::OpaqueEvent,
        )),
        RouterSubmitOutcome::RejectedDeactivated { .. }
    ));
    assert_eq!(
        restored.mvp7_lifecycle("principal_keyed").map(|record| record.state),
        Some(AccountLifecycleState::Deactivated)
    );
    assert!(restored.mvp7_lifecycle_tombstone_by_hash(&tombstone_hash).is_some());
    assert!(restored.mvp7_abuse_report("report_keyed").is_some());
    assert!(matches!(
        restored.submit_envelope_at(
            envelope("env_keyed_pending", "target_pending_keyed", DeliveryClass::OpaqueEvent),
            1_760_000_003,
        ),
        RouterSubmitOutcome::RejectedSecurity { .. }
    ));
    Ok(())
}

#[test]
fn retention_redb_store_restores_incidents_and_rate_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("retention_redb_store_restores_incidents_and_rate_limits")?;
    let store = RetentionRedbStore::open(&path)?;
    store.report_incident(security_incident("incident_1"))?;
    store.record_rate_limit_abuse(rate_limit_abuse("bucket_1"))?;
    drop(store);

    let reopened = RetentionRedbStore::open(&path)?;
    let state = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("retention_state".to_owned()))?;
    assert_eq!(state.incident_count(), 1);
    assert_eq!(
        state.incident("incident_1").map(|incident| incident.incident_class.as_str()),
        Some("service_auth_failed")
    );
    assert_eq!(
        state.rate_limit_metadata("bucket_1").map(|metadata| metadata.abuse_signal.as_str()),
        Some("deviceproof_rate_limited")
    );
    Ok(())
}

#[test]
fn notify_redb_store_restores_wake_queue() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_redb_store_restores_wake_queue")?;
    let store = NotifyRedbStore::open(&path)?;
    let entry =
        store.queue_wake(notification_wake("wake_1", 60), "push_alias_hash", 1_760_000_000)?;
    assert_eq!(entry.expires_at, 1_760_000_060);
    drop(store);

    let reopened = NotifyRedbStore::open(&path)?;
    let mut state = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("notify_queue".to_owned()))?;
    assert_eq!(state.pending_count(), 1);
    assert_eq!(
        state.entry("wake_1").map(|entry| entry.push_alias_hash.as_str()),
        Some("push_alias_hash")
    );
    assert_eq!(state.drop_expired(1_760_000_061), 1);
    assert_eq!(
        state.entry("wake_1").map(|entry| entry.status.clone()),
        Some(NotifyQueueStatus::DroppedExpired)
    );
    Ok(())
}

#[test]
fn notify_redb_incremental_attempt_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_redb_incremental_attempt_survives_restart")?;
    let store = NotifyRedbStore::open_without_wal(&path)?;
    store.queue_wake(
        notification_wake("wake_incremental_attempt", 60),
        "push_alias_hash",
        1_760_000_000,
    )?;
    store.record_provider_attempt(notify_attempt("wake_incremental_attempt", true))?;
    drop(store);

    let reopened = NotifyRedbStore::open_without_wal(&path)?;
    let state = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("notify_incremental".to_owned()))?;
    let entry = state
        .entry("wake_incremental_attempt")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("wake_incremental_attempt".to_owned()))?;
    assert_eq!(entry.status, NotifyQueueStatus::Delivered);
    assert_eq!(entry.attempt_count, 1);
    assert_eq!(state.provider_attempts("wake_incremental_attempt").len(), 1);
    Ok(())
}

#[test]
fn notify_redb_legacy_snapshot_loads_without_incremental_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_redb_legacy_snapshot_loads_without_incremental_rows")?;
    let store = NotifyRedbStore::open(&path)?;
    let mut state = NotifyQueueState::new();
    state.queue_wake(
        notification_wake("wake_legacy_notify", 120),
        "legacy_push_alias_hash",
        1_760_000_000,
    );
    state.record_provider_attempt(notify_attempt("wake_legacy_notify", false));
    store.save_legacy_state_only(&state)?;
    drop(store);

    let reopened = NotifyRedbStore::open(&path)?;
    let restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("notify_legacy".to_owned()))?;
    assert_eq!(
        restored.entry("wake_legacy_notify").map(|entry| entry.push_alias_hash.as_str()),
        Some("legacy_push_alias_hash")
    );
    assert_eq!(restored.provider_attempts("wake_legacy_notify").len(), 1);
    Ok(())
}

#[test]
fn notify_redb_legacy_json_incremental_rows_load() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_redb_legacy_json_incremental_rows_load")?;
    let store = NotifyRedbStore::open(&path)?;
    let mut state = NotifyQueueState::new();
    let entry = state.queue_wake(
        notification_wake("wake_legacy_json_incremental", 120),
        "legacy_json_push_alias_hash",
        1_760_000_000,
    );
    let attempt = notify_attempt("wake_legacy_json_incremental", false);
    store.save_legacy_json_incremental_entry_and_attempt(&entry, &attempt)?;
    drop(store);

    let reopened = NotifyRedbStore::open(&path)?;
    let restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("notify_legacy_json".to_owned()))?;
    assert_eq!(
        restored.entry("wake_legacy_json_incremental").map(|entry| entry.push_alias_hash.as_str()),
        Some("legacy_json_push_alias_hash")
    );
    assert_eq!(restored.provider_attempts("wake_legacy_json_incremental").len(), 1);
    Ok(())
}

#[test]
fn notify_redb_incremental_routes_and_credentials_survive_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_redb_incremental_routes_and_credentials_survive_restart")?;
    let store = NotifyRedbStore::open(&path)?;
    store.update_provider_credential(notify_webpush_credential("credential_incremental"))?;
    store.register_push_route(notify_webpush_route(
        "device_incremental_notify",
        "credential_incremental",
    ))?;
    drop(store);

    let reopened = NotifyRedbStore::open(&path)?;
    let (entry, pushes) = reopened.queue_wake_for_push(
        "device_incremental_notify",
        &notification_wake("wake_incremental_routes", 60),
        1_760_000_000,
        false,
    )?;
    assert_eq!(entry.queue_id, "wake_incremental_routes");
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].route.device_delivery_id, "device_incremental_notify");
    assert_eq!(pushes[0].credential.credential_id(), "credential_incremental");
    drop(reopened);

    let reopened = NotifyRedbStore::open(&path)?;
    let state = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("notify_routes".to_owned()))?;
    assert_eq!(state.push_routes("device_incremental_notify", 1_760_000_000).len(), 1);
    assert!(state.provider_credential("credential_incremental").is_some());
    Ok(())
}

#[test]
fn notify_wal_store_restores_pending_async_wakes() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_wal_store_restores_pending_async_wakes")?;
    let wal_root = path.with_extension("wal");
    let store = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    let entry = store.queue_wake_for_async_accept(
        "device_notify_wal_restore",
        &notification_wake("wake_notify_wal_restore", 60),
        1_760_000_000,
        false,
    )?;
    assert_eq!(entry.queue_id, "wake_notify_wal_restore");
    drop(store);

    let reopened = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    let pending = reopened.pending_entries_without_attempts(10)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].queue_id, "wake_notify_wal_restore");
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn notify_wal_store_replays_delivered_tombstones() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_wal_store_replays_delivered_tombstones")?;
    let wal_root = path.with_extension("wal");
    let store = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    store.queue_wake_for_async_accept(
        "device_notify_wal_delivered",
        &notification_wake("wake_notify_wal_delivered", 60),
        1_760_000_000,
        false,
    )?;
    store.record_provider_attempt(notify_attempt("wake_notify_wal_delivered", true))?;
    drop(store);

    let reopened = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    assert!(reopened.pending_entries_without_attempts(10)?.is_empty());
    let state = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("notify_wal_delivered".to_owned()))?;
    assert_eq!(state.provider_attempts("wake_notify_wal_delivered").len(), 1);
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn notify_wal_store_restores_raw_async_wakes() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_wal_store_restores_raw_async_wakes")?;
    let wal_root = path.with_extension("wal");
    let store = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    let raw = serde_json::to_vec(&serde_json::json!({
        "device_delivery_id": "device_notify_wal_raw",
        "wake": notification_wake("wake_notify_wal_raw", 60),
        "queued_at": 1_760_000_000_u64,
        "dnd_active": false
    }))?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let raw =
        runtime.block_on(store.queue_raw_wake_for_async_accept_async(raw, now_unix_seconds()))?;
    assert!(raw.queue_id.starts_with("raw_wake_"));
    drop(store);

    let reopened = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    let pending = reopened.pending_entries_without_attempts(10)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].queue_id, raw.queue_id);
    assert_eq!(pending[0].device_delivery_id, "device_notify_wal_raw");
    assert_eq!(pending[0].wake.wake_id, "wake_notify_wal_raw");
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn notify_wal_store_async_accept_uses_server_time_for_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_wal_store_async_accept_uses_server_time_for_expiry")?;
    let wal_root = path.with_extension("wal");
    let store = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    let old_client_queued_at = 1_760_000_000;
    let before = now_unix_seconds();
    let entry = store.queue_wake_for_async_accept(
        "device_notify_wal_server_time",
        &notification_wake("wake_notify_wal_server_time", 60),
        old_client_queued_at,
        false,
    )?;
    assert!(entry.queued_at >= before);
    assert_ne!(entry.queued_at, old_client_queued_at);
    assert_eq!(entry.expires_at, entry.queued_at.saturating_add(60));
    assert!(entry.expires_at > now_unix_seconds());
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn notify_wal_store_prepares_recovered_raw_wake_for_provider_push()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("notify_wal_store_prepares_recovered_raw_wake_for_provider_push")?;
    let wal_root = path.with_extension("wal");
    let store = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    store.update_provider_credential(notify_webpush_credential("credential_raw_recovered"))?;
    let mut route =
        notify_webpush_route("device_notify_wal_raw_recovered", "credential_raw_recovered");
    route.expires_at = 4_102_444_800;
    store.register_push_route(route)?;
    let raw = serde_json::to_vec(&serde_json::json!({
        "device_delivery_id": "device_notify_wal_raw_recovered",
        "wake": notification_wake("wake_notify_wal_raw_recovered", 60),
        "queued_at": 1_760_000_000_u64,
        "dnd_active": false
    }))?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let raw =
        runtime.block_on(store.queue_raw_wake_for_async_accept_async(raw, now_unix_seconds()))?;
    drop(store);

    let reopened = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    let pending = reopened.pending_entries_without_attempts(10)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].queue_id, raw.queue_id);
    assert_eq!(pending[0].device_delivery_id, "device_notify_wal_raw_recovered");
    let pushes = reopened.prepare_provider_pushes_for_entry(&pending[0])?;
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].route.device_delivery_id, "device_notify_wal_raw_recovered");
    assert_eq!(pushes[0].payload.wake_id, "wake_notify_wal_raw_recovered");
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn notify_wal_store_recovers_existing_shards_when_configured_count_shrinks()
-> Result<(), Box<dyn std::error::Error>> {
    let path =
        temp_store_path("notify_wal_store_recovers_existing_shards_when_configured_count_shrinks")?;
    let wal_root = path.with_extension("wal");
    let store = NotifyRedbStore::open_with_wal_shard_count(&path, &wal_root, 4)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    for shard_id in 0..4 {
        let raw = serde_json::to_vec(&serde_json::json!({
            "device_delivery_id": format!("device_notify_wal_shard_{shard_id}"),
            "wake": notification_wake(&format!("wake_notify_wal_shard_{shard_id}"), 60),
            "queued_at": 1_760_000_000_u64 + u64::try_from(shard_id)?,
            "dnd_active": false
        }))?;
        runtime.block_on(store.queue_raw_wake_for_async_accept_shard_async(
            shard_id,
            raw,
            1_760_000_000 + u64::try_from(shard_id)?,
        ))?;
    }
    drop(store);

    let reopened = NotifyRedbStore::open_with_wal_shard_count(&path, &wal_root, 1)?;
    assert_eq!(reopened.notify_ingest_shard_count(), 4);
    let pending = reopened.pending_entries_without_attempts(10)?;
    assert_eq!(pending.len(), 4);
    let wake_ids = pending.iter().map(|entry| entry.wake.wake_id.as_str()).collect::<BTreeSet<_>>();
    assert_eq!(
        wake_ids,
        BTreeSet::from([
            "wake_notify_wal_shard_0",
            "wake_notify_wal_shard_1",
            "wake_notify_wal_shard_2",
            "wake_notify_wal_shard_3"
        ])
    );
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn notify_wal_store_drops_bad_raw_wake_without_repeating() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_store_path("notify_wal_store_drops_bad_raw_wake_without_repeating")?;
    let wal_root = path.with_extension("wal");
    let store = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let raw = runtime.block_on(
        store.queue_raw_wake_for_async_accept_async(b"{\"bad\":true}".to_vec(), 1_760_000_000),
    )?;

    assert!(store.pending_entries_without_attempts(10)?.is_empty());
    assert!(store.pending_entries_without_attempts(10)?.is_empty());
    let state = store
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("notify_raw_attempt".to_owned()))?;
    let attempts = state.provider_attempts(&raw.queue_id);
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].queue_id, raw.queue_id);
    assert!(!attempts[0].accepted);
    drop(store);

    let reopened = NotifyRedbStore::open_with_wal(&path, &wal_root)?;
    assert!(reopened.pending_entries_without_attempts(10)?.is_empty());
    let state = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("notify_raw_attempt_reopen".to_owned()))?;
    assert_eq!(state.provider_attempts(&raw.queue_id).len(), 1);
    let _removed = std::fs::remove_dir_all(wal_root);
    Ok(())
}

#[test]
fn relay_redb_store_restores_encrypted_chunk_cache() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("relay_redb_store_restores_encrypted_chunk_cache")?;
    let store = RelayRedbStore::open(&path)?;
    store.put_chunk(&relay_chunk("chunk_1", 1_760_000_000, 60))?;
    drop(store);

    let reopened = RelayRedbStore::open(&path)?;
    let mut state = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("relay_cache".to_owned()))?;
    let chunk = state
        .get_available_chunk("chunk_1", 1_760_000_010)
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_1".to_owned()))?;
    assert_eq!(chunk.encrypted_chunk, b"encrypted chunk bytes");
    assert_eq!(state.available_count(1_760_000_010), 1);
    assert_eq!(state.expire_chunks(1_760_000_061), 1);
    assert_eq!(state.available_count(1_760_000_061), 0);
    Ok(())
}

#[test]
fn relay_redb_incremental_tombstone_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("relay_redb_incremental_tombstone_survives_restart")?;
    let service_key = b"relay service key for object chunks";
    let now = 1_760_000_000;
    let store = RelayRedbStore::open(&path)?;
    let mut state = RelayCacheState::new();
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    let entry = state.put_object_chunk_frame(frame.clone(), service_key, now)?;
    store.record_relay_chunk_entry(&entry)?;
    let tombstone = ObjectRelayTombstone {
        object_id: frame.object_id.clone(),
        manifest_hash: Some(frame.manifest_hash.clone()),
        tombstone_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay_tombstone.test.v1",
            b"tombstone",
        ),
        source_event_id: "event_tombstone_incremental".to_owned(),
        signed_at: now + 1,
        expires_at: now + OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS,
        relay_token: relay_token(service_key, ObjectRelayCapability::Tombstone, now + 1, false)?,
        object_permission_envelope: object_permission(ObjectRelayCapability::Tombstone, now + 1)?,
    };
    let mutation = state.apply_object_tombstone_mutation(tombstone, service_key, now + 1)?;
    store.record_relay_tombstone_mutation(&mutation)?;
    drop(store);

    let reopened = RelayRedbStore::open(&path)?;
    let restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("relay_incremental_tombstone".to_owned()))?;
    assert!(restored.tombstone("object_relay_1").is_some());
    let chunk = restored
        .chunk_entry("chunk_relay_1")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_relay_1".to_owned()))?;
    assert_eq!(chunk.status, RelayChunkStatus::Tombstoned);
    assert!(chunk.encrypted_chunk.is_empty());
    Ok(())
}

#[test]
fn relay_redb_legacy_snapshot_loads_without_incremental_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("relay_redb_legacy_snapshot_loads_without_incremental_rows")?;
    let store = RelayRedbStore::open(&path)?;
    let mut state = RelayCacheState::new();
    state.put_chunk(relay_chunk("chunk_legacy", 1_760_000_000, 120));
    store.save_legacy_state_only(&state)?;
    drop(store);

    let reopened = RelayRedbStore::open(&path)?;
    let restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("relay_legacy".to_owned()))?;
    let chunk = restored
        .get_available_chunk("chunk_legacy", 1_760_000_010)
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_legacy".to_owned()))?;
    assert_eq!(chunk.encrypted_chunk, b"encrypted chunk bytes");
    Ok(())
}

#[test]
fn relay_redb_expiry_removes_incremental_chunk_key() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("relay_redb_expiry_removes_incremental_chunk_key")?;
    let store = RelayRedbStore::open(&path)?;
    store.put_chunk(&relay_chunk("chunk_expire_incremental", 1_760_000_000, 60))?;
    let mut state = store
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("relay_expire".to_owned()))?;
    let mutation = state.expire_chunks_mutation(1_760_000_061);
    assert_eq!(mutation.expired_chunk_ids, vec!["chunk_expire_incremental".to_owned()]);
    store.record_relay_expiry_mutation(&mutation)?;
    drop(store);

    let reopened = RelayRedbStore::open(&path)?;
    assert!(reopened.load_state()?.is_none());
    Ok(())
}

#[test]
fn object_relay_requires_token_permission_and_hash() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    let mut tampered = frame.clone();
    tampered.encrypted_chunk[0] ^= 0x01;
    assert!(state.put_object_chunk_frame(tampered, service_key, now).is_err());

    let stored = state.put_object_chunk_frame(frame, service_key, now)?;
    assert_eq!(stored.encrypted_chunk, b"opaque encrypted relay chunk");
    assert!(!stored.encrypted_chunk.windows(9).any(|window| window == b"plaintext"));

    let get_token = relay_token(service_key, ObjectRelayCapability::Get, now, false)?;
    let get_permission = object_permission(ObjectRelayCapability::Get, now)?;
    let fetched =
        state.get_object_chunk("chunk_relay_1", &get_token, &get_permission, service_key, now)?;
    assert_eq!(fetched.chunk_cipher_hash, stored.chunk_cipher_hash);

    let mut forged_token = get_token.clone();
    forged_token.recipient_device_hash = "wrong_device_hash".to_owned();
    assert!(
        state
            .get_object_chunk("chunk_relay_1", &forged_token, &get_permission, service_key, now)
            .is_err()
    );
    let forged_permission =
        object_permission_with_seed(ObjectRelayCapability::Get, now, [0x42; 32], "forged_owner")?;
    assert!(
        state
            .get_object_chunk("chunk_relay_1", &get_token, &forged_permission, service_key, now)
            .is_err(),
        "permission signed by a key not bound into the relay token was accepted"
    );
    Ok(())
}

#[test]
fn object_relay_ack_deletes_before_ttl_and_tombstone_wins() -> Result<(), Box<dyn std::error::Error>>
{
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, true)?;
    state.put_object_chunk_frame(frame.clone(), service_key, now)?;

    let ack = ObjectRelayAck {
        object_id: frame.object_id.clone(),
        manifest_hash: frame.manifest_hash.clone(),
        chunk_id: frame.chunk_id.clone(),
        recipient_device_hash: frame.relay_token.recipient_device_hash.clone(),
        relay_token: relay_token(service_key, ObjectRelayCapability::Ack, now, true)?,
        object_permission_envelope: object_permission(ObjectRelayCapability::Ack, now)?,
        acked_at: now + 1,
    };
    let acked = state.ack_object_chunk(ack, service_key, now + 1)?;
    assert_eq!(acked.status, RelayChunkStatus::AckedDeleted);
    assert!(acked.encrypted_chunk.is_empty());
    assert!(state.get_available_chunk("chunk_relay_1", now + 2).is_none());

    let next_frame = relay_object_frame_with_chunk(
        service_key,
        ObjectRelayCapability::Put,
        now + 2,
        "chunk_relay_2",
        false,
    )?;
    state.put_object_chunk_frame(next_frame.clone(), service_key, now + 2)?;
    let tombstone = ObjectRelayTombstone {
        object_id: next_frame.object_id.clone(),
        manifest_hash: Some(next_frame.manifest_hash.clone()),
        tombstone_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay_tombstone.test.v1",
            b"tombstone",
        ),
        source_event_id: "event_tombstone_1".to_owned(),
        signed_at: now + 3,
        expires_at: now + OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS,
        relay_token: relay_token(service_key, ObjectRelayCapability::Tombstone, now + 3, false)?,
        object_permission_envelope: object_permission(ObjectRelayCapability::Tombstone, now + 3)?,
    };
    state.apply_object_tombstone(tombstone, service_key, now + 3)?;
    assert!(state.tombstone("object_relay_1").is_some());
    assert!(state.get_available_chunk("chunk_relay_2", now + 4).is_none());

    let blocked = relay_object_frame_with_chunk(
        service_key,
        ObjectRelayCapability::Put,
        now + 4,
        "chunk_relay_3",
        false,
    )?;
    assert!(state.put_object_chunk_frame(blocked, service_key, now + 4).is_err());
    Ok(())
}

#[test]
fn object_relay_expire_chunks_removes_expired_entries() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let mut frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    frame.expires_at = now + 1;
    state.put_object_chunk_frame(frame, service_key, now)?;
    assert_eq!(state.expire_chunks(now + 2), 1);
    assert_eq!(state.available_count(now + 2), 0);
    Ok(())
}

#[test]
fn object_relay_caps_long_chunk_ttl_and_expires() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let mut frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    let requested_expires_at = now + OBJECT_RELAY_CHUNK_MAX_TTL_SECONDS + 3_600;
    set_relay_frame_expires_at(&mut frame, service_key, requested_expires_at)?;

    let entry = state.put_object_chunk_frame(frame, service_key, now)?;
    let capped_expires_at = now + OBJECT_RELAY_CHUNK_MAX_TTL_SECONDS;
    assert_eq!(entry.expires_at, capped_expires_at);
    assert_eq!(object_relay_retention_record(&entry, now).expires_at, capped_expires_at);
    assert!(state.get_available_chunk("chunk_relay_1", capped_expires_at - 1).is_some());

    assert_eq!(state.expire_chunks(capped_expires_at), 1);
    assert!(state.get_available_chunk("chunk_relay_1", capped_expires_at).is_none());
    Ok(())
}

#[test]
fn object_relay_chunk_ttl_cap_helper_honors_configured_max() {
    let now = 1_760_000_000;
    let requested_expires_at = now + OBJECT_RELAY_CHUNK_MAX_TTL_SECONDS;
    assert_eq!(clamp_relay_chunk_expires_at_with_max_ttl(now, requested_expires_at, 60), now + 60);
}

const DEVICE_B_OWNER_SEED: [u8; 32] = [0x42; 32];
const DEVICE_B_OWNER_KEY_ID: &str = "device_b_owner";

// RQ-03 fix A: an exact same-owner, same-content re-put must be idempotent and return the stored
// entry unchanged. Fields that accrue after the first put (acked_by, stored_at, expires_at, delete
// policy, status) must never be reset by a replay.
#[test]
fn object_relay_put_replay_is_idempotent_and_preserves_state()
-> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    state.put_object_chunk_frame(frame.clone(), service_key, now)?;

    // Advance the stored entry's state (records an ack) so a reset would be observable.
    let ack = ObjectRelayAck {
        object_id: "object_relay_1".to_owned(),
        manifest_hash: "manifest_relay_1".to_owned(),
        chunk_id: "chunk_relay_1".to_owned(),
        recipient_device_hash: "recipient_device_hash_1".to_owned(),
        relay_token: relay_token(service_key, ObjectRelayCapability::Ack, now, false)?,
        object_permission_envelope: object_permission(ObjectRelayCapability::Ack, now)?,
        acked_at: now + 1,
    };
    state.ack_object_chunk(ack, service_key, now + 1)?;
    let before = state
        .chunk_entry("chunk_relay_1")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_relay_1".to_owned()))?
        .clone();
    assert!(before.acked_by.contains("recipient_device_hash_1"));
    assert_eq!(before.stored_at, now);

    // Replay the identical frame later (still within the token TTL): it must return the stored
    // entry verbatim and mutate nothing (stored_at not bumped to now + 100, acked_by not cleared).
    let replay = state.put_object_chunk_frame(frame, service_key, now + 100)?;
    assert_eq!(replay, before, "idempotent replay must return the stored entry unchanged");
    let after = state
        .chunk_entry("chunk_relay_1")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_relay_1".to_owned()))?;
    assert_eq!(after, &before, "idempotent replay must not mutate the stored entry");
    Ok(())
}

// A foreign owner cannot overwrite an existing chunk id, and even the original owner cannot silently
// replace the stored ciphertext with different content under the same chunk id.
#[test]
fn object_relay_put_rejects_cross_owner_and_content_overwrite()
-> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    state.put_object_chunk_frame(frame, service_key, now)?;

    // Device B cannot overwrite A's chunk id.
    let foreign_frame = relay_object_frame_for_owner(
        service_key,
        now + 2,
        "chunk_relay_1",
        DEVICE_B_OWNER_KEY_ID,
        DEVICE_B_OWNER_SEED,
    )?;
    let cross_owner = state.put_object_chunk_frame(foreign_frame, service_key, now + 2);
    assert!(
        matches!(cross_owner, Err(NodeCoreError::Unauthorized(_))),
        "cross-owner overwrite should be rejected, got {cross_owner:?}"
    );

    // Even the original owner cannot silently replace the ciphertext with different content under
    // the same chunk id.
    let mut overwrite =
        relay_object_frame(service_key, ObjectRelayCapability::Put, now + 3, false)?;
    let tampered_chunk = b"different opaque ciphertext!!".to_vec();
    overwrite.chunk_cipher_hash =
        object_relay_chunk_cipher_hash("manifest_relay_1", 0, &tampered_chunk);
    overwrite.cipher_size = tampered_chunk.len() as u64;
    overwrite.encrypted_chunk = tampered_chunk;
    let content_overwrite = state.put_object_chunk_frame(overwrite, service_key, now + 3);
    assert!(
        matches!(content_overwrite, Err(NodeCoreError::Unauthorized(_))),
        "content overwrite should be rejected, got {content_overwrite:?}"
    );

    // The original ciphertext is intact after the rejected writes.
    let stored = state
        .chunk_entry("chunk_relay_1")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_relay_1".to_owned()))?;
    assert_eq!(stored.encrypted_chunk, b"opaque encrypted relay chunk");
    assert_eq!(stored.owner_signing_key_id, "owner_fixture_key");
    Ok(())
}

// A record persisted before owner binding existed (no owner fields) deserializes with an empty
// binding and must be immutable: no one can overwrite it, fail closed.
#[test]
fn object_relay_legacy_unbound_chunk_rejects_overwrite() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();

    // Build a legacy record by stripping the owner-binding fields from a modern chunk.
    let bound = relay_chunk("chunk_relay_1", now, OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS);
    let mut value = serde_json::to_value(&bound)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| NodeCoreError::ItestJson("relay chunk is not a json object".to_owned()))?;
    object.remove("owner_signing_key_id");
    object.remove("owner_public_key");
    let legacy: RelayChunkEntry = serde_json::from_value(value)?;
    assert!(!legacy.has_owner_binding());
    state.put_chunk(legacy);

    // A well-formed put for the same chunk id cannot overwrite the unbound legacy record.
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    let overwrite = state.put_object_chunk_frame(frame, service_key, now);
    assert!(
        matches!(overwrite, Err(NodeCoreError::Unauthorized(_))),
        "legacy unbound chunk must not be overwritable, got {overwrite:?}"
    );
    Ok(())
}

// RQ-03 invariant 4: deletion on ack is governed only by the delete policy the owner stored at put
// time; an ack token flipping delete_after_ack cannot self-elevate to delete the chunk.
#[test]
fn object_relay_ack_ignores_token_delete_after_ack_elevation()
-> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    // Owner stored the chunk with delete_after_ack = false.
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    state.put_object_chunk_frame(frame, service_key, now)?;

    // An ack whose token sets delete_after_ack = true must NOT delete the chunk.
    let elevating_ack = ObjectRelayAck {
        object_id: "object_relay_1".to_owned(),
        manifest_hash: "manifest_relay_1".to_owned(),
        chunk_id: "chunk_relay_1".to_owned(),
        recipient_device_hash: "recipient_device_hash_1".to_owned(),
        relay_token: relay_token(service_key, ObjectRelayCapability::Ack, now, true)?,
        object_permission_envelope: object_permission(ObjectRelayCapability::Ack, now)?,
        acked_at: now + 1,
    };
    let acked = state.ack_object_chunk(elevating_ack, service_key, now + 1)?;
    assert_eq!(acked.status, RelayChunkStatus::Available);
    assert_eq!(acked.encrypted_chunk, b"opaque encrypted relay chunk");
    Ok(())
}

// A foreign owner cannot tombstone (delete) A's chunk; the rejected request leaves no tombstone
// and does not clear the ciphertext.
#[test]
fn object_relay_tombstone_rejects_cross_owner() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    state.put_object_chunk_frame(frame, service_key, now)?;

    let tombstone = ObjectRelayTombstone {
        object_id: "object_relay_1".to_owned(),
        manifest_hash: Some("manifest_relay_1".to_owned()),
        tombstone_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay_tombstone.test.v1",
            b"foreign-tombstone",
        ),
        source_event_id: "event_tombstone_foreign".to_owned(),
        signed_at: now + 1,
        expires_at: now + OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS,
        relay_token: relay_token_with_owner(
            service_key,
            ObjectRelayCapability::Tombstone,
            now + 1,
            "chunk_relay_1",
            DEVICE_B_OWNER_KEY_ID,
            DEVICE_B_OWNER_SEED,
        )?,
        object_permission_envelope: object_permission_with_seed(
            ObjectRelayCapability::Tombstone,
            now + 1,
            DEVICE_B_OWNER_SEED,
            DEVICE_B_OWNER_KEY_ID,
        )?,
    };
    let result = state.apply_object_tombstone_mutation(tombstone, service_key, now + 1);
    assert!(
        matches!(result, Err(NodeCoreError::Unauthorized(_))),
        "cross-owner tombstone should be rejected, got {result:?}"
    );
    // No tombstone recorded and ciphertext untouched.
    assert!(state.tombstone("object_relay_1").is_none());
    let chunk = state
        .chunk_entry("chunk_relay_1")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_relay_1".to_owned()))?;
    assert_eq!(chunk.status, RelayChunkStatus::Available);
    assert_eq!(chunk.encrypted_chunk, b"opaque encrypted relay chunk");
    Ok(())
}

// RQ-03 fix B: with no object-owner registry, a tombstone that matches zero stored chunks cannot
// prove object ownership and must fail closed without recording an object-level tombstone. This
// blocks any device from pre-placing a tombstone to deny a future legitimate owner's puts.
#[test]
fn object_relay_tombstone_rejects_empty_scope() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();

    // No chunk was ever put for object_relay_1.
    let tombstone = ObjectRelayTombstone {
        object_id: "object_relay_1".to_owned(),
        manifest_hash: Some("manifest_relay_1".to_owned()),
        tombstone_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay_tombstone.test.v1",
            b"empty-scope-tombstone",
        ),
        source_event_id: "event_tombstone_empty".to_owned(),
        signed_at: now + 1,
        expires_at: now + OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS,
        relay_token: relay_token(service_key, ObjectRelayCapability::Tombstone, now + 1, false)?,
        object_permission_envelope: object_permission(ObjectRelayCapability::Tombstone, now + 1)?,
    };
    let result = state.apply_object_tombstone_mutation(tombstone, service_key, now + 1);
    assert!(
        matches!(result, Err(NodeCoreError::Unauthorized(_))),
        "empty-scope tombstone should be rejected, got {result:?}"
    );
    assert!(state.tombstone("object_relay_1").is_none());
    Ok(())
}

// RQ-03-AB2 fix: a semantically identical tombstone replay returns the stored record with zero
// mutation — every field equal, retention expiry never recomputed/extended, affected chunks empty,
// changed=false.
#[test]
fn object_relay_tombstone_replay_is_idempotent_zero_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    state.put_object_chunk_frame(frame, service_key, now)?;

    let expires_at = now + OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS;
    let first = state.apply_object_tombstone_mutation(
        fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, expires_at)?,
        service_key,
        now + 1,
    )?;
    assert!(first.changed, "first tombstone must be a durable change");
    assert_eq!(first.affected_chunks.len(), 1);

    let stored_tombstone = state
        .tombstone("object_relay_1")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("object_relay_1".to_owned()))?
        .clone();
    let stored_chunk = state
        .chunk_entry("chunk_relay_1")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_relay_1".to_owned()))?
        .clone();

    // Replay the identical tombstone much later (still within token TTL): zero-mutation no-op.
    let replay = state.apply_object_tombstone_mutation(
        fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, expires_at)?,
        service_key,
        now + 300,
    )?;
    assert!(!replay.changed, "stable replay must report changed=false");
    assert!(replay.affected_chunks.is_empty(), "stable replay must not touch chunks");
    assert_eq!(replay.tombstone, stored_tombstone, "replay returns the stored record verbatim");
    assert_eq!(replay.tombstone.expires_at, expires_at, "expiry must not be recomputed/extended");
    assert_eq!(state.tombstone("object_relay_1"), Some(&stored_tombstone));
    assert_eq!(state.chunk_entry("chunk_relay_1"), Some(&stored_chunk));
    Ok(())
}

// Any field/owner/scope/expiry change on a repeat tombstone for the same object id is rejected and
// leaves the stored record untouched.
#[test]
fn object_relay_tombstone_rejects_changed_replay() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";
    let mut state = RelayCacheState::new();
    let frame = relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?;
    state.put_object_chunk_frame(frame, service_key, now)?;

    let expires_at = now + OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS;
    state.apply_object_tombstone_mutation(
        fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, expires_at)?,
        service_key,
        now + 1,
    )?;
    let stored = state
        .tombstone("object_relay_1")
        .ok_or_else(|| NodeCoreError::EnvelopeNotFound("object_relay_1".to_owned()))?
        .clone();

    // Different tombstone_hash / source_event_id / signed_at / expiry(extension) / scope: all reject.
    let diff_hash = fixture_tombstone(service_key, now, "hash-b", "event-a", now + 1, expires_at)?;
    let diff_source =
        fixture_tombstone(service_key, now, "hash-a", "event-b", now + 1, expires_at)?;
    let diff_signed =
        fixture_tombstone(service_key, now, "hash-a", "event-a", now + 2, expires_at)?;
    let diff_expiry =
        fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, expires_at + 100)?;
    let mut diff_scope =
        fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, expires_at)?;
    diff_scope.manifest_hash = None;

    for (label, request) in [
        ("hash", diff_hash),
        ("source", diff_source),
        ("signed_at", diff_signed),
        ("expiry", diff_expiry),
        ("scope", diff_scope),
    ] {
        let result = state.apply_object_tombstone_mutation(request, service_key, now + 2);
        assert!(
            matches!(result, Err(NodeCoreError::Unauthorized(_))),
            "changed tombstone replay ({label}) should be rejected, got {result:?}"
        );
    }
    // Stored record untouched (expiry not extended).
    assert_eq!(state.tombstone("object_relay_1"), Some(&stored));
    Ok(())
}

// A stable replay must make record_relay_tombstone_mutation a complete no-op: after the first
// durable write, replaying and re-recording leaves the persisted redb rows byte-identical.
#[test]
fn object_relay_tombstone_redb_replay_no_rewrite() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("object_relay_tombstone_redb_replay_no_rewrite")?;
    let service_key = b"relay service key for object chunks";
    let now = 1_760_000_000;
    let expires_at = now + OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS;

    let store = RelayRedbStore::open(&path)?;
    let mut state = RelayCacheState::new();
    let entry = state.put_object_chunk_frame(
        relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?,
        service_key,
        now,
    )?;
    store.record_relay_chunk_entry(&entry)?;
    let first = state.apply_object_tombstone_mutation(
        fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, expires_at)?,
        service_key,
        now + 1,
    )?;
    assert!(first.changed);
    store.record_relay_tombstone_mutation(&first)?;
    drop(store);

    let baseline = RelayRedbStore::open(&path)?
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("relay_tombstone_baseline".to_owned()))?;

    // Replay stable tombstone -> changed=false -> record must not rewrite redb.
    let store2 = RelayRedbStore::open(&path)?;
    let mut state2 = store2
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("relay_tombstone_reload".to_owned()))?;
    let replay = state2.apply_object_tombstone_mutation(
        fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, expires_at)?,
        service_key,
        now + 300,
    )?;
    assert!(!replay.changed);
    store2.record_relay_tombstone_mutation(&replay)?;
    drop(store2);

    let after = RelayRedbStore::open(&path)?
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("relay_tombstone_after".to_owned()))?;
    assert_eq!(after.tombstone("object_relay_1"), baseline.tombstone("object_relay_1"));
    assert_eq!(after.chunk_entry("chunk_relay_1"), baseline.chunk_entry("chunk_relay_1"));
    let _ = std::fs::remove_file(path);
    Ok(())
}

// RQ-03-AB2: tombstone retention TTL is fail-closed (no clamp/default). An expired or over-max
// expiry is rejected before any mutation, and the accepted boundary value is stored unchanged so an
// identical replay matches.
#[test]
fn object_relay_tombstone_ttl_is_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_760_000_000;
    let service_key = b"relay service key for object chunks";

    // expires_at <= now: rejected, no mutation.
    {
        let mut state = RelayCacheState::new();
        state.put_object_chunk_frame(
            relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?,
            service_key,
            now,
        )?;
        let expired = fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, now)?;
        let result = state.apply_object_tombstone_mutation(expired, service_key, now);
        assert!(
            matches!(result, Err(NodeCoreError::TtlExpired { .. })),
            "expired tombstone expiry should be rejected, got {result:?}"
        );
        assert!(state.tombstone("object_relay_1").is_none());
        let chunk = state
            .chunk_entry("chunk_relay_1")
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_relay_1".to_owned()))?;
        assert_eq!(chunk.status, RelayChunkStatus::Available);
        assert_eq!(chunk.encrypted_chunk, b"opaque encrypted relay chunk");
    }

    // expires_at > now + MAX: rejected, no mutation.
    {
        let mut state = RelayCacheState::new();
        state.put_object_chunk_frame(
            relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?,
            service_key,
            now,
        )?;
        let over_max = fixture_tombstone(
            service_key,
            now,
            "hash-a",
            "event-a",
            now + 1,
            now + OBJECT_RELAY_TOMBSTONE_MAX_TTL_SECONDS + 1,
        )?;
        let result = state.apply_object_tombstone_mutation(over_max, service_key, now);
        assert!(
            matches!(result, Err(NodeCoreError::TtlExpired { .. })),
            "over-max tombstone expiry should be rejected, got {result:?}"
        );
        assert!(state.tombstone("object_relay_1").is_none());
        let chunk = state
            .chunk_entry("chunk_relay_1")
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound("chunk_relay_1".to_owned()))?;
        assert_eq!(chunk.status, RelayChunkStatus::Available);
    }

    // expires_at == now + MAX (boundary): accepted and stored unchanged; identical replay is a
    // zero-mutation no-op with the same expiry.
    {
        let mut state = RelayCacheState::new();
        state.put_object_chunk_frame(
            relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?,
            service_key,
            now,
        )?;
        let max_expiry = now + OBJECT_RELAY_TOMBSTONE_MAX_TTL_SECONDS;
        let first = state.apply_object_tombstone_mutation(
            fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, max_expiry)?,
            service_key,
            now,
        )?;
        assert!(first.changed);
        assert_eq!(first.tombstone.expires_at, max_expiry, "boundary expiry stored unchanged");

        let replay = state.apply_object_tombstone_mutation(
            fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, max_expiry)?,
            service_key,
            now + 300,
        )?;
        assert!(!replay.changed, "identical replay of a boundary tombstone must be a no-op");
        assert_eq!(replay.tombstone.expires_at, max_expiry, "expiry must not change on replay");
    }

    // A stored short-lived tombstone cannot be replayed successfully after its retention expiry,
    // even while the operation token and permission are still valid.
    {
        let mut state = RelayCacheState::new();
        state.put_object_chunk_frame(
            relay_object_frame(service_key, ObjectRelayCapability::Put, now, false)?,
            service_key,
            now,
        )?;
        let short_expiry = now + 10;
        state.apply_object_tombstone_mutation(
            fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, short_expiry)?,
            service_key,
            now + 1,
        )?;
        let replay = state.apply_object_tombstone_mutation(
            fixture_tombstone(service_key, now, "hash-a", "event-a", now + 1, short_expiry)?,
            service_key,
            now + 11,
        );
        assert!(
            matches!(replay, Err(NodeCoreError::TtlExpired { .. })),
            "expired stored tombstone replay should be rejected, got {replay:?}"
        );
        assert_eq!(
            state.tombstone("object_relay_1").map(|item| item.expires_at),
            Some(short_expiry)
        );
    }
    Ok(())
}

fn fixture_tombstone(
    service_key: &[u8],
    now: u64,
    tombstone_hash: &str,
    source_event_id: &str,
    signed_at: u64,
    expires_at: u64,
) -> Result<ObjectRelayTombstone, Box<dyn std::error::Error>> {
    Ok(ObjectRelayTombstone {
        object_id: "object_relay_1".to_owned(),
        manifest_hash: Some("manifest_relay_1".to_owned()),
        tombstone_hash: tombstone_hash.to_owned(),
        source_event_id: source_event_id.to_owned(),
        signed_at,
        expires_at,
        relay_token: relay_token(service_key, ObjectRelayCapability::Tombstone, now, false)?,
        object_permission_envelope: object_permission(ObjectRelayCapability::Tombstone, now)?,
    })
}

fn relay_object_frame(
    service_key: &[u8],
    capability: ObjectRelayCapability,
    now: u64,
    delete_after_ack: bool,
) -> Result<ObjectChunkFrame, Box<dyn std::error::Error>> {
    relay_object_frame_with_chunk(service_key, capability, now, "chunk_relay_1", delete_after_ack)
}

fn relay_object_frame_for_owner(
    service_key: &[u8],
    now: u64,
    chunk_id: &str,
    owner_signing_key_id: &str,
    owner_seed: [u8; 32],
) -> Result<ObjectChunkFrame, Box<dyn std::error::Error>> {
    let encrypted_chunk = b"opaque encrypted relay chunk".to_vec();
    Ok(ObjectChunkFrame {
        schema: "ramflux.object_chunk_frame.v1".to_owned(),
        object_id: "object_relay_1".to_owned(),
        manifest_hash: "manifest_relay_1".to_owned(),
        chunk_index: 0,
        chunk_id: chunk_id.to_owned(),
        chunk_cipher_hash: object_relay_chunk_cipher_hash("manifest_relay_1", 0, &encrypted_chunk),
        cipher_size: encrypted_chunk.len() as u64,
        encrypted_chunk,
        relay_token: relay_token_with_owner(
            service_key,
            ObjectRelayCapability::Put,
            now,
            chunk_id,
            owner_signing_key_id,
            owner_seed,
        )?,
        object_permission_envelope: object_permission_with_seed(
            ObjectRelayCapability::Put,
            now,
            owner_seed,
            owner_signing_key_id,
        )?,
        expires_at: now + OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        delete_after_ack: false,
    })
}

fn relay_token_with_owner(
    service_key: &[u8],
    capability: ObjectRelayCapability,
    now: u64,
    chunk_id: &str,
    owner_signing_key_id: &str,
    owner_seed: [u8; 32],
) -> Result<RelayToken, Box<dyn std::error::Error>> {
    let mut token = RelayToken {
        token_version: OBJECT_RELAY_TOKEN_VERSION,
        token_id: format!("token_{chunk_id}_{capability:?}_{owner_signing_key_id}"),
        object_id: "object_relay_1".to_owned(),
        manifest_hash: "manifest_relay_1".to_owned(),
        chunk_id: chunk_id.to_owned(),
        recipient_device_hash: "recipient_device_hash_1".to_owned(),
        owner_signing_key_id: owner_signing_key_id.to_owned(),
        owner_public_key: ramflux_crypto::public_key_base64url_from_seed(owner_seed),
        issuer_service: OBJECT_RELAY_TOKEN_ISSUER_GATEWAY.to_owned(),
        audience_service: OBJECT_RELAY_TOKEN_AUDIENCE_RELAY.to_owned(),
        capabilities: vec![capability],
        delete_after_ack: false,
        issued_at: now,
        expires_at: now + OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        nonce: format!("nonce_{owner_signing_key_id}"),
        mac: String::new(),
    };
    token.mac = relay_token_mac(service_key, &token)?;
    Ok(token)
}

fn relay_object_frame_with_chunk(
    service_key: &[u8],
    capability: ObjectRelayCapability,
    now: u64,
    chunk_id: &str,
    delete_after_ack: bool,
) -> Result<ObjectChunkFrame, Box<dyn std::error::Error>> {
    let encrypted_chunk = b"opaque encrypted relay chunk".to_vec();
    Ok(ObjectChunkFrame {
        schema: "ramflux.object_chunk_frame.v1".to_owned(),
        object_id: "object_relay_1".to_owned(),
        manifest_hash: "manifest_relay_1".to_owned(),
        chunk_index: 0,
        chunk_id: chunk_id.to_owned(),
        chunk_cipher_hash: object_relay_chunk_cipher_hash("manifest_relay_1", 0, &encrypted_chunk),
        cipher_size: encrypted_chunk.len() as u64,
        encrypted_chunk,
        relay_token: relay_token_for_chunk(
            service_key,
            capability,
            now,
            chunk_id,
            delete_after_ack,
        )?,
        object_permission_envelope: object_permission(capability, now)?,
        expires_at: now + OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        delete_after_ack,
    })
}

fn set_relay_frame_expires_at(
    frame: &mut ObjectChunkFrame,
    service_key: &[u8],
    expires_at: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    frame.expires_at = expires_at;
    frame.relay_token.expires_at = expires_at;
    frame.relay_token.mac = relay_token_mac(service_key, &frame.relay_token)?;
    frame.object_permission_envelope.expires_at = expires_at;
    frame.object_permission_envelope.owner_signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(
            &object_permission_canonical_bytes(&frame.object_permission_envelope)?,
            ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
        );
    Ok(())
}

fn relay_token(
    service_key: &[u8],
    capability: ObjectRelayCapability,
    now: u64,
    delete_after_ack: bool,
) -> Result<RelayToken, Box<dyn std::error::Error>> {
    relay_token_for_chunk(service_key, capability, now, "chunk_relay_1", delete_after_ack)
}

fn relay_token_for_chunk(
    service_key: &[u8],
    capability: ObjectRelayCapability,
    now: u64,
    chunk_id: &str,
    delete_after_ack: bool,
) -> Result<RelayToken, Box<dyn std::error::Error>> {
    let mut token = RelayToken {
        token_version: OBJECT_RELAY_TOKEN_VERSION,
        token_id: format!("token_{chunk_id}_{capability:?}"),
        object_id: "object_relay_1".to_owned(),
        manifest_hash: "manifest_relay_1".to_owned(),
        chunk_id: chunk_id.to_owned(),
        recipient_device_hash: "recipient_device_hash_1".to_owned(),
        owner_signing_key_id: "owner_fixture_key".to_owned(),
        owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
        issuer_service: OBJECT_RELAY_TOKEN_ISSUER_GATEWAY.to_owned(),
        audience_service: OBJECT_RELAY_TOKEN_AUDIENCE_RELAY.to_owned(),
        capabilities: vec![capability],
        delete_after_ack,
        issued_at: now,
        expires_at: now + OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        nonce: "nonce_relay_1".to_owned(),
        mac: String::new(),
    };
    token.mac = relay_token_mac(service_key, &token)?;
    Ok(token)
}

fn object_permission(
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<ObjectPermissionEnvelope, Box<dyn std::error::Error>> {
    object_permission_with_seed(
        capability,
        now,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
        "owner_fixture_key",
    )
}

fn object_permission_with_seed(
    capability: ObjectRelayCapability,
    now: u64,
    seed: [u8; 32],
    signing_key_id: &str,
) -> Result<ObjectPermissionEnvelope, Box<dyn std::error::Error>> {
    let mut permission = ObjectPermissionEnvelope {
        object_id: "object_relay_1".to_owned(),
        manifest_hash: "manifest_relay_1".to_owned(),
        grantee_device_hash: "recipient_device_hash_1".to_owned(),
        capability,
        issued_at: now,
        expires_at: now + OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        owner_signing_key_id: signing_key_id.to_owned(),
        owner_public_key: ramflux_crypto::public_key_base64url_from_seed(seed),
        owner_signature: String::new(),
    };
    permission.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &object_permission_canonical_bytes(&permission)?,
        seed,
    );
    Ok(permission)
}
