// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retained outbound retries are independent of migrated-source client admission.
use super::*;

#[test]
fn outbound_spool_accepted_before_commit_still_delivers_without_extra_hop()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::temp_dir().join(format!(
        "rf-outbound-migration-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    std::fs::create_dir(&directory)?;
    let spool_path = directory.join("federation.redb");
    let router_path = directory.join("router.redb");
    let store = ramflux_node_core::FederationRedbStore::open(&spool_path)?;
    let router = ramflux_node_core::RouterRedbStore::open(&router_path)?;
    let core = ramflux_node_core::RouterCore::new();
    let retained = inbound_handler_request()?;
    let source = core.authenticated_envelope_source_from(
        &retained.envelope,
        Some(&router),
        ramflux_node_core::RouterEnvelopeOrigin::Federation,
    )?;
    // Positive admission before cutover; enqueue an already accepted outbound send.
    drop(router.acquire_home_operation(source.root_commitment())?);
    store.spool_outbound_forward(&retained.target_node_id, &retained, 100, 1000)?;
    drop(router);
    // Install the same durable source-gate shape used by the router submit fixture.
    // This test covers spool retry across that gate, not the migration commit protocol.
    {
        let db = redb::Database::create(&router_path)?;
        let tx = db.begin_write()?;
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("home_root_gates_v1"))?.insert(
            source.root_commitment(),
            serde_json::to_vec(&ramflux_protocol::home_migration::Refusal::HomeMigrated)?
                .as_slice(),
        )?;
        tx.commit()?;
    }
    let router = ramflux_node_core::RouterRedbStore::open(&router_path)?;
    assert!(matches!(
        router.acquire_home_operation(source.root_commitment()),
        Err(ramflux_node_core::NodeCoreError::HomeMigration(
            ramflux_protocol::home_migration::Refusal::HomeMigrated
        ))
    ));
    drop(store);
    let store = ramflux_node_core::FederationRedbStore::open(&spool_path)?;
    let mut trust = ramflux_node_core::FederationTrustState::new();
    trust.set_node_signing_seed([9; 32]);
    let trust = crate::SharedFederationTrustState::new(trust);
    let mut attempts = 0;
    retry_outbound_spool_with(&store, 101, 64, |entry| {
        attempts += 1;
        assert_eq!(entry.forward, retained);
        let forward = refresh_spooled_forward(&entry.forward, &trust, |envelope| {
            // The production authority-refresh endpoint uses Federation origin;
            // already accepted sends must not reacquire Gateway source admission.
            core.authenticated_envelope_source_from(
                envelope,
                Some(&router),
                ramflux_node_core::RouterEnvelopeOrigin::Federation,
            )?;
            core.refresh_registered_envelope_authority(envelope)
        })?;
        assert_eq!(forward.target_node_id, retained.target_node_id);
        assert_eq!(forward.source_node_id, retained.source_node_id);
        assert_eq!(forward.envelope, retained.envelope);
        assert!(forward.migration_evidence.is_none());
        assert!(!forward.envelope.ext.ext.contains_key("home_node_migration_forward_count"));
        ramflux_node_core::verify_federated_envelope_forward(
            &forward,
            &ramflux_crypto::public_key_base64url_from_seed([9; 32]),
        )?;
        // Peer delivery is injected at the existing spool transport seam.
        Ok("offline_queued".into())
    })?;
    assert_eq!(attempts, 1);
    assert_eq!(store.list_pending_outbound(64)?, []);
    assert_eq!(store.outbound_dead_letter_count()?, 0);
    drop(store);
    let store = ramflux_node_core::FederationRedbStore::open(&spool_path)?;
    assert_eq!(store.list_pending_outbound(64)?, []);
    drop(store);
    drop(router);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
