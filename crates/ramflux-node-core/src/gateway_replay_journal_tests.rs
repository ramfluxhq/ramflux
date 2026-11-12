// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Expiry renewal must survive both obsolete-index cleanup and an ordinary reopen.
use super::*;

fn request(index: usize, expires_at: i64) -> ramflux_protocol::SignedRequest {
    ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".into(),
        version: 1,
        domain: "ramflux.signed_request.v1".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "device".into(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "fixture-signature-already-validated".into(),
        },
        source_device_id: "device".into(),
        request_id: format!("request-{index}"),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/gateway/session/auth".into(),
        device_proof_hash: "bound".into(),
        body_hash: "bound".into(),
        nonce: format!("nonce-{index}"),
        created_at: 0,
        expires_at,
    }
}

fn renewal_case(inject_obsolete_index: bool) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "gateway-renewed-replay-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let root = ramflux_crypto::create_identity_root("owner", [41; 32]);
    let branch = ramflux_crypto::create_device_branch("owner", "device", 1, [42; 32]);
    let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
    let mut requests: Vec<_> = (0..130).map(|index| request(index, 100)).collect();
    requests.sort_by_cached_key(|request| request.replay_tuple_key(&source).unwrap_or_default());
    let mut renewed = requests.get(100).ok_or("renewal tuple")?.clone();
    renewed.created_at = 101;
    renewed.expires_at = 1000;
    let key = renewed.replay_tuple_key(&source)?;
    {
        let store = GatewayRedbStore::open(&path)?;
        store.configure_replay(crate::GatewayReplayConfig::small_node(), 0)?;
        for request in &requests {
            store.save_auth_replay(&source, request, 0)?;
        }
        store.save_auth_replay(&source, &renewed, 101)?;
        if inject_obsolete_index {
            let read = store.db.begin_read()?;
            let index = read.open_table(EXPIRY)?;
            assert!(
                index.get((100, key.as_str()))?.is_none(),
                "renewal left its prior expiry index row"
            );
        }
        // Exercise the prune-side equality fence independently of replacement cleanup.
        if inject_obsolete_index {
            let write = store.db.begin_write()?;
            write.open_table(EXPIRY)?.insert((100, key.as_str()), 0)?;
            write.commit()?;
        }
        let next = request(1000, 1000);
        store.save_auth_replay(&source, &next, 101)?;
    }
    let store = GatewayRedbStore::open(&path)?;
    store.configure_replay(crate::GatewayReplayConfig::small_node(), 102)?;
    assert!(store.load_state()?.ok_or("renewed state")?.replay_guard_state_mut().is_empty());
    assert!(
        matches!(
            store.save_auth_replay(&source, &renewed, 102),
            Err(NodeCoreError::ReplayGuard(_))
        ),
        "renewed live request replayed after restart"
    );
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn renewed_replay_evidence_survives_expiry_prune_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    renewal_case(false)
}
#[test]
fn obsolete_replay_index_rows_cannot_delete_renewed_entries()
-> Result<(), Box<dyn std::error::Error>> {
    renewal_case(true)
}

fn source(seed: u8) -> Result<ramflux_crypto::RootQualifiedDeviceRef, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("owner", [seed; 32]);
    let device = ramflux_crypto::create_device_branch("owner", "device", 1, [42; 32]);
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &device)?)
}
fn test_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(std::env::temp_dir().join(format!(
        "gateway-quota-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    )))
}
fn config(roots: u64, share: u64) -> crate::GatewayReplayConfig {
    crate::GatewayReplayConfig {
        root_budget: roots,
        per_root_share: share,
        storage_budget_bytes: 128 * 1024 * 1024,
    }
}
fn root_count(store: &GatewayRedbStore) -> Result<u64, NodeCoreError> {
    Ok(store
        .db
        .begin_read()
        .map_err(error)?
        .open_table(ROOTS)
        .map_err(error)?
        .len()
        .map_err(error)?)
}
#[test]
fn inclusive_expiry_releases_zero_live_roots_without_resurrection()
-> Result<(), Box<dyn std::error::Error>> {
    let path = test_path()?;
    let alice = source(1)?;
    let bob = source(2)?;
    {
        let store = GatewayRedbStore::open(&path)?;
        store.configure_replay(config(1, 256), 0)?;
        for index in 0..200 {
            store.save_auth_replay(&alice, &request(index, 100), 0)?;
        }
        assert!(
            matches!(
                store.save_auth_replay(&bob, &request(201, 100), 100),
                Err(NodeCoreError::GatewayReplayCapacity)
            ),
            "inclusive expiry released a live reservation"
        );
        let mut next = request(202, 200);
        next.created_at = 101;
        store.save_auth_replay(&bob, &next, 101)?;
        assert_eq!(root_count(&store)?, 1);
        assert!(
            store.db.begin_read()?.open_table(REPLAY)?.len()? > 64,
            "test must leave expired bodies on disk"
        );
    }
    {
        let store = GatewayRedbStore::open(&path)?;
        store.configure_replay(config(1, 256), 102)?;
        assert_eq!(root_count(&store)?, 1, "expired bodies resurrected old root");
        let mut next = request(203, 200);
        next.created_at = 102;
        store.save_auth_replay(&bob, &next, 102)?;
        store.configure_replay(config(1, 256), 201)?;
        assert_eq!(root_count(&store)?, 0);
        let mut next = request(204, 300);
        next.created_at = 201;
        store.save_auth_replay(&alice, &next, 201)?;
        assert_eq!(root_count(&store)?, 1);
    }
    std::fs::remove_file(path)?;
    Ok(())
}
#[test]
fn pending_failed_commit_never_installs_or_reserves_a_root_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let path = test_path()?;
    let store = std::sync::Arc::new(GatewayRedbStore::open(&path)?);
    store.configure_replay(config(1, 4), 0)?;
    let (entered, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    store.pause_next_admission_commit(entered, waiting)?;
    let child = store.clone();
    let writer = std::thread::spawn(move || {
        child.save_auth_replay(&source(1).map_err(error)?, &request(1, 100), 0)
    });
    observed.recv_timeout(std::time::Duration::from_secs(10))?;
    assert_eq!(root_count(&store)?, 0, "pending reservation became visible");
    store.fail_next_pre_auth_commit();
    release.send(())?;
    assert!(writer.join().map_err(|_| "writer panic")?.is_err());
    assert_eq!(root_count(&store)?, 0, "failed commit reserved a root");
    drop(store);
    let store = GatewayRedbStore::open(&path)?;
    store.configure_replay(config(1, 4), 0)?;
    assert_eq!(root_count(&store)?, 0);
    store.save_auth_replay(&source(2)?, &request(2, 100), 0)?;
    assert_eq!(root_count(&store)?, 1);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}
#[test]
fn disk_replay_storage_measurement_and_bounded_restore() -> Result<(), Box<dyn std::error::Error>> {
    let path = test_path()?;
    let owner = source(3)?;
    let store = GatewayRedbStore::open(&path)?;
    store.configure_replay(config(1, 8192), 0)?;
    let baseline = std::fs::metadata(&path)?.len();
    for index in 0..4096 {
        store.save_auth_replay(&owner, &request(index, 1000), 0)?;
    }
    let bytes = std::fs::metadata(&path)?.len();
    let read = store.db.begin_read()?;
    let stats = [
        read.open_table(REPLAY)?.stats()?,
        read.open_table(EXPIRY)?.stats()?,
        read.open_table(OWN_EXPIRY)?.stats()?,
        read.open_table(ROOTS)?.stats()?,
        read.open_table(ROOT_EXPIRY)?.stats()?,
    ];
    let stored: u64 = stats.iter().map(redb::TableStats::stored_bytes).sum();
    let overhead: u64 =
        stats.iter().map(|stats| stats.metadata_bytes() + stats.fragmented_bytes()).sum();
    eprintln!(
        "REPLAY_STORAGE_MEASURED identities=4096 initial_file_bytes={baseline} final_file_bytes={bytes} growth_bytes_per_identity={} all_index_stored_bytes_per_identity={} index_metadata_and_fragmentation_bytes_per_identity={} page_cache_bytes={}",
        (bytes - baseline) / 4096,
        stored / 4096,
        overhead / 4096,
        super::super::GATEWAY_REPLAY_PAGE_CACHE_BYTES
    );
    assert_eq!(read.open_table(REPLAY)?.len()?, 4096);
    drop(read);
    drop(store);
    for _ in 0..2 {
        let store = GatewayRedbStore::open(&path)?;
        store.configure_replay(config(1, 8192), 0)?;
        assert!(
            store.load_state()?.ok_or("missing state")?.replay_guard_state_mut().is_empty(),
            "startup loaded all evidence into memory"
        );
        assert!(matches!(
            store.save_auth_replay(&owner, &request(1, 1000), 0),
            Err(NodeCoreError::ReplayGuard(_))
        ));
    }
    const {
        assert!(
            super::super::GATEWAY_REPLAY_PAGE_CACHE_BYTES
                < super::super::GATEWAY_REPLAY_MEMORY_LIMIT_BYTES
        );
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn own_expired_share_is_reclaimed_before_other_roots_backlog()
-> Result<(), Box<dyn std::error::Error>> {
    let path = test_path()?;
    let store = GatewayRedbStore::open(&path)?;
    store.configure_replay(config(3, 256), 0)?;
    let attacker = source(8)?;
    let honest = source(9)?;
    for index in 0..200 {
        store.save_auth_replay(&attacker, &request(index, 99), 0)?;
    }
    for index in 200..455 {
        store.save_auth_replay(&honest, &request(index, 100), 0)?;
    }
    store.save_auth_replay(&honest, &request(456, 1000), 0)?;
    let mut fresh = request(457, 1000);
    fresh.created_at = 101;
    store.save_auth_replay(&honest, &fresh, 101)?;
    assert!(
        matches!(
            store.save_auth_replay(&honest, &request(456, 1000), 101),
            Err(NodeCoreError::ReplayGuard(_))
        ),
        "share reclamation forgot live evidence"
    );
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}
