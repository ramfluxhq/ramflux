// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::relay::{
    BTreeSet, RELAY_METADATA_MAX_BYTES_DEFAULT, RelayCacheState, RelayChunkEntry, RelayChunkStatus,
    RelayRedbStore, env, fs, thread,
};

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn shared_relay_store_handles_concurrent_save_and_expiry_without_reopen() -> Result<(), String> {
    let store_path = std::env::temp_dir().join(format!(
        "ramflux-relay-shared-store-{}-{}.redb",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|source| source.to_string())?
            .as_nanos()
    ));
    let store = Arc::new(RelayRedbStore::open(&store_path).map_err(|source| source.to_string())?);
    let state = Arc::new(Mutex::new(RelayCacheState::new()));
    {
        let state = state.lock().map_err(|source| source.to_string())?;
        store.save_state(&state).map_err(|source| source.to_string())?;
    }

    let mut workers = Vec::new();
    for index in 0..4 {
        let store = Arc::clone(&store);
        let state = Arc::clone(&state);
        workers.push(thread::spawn(move || -> Result<(), String> {
            let mut state = state.lock().map_err(|source| source.to_string())?;
            state
                .put_chunk(RelayChunkEntry {
                    chunk_id: format!("chunk-{index}"),
                    object_id: "object-shared-store".to_owned(),
                    manifest_hash: "manifest-shared-store".to_owned(),
                    chunk_index: index,
                    chunk_cipher_hash: format!("cipher-hash-{index}"),
                    owner_signing_key_id: "owner-shared-store".to_owned(),
                    owner_public_key: "owner-public-shared-store".to_owned(),
                    encrypted_chunk: vec![
                        u8::try_from(index).map_err(|source| source.to_string())?;
                        8
                    ],
                    stored_at: 0,
                    expires_at: 1,
                    delete_after_ack: false,
                    acked_by: BTreeSet::new(),
                    status: RelayChunkStatus::Available,
                })
                .map_err(|source| source.to_string())?;
            store.save_state(&state).map_err(|source| source.to_string())
        }));
    }
    for worker in workers {
        worker.join().map_err(|_source| "relay worker panicked".to_owned())??;
    }

    {
        let mut state = state.lock().map_err(|source| source.to_string())?;
        let expired = state.expire_chunks(u64::MAX);
        assert_eq!(expired, 4);
        store.save_state(&state).map_err(|source| source.to_string())?;
    }
    let loaded = store
        .load_state(RELAY_METADATA_MAX_BYTES_DEFAULT)
        .map_err(|source| source.to_string())?
        .ok_or_else(|| "relay state should exist".to_owned())?;
    assert_eq!(loaded.available_count(u64::MAX), 0);

    drop(state);
    drop(store);
    let _ = std::fs::remove_file(store_path);
    Ok(())
}
