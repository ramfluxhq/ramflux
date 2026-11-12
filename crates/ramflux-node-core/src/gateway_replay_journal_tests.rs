// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Expiry renewal must survive both obsolete-index cleanup and an ordinary reopen.
use super::*;
use crate::NodeReplayGuardState;

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
        let mut guard = NodeReplayGuardState::new();
        for request in &requests {
            guard.check_gateway_signed_request(&source, request, 0)?;
            store.save_auth_replay(&source, request, 0)?;
        }
        guard.prune(101);
        guard.prune(101);
        guard.check_gateway_signed_request(&source, &renewed, 101)?;
        store.save_auth_replay(&source, &renewed, 101)?;
        {
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
        guard.check_gateway_signed_request(&source, &next, 101)?;
        store.save_auth_replay(&source, &next, 101)?;
    }
    let store = GatewayRedbStore::open(&path)?;
    let mut restored = store.load_state()?.ok_or("renewed state")?;
    assert!(
        matches!(
            restored.replay_guard_state_mut().check_gateway_signed_request(&source, &renewed, 102),
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
