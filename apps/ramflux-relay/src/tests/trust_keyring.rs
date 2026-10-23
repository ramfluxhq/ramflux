// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

const OFFLINE_ROOT_SEED: [u8; 32] = [0xa1; 32];
const WRONG_ROOT_SEED: [u8; 32] = [0xa9; 32];
const K1_SEED: [u8; 32] = [0xa2; 32];
const NODE: &str = "node-b.realnet";
const NOW: u64 = 2_000_000_000;

fn pk(seed: [u8; 32]) -> String {
    ramflux_crypto::public_key_base64url_from_seed(seed)
}

fn sign(bytes: &[u8], seed: [u8; 32]) -> String {
    ramflux_crypto::sign_canonical_bytes_with_seed(bytes, seed)
}

fn snapshot(generation: u64) -> ramflux_node_core::FederatedIssuerTrustSnapshot {
    ramflux_node_core::FederatedIssuerTrustSnapshot {
        schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        node_id: NODE.to_owned(),
        generation,
        pin_epoch: 1,
        trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
        roots: Vec::new(),
        revoked_cert_ids: std::collections::BTreeSet::new(),
        hard_stale_at: NOW + 3_600,
    }
}

fn keyring(keyring_epoch: u64, offline_seed: [u8; 32]) -> ramflux_node_core::ProviderKeyring {
    let mut keyring = ramflux_node_core::ProviderKeyring {
        schema: ramflux_node_core::PROVIDER_KEYRING_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_KEYRING_VERSION,
        issuer_node_id: NODE.to_owned(),
        keyring_epoch,
        keys: vec![ramflux_node_core::ProviderKeyEntry {
            key_id: "k1".to_owned(),
            public_key: pk(K1_SEED),
            not_before: NOW - 100,
            not_after: NOW + 3_600,
            retired_at: None,
            authorized_provider_epoch: 1,
        }],
        keyring_signature: String::new(),
    };
    keyring.keyring_signature =
        sign(&ramflux_node_core::provider_keyring_signing_bytes(&keyring).unwrap(), offline_seed);
    keyring
}

fn envelope(generation: u64) -> ramflux_node_core::ProviderSignedTrustSnapshot {
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: snapshot(generation),
        provider_signing_key_id: "k1".to_owned(),
        provider_public_key: pk(K1_SEED),
        provider_epoch: 1,
        issued_at: NOW,
        expires_at: NOW + 300,
        signature: String::new(),
    };
    envelope.signature = sign(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope).unwrap(),
        K1_SEED,
    );
    envelope
}

const K2_SEED: [u8; 32] = [0xa3; 32];

/// A two-key keyring at `epoch` (K1 optionally retired, K2 authorized for `provider_epoch` 2).
fn keyring_two(epoch: u64, k1_retired: bool) -> ramflux_node_core::ProviderKeyring {
    let mut keyring = ramflux_node_core::ProviderKeyring {
        schema: ramflux_node_core::PROVIDER_KEYRING_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_KEYRING_VERSION,
        issuer_node_id: NODE.to_owned(),
        keyring_epoch: epoch,
        keys: vec![
            ramflux_node_core::ProviderKeyEntry {
                key_id: "k1".to_owned(),
                public_key: pk(K1_SEED),
                not_before: NOW - 100,
                not_after: NOW + 3_600,
                retired_at: if k1_retired { Some(NOW - 1) } else { None },
                authorized_provider_epoch: 1,
            },
            ramflux_node_core::ProviderKeyEntry {
                key_id: "k2".to_owned(),
                public_key: pk(K2_SEED),
                not_before: NOW - 100,
                not_after: NOW + 3_600,
                retired_at: None,
                authorized_provider_epoch: 2,
            },
        ],
        keyring_signature: String::new(),
    };
    keyring.keyring_signature = sign(
        &ramflux_node_core::provider_keyring_signing_bytes(&keyring).unwrap(),
        OFFLINE_ROOT_SEED,
    );
    keyring
}

fn envelope_k2(generation: u64) -> ramflux_node_core::ProviderSignedTrustSnapshot {
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: snapshot(generation),
        provider_signing_key_id: "k2".to_owned(),
        provider_public_key: pk(K2_SEED),
        provider_epoch: 2,
        issued_at: NOW,
        expires_at: NOW + 300,
        signature: String::new(),
    };
    envelope.signature = sign(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope).unwrap(),
        K2_SEED,
    );
    envelope
}

fn validate(
    keyring: &ramflux_node_core::ProviderKeyring,
) -> ramflux_node_core::ValidatedProviderKeyring {
    ramflux_node_core::verify_provider_keyring(keyring, &pk(OFFLINE_ROOT_SEED), NODE).unwrap()
}

/// A live cache holding K1/e1 at snapshot generation 5.
fn live_k1() -> ramflux_node_core::RelayTrustSnapshotCache {
    let mut cache = ramflux_node_core::RelayTrustSnapshotCache::new();
    cache
        .update_from_keyring_signed(
            &envelope(5),
            &validate(&keyring(1, OFFLINE_ROOT_SEED)),
            NODE,
            NOW,
        )
        .unwrap();
    cache
}

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("ramflux-a2b2-{name}-{}.json", std::process::id()))
}

#[test]
fn keyring_provider_config_requires_all_five_fields_fail_closed() {
    let (endpoint, keyring, root, node, cache) =
        (Some("ep"), Some("kr"), Some("root"), Some("node"), Some("cache"));
    // Positive: all five present → config resolved.
    assert!(
        relay_keyring_provider_config_from_values(endpoint, keyring, root, node, cache).is_some()
    );
    // Negative: each missing / empty field independently disables the provider (fail-closed).
    assert!(relay_keyring_provider_config_from_values(None, keyring, root, node, cache).is_none());
    assert!(relay_keyring_provider_config_from_values(endpoint, None, root, node, cache).is_none());
    assert!(
        relay_keyring_provider_config_from_values(endpoint, keyring, None, node, cache).is_none()
    );
    assert!(
        relay_keyring_provider_config_from_values(endpoint, keyring, root, None, cache).is_none()
    );
    assert!(
        relay_keyring_provider_config_from_values(endpoint, keyring, root, node, None).is_none()
    );
    assert!(
        relay_keyring_provider_config_from_values(Some("  "), keyring, root, node, cache).is_none()
    );
    assert!(
        relay_keyring_provider_config_from_values(endpoint, keyring, root, node, Some(""))
            .is_none()
    );
}

#[test]
fn keyring_provider_startup_readiness_fails_closed_with_error() {
    // Incomplete config → Err (fail-closed at startup, NOT a silent disable).
    assert!(require_keyring_provider_ready_from(None).is_err());

    let good = tmp("readiness-good");
    std::fs::write(&good, serde_json::to_vec_pretty(&keyring(1, OFFLINE_ROOT_SEED)).unwrap())
        .unwrap();
    let config = |keyring_file: &str, offline_root: &str, issuer: &str| {
        Some((
            "ramflux-federation:7443".to_owned(),
            keyring_file.to_owned(),
            offline_root.to_owned(),
            issuer.to_owned(),
            "/var/lib/ramflux/relay/trust-snapshot.json".to_owned(),
        ))
    };
    // Complete config + valid keyring → Ok (proceeds to startup init).
    assert!(
        require_keyring_provider_ready_from(config(
            good.to_str().unwrap(),
            &pk(OFFLINE_ROOT_SEED),
            NODE
        ))
        .is_ok()
    );
    // Missing keyring file → Err.
    assert!(
        require_keyring_provider_ready_from(config(
            "/nonexistent/provider-keyring.json",
            &pk(OFFLINE_ROOT_SEED),
            NODE
        ))
        .is_err()
    );
    // Forged offline root (keyring signed by a non-pinned root) → Err.
    let forged = tmp("readiness-forged");
    std::fs::write(&forged, serde_json::to_vec_pretty(&keyring(1, WRONG_ROOT_SEED)).unwrap())
        .unwrap();
    assert!(
        require_keyring_provider_ready_from(config(
            forged.to_str().unwrap(),
            &pk(OFFLINE_ROOT_SEED),
            NODE
        ))
        .is_err()
    );
    // Issuer-node mismatch → Err.
    assert!(
        require_keyring_provider_ready_from(config(
            good.to_str().unwrap(),
            &pk(OFFLINE_ROOT_SEED),
            "node-wrong.realnet"
        ))
        .is_err()
    );
    let _ = std::fs::remove_file(&good);
    let _ = std::fs::remove_file(&forged);
}

#[test]
fn provider_keyring_loads_from_file_and_rejects_forgery() {
    let good = tmp("keyring-good");
    std::fs::write(&good, serde_json::to_vec_pretty(&keyring(1, OFFLINE_ROOT_SEED)).unwrap())
        .unwrap();
    assert!(load_provider_keyring(good.to_str().unwrap(), &pk(OFFLINE_ROOT_SEED), NODE).is_ok());
    // Forged keyring (signed by a non-root key) is rejected against the pinned offline root.
    let forged = tmp("keyring-forged");
    std::fs::write(&forged, serde_json::to_vec_pretty(&keyring(1, WRONG_ROOT_SEED)).unwrap())
        .unwrap();
    assert!(load_provider_keyring(forged.to_str().unwrap(), &pk(OFFLINE_ROOT_SEED), NODE).is_err());
    let _ = std::fs::remove_file(&good);
    let _ = std::fs::remove_file(&forged);
}

#[test]
fn keyring_trust_persist_restore_roundtrip_honors_high_water() {
    let validated = validate(&keyring(2, OFFLINE_ROOT_SEED));
    let mut cache = ramflux_node_core::RelayTrustSnapshotCache::new();
    cache.update_from_keyring_signed(&envelope(5), &validated, NODE, NOW).unwrap();
    assert_eq!(cache.generation(), Some(5));

    let path = tmp("keyring-cache");
    persist_keyring_trust(path.to_str().unwrap(), &cache, Some(&envelope(5))).unwrap();

    // A cold cache restores the persisted snapshot + high-water (incl. fingerprint).
    let mut restarted = ramflux_node_core::RelayTrustSnapshotCache::new();
    let restored =
        load_keyring_trust(path.to_str().unwrap(), &mut restarted, &validated, NODE, NOW).unwrap();
    assert!(restored.is_some());
    assert_eq!(restarted.generation(), Some(5));
    assert_eq!(restarted.provider_epoch_high_water(), 1);
    assert_eq!(restarted.keyring_epoch_high_water(), 2);
    assert!(restarted.keyring_fingerprint_high_water().is_some());
    assert_eq!(restarted.accepted_signer_key_id(), Some("k1"));

    // The restored cache rejects a generation rollback.
    assert!(restarted.update_from_keyring_signed(&envelope(4), &validated, NODE, NOW).is_err());
    assert_eq!(restarted.generation(), Some(5));
    let _ = std::fs::remove_file(&path);
}

// ---- CTRL-046 closure tests ----

// (1) A same-`keyring_epoch` content replacement (validly offline-root-signed) is not adopted, so
// the candidate planner leaves the live cache untouched.
#[test]
fn closure_same_epoch_content_replacement_not_published() {
    let live = live_k1();
    let alt = validate(&keyring_two(1, false)); // same epoch 1, different content
    assert!(
        plan_keyring_candidate(&live, &alt, None, Some(&envelope(5)), NODE, NOW).is_none(),
        "same-epoch content replacement must not produce a publishable candidate"
    );
}

// (2) A persistence failure must NOT publish the candidate: the live cache and disk stay at K1.
#[test]
fn closure_persist_failure_does_not_publish() {
    let live = Mutex::new(live_k1());
    // Build a K2 candidate.
    let mut candidate = live.lock().unwrap().clone();
    candidate
        .update_from_keyring_signed(&envelope_k2(6), &validate(&keyring_two(2, false)), NODE, NOW)
        .unwrap();
    // Force persist failure: a path whose parent is a regular file.
    let blocker = tmp("persist-blocker");
    std::fs::write(&blocker, b"x").unwrap();
    let bad_path = blocker.join("child.json");
    assert!(
        publish_keyring_candidate(
            &live,
            candidate,
            Some(&envelope_k2(6)),
            bad_path.to_str().unwrap()
        )
        .is_err(),
        "a persistence failure must be surfaced"
    );
    assert_eq!(
        live.lock().unwrap().generation(),
        Some(5),
        "live must remain K1 after persist failure"
    );
    let _ = std::fs::remove_file(&blocker);
}

// (3) Persist success THEN publish; a restart from the persisted file restores the published K2.
#[test]
fn closure_persist_success_publishes_and_survives_restart() {
    let live = Mutex::new(live_k1());
    let mut candidate = live.lock().unwrap().clone();
    candidate
        .update_from_keyring_signed(&envelope_k2(6), &validate(&keyring_two(2, false)), NODE, NOW)
        .unwrap();
    let path = tmp("keyring-publish");
    publish_keyring_candidate(&live, candidate, Some(&envelope_k2(6)), path.to_str().unwrap())
        .unwrap();
    assert_eq!(live.lock().unwrap().generation(), Some(6), "K2 published after persist success");

    let mut restarted = ramflux_node_core::RelayTrustSnapshotCache::new();
    load_keyring_trust(
        path.to_str().unwrap(),
        &mut restarted,
        &validate(&keyring_two(2, false)),
        NODE,
        NOW,
    )
    .unwrap();
    assert_eq!(restarted.generation(), Some(6), "restart restores published K2");
    assert_eq!(restarted.provider_epoch_high_water(), 2);
    let _ = std::fs::remove_file(&path);
}

// (4) Retire-current-signer + fetch failure persists the empty-authorization state, then publishes
// fail-closed; a restart stays fail-closed while preserving the anti-rollback high-water.
#[test]
fn closure_retire_fetch_fail_persists_empty_and_restart_fail_closed() {
    let live = live_k1();
    let retire = validate(&keyring_two(2, true)); // epoch 2, K1 retired, K2 present
    let (candidate, candidate_envelope) =
        plan_keyring_candidate(&live, &retire, None, Some(&envelope(5)), NODE, NOW)
            .expect("retirement must produce a fail-closed candidate");
    assert!(candidate_envelope.is_none(), "retired signer leaves no authoritative envelope");
    assert!(candidate.generation().is_none(), "retired signer clears the cached snapshot");

    let path = tmp("keyring-retire");
    let mutex = Mutex::new(live);
    publish_keyring_candidate(
        &mutex,
        candidate,
        candidate_envelope.as_ref(),
        path.to_str().unwrap(),
    )
    .unwrap();
    assert!(
        mutex.lock().unwrap().current(NODE, NOW).is_err(),
        "live must be fail-closed after retire"
    );

    let mut restarted = ramflux_node_core::RelayTrustSnapshotCache::new();
    let restored =
        load_keyring_trust(path.to_str().unwrap(), &mut restarted, &retire, NODE, NOW).unwrap();
    assert!(restored.is_none());
    assert!(restarted.current(NODE, NOW).is_err(), "restart stays fail-closed");
    assert_eq!(restarted.keyring_epoch_high_water(), 2, "anti-rollback high-water preserved");
    let _ = std::fs::remove_file(&path);
}

// (5) An old-epoch (rolled-back) keyring is non-adoptable: it never triggers signer reconciliation
// and never clears the existing valid cache.
#[test]
fn closure_old_epoch_keyring_no_reconciliation() {
    // Live cache at K2/e2, keyring epoch 2.
    let mut live = ramflux_node_core::RelayTrustSnapshotCache::new();
    live.update_from_keyring_signed(&envelope_k2(6), &validate(&keyring_two(2, false)), NODE, NOW)
        .unwrap();
    // A rolled-back keyring at epoch 1 must not be adopted.
    let old = validate(&keyring(1, OFFLINE_ROOT_SEED));
    assert!(
        plan_keyring_candidate(&live, &old, None, Some(&envelope_k2(6)), NODE, NOW).is_none(),
        "an old-epoch keyring must not produce a publishable candidate"
    );
    assert_eq!(live.generation(), Some(6), "existing valid cache is retained");
}
