// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::relay::{
    FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA, RelayTrustSnapshotCache,
    provider_keyring_signing_bytes, verify_provider_signed_trust_snapshot,
};

use crate::relay::test_support::{
    A2B2_K1, A2B2_K1_SEED, A2B2_K2, A2B2_K2_SEED, A2B2_WRONG_SEED, V3_ISSUER_NODE, a2b2_entry,
    a2b2_envelope, a2b2_keyring, a2b2_validate, v3_pk, v3_sign,
};

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn a2b2_keyring_valid_selection_and_structural_rejections() -> Result<(), String> {
    let now = 1_000_000;
    let keyring = a2b2_keyring(
        2,
        vec![
            a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
            a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2),
        ],
        |_k| {},
    );
    let validated = a2b2_validate(&keyring).map_err(|e| e.to_string())?;
    assert_eq!(validated.keyring_epoch(), 2);
    assert_eq!(validated.select(A2B2_K1).map(|e| e.authorized_provider_epoch), Some(1));
    assert_eq!(validated.select(A2B2_K2).map(|e| e.authorized_provider_epoch), Some(2));
    assert!(validated.select("prov-unknown").is_none());

    // Wrong schema / version.
    assert!(
        a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |k| k.schema = "x".to_owned()
        ))
        .is_err()
    );
    assert!(
        a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |k| k.version = 99
        ))
        .is_err()
    );
    // Wrong issuer node.
    assert!(
        a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |k| k.issuer_node_id = "node-z".to_owned()
        ))
        .is_err()
    );
    // Empty keys.
    assert!(a2b2_validate(&a2b2_keyring(1, vec![], |_k| {})).is_err());
    // Duplicate key_id.
    assert!(
        a2b2_validate(&a2b2_keyring(
            1,
            vec![
                a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
                a2b2_entry(A2B2_K1, A2B2_K2_SEED, now, None, 2)
            ],
            |_k| {}
        ))
        .is_err()
    );
    // Duplicate authorized_provider_epoch.
    assert!(
        a2b2_validate(&a2b2_keyring(
            1,
            vec![
                a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
                a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 1)
            ],
            |_k| {}
        ))
        .is_err()
    );
    // Empty validity window.
    assert!(
        a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |k| {
                k.keys[0].not_before = now;
                k.keys[0].not_after = now;
            }
        ))
        .is_err()
    );
    // Forged offline-root signature (re-signed by a non-root key).
    let mut forged =
        a2b2_keyring(1, vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)], |_k| {});
    forged.keyring_signature = v3_sign(
        &provider_keyring_signing_bytes(&forged).map_err(|e| e.to_string())?,
        A2B2_WRONG_SEED,
    );
    assert!(a2b2_validate(&forged).is_err());
    Ok(())
}

#[test]
fn a2b2_envelope_binding_and_rejections() -> Result<(), String> {
    let now = 1_000_000;
    let validated = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;

    // Valid K1/e1.
    let entry = verify_provider_signed_trust_snapshot(
        &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
        &validated,
        now,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(entry.key_id, A2B2_K1);

    // Unknown signer key id.
    assert!(
        verify_provider_signed_trust_snapshot(
            &a2b2_envelope(now, "prov-unknown", A2B2_K1_SEED, 1, |_e| {}),
            &validated,
            now
        )
        .is_err()
    );
    // Wrong provider_epoch (not the entry's authorized epoch).
    assert!(
        verify_provider_signed_trust_snapshot(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 2, |_e| {}),
            &validated,
            now
        )
        .is_err()
    );
    // provider_public_key mismatch (signed by K1 but declares K2's key).
    assert!(
        verify_provider_signed_trust_snapshot(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |e| e.provider_public_key =
                v3_pk(A2B2_K2_SEED)),
            &validated,
            now
        )
        .is_err()
    );
    // Legacy v3 schema hard-rejected.
    assert!(
        verify_provider_signed_trust_snapshot(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |e| e.schema =
                FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned()),
            &validated,
            now
        )
        .is_err()
    );
    // Forged signature (tamper a signed field after signing).
    let mut tampered = a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {});
    tampered.snapshot.generation += 1;
    assert!(verify_provider_signed_trust_snapshot(&tampered, &validated, now).is_err());

    // Retired key.
    let retired = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, Some(now - 1), 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    assert!(
        verify_provider_signed_trust_snapshot(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &retired,
            now
        )
        .is_err()
    );
    // Not-yet-valid key.
    let future = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |k| {
            k.keys[0].not_before = now + 10_000;
            k.keys[0].not_after = now + 20_000;
        },
    ))
    .map_err(|e| e.to_string())?;
    assert!(
        verify_provider_signed_trust_snapshot(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &future,
            now
        )
        .is_err()
    );
    // Expired key.
    let expired = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |k| {
            k.keys[0].not_before = now - 20_000;
            k.keys[0].not_after = now - 10_000;
        },
    ))
    .map_err(|e| e.to_string())?;
    assert!(
        verify_provider_signed_trust_snapshot(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &expired,
            now
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn a2b2_cache_transition_and_seizure_rejected() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    // K1 stage: install K1/e1 gen5.
    let kr1 = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    cache
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &kr1,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(5));
    assert_eq!(cache.provider_epoch_high_water(), 1);
    assert_eq!(cache.accepted_signer_key_id(), Some(A2B2_K1));

    // Stage K2 and switch to K2/e2 gen6 → provider-epoch high-water advances to 2.
    let kr2 = a2b2_validate(&a2b2_keyring(
        2,
        vec![
            a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
            a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2),
        ],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    cache
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K2, A2B2_K2_SEED, 2, |s| s.snapshot.generation = 6),
            &kr2,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(6));
    assert_eq!(cache.provider_epoch_high_water(), 2);
    assert_eq!(cache.accepted_signer_key_id(), Some(A2B2_K2));

    // Seizure attempt 1: compromised K1 signs a HIGHER generation (7) but only its own epoch (1),
    // which is now below the high-water → rejected; cache stays exactly at gen6/e2/K2.
    assert!(
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |s| s.snapshot.generation = 7),
                &kr2,
                V3_ISSUER_NODE,
                now
            )
            .is_err()
    );
    // Seizure attempt 2: compromised K1 forges provider_epoch=2 → not its authorized epoch → rejected.
    assert!(
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 2, |s| s.snapshot.generation = 7),
                &kr2,
                V3_ISSUER_NODE,
                now
            )
            .is_err()
    );
    assert_eq!(cache.generation(), Some(6));
    assert_eq!(cache.provider_epoch_high_water(), 2);
    assert_eq!(cache.accepted_signer_key_id(), Some(A2B2_K2));

    // Legitimate K2 continues to advance at its own epoch.
    cache
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K2, A2B2_K2_SEED, 2, |s| s.snapshot.generation = 7),
            &kr2,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(7));
    Ok(())
}

#[test]
fn a2b2_keyring_epoch_rollback_rejected() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    let kr2 = a2b2_validate(&a2b2_keyring(
        2,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    cache
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &kr2,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.keyring_epoch_high_water(), 2);
    // A keyring whose epoch regressed below the accepted high-water is rejected.
    let kr1 = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    assert!(
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |s| s.snapshot.generation = 6),
                &kr1,
                V3_ISSUER_NODE,
                now
            )
            .is_err()
    );
    assert_eq!(cache.generation(), Some(5));
    Ok(())
}

#[test]
fn a2b2_retire_current_signer_fails_closed_or_installs_successor() -> Result<(), String> {
    let now = 1_000_000;
    // Case A: retiring the current signer with no successor clears the cache (fail-closed).
    let mut cache = RelayTrustSnapshotCache::new();
    let kr1 = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    cache
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &kr1,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
    let kr_retire = a2b2_validate(&a2b2_keyring(
        2,
        vec![
            a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, Some(now - 1), 1),
            a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2),
        ],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    cache.reconcile_keyring(&kr_retire, now).map_err(|e| e.to_string())?;
    assert!(cache.current(V3_ISSUER_NODE, now).is_err(), "retired signer must fail closed");

    // Case B: a valid successor installed by K2 before the retirement reconcile is retained.
    let mut cache2 = RelayTrustSnapshotCache::new();
    cache2
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &kr1,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    cache2
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K2, A2B2_K2_SEED, 2, |s| s.snapshot.generation = 6),
            &kr_retire,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    cache2.reconcile_keyring(&kr_retire, now).map_err(|e| e.to_string())?;
    assert!(cache2.current(V3_ISSUER_NODE, now).is_ok(), "valid K2 successor must be retained");
    assert_eq!(cache2.generation(), Some(6));
    Ok(())
}

#[test]
fn a2b2_provider_outage_keeps_valid_cache_and_restart_roundtrip() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    let kr = a2b2_validate(&a2b2_keyring(
        3,
        vec![a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    cache
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K2, A2B2_K2_SEED, 2, |s| s.snapshot.generation = 6),
            &kr,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;

    // Provider outage = no new envelope; reconciling against the same (still-valid) keyring keeps
    // the cached snapshot authorizing.
    cache.reconcile_keyring(&kr, now).map_err(|e| e.to_string())?;
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
    assert_eq!(cache.generation(), Some(6));

    // Restart roundtrip: a cold cache that restores the persisted high-waters rejects a replayed
    // lower-epoch envelope, so a restart cannot be tricked into accepting a superseded epoch.
    let mut restarted = RelayTrustSnapshotCache::new();
    restarted.restore_high_water(Some(A2B2_K2.to_owned()), 2, 3, None);
    let kr_replay = a2b2_validate(&a2b2_keyring(
        2,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    assert!(
        restarted
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &kr_replay,
                V3_ISSUER_NODE,
                now
            )
            .is_err(),
        "restart must honor persisted epoch high-water"
    );
    Ok(())
}

#[test]
fn a2b2_same_keyring_epoch_content_replacement_rejected() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    // Adopt keyring epoch 1 = {K1}.
    let kr1 = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    cache
        .update_from_keyring_signed(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &kr1,
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    let fingerprint = cache.keyring_fingerprint_high_water().map(str::to_owned);
    assert!(fingerprint.is_some());

    // A different keyring at the SAME epoch (adds K2) is validly offline-root-signed but is a
    // content replacement — rejected by both ingress paths, leaving the cache/fingerprint inert.
    let kr1_alt = a2b2_validate(&a2b2_keyring(
        1,
        vec![
            a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
            a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2),
        ],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    assert_ne!(kr1_alt.fingerprint(), kr1.fingerprint());
    assert!(
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |s| s.snapshot.generation = 6),
                &kr1_alt,
                V3_ISSUER_NODE,
                now
            )
            .is_err(),
        "same-epoch content replacement must be rejected on the update path"
    );
    assert!(
        cache.reconcile_keyring(&kr1_alt, now).is_err(),
        "same-epoch content replacement must be rejected on the reconcile path"
    );
    assert_eq!(cache.generation(), Some(5));
    assert_eq!(cache.keyring_fingerprint_high_water().map(str::to_owned), fingerprint);

    // Re-adopting the SAME keyring content (same fingerprint) is idempotent, not a replacement.
    let kr1_same = a2b2_validate(&a2b2_keyring(
        1,
        vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
        |_k| {},
    ))
    .map_err(|e| e.to_string())?;
    assert_eq!(kr1_same.fingerprint(), kr1.fingerprint());
    cache.reconcile_keyring(&kr1_same, now).map_err(|e| e.to_string())?;
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
    Ok(())
}
