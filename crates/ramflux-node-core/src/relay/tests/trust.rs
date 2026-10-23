// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::relay::{
    BTreeSet, FederatedIssuerTrustStatus, NodeCoreError, ObjectRelayCapability,
    RelayTrustSnapshotCache, signed_federated_issuer_trust_snapshot_signing_bytes,
    verify_federated_issuer_trust_snapshot, verify_federated_issuer_trust_snapshot_admission,
    verify_federated_issuer_trust_snapshot_successor, verify_federated_trust_snapshot_envelope,
    verify_relay_token_v3_with_trust_snapshot, verify_signed_federated_issuer_trust_snapshot,
};

use crate::relay::test_support::{
    V3_AUDIENCE_NODE, V3_CERT_ID, V3_ISSUER_NODE, V3_PROVIDER_SEED, V3_ROOT_KEY_ID,
    V3_ROOT_PREV_KEY_ID, V3_ROOT_PREV_SEED, V3_ROOT_SEED, signed_trust_snapshot_envelope, v3_pk,
    v3_previous_root, v3_sign, v3_signed_snapshot_envelope, v3_token_signed_by_root,
    v3_trust_snapshot,
};

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn relay_trust_snapshot_cache_update_and_current_happy_path() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    // Empty cache is fail-closed.
    assert!(cache.current(V3_ISSUER_NODE, now).is_err());

    cache
        .update(v3_trust_snapshot(now, |_s| {}), V3_ISSUER_NODE, now)
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(5));
    let snapshot = cache.current(V3_ISSUER_NODE, now).map_err(|e| e.to_string())?;
    assert_eq!(snapshot.generation, 5);

    // A monotonically newer snapshot is accepted.
    cache
        .update(
            v3_trust_snapshot(now, |s| {
                s.generation = 6;
                s.pin_epoch = 4;
            }),
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(6));
    Ok(())
}

#[test]
fn relay_trust_snapshot_cache_rejects_rollback_and_wrong_node() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    cache
        .update(
            v3_trust_snapshot(now, |s| {
                s.generation = 5;
                s.pin_epoch = 3;
            }),
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;

    // Generation rollback.
    assert!(
        cache
            .update(
                v3_trust_snapshot(now, |s| {
                    s.generation = 4;
                    s.pin_epoch = 3;
                }),
                V3_ISSUER_NODE,
                now
            )
            .is_err()
    );
    // Pin epoch rollback.
    assert!(
        cache
            .update(
                v3_trust_snapshot(now, |s| {
                    s.generation = 5;
                    s.pin_epoch = 2;
                }),
                V3_ISSUER_NODE,
                now
            )
            .is_err()
    );
    // Different node id.
    assert!(
        cache
            .update(
                v3_trust_snapshot(now, |s| s.node_id = "node-z".to_owned()),
                V3_ISSUER_NODE,
                now
            )
            .is_err()
    );
    // The cached snapshot is unchanged after every rejected update.
    assert_eq!(cache.generation(), Some(5));
    Ok(())
}

#[test]
fn relay_trust_snapshot_cache_current_fail_closed_when_empty_or_stale() -> Result<(), String> {
    let now = 1_000_000;
    let empty = RelayTrustSnapshotCache::new();
    assert!(empty.current(V3_ISSUER_NODE, now).is_err());

    let mut cache = RelayTrustSnapshotCache::new();
    cache
        .update(v3_trust_snapshot(now, |_s| {}), V3_ISSUER_NODE, now)
        .map_err(|e| e.to_string())?;
    // Usable within the staleness window.
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
    // Fail-closed past the hard staleness deadline (hard_stale_at = now + 300).
    assert!(cache.current(V3_ISSUER_NODE, now + 301).is_err());
    // An already-stale incoming snapshot is rejected on update.
    assert!(
        cache
            .update(
                v3_trust_snapshot(now, |s| {
                    s.generation = 6;
                    s.hard_stale_at = now - 1;
                }),
                V3_ISSUER_NODE,
                now
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn relay_trust_snapshot_cache_clone_is_value_independent() -> Result<(), String> {
    // The cache has no interior mutability: sharing is by clone, so updates to one copy never
    // affect another.
    let now = 1_000_000;
    let mut base = RelayTrustSnapshotCache::new();
    base.update(v3_trust_snapshot(now, |_s| {}), V3_ISSUER_NODE, now).map_err(|e| e.to_string())?;
    let mut cloned = base.clone();
    cloned
        .update(
            v3_trust_snapshot(now, |s| {
                s.generation = 6;
                s.pin_epoch = 4;
            }),
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert_eq!(base.generation(), Some(5));
    assert_eq!(cloned.generation(), Some(6));
    Ok(())
}

#[test]
fn relay_trust_snapshot_envelope_valid_admits_to_cache() -> Result<(), String> {
    let now = 1_000_000;
    let provider_pk = v3_pk(V3_PROVIDER_SEED);
    let envelope = v3_signed_snapshot_envelope(now, |_e| {})?;
    verify_signed_federated_issuer_trust_snapshot(&envelope, &provider_pk, now)
        .map_err(|e| e.to_string())?;

    let mut cache = RelayTrustSnapshotCache::new();
    cache
        .update_from_signed(&envelope, &provider_pk, V3_ISSUER_NODE, now)
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(5));
    Ok(())
}

#[test]
fn relay_trust_snapshot_envelope_rejects_tamper() -> Result<(), String> {
    let now = 1_000_000;
    let provider_pk = v3_pk(V3_PROVIDER_SEED);
    // Tamper the inner snapshot after signing: the provider signature no longer verifies.
    let mut tampered = v3_signed_snapshot_envelope(now, |_e| {})?;
    tampered.snapshot.generation = 999;
    assert!(verify_signed_federated_issuer_trust_snapshot(&tampered, &provider_pk, now).is_err());

    let mut cache = RelayTrustSnapshotCache::new();
    assert!(
        cache.update_from_signed(&tampered, &provider_pk, V3_ISSUER_NODE, now).is_err(),
        "a tampered envelope must never reach the cache"
    );
    assert_eq!(cache.generation(), None);
    Ok(())
}

// T23-A1a closure: a provider-signed non-Active snapshot must be admissible over the full signed
// ingress path (update_from_signed), replacing a stale Active, yet fail requests closed; and a
// wrong-provider signature over the same body must be rejected without mutating the cache.
#[test]
fn t23a1a_signed_suspended_admits_but_rejects_requests_and_forged_is_inert() -> Result<(), String> {
    let now = 1_000_000;
    let provider_pk = v3_pk(V3_PROVIDER_SEED);
    let mut cache = RelayTrustSnapshotCache::new();

    // G1 Active installs and authorizes over the signed path.
    let g1 = v3_signed_snapshot_envelope(now, |e| e.snapshot.generation = 1)?;
    cache.update_from_signed(&g1, &provider_pk, V3_ISSUER_NODE, now).map_err(|e| e.to_string())?;
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());

    // A provider-signed Suspended G2 is admitted (generation replaced to 2)...
    let g2 = v3_signed_snapshot_envelope(now, |e| {
        e.snapshot.generation = 2;
        e.snapshot.trust_status = FederatedIssuerTrustStatus::Suspended;
    })?;
    cache.update_from_signed(&g2, &provider_pk, V3_ISSUER_NODE, now).map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(2));
    // ...but the read path is Active-only: requests fail closed; the stale Active is not retained.
    assert!(matches!(cache.current(V3_ISSUER_NODE, now), Err(NodeCoreError::Unauthorized(_))));

    // A wrong-provider signature over a would-be successor (still declaring the pinned provider
    // key) is rejected and leaves the installed Suspended G2 in force.
    let mut forged = v3_signed_snapshot_envelope(now, |e| {
        e.snapshot.generation = 3;
        e.snapshot.trust_status = FederatedIssuerTrustStatus::Suspended;
    })?;
    forged.signature = v3_sign(
        &signed_federated_issuer_trust_snapshot_signing_bytes(&forged)
            .map_err(|e| e.to_string())?,
        [0x99; 32],
    );
    assert!(cache.update_from_signed(&forged, &provider_pk, V3_ISSUER_NODE, now).is_err());
    assert_eq!(cache.generation(), Some(2), "wrong-provider envelope must not mutate the cache");
    assert!(matches!(cache.current(V3_ISSUER_NODE, now), Err(NodeCoreError::Unauthorized(_))));
    Ok(())
}

#[test]
fn relay_trust_snapshot_envelope_rejects_wrong_root() -> Result<(), String> {
    let now = 1_000_000;
    let envelope = v3_signed_snapshot_envelope(now, |_e| {})?;

    // Expected provider key differs from the envelope's declared provider key.
    assert!(
        verify_signed_federated_issuer_trust_snapshot(&envelope, &v3_pk(V3_ROOT_SEED), now)
            .is_err()
    );

    // Envelope signed by a non-provider key (declared provider key kept, signature forged).
    let mut forged = v3_signed_snapshot_envelope(now, |_e| {})?;
    forged.signature = v3_sign(
        &signed_federated_issuer_trust_snapshot_signing_bytes(&forged)
            .map_err(|e| e.to_string())?,
        V3_ROOT_SEED,
    );
    assert!(
        verify_signed_federated_issuer_trust_snapshot(&forged, &v3_pk(V3_PROVIDER_SEED), now)
            .is_err()
    );
    Ok(())
}

#[test]
fn relay_trust_snapshot_envelope_rejects_expired() -> Result<(), String> {
    let now = 1_000_000;
    let provider_pk = v3_pk(V3_PROVIDER_SEED);
    // Signature covers the (past) window, so this is a validly-signed but expired envelope.
    let expired = v3_signed_snapshot_envelope(now, |e| {
        e.issued_at = now - 600;
        e.expires_at = now;
    })?;
    assert!(matches!(
        verify_signed_federated_issuer_trust_snapshot(&expired, &provider_pk, now),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    let mut cache = RelayTrustSnapshotCache::new();
    assert!(cache.update_from_signed(&expired, &provider_pk, V3_ISSUER_NODE, now).is_err());
    assert_eq!(cache.generation(), None);
    Ok(())
}

#[test]
fn v3_trust_snapshot_active_current_root_accepts() -> Result<(), String> {
    let now = 1_000_000;
    let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_SEED, V3_ROOT_KEY_ID)?;
    let snapshot = v3_trust_snapshot(now, |_s| {});
    verify_federated_issuer_trust_snapshot(&snapshot, V3_ISSUER_NODE, now)
        .map_err(|e| e.to_string())?;
    verify_relay_token_v3_with_trust_snapshot(
        &token,
        &cert,
        &snapshot,
        ObjectRelayCapability::Get,
        V3_AUDIENCE_NODE,
        now,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v3_trust_snapshot_previous_overlap_root_accepts() -> Result<(), String> {
    let now = 1_000_000;
    let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_PREV_SEED, V3_ROOT_PREV_KEY_ID)?;
    // Snapshot carries both current and previous (overlapping) roots.
    let snapshot = v3_trust_snapshot(now, |s| {
        s.roots.push(v3_previous_root(now, Some(now + 120)));
    });
    verify_relay_token_v3_with_trust_snapshot(
        &token,
        &cert,
        &snapshot,
        ObjectRelayCapability::Get,
        V3_AUDIENCE_NODE,
        now,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v3_trust_snapshot_rejects_unknown_expired_retired_root() -> Result<(), String> {
    let now = 1_000_000;
    // Unknown signer key id: token signed by the previous root, snapshot has only the current.
    let (prev_token, prev_cert) =
        v3_token_signed_by_root(now, V3_ROOT_PREV_SEED, V3_ROOT_PREV_KEY_ID)?;
    let current_only = v3_trust_snapshot(now, |_s| {});
    assert!(matches!(
        verify_relay_token_v3_with_trust_snapshot(
            &prev_token,
            &prev_cert,
            &current_only,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_SEED, V3_ROOT_KEY_ID)?;

    // Expired root: current root's window is in the past.
    let expired_root = v3_trust_snapshot(now, |s| {
        s.roots[0].not_before = now - 200;
        s.roots[0].not_after = now - 1;
    });
    assert!(matches!(
        verify_relay_token_v3_with_trust_snapshot(
            &token,
            &cert,
            &expired_root,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Retired root: retired_at is in the past.
    let retired_root = v3_trust_snapshot(now, |s| {
        s.roots[0].retired_at = Some(now - 1);
    });
    assert!(matches!(
        verify_relay_token_v3_with_trust_snapshot(
            &token,
            &cert,
            &retired_root,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_trust_snapshot_rejects_revoked_certificate() -> Result<(), String> {
    let now = 1_000_000;
    let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_SEED, V3_ROOT_KEY_ID)?;
    let snapshot = v3_trust_snapshot(now, |s| {
        s.revoked_cert_ids.insert(V3_CERT_ID.to_owned());
    });
    assert!(matches!(
        verify_relay_token_v3_with_trust_snapshot(
            &token,
            &cert,
            &snapshot,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_trust_snapshot_rejects_stale_status_generation_and_identity() -> Result<(), String> {
    let now = 1_000_000;
    let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_SEED, V3_ROOT_KEY_ID)?;

    // Past the hard staleness deadline.
    let stale = v3_trust_snapshot(now, |s| s.hard_stale_at = now - 1);
    assert!(matches!(
        verify_federated_issuer_trust_snapshot(&stale, V3_ISSUER_NODE, now),
        Err(NodeCoreError::TtlExpired { .. })
    ));
    let boundary = v3_trust_snapshot(now, |s| s.hard_stale_at = now);
    assert!(matches!(
        verify_federated_issuer_trust_snapshot(&boundary, V3_ISSUER_NODE, now),
        Err(NodeCoreError::TtlExpired { .. })
    ));
    assert!(matches!(
        verify_relay_token_v3_with_trust_snapshot(
            &token,
            &cert,
            &stale,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    // Non-Active statuses fail closed (Migrated included).
    for status in [
        FederatedIssuerTrustStatus::Invited,
        FederatedIssuerTrustStatus::Suspended,
        FederatedIssuerTrustStatus::Revoked,
        FederatedIssuerTrustStatus::Migrated,
    ] {
        let snap = v3_trust_snapshot(now, |s| s.trust_status = status);
        assert!(
            matches!(
                verify_federated_issuer_trust_snapshot(&snap, V3_ISSUER_NODE, now),
                Err(NodeCoreError::Unauthorized(_))
            ),
            "status {status:?} must fail closed"
        );
    }

    // Zero generation and identity mismatch.
    let zero_gen = v3_trust_snapshot(now, |s| s.generation = 0);
    assert!(matches!(
        verify_federated_issuer_trust_snapshot(&zero_gen, V3_ISSUER_NODE, now),
        Err(NodeCoreError::Unauthorized(_))
    ));
    let good = v3_trust_snapshot(now, |_s| {});
    assert!(matches!(
        verify_federated_issuer_trust_snapshot(&good, "node-z", now),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Wrong schema / version.
    let bad_schema = v3_trust_snapshot(now, |s| s.schema = "wrong".to_owned());
    assert!(matches!(
        verify_federated_issuer_trust_snapshot(&bad_schema, V3_ISSUER_NODE, now),
        Err(NodeCoreError::ItestJson(_))
    ));
    let bad_version = v3_trust_snapshot(now, |s| s.version = 2);
    assert!(matches!(
        verify_federated_issuer_trust_snapshot(&bad_version, V3_ISSUER_NODE, now),
        Err(NodeCoreError::ItestJson(_))
    ));
    Ok(())
}

#[test]
fn v3_trust_snapshot_successor_rollback_rejected() -> Result<(), String> {
    let now = 1_000_000;
    let previous = v3_trust_snapshot(now, |s| {
        s.generation = 5;
        s.pin_epoch = 3;
    });

    // Monotonic non-decreasing successor is accepted.
    let ok_next = v3_trust_snapshot(now, |s| {
        s.generation = 6;
        s.pin_epoch = 4;
    });
    verify_federated_issuer_trust_snapshot_successor(&previous, &ok_next)
        .map_err(|e| e.to_string())?;

    let same_epoch_changed = v3_trust_snapshot(now, |s| {
        s.generation = previous.generation;
        s.pin_epoch = previous.pin_epoch;
        s.hard_stale_at += 1;
    });
    assert!(matches!(
        verify_federated_issuer_trust_snapshot_successor(&previous, &same_epoch_changed),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Generation rollback.
    let gen_rollback = v3_trust_snapshot(now, |s| {
        s.generation = 4;
        s.pin_epoch = 3;
    });
    assert!(matches!(
        verify_federated_issuer_trust_snapshot_successor(&previous, &gen_rollback),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Pin epoch rollback.
    let pin_rollback = v3_trust_snapshot(now, |s| {
        s.generation = 5;
        s.pin_epoch = 2;
    });
    assert!(matches!(
        verify_federated_issuer_trust_snapshot_successor(&previous, &pin_rollback),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Different node.
    let other_node = v3_trust_snapshot(now, |s| s.node_id = "node-z".to_owned());
    assert!(matches!(
        verify_federated_issuer_trust_snapshot_successor(&previous, &other_node),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn trust_snapshot_cache_requires_valid_monotonic_state() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    assert!(matches!(cache.current(V3_ISSUER_NODE, now), Err(NodeCoreError::Unauthorized(_))));

    cache
        .update(v3_trust_snapshot(now, |_snapshot| {}), V3_ISSUER_NODE, now)
        .map_err(|error| error.to_string())?;
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());

    let rollback = v3_trust_snapshot(now, |snapshot| snapshot.generation = 4);
    assert!(matches!(
        cache.update(rollback, V3_ISSUER_NODE, now),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

// T23-A1a: snapshot admission (entering the cache) is separated from request authorization
// (Active-only). A validly-signed non-Active snapshot is admissible so a node-status transition
// propagates and replaces a stale Active; requests are then gated Active-only.
#[test]
fn t23a1a_admission_accepts_nonactive_but_authorization_rejects() -> Result<(), String> {
    let now = 1_000_000;
    for status in [
        FederatedIssuerTrustStatus::Suspended,
        FederatedIssuerTrustStatus::Revoked,
        FederatedIssuerTrustStatus::Invited,
        FederatedIssuerTrustStatus::Migrated,
    ] {
        let snap = v3_trust_snapshot(now, |s| s.trust_status = status);
        verify_federated_issuer_trust_snapshot_admission(&snap, V3_ISSUER_NODE, now)
            .map_err(|e| format!("admission must accept {status:?}: {e}"))?;
        assert!(
            matches!(
                verify_federated_issuer_trust_snapshot(&snap, V3_ISSUER_NODE, now),
                Err(NodeCoreError::Unauthorized(_))
            ),
            "authorization must reject {status:?}"
        );
    }
    // A hard-stale snapshot is inadmissible even though it is Active (cannot install or authorize).
    let stale = v3_trust_snapshot(now, |s| s.hard_stale_at = now);
    assert!(matches!(
        verify_federated_issuer_trust_snapshot_admission(&stale, V3_ISSUER_NODE, now),
        Err(NodeCoreError::TtlExpired { .. })
    ));
    Ok(())
}

#[test]
fn t23a1a_suspended_replaces_active_and_fails_requests_closed() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    cache
        .update(v3_trust_snapshot(now, |s| s.generation = 1), V3_ISSUER_NODE, now)
        .map_err(|e| e.to_string())?;
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
    // A validly-signed Suspended successor is admitted and advances the cached generation...
    cache
        .update(
            v3_trust_snapshot(now, |s| {
                s.generation = 2;
                s.trust_status = FederatedIssuerTrustStatus::Suspended;
            }),
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(2), "suspended snapshot must be installed");
    // ...but the stale Active is NOT retained: node-level suspension takes effect, requests 403.
    assert!(matches!(cache.current(V3_ISSUER_NODE, now), Err(NodeCoreError::Unauthorized(_))));
    // A later Active successor recovers the node status (generation advances again).
    cache
        .update(v3_trust_snapshot(now, |s| s.generation = 3), V3_ISSUER_NODE, now)
        .map_err(|e| e.to_string())?;
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
    Ok(())
}

#[test]
fn t23a1a_successor_crl_must_not_shrink() -> Result<(), String> {
    let now = 1_000_000;
    let revoked =
        |ids: &[&str]| ids.iter().map(|id| (*id).to_owned()).collect::<BTreeSet<String>>();
    let previous = v3_trust_snapshot(now, |s| {
        s.generation = 5;
        s.revoked_cert_ids = revoked(&["cert-a"]);
    });
    // Adding revocations (superset) is a valid successor.
    let grows = v3_trust_snapshot(now, |s| {
        s.generation = 6;
        s.revoked_cert_ids = revoked(&["cert-a", "cert-b"]);
    });
    verify_federated_issuer_trust_snapshot_successor(&previous, &grows)
        .map_err(|e| e.to_string())?;
    // Dropping a revocation (even at a higher generation) is rejected — the CRL is monotonic.
    let shrinks = v3_trust_snapshot(now, |s| {
        s.generation = 7;
        s.revoked_cert_ids = revoked(&[]);
    });
    assert!(matches!(
        verify_federated_issuer_trust_snapshot_successor(&previous, &shrinks),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn t23a1a_rejected_successor_leaves_cache_unchanged() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    cache
        .update(
            v3_trust_snapshot(now, |s| {
                s.generation = 5;
                s.revoked_cert_ids = ["cert-a".to_owned()].into_iter().collect();
            }),
            V3_ISSUER_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
    assert_eq!(cache.generation(), Some(5));

    // generation rollback / CRL shrink / hard-stale / wrong-node — each rejected, cache unchanged.
    let attempts = [
        v3_trust_snapshot(now, |s| s.generation = 4),
        v3_trust_snapshot(now, |s| {
            s.generation = 6;
            s.revoked_cert_ids = BTreeSet::new();
        }),
        v3_trust_snapshot(now, |s| {
            s.generation = 6;
            s.hard_stale_at = now;
        }),
        v3_trust_snapshot(now, |s| {
            s.generation = 6;
            s.node_id = "node-z".to_owned();
        }),
    ];
    for attempt in attempts {
        assert!(cache.update(attempt, V3_ISSUER_NODE, now).is_err());
        assert_eq!(cache.generation(), Some(5), "rejected update must not mutate the cache");
    }
    assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
    Ok(())
}

#[test]
fn trust_snapshot_cache_rejects_stale_replacement_and_reads() -> Result<(), String> {
    let now = 1_000_000;
    let mut cache = RelayTrustSnapshotCache::new();
    cache
        .update(v3_trust_snapshot(now, |_snapshot| {}), V3_ISSUER_NODE, now)
        .map_err(|error| error.to_string())?;

    let stale = v3_trust_snapshot(now, |snapshot| snapshot.hard_stale_at = now);
    assert!(matches!(
        cache.update(stale, V3_ISSUER_NODE, now),
        Err(NodeCoreError::TtlExpired { .. })
    ));
    assert!(cache.current(V3_ISSUER_NODE, now + 301).is_err());
    Ok(())
}

#[test]
fn trust_snapshot_envelope_accepts_valid_and_rejects_tamper_or_wrong_signer() -> Result<(), String>
{
    let now = 1_000_000;
    let envelope = signed_trust_snapshot_envelope(now, V3_ROOT_SEED)?;
    verify_federated_trust_snapshot_envelope(
        &envelope,
        V3_ISSUER_NODE,
        V3_ROOT_KEY_ID,
        &v3_pk(V3_ROOT_SEED),
        now,
    )
    .map_err(|error| error.to_string())?;

    let mut tampered = envelope.clone();
    tampered.snapshot.generation += 1;
    assert!(
        verify_federated_trust_snapshot_envelope(
            &tampered,
            V3_ISSUER_NODE,
            V3_ROOT_KEY_ID,
            &v3_pk(V3_ROOT_SEED),
            now,
        )
        .is_err()
    );
    assert!(
        verify_federated_trust_snapshot_envelope(
            &envelope,
            V3_ISSUER_NODE,
            "wrong-key",
            &v3_pk(V3_ROOT_SEED),
            now,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn trust_snapshot_envelope_rejects_expired_or_wrong_root_signature() -> Result<(), String> {
    let now = 1_000_000;
    let mut expired = signed_trust_snapshot_envelope(now, V3_ROOT_SEED)?;
    expired.expires_at = now;
    assert!(matches!(
        verify_federated_trust_snapshot_envelope(
            &expired,
            V3_ISSUER_NODE,
            V3_ROOT_KEY_ID,
            &v3_pk(V3_ROOT_SEED),
            now,
        ),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    let wrong_root = signed_trust_snapshot_envelope(now, V3_ROOT_PREV_SEED)?;
    assert!(
        verify_federated_trust_snapshot_envelope(
            &wrong_root,
            V3_ISSUER_NODE,
            V3_ROOT_KEY_ID,
            &v3_pk(V3_ROOT_SEED),
            now,
        )
        .is_err()
    );
    Ok(())
}
