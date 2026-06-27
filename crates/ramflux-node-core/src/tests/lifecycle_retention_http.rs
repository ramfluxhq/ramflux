// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

#[test]
fn account_lifecycle_finalization_removes_metadata_and_rejects_delivery()
-> Result<(), Box<dyn std::error::Error>> {
    let router = RouterCore::new();
    let register = registration_request("principal_delete", "device_delete", 91, None, "ip_a")?;
    router.mvp1_register_identity(&register)?;
    router.submit_envelope(envelope(
        "env_before_delete",
        "target_principal_delete",
        DeliveryClass::OpaqueEvent,
    ));
    assert!(router.mvp7_metadata_summary("principal_delete").metadata_present);

    let deactivated = router.mvp7_apply_lifecycle_event(&lifecycle_request(
        "principal_delete",
        "evt_deactivated",
        "identity.deactivated",
        1,
        1_760_000_000,
        None,
    ))?;
    assert_eq!(deactivated.record.state, AccountLifecycleState::Deactivated);
    assert!(deactivated.metadata_present);
    let pending = router.mvp7_apply_lifecycle_event(&lifecycle_request(
        "principal_delete",
        "evt_deleted",
        "identity.deleted",
        2,
        1_760_000_010,
        Some(10),
    ))?;
    assert_eq!(pending.record.state, AccountLifecycleState::DeletePending);
    assert!(
        router
            .mvp7_finalize_delete(&ItestMvp7LifecycleFinalizeRequest {
                principal_id: "principal_delete".to_owned(),
                now: 1_760_000_015,
            })
            .is_err()
    );
    let finalized = router.mvp7_finalize_delete(&ItestMvp7LifecycleFinalizeRequest {
        principal_id: "principal_delete".to_owned(),
        now: 1_760_000_021,
    })?;
    assert_eq!(finalized.record.state, AccountLifecycleState::Deleted);
    assert!(finalized.record.deletion_proof.is_some());
    assert!(!router.mvp7_metadata_summary("principal_delete").metadata_present);
    assert!(matches!(
        router.submit_envelope(envelope(
            "env_after_delete",
            "target_principal_delete",
            DeliveryClass::OpaqueEvent,
        )),
        RouterSubmitOutcome::RejectedDeleted { .. }
    ));
    Ok(())
}

#[test]
fn retention_gc_deletes_expired_records_and_preserves_legal_hold()
-> Result<(), Box<dyn std::error::Error>> {
    let mut state = RetentionState::new();
    state.record_metadata(retention_record("expired", "subject_a", 1_760_000_010, false))?;
    state.record_metadata(retention_record("legal_hold", "subject_a", 1_760_000_010, true))?;
    state.record_metadata(retention_record("live", "subject_a", 1_760_001_000, false))?;
    let gc = state.gc_expired(1_760_000_020);
    assert_eq!(gc.deleted_record_ids, vec!["expired"]);
    assert_eq!(gc.retained_legal_hold_ids, vec!["legal_hold"]);
    assert_eq!(state.metadata_count(), 2);
    let finalized = state.finalize_identity_delete_legacy("subject_a");
    assert_eq!(finalized.deleted_record_ids, vec!["live"]);
    assert_eq!(finalized.retained_legal_hold_ids, vec!["legal_hold"]);
    assert_eq!(state.metadata_count(), 1);
    Ok(())
}

#[test]
fn identity_deletion_proof_commits_deleted_rows_and_rejects_bad_tombstone()
-> Result<(), Box<dyn std::error::Error>> {
    let mut state = RetentionState::new();
    state.record_metadata(retention_record("b_row", "subject_delete", 1_760_000_900, false))?;
    state.record_metadata(retention_record("a_row", "subject_delete", 1_760_000_900, false))?;
    state.record_metadata(retention_record("held", "subject_delete", 1_760_000_100, true))?;
    let signer = RetentionNodeSigner {
        node_id: "node_a.example".to_owned(),
        node_epoch: 2,
        signing_key_id: "node_a.example#node".to_owned(),
        signing_seed: seed_from_nonce(0x77, 1),
    };
    let context = RetentionIdentityDeleteContext {
        subject_hash: "subject_delete".to_owned(),
        lifecycle_epoch: 4,
        identity_deleted_event_id: "evt_delete_subject".to_owned(),
        identity_lifecycle_tombstone_hash: "valid_tombstone_hash".to_owned(),
        retention_policy_id: "identity_lifecycle_tombstone.default_24_months".to_owned(),
        finalized_at: 1_760_000_200,
    };
    let response = state.finalize_identity_delete(&context, &signer);
    assert_eq!(response.status, RetentionIdentityDeleteStatus::Deleted);
    assert_eq!(response.deleted_record_ids, vec!["a_row", "b_row"]);
    assert_eq!(response.retained_legal_hold_ids, vec!["held"]);
    assert_eq!(response.deletion_scope, vec!["router_inbox"]);
    let proof = response.deletion_proof.as_ref().ok_or("missing deletion proof")?;
    assert_eq!(proof.domain, ramflux_protocol::domain::IDENTITY_DELETION_PROOF);
    assert_eq!(proof.identity_lifecycle_tombstone_hash, "valid_tombstone_hash");
    assert_eq!(proof.legal_hold_ids, vec!["held"]);
    assert!(response.deletion_proof_hash.is_some());
    let tombstone =
        state.identity_tombstone("subject_delete").ok_or("missing stored retention tombstone")?;
    assert_eq!(tombstone.status, RetentionIdentityDeleteStatus::Deleted);
    verify_identity_deletion_proof_tombstone(proof, &context.identity_lifecycle_tombstone_hash)?;

    let mut bad_proof = proof.clone();
    bad_proof.identity_lifecycle_tombstone_hash = "bad_tombstone_hash".to_owned();
    assert!(
        verify_identity_deletion_proof_tombstone(
            &bad_proof,
            &context.identity_lifecycle_tombstone_hash,
        )
        .is_err()
    );
    let bad_fixture: ramflux_protocol::IdentityDeletionProof = serde_json::from_str(include_str!(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../ramflux-protocol/fixtures/protocol/v1/identity_deletion_proof/identity_deletion_proof.bad_tombstone.reject.json"
        )
    ))?;
    assert!(
        verify_identity_deletion_proof_tombstone(&bad_fixture, "dG9tYnN0b25lLWhhc2g",).is_err()
    );
    Ok(())
}

#[test]
fn recovery_quorum_proof_accepts_threshold_and_rejects_weak_sets()
-> Result<(), Box<dyn std::error::Error>> {
    let context = recovery_context(None);
    let quorum = recovery_quorum_config(&[
        (ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "root-share", [0x11; 32]),
        (ramflux_protocol::RecoveryQuorumMemberKind::DeviceShare, "device-share", [0x22; 32]),
        (ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare, "guardian-share", [0x33; 32]),
    ]);
    let proof = recovery_proof(
        &context,
        &[
            (ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "root-share", [0x11; 32]),
            (
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                "guardian-share",
                [0x33; 32],
            ),
        ],
    )?;
    verify_recovery_quorum_proof(&quorum, &proof, 1_760_000_000)?;

    let insufficient = recovery_proof(
        &context,
        &[(ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "root-share", [0x11; 32])],
    )?;
    assert!(matches!(
        verify_recovery_quorum_proof(&quorum, &insufficient, 1_760_000_000),
        Err(NodeCoreError::Unauthorized(_))
    ));

    let unknown_member = recovery_proof(
        &context,
        &[
            (ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "unknown-root", [0x11; 32]),
            (
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                "guardian-share",
                [0x33; 32],
            ),
        ],
    )?;
    assert!(matches!(
        verify_recovery_quorum_proof(&quorum, &unknown_member, 1_760_000_000),
        Err(NodeCoreError::Unauthorized(_))
    ));

    let forged = recovery_proof(
        &context,
        &[
            (ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "root-share", [0xaa; 32]),
            (
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                "guardian-share",
                [0x33; 32],
            ),
        ],
    )?;
    assert!(matches!(
        verify_recovery_quorum_proof(&quorum, &forged, 1_760_000_000),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn recovery_quorum_rejects_guardian_only_and_active_timelock()
-> Result<(), Box<dyn std::error::Error>> {
    let guardian_quorum = recovery_quorum_config(&[
        (ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare, "guardian-a", [0x41; 32]),
        (ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare, "guardian-b", [0x42; 32]),
        (ramflux_protocol::RecoveryQuorumMemberKind::DeviceShare, "device-a", [0x43; 32]),
    ]);
    let guardian_only = recovery_proof(
        &recovery_context(None),
        &[
            (ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare, "guardian-a", [0x41; 32]),
            (ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare, "guardian-b", [0x42; 32]),
        ],
    )?;
    assert!(matches!(
        verify_recovery_quorum_proof(&guardian_quorum, &guardian_only, 1_760_000_000),
        Err(NodeCoreError::Unauthorized(_))
    ));

    let router = RouterCore::new();
    let quorum = recovery_quorum_config(&[
        (ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "root-share", [0x51; 32]),
        (ramflux_protocol::RecoveryQuorumMemberKind::DeviceShare, "device-share", [0x52; 32]),
        (ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare, "guardian-share", [0x53; 32]),
    ]);
    let context = recovery_context(Some(1_760_000_100));
    let proof = recovery_proof(
        &context,
        &[
            (ramflux_protocol::RecoveryQuorumMemberKind::RootShare, "root-share", [0x51; 32]),
            (
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                "guardian-share",
                [0x53; 32],
            ),
        ],
    )?;
    let mut request = lifecycle_request(
        "principal_recovery",
        "evt_recovery_reactivate",
        "identity.reactivated",
        1,
        1_760_000_000,
        None,
    );
    request.recovery_quorum = Some(quorum);
    request.recovery_quorum_proof = Some(proof);
    assert!(matches!(
        router.mvp7_apply_lifecycle_event(&request),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

fn recovery_quorum_config(
    members: &[(ramflux_protocol::RecoveryQuorumMemberKind, &str, [u8; 32])],
) -> ramflux_protocol::RecoveryQuorumConfigured {
    ramflux_protocol::RecoveryQuorumConfigured {
        recovery_quorum_id: "quorum_test".to_owned(),
        threshold: 2,
        total: u8::try_from(members.len()).unwrap_or(u8::MAX),
        members: members
            .iter()
            .map(|(member_kind, signing_key_id, seed)| {
                ramflux_protocol::RecoveryQuorumMemberCommitment {
                    member_kind: member_kind.clone(),
                    signing_key_id: (*signing_key_id).to_owned(),
                    public_key_base64url: ramflux_crypto::public_key_base64url_from_seed(*seed),
                }
            })
            .collect(),
    }
}

fn recovery_context(timelock_until: Option<u64>) -> ramflux_protocol::RecoveryApprovalContext {
    ramflux_protocol::RecoveryApprovalContext {
        recovery_id: "recovery_test".to_owned(),
        event_type: "identity.reactivated".to_owned(),
        principal_id: "principal_recovery".to_owned(),
        lifecycle_epoch: 1,
        lineage_head: Some("lineage_head_test".to_owned()),
        timelock_until,
    }
}

fn recovery_proof(
    context: &ramflux_protocol::RecoveryApprovalContext,
    approvals: &[(ramflux_protocol::RecoveryQuorumMemberKind, &str, [u8; 32])],
) -> Result<ramflux_protocol::RecoveryQuorumProof, ramflux_crypto::CryptoError> {
    Ok(ramflux_protocol::RecoveryQuorumProof {
        context: context.clone(),
        approvals: approvals
            .iter()
            .map(|(member_kind, signing_key_id, seed)| {
                Ok(ramflux_protocol::RecoveryApproval {
                    member_kind: member_kind.clone(),
                    signing_key_id: (*signing_key_id).to_owned(),
                    signature_alg: SignatureAlg::Ed25519,
                    signature: ramflux_crypto::sign_protocol_object_with_seed(&context, *seed)?,
                })
            })
            .collect::<Result<Vec<_>, ramflux_crypto::CryptoError>>()?,
    })
}

#[test]
fn retention_record_requires_policy_expiry_and_legal_hold_review() {
    let mut state = RetentionState::new();
    let mut missing_policy = retention_record("missing_policy", "subject_a", 1_760_000_010, false);
    missing_policy.retention_policy_id.clear();
    assert!(state.record_metadata(missing_policy).is_err());

    let mut missing_expiry = retention_record("missing_expiry", "subject_a", 1_760_000_010, false);
    missing_expiry.expires_at = 0;
    assert!(state.record_metadata(missing_expiry).is_err());

    let mut stale_review = retention_record("stale_review", "subject_a", 1_760_000_010, true);
    stale_review.legal_hold_next_review_at = Some(1_760_000_000 + 181 * 24 * 60 * 60);
    assert!(state.record_metadata(stale_review).is_err());
}

#[test]
fn retention_gc_delete_after_ack_takes_precedence() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = RetentionState::new();
    let mut record = retention_record("ack_deleted", "subject_a", 1_760_100_000, false);
    record.delete_after_ack = Some(1_760_000_010);
    state.record_metadata(record)?;
    let gc = state.gc_expired(1_760_000_020);
    assert_eq!(gc.deleted_record_ids, vec!["ack_deleted"]);
    assert_eq!(state.metadata_count(), 0);
    Ok(())
}

#[test]
fn retention_gc_sweep_authz_accepts_retention_peer_only_for_gc_path()
-> Result<(), Box<dyn std::error::Error>> {
    let allowed = BTreeSet::from(["ramflux-router".to_owned(), "ramflux-retention".to_owned()]);
    for service_id in [
        "ramflux-gateway",
        "ramflux-router",
        "ramflux-notify",
        "ramflux-relay",
        "ramflux-signaling",
        "ramflux-federation",
    ] {
        assert!(service_matrix_allows("ramflux-retention", service_id));
        assert!(service_matrix_allows(service_id, "ramflux-retention"));
    }
    let accepted = authorize_retention_gc_sweep(
        "ramflux-router",
        &allowed,
        Some("spiffe://node-a/ramflux-retention"),
        "/internal/retention/gc_sweep",
    )?;
    assert_eq!(accepted.service_id, "ramflux-retention");
    assert!(
        authorize_retention_gc_sweep(
            "ramflux-router",
            &allowed,
            Some("spiffe://node-a/ramflux-retention"),
            "/mvp0/envelope",
        )
        .is_err()
    );
    assert!(
        authorize_retention_gc_sweep(
            "ramflux-router",
            &allowed,
            Some("spiffe://node-a/ramflux-gateway"),
            "/internal/retention/gc_sweep",
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn itest_http_reader_requires_complete_header_and_body() -> Result<(), Box<dyn std::error::Error>> {
    assert_incomplete_request_times_out(
        b"POST /mvp6/preauth/probe HTTP/1.1\r\nHost: ramflux-gateway\r\nContent-Length: 2\r\n",
    )?;
    assert_incomplete_request_times_out(
        b"POST /mvp6/preauth/probe HTTP/1.1\r\nHost: ramflux-gateway\r\nContent-Length: 2\r\n\r\n",
    )?;
    Ok(())
}
