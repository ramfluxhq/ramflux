// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    wire: String,
    #[serde(default)]
    bytes: usize,
    #[serde(default)]
    field: String,
}
#[derive(Deserialize)]
struct Legacy {
    profile: String,
    signing: String,
    native: String,
}
#[derive(Deserialize)]
struct Corpus {
    valid: Vec<Case>,
    invalid: Vec<Case>,
    legacy: Legacy,
    transcripts: std::collections::BTreeMap<String, String>,
    review_rules: std::collections::BTreeMap<String, String>,
}
fn corpus() -> Result<Corpus, serde_json::Error> {
    serde_json::from_str(include_str!(
        "../../../../scripts/reference/username_directory/wire_vectors.json"
    ))
}
fn roundtrip(kind: &str, bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    match kind {
        "UsernameBindingBody" => encode(&decode::<UsernameBindingBody>(bytes)?),
        "ProfileRef" => encode(&decode::<ProfileRef>(bytes)?),
        "AvatarRef" => encode(&decode::<AvatarRef>(bytes)?),
        "IdentityProfileV2Body" => encode(&decode::<IdentityProfileV2Body>(bytes)?),
        "UsernameOperationBody" => encode(&decode::<UsernameOperationBody>(bytes)?),
        "DirectoryReceiptBody" => encode(&decode::<DirectoryReceiptBody>(bytes)?),
        "DirectoryResolveBody" => encode(&decode::<DirectoryResolveBody>(bytes)?),
        "ReceiptDecision" => encode(&decode::<ReceiptDecision>(bytes)?),
        "RootRow" => encode(&decode::<RootRow>(bytes)?),
        "NameRow" => encode(&decode::<NameRow>(bytes)?),
        "SkeletonRow" => encode(&decode::<SkeletonRow>(bytes)?),
        "HoldKey" => encode(&decode::<HoldKey>(bytes)?),
        "HoldRow" => encode(&decode::<HoldRow>(bytes)?),
        "OperationKey" => encode(&decode::<OperationKey>(bytes)?),
        "OperationRow" => encode(&decode::<OperationRow>(bytes)?),
        "OperationOwnerRow" => encode(&decode::<OperationOwnerRow>(bytes)?),
        "DueRow" => encode(&decode::<DueRow>(bytes)?),
        "CounterRow" => encode(&decode::<CounterRow>(bytes)?),
        "CheckpointDelta" => encode(&decode::<CheckpointDelta>(bytes)?),
        "Checkpoint" => encode(&decode::<Checkpoint>(bytes)?),
        "HomeRevalidateRequest" => encode(&decode::<HomeRevalidateRequest>(bytes)?),
        "HomeRevalidateResult" => encode(&decode::<HomeRevalidateResult>(bytes)?),
        "DirectoryFailure" => encode(&decode::<DirectoryFailure>(bytes)?),
        "UsernameBinding" => encode(&decode::<UsernameBinding>(bytes)?),
        "SignedIdentityProfileV2" => encode(&decode::<SignedIdentityProfileV2>(bytes)?),
        "UsernameOperation" => encode(&decode::<UsernameOperation>(bytes)?),
        "DirectoryReceipt" => encode(&decode::<DirectoryReceipt>(bytes)?),
        "DirectoryResolve" => encode(&decode::<DirectoryResolve>(bytes)?),
        "Replacement" => encode(&decode::<Replacement>(bytes)?),
        "DueKey" => encode(&decode::<DueKey>(bytes)?),
        "CounterKey" => encode(&decode::<CounterKey>(bytes)?),
        "ServeCandidate" => encode(&decode::<ServeCandidate>(bytes)?),
        _ => Err(CodecError::Field("unknown test type")),
    }
}

// Fixed review obligations: deleting a vector or weakening its expected field is a failure.
const REVIEW_RULES: &[(&str, &str)] = &[
    ("review_reserved_claim_admin", "name"),
    ("review_reserved_claim_administrator", "name"),
    ("review_reserved_claim_root", "name"),
    ("review_reserved_claim_system", "name"),
    ("review_reserved_claim_support", "name"),
    ("review_reserved_claim_security", "name"),
    ("review_reserved_claim_ramflux", "name"),
    ("review_reserved_claim_official", "name"),
    ("review_reserved_claim_moderator", "name"),
    ("review_reserved_claim_notify", "name"),
    ("review_reserved_claim_federation", "name"),
    ("review_skeleton_claim_adrnin", "name"),
    ("review_skeleton_claim_adrninistrator", "name"),
    ("review_skeleton_claim_systern", "name"),
    ("review_skeleton_claim_rarnflux", "name"),
    ("review_skeleton_claim_ramf1ux", "name"),
    ("review_skeleton_claim_officia1", "name"),
    ("review_skeleton_claim_rnoderator", "name"),
    ("review_prefix_claim_ramflux_user", "name"),
    ("review_prefix_claim_system_user", "name"),
    ("review_prefix_claim_rarnflux_user", "name"),
    ("review_prefix_claim_ramf1ux_user", "name"),
    ("review_prefix_claim_systern_user", "name"),
    ("review_reserved_rename_admin", "name"),
    ("review_reserved_rename_administrator", "name"),
    ("review_reserved_rename_root", "name"),
    ("review_reserved_rename_system", "name"),
    ("review_reserved_rename_support", "name"),
    ("review_reserved_rename_security", "name"),
    ("review_reserved_rename_ramflux", "name"),
    ("review_reserved_rename_official", "name"),
    ("review_reserved_rename_moderator", "name"),
    ("review_reserved_rename_notify", "name"),
    ("review_reserved_rename_federation", "name"),
    ("review_skeleton_rename_adrnin", "name"),
    ("review_skeleton_rename_adrninistrator", "name"),
    ("review_skeleton_rename_systern", "name"),
    ("review_skeleton_rename_rarnflux", "name"),
    ("review_skeleton_rename_ramf1ux", "name"),
    ("review_skeleton_rename_officia1", "name"),
    ("review_skeleton_rename_rnoderator", "name"),
    ("review_prefix_rename_ramflux_user", "name"),
    ("review_prefix_rename_system_user", "name"),
    ("review_prefix_rename_rarnflux_user", "name"),
    ("review_prefix_rename_ramf1ux_user", "name"),
    ("review_prefix_rename_systern_user", "name"),
    ("review_initial_action_rename", "expected_epoch"),
    ("review_initial_action_release", "expected_epoch"),
    ("review_initial_action_delete", "expected_epoch"),
    ("review_initial_action_set_visibility", "expected_epoch"),
    ("review_initial_action_move_home", "expected_epoch"),
    ("review_initial_expected_profile", "expected_epoch"),
    ("review_initial_claim_binding", "expected_epoch"),
    ("review_initial_nameless_binding", "expected_epoch"),
    ("review_claim_old_name", "old_name"),
    ("review_claim_missing_binding", "old_name"),
    ("review_rename_same_name", "name"),
    ("review_rename_same_skeleton", "name"),
    ("review_rename_missing_old_name", "old_name"),
    ("review_rename_missing_binding", "binding"),
    ("review_release_binding", "binding"),
    ("review_release_visible", "binding"),
    ("review_delete_binding", "binding"),
    ("review_delete_visible", "binding"),
    ("review_release_nameless", "old_name"),
    ("review_set_visibility_old_name_alice", "old_name"),
    ("review_set_visibility_old_name_None", "old_name"),
    ("review_move_home_old_name_alice", "old_name"),
    ("review_move_home_old_name_None", "old_name"),
    ("review_profile_update_old_name_alice", "old_name"),
    ("review_profile_update_old_name_None", "old_name"),
    ("review_operation_binding_epoch", "binding"),
    ("review_operation_binding_principal_commitment", "binding"),
    ("review_profile_update_increment", "profile"),
    ("review_operation_profile_version", "profile"),
    ("review_operation_expected_version", "expected_profile"),
    ("review_claim_profile_preserved", "profile"),
    ("review_rename_profile_preserved", "profile"),
    ("review_release_profile_preserved", "profile"),
    ("review_delete_profile_preserved", "profile"),
    ("review_set_visibility_profile_preserved", "profile"),
    ("review_move_home_profile_preserved", "profile"),
    ("review_root_pair_1", "current_binding"),
    ("review_root_pair_2", "current_binding"),
    ("review_root_pair_3", "current_binding"),
    ("review_root_pair_4", "current_binding"),
    ("review_root_pair_5", "current_binding"),
    ("review_root_pair_6", "current_binding"),
    ("review_root_committed_last_operation_id", "receipt_decision"),
    ("review_root_uncommitted_last_operation_id", "receipt_decision"),
    ("review_root_committed_last_operation_hash", "receipt_decision"),
    ("review_root_uncommitted_last_operation_hash", "receipt_decision"),
    ("review_root_committed_receipt_decision", "receipt_decision"),
    ("review_root_uncommitted_receipt_decision", "receipt_decision"),
    ("review_root_profile_legacy", "profile"),
    ("review_root_uncommitted_profile", "profile"),
    ("review_root_uncommitted_name", "profile"),
    ("review_root_binding_name", "current_binding"),
    ("review_root_binding_node", "current_binding"),
    ("review_root_binding_epoch", "current_binding"),
    ("review_deleted_named", "deleted"),
    ("review_deleted_pending_operation_id", "deleted"),
    ("review_deleted_discoverable", "deleted"),
    ("review_deleted_uncommitted", "deleted"),
    ("review_changes_spacing", "changes"),
    ("review_changes_decrease", "changes"),
    ("review_changes_duplicate", "changes"),
    ("review_hold_unsorted", "hold_deadlines"),
    ("review_deleted_hold_limit", "hold_deadlines"),
    ("review_pending_reuses_last", "pending_operation_id"),
    ("review_receipt_reserved_ttl_119", "expires_at"),
    ("review_receipt_reserved_ttl_121", "expires_at"),
    ("review_receipt_expired_committed", "expires_at"),
    ("review_receipt_expired_reserved", "expires_at"),
    ("review_receipt_expired_aborted", "expires_at"),
    ("review_receipt_profile_version", "profile"),
    ("review_reserved_has_finished_at", "finished_at"),
    ("review_reserved_has_retain_until", "finished_at"),
    ("review_terminal_missing_time", "finished_at"),
    ("review_terminal_missing_retention", "retain_until"),
    ("review_terminal_before_reserve", "retain_until"),
    ("review_operation_reservation_expiry_at", "finished_at"),
    ("review_operation_reservation_expiry_past", "finished_at"),
    ("review_operation_signed_expiry_at", "finished_at"),
    ("review_operation_signed_expiry_past", "finished_at"),
    ("review_delta_unexpected_operation_abort", "operation"),
    ("review_delta_unexpected_operation_expire", "operation"),
    ("review_delta_unexpected_operation_gc", "operation"),
    ("review_delta_unexpected_operation_clock", "operation"),
    ("review_delta_missing_operation_reserve", "operation"),
    ("review_delta_operation_new_mismatch_reserve", "operation"),
    ("review_delta_operation_old_mismatch_reserve", "operation"),
    ("review_delta_missing_operation_commit", "operation"),
    ("review_delta_operation_new_mismatch_commit", "operation"),
    ("review_delta_operation_old_mismatch_commit", "operation"),
    ("review_clock_rows", "rows"),
    ("review_genesis_digest", "lsn"),
    ("review_genesis_kind", "lsn"),
    ("review_genesis_rows", "rows"),
    ("review_checkpoint_generation", "generation"),
    ("review_identical_replacement_root", "images"),
    ("review_identical_replacement_name", "images"),
    ("review_identical_replacement_skeleton", "images"),
    ("review_identical_replacement_hold", "images"),
    ("review_identical_replacement_operation", "images"),
    ("review_identical_replacement_op_owner", "images"),
    ("review_identical_replacement_due_hold", "images"),
    ("review_identical_replacement_counter_global", "images"),
    ("review_empty_images", "images"),
    ("review_skeleton_key", "skeleton"),
    ("review_operation_key_root", "operation"),
    ("review_operation_key_operation_id", "operation"),
    ("review_root_key", "current_binding"),
    ("review_root_deletion", "root"),
    ("review_root_resurrection", "deleted"),
    ("review_root_epoch_decrease", "epoch"),
    ("review_serve_generation_receipt", "generation"),
    ("review_serve_generation_status", "generation"),
    ("review_serve_generation_resolve", "generation"),
    ("review_serve_generation_refusal", "generation"),
    ("review_home_missing_receipt", "current_receipt"),
    ("review_home_binding_root", "current_binding"),
    ("review_home_current_root", "current_receipt"),
    ("review_home_current_state_reserved", "current_receipt"),
    ("review_home_current_state_aborted", "current_receipt"),
    ("review_home_missing_binding_hash", "current_binding"),
    ("review_home_missing_binding", "current_binding"),
    ("review_home_binding_epoch", "epoch"),
    ("review_home_pending_root", "pending_receipt"),
    ("review_home_pending_state_committed", "pending_receipt"),
    ("review_home_pending_state_aborted", "pending_receipt"),
    ("review_home_pending_epoch", "pending_epoch"),
    ("review_home_pending_exhaustion", "pending_epoch"),
    ("review_home_initial_pending_epoch", "pending_epoch"),
    ("review_home_center", "center_id"),
    ("review_home_lookup_nameless", "lookup_allowed"),
    ("review_home_lookup_hidden", "lookup_allowed"),
    ("review_home_lookup_unenrolled", "lookup_allowed"),
    ("review_index_active_operation_NameRow", "operation_id"),
    ("review_index_reserved_operation_NameRow", "operation_id"),
    ("review_index_active_operation_SkeletonRow", "operation_id"),
    ("review_index_reserved_operation_SkeletonRow", "operation_id"),
    ("review_hold_key_skeleton", "skeleton"),
    ("review_absent_profile_epoch", "profile_ref"),
    ("review_absent_profile_hash", "profile_ref"),
    ("review_required_v2_DirectoryResolveBody", "profile"),
    ("review_required_v2_DirectoryReceiptBody", "profile"),
    ("review_profile_v2_epoch_zero", "epoch"),
    ("review_resolve_epoch_zero", "epoch"),
    ("review_width_UsernameBinding_signature_63", "signature"),
    ("review_width_UsernameBinding_signature_65", "signature"),
    ("review_width_SignedIdentityProfileV2_signature_63", "signature"),
    ("review_width_SignedIdentityProfileV2_signature_65", "signature"),
    ("review_width_UsernameOperation_signature_63", "signature"),
    ("review_width_UsernameOperation_signature_65", "signature"),
    ("review_width_DirectoryReceipt_signature_63", "signature"),
    ("review_width_DirectoryReceipt_signature_65", "signature"),
    ("review_width_DirectoryResolve_signature_63", "signature"),
    ("review_width_DirectoryResolve_signature_65", "signature"),
    ("review_width_ProfileRef_hash_31", "hash"),
    ("review_width_ProfileRef_hash_33", "hash"),
    ("review_width_AvatarRef_content_hash_31", "content_hash"),
    ("review_width_AvatarRef_content_hash_33", "content_hash"),
    ("review_width_AvatarRef_relay_ref_31", "relay_ref"),
    ("review_width_AvatarRef_relay_ref_33", "relay_ref"),
    ("review_width_RootRow_binding_hash_31", "binding_hash"),
    ("review_width_RootRow_binding_hash_33", "binding_hash"),
    ("review_width_RootRow_last_operation_id_31", "last_operation_id"),
    ("review_width_RootRow_last_operation_id_33", "last_operation_id"),
    ("review_width_RootRow_last_operation_hash_31", "last_operation_hash"),
    ("review_width_RootRow_last_operation_hash_33", "last_operation_hash"),
    ("review_width_RootRow_pending_operation_id_31", "pending_operation_id"),
    ("review_width_RootRow_pending_operation_id_33", "pending_operation_id"),
    ("review_width_NameRow_root_31", "root"),
    ("review_width_NameRow_root_33", "root"),
    ("review_width_NameRow_operation_id_31", "operation_id"),
    ("review_width_NameRow_operation_id_33", "operation_id"),
    ("review_width_SkeletonRow_root_31", "root"),
    ("review_width_SkeletonRow_root_33", "root"),
    ("review_width_SkeletonRow_operation_id_31", "operation_id"),
    ("review_width_SkeletonRow_operation_id_33", "operation_id"),
    ("review_width_OperationKey_root_31", "root"),
    ("review_width_OperationKey_root_33", "root"),
    ("review_width_OperationKey_operation_id_31", "operation_id"),
    ("review_width_OperationKey_operation_id_33", "operation_id"),
    ("review_width_OperationRow_operation_hash_31", "operation_hash"),
    ("review_width_OperationRow_operation_hash_33", "operation_hash"),
    ("review_width_OperationOwnerRow_root_31", "root"),
    ("review_width_OperationOwnerRow_root_33", "root"),
    ("review_width_OperationOwnerRow_operation_hash_31", "operation_hash"),
    ("review_width_OperationOwnerRow_operation_hash_33", "operation_hash"),
    ("review_width_HomeRevalidateRequest_root_31", "root"),
    ("review_width_HomeRevalidateRequest_root_33", "root"),
    ("review_width_HomeRevalidateRequest_operation_id_31", "operation_id"),
    ("review_width_HomeRevalidateRequest_operation_id_33", "operation_id"),
    ("review_width_HomeRevalidateRequest_nonce_31", "nonce"),
    ("review_width_HomeRevalidateRequest_nonce_33", "nonce"),
    ("review_width_HomeRevalidateResult_root_31", "root"),
    ("review_width_HomeRevalidateResult_root_33", "root"),
    ("review_width_HomeRevalidateResult_nonce_31", "nonce"),
    ("review_width_HomeRevalidateResult_nonce_33", "nonce"),
    ("review_width_CheckpointDelta_tx_id_31", "tx_id"),
    ("review_width_CheckpointDelta_tx_id_33", "tx_id"),
    ("review_width_CheckpointDelta_writer_incarnation_31", "writer_incarnation"),
    ("review_width_CheckpointDelta_writer_incarnation_33", "writer_incarnation"),
    ("review_safe_CheckpointDelta_clock_floor", "!i_json"),
    ("review_safe_Checkpoint_generation", "!i_json"),
    ("review_safe_Checkpoint_lsn", "!i_json"),
    ("review_width_Checkpoint_previous_digest_31", "previous_digest"),
    ("review_width_Checkpoint_previous_digest_33", "previous_digest"),
    ("review_width_UsernameBindingBody_principal_commitment_31", "principal_commitment"),
    ("review_width_UsernameBindingBody_principal_commitment_33", "principal_commitment"),
    ("review_width_IdentityProfileV2Body_principal_commitment_31", "principal_commitment"),
    ("review_width_IdentityProfileV2Body_principal_commitment_33", "principal_commitment"),
    ("review_width_UsernameOperationBody_operation_id_31", "operation_id"),
    ("review_width_UsernameOperationBody_operation_id_33", "operation_id"),
    ("review_width_UsernameOperationBody_principal_commitment_31", "principal_commitment"),
    ("review_width_UsernameOperationBody_principal_commitment_33", "principal_commitment"),
    ("review_width_DirectoryReceiptBody_operation_id_31", "operation_id"),
    ("review_width_DirectoryReceiptBody_operation_id_33", "operation_id"),
    ("review_width_DirectoryReceiptBody_operation_hash_31", "operation_hash"),
    ("review_width_DirectoryReceiptBody_operation_hash_33", "operation_hash"),
    ("review_width_DirectoryReceiptBody_principal_commitment_31", "principal_commitment"),
    ("review_width_DirectoryReceiptBody_principal_commitment_33", "principal_commitment"),
    ("review_width_DirectoryReceiptBody_binding_hash_31", "binding_hash"),
    ("review_width_DirectoryReceiptBody_binding_hash_33", "binding_hash"),
    ("review_width_DirectoryResolveBody_principal_commitment_31", "principal_commitment"),
    ("review_width_DirectoryResolveBody_principal_commitment_33", "principal_commitment"),
    ("review_width_DirectoryResolveBody_binding_hash_31", "binding_hash"),
    ("review_width_DirectoryResolveBody_binding_hash_33", "binding_hash"),
    ("review_width_DirectoryResolveBody_request_nonce_31", "request_nonce"),
    ("review_width_DirectoryResolveBody_request_nonce_33", "request_nonce"),
    ("review_duration_HomeRevalidateResult_zero", "expires_at"),
    ("review_duration_HomeRevalidateResult_reverse", "expires_at"),
    ("review_duration_DirectoryResolveBody_zero", "expires_at"),
    ("review_duration_DirectoryResolveBody_reverse", "expires_at"),
    ("review_operation_short_lifetime", "expires_at"),
];

fn require_review_coverage(vectors: &Corpus) -> Result<(), std::io::Error> {
    assert_eq!(vectors.review_rules.len(), REVIEW_RULES.len());
    for &(name, field) in REVIEW_RULES {
        assert_eq!(
            vectors.review_rules.get(name).map(String::as_str),
            Some(field),
            "review manifest {name}"
        );
        let mut matching = vectors.invalid.iter().filter(|case| case.name == name);
        let case = matching
            .next()
            .ok_or_else(|| std::io::Error::other(format!("missing review vector {name}")))?;
        assert!(matching.next().is_none(), "duplicate review vector {name}");
        assert_eq!(case.field, field, "specific rejection for {name}");
    }
    Ok(())
}

fn assert_negative_cases(cases: &[Case]) {
    let mut violations = Vec::new();
    for case in cases {
        let result = roundtrip(&case.kind, case.wire.as_bytes());
        let correct = if case.field == "!i_json" {
            matches!(&result, Err(CodecError::Protocol(crate::ProtocolError::IJson(_))))
        } else if case.field.is_empty() {
            result.is_err()
        } else {
            matches!(&result, Err(CodecError::Field(field)) if *field == case.field)
        };
        if !correct {
            let actual = match result {
                Ok(_) => "accepted".to_owned(),
                Err(error) => format!("{error:?}"),
            };
            violations.push(format!("{} expected {}: {actual}", case.name, case.field));
        }
    }
    assert!(violations.is_empty(), "negative vector failures:\n{}", violations.join("\n"));
}

#[test]
fn username_canonical_domains_and_maxima() -> Result<(), Box<dyn std::error::Error>> {
    assert!(!enabled());
    let vectors = corpus()?;
    require_review_coverage(&vectors)?;
    for case in &vectors.valid {
        if let Some(expected) = vectors.transcripts.get(&case.name) {
            let bytes = case.wire.as_bytes();
            let actual = match case.kind.as_str() {
                "UsernameBinding" => signing_bytes(&decode::<UsernameBinding>(bytes)?.body)?,
                "SignedIdentityProfileV2" => {
                    signing_bytes(&decode::<SignedIdentityProfileV2>(bytes)?.body)?
                }
                "UsernameOperation" => signing_bytes(&decode::<UsernameOperation>(bytes)?.body)?,
                "DirectoryReceipt" => signing_bytes(&decode::<DirectoryReceipt>(bytes)?.body)?,
                "DirectoryResolve" => signing_bytes(&decode::<DirectoryResolve>(bytes)?.body)?,
                _ => return Err(std::io::Error::other("unknown transcript kind").into()),
            };
            assert_eq!(actual, expected.as_bytes(), "{} frozen E transcript", case.name);
        }
    }
    assert_eq!(DirectoryFailure::new(DirectoryCode::Capacity, 0).retry_after_ms, Some(1000));
    assert_eq!(
        DirectoryFailure::new(DirectoryCode::RateLimited, u64::MAX).retry_after_ms,
        Some(60000)
    );
    assert_eq!(DirectoryCode::AuthenticationRequired.http_status(), 401);
    for case in vectors.valid {
        let bytes = roundtrip(&case.kind, case.wire.as_bytes())
            .map_err(|e| std::io::Error::other(format!("{}: {e}", case.name)))?;
        assert_eq!(bytes, case.wire.as_bytes(), "{} identity", case.name);
        assert_eq!(bytes.len(), case.bytes, "{} maximum", case.name);
    }
    assert_negative_cases(&vectors.invalid);
    let sources: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../scripts/reference/username_directory/oracle_sources.json"
    ))?;
    for (name, domain) in [
        ("USERNAME_BINDING", crate::domain::USERNAME_BINDING),
        ("IDENTITY_PROFILE_V2", crate::domain::IDENTITY_PROFILE_V2),
        ("USERNAME_OPERATION", crate::domain::USERNAME_OPERATION),
        ("USERNAME_OPERATION_HASH", crate::domain::USERNAME_OPERATION_HASH),
        ("USERNAME_CHECKPOINT", crate::domain::USERNAME_CHECKPOINT),
        ("USERNAME_PROFILE_HASH", crate::domain::USERNAME_PROFILE_HASH),
        ("USERNAME_BINDING_HASH", crate::domain::USERNAME_BINDING_HASH),
        ("USERNAME_RECEIPT", crate::domain::USERNAME_RECEIPT),
        ("USERNAME_RESOLVE", crate::domain::USERNAME_RESOLVE),
        ("AVATAR_CONTENT", crate::domain::AVATAR_CONTENT),
    ] {
        assert_eq!(sources["domains"][name].as_str(), Some(domain), "{name}");
    }
    for c in "abcdefghijklmnopqrstuvwxyz0123456789_".chars() {
        let name = c.to_string().repeat(5);
        let expected = match c {
            'm' => "rn".repeat(5),
            '0' => "O".repeat(5),
            '1' => "l".repeat(5),
            _ => name.clone(),
        };
        assert_eq!(crate::identity_name::username_comparison_key(&name)?, expected);
    }
    assert_eq!(normalize_username("  ALICE  ")?, "alice");
    assert_eq!(normalize_bio(" Cafe\u{301} ")?, "Café");
    Ok(())
}

#[test]
fn username_v1_native_profile_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let vectors = corpus()?;
    let legacy = vectors.legacy;
    let profile: crate::SignedIdentityProfile = crate::parse_i_json(legacy.profile.as_bytes())?;
    assert_eq!(crate::identity_profile_signing_bytes(&profile)?, legacy.signing.as_bytes());
    assert_eq!(crate::canonical_json_bytes(&profile)?, legacy.profile.as_bytes());
    let native: crate::custody::Profile = crate::parse_i_json(legacy.native.as_bytes())?;
    assert_eq!(crate::canonical_json_bytes(&native)?, legacy.native.as_bytes());
    let document = crate::identity_profile_v2::decode_profile_document(legacy.profile.as_bytes())?;
    assert!(matches!(document, crate::identity_profile_v2::IdentityProfileDocument::V1(_)));
    assert_eq!(document.encode()?, legacy.profile.as_bytes());
    let v2 = vectors
        .valid
        .iter()
        .find(|c| c.kind == "SignedIdentityProfileV2")
        .ok_or_else(|| std::io::Error::other("missing v2 fixture"))?;
    let parsed = crate::identity_profile_v2::decode_profile_document(v2.wire.as_bytes())?;
    assert!(matches!(parsed, crate::identity_profile_v2::IdentityProfileDocument::V2(_)));
    assert_eq!(parsed.encode()?, v2.wire.as_bytes());
    let invalid =
        v2.wire.replace(crate::domain::IDENTITY_PROFILE_V2, "ramflux.identity.profile.v9");
    assert!(crate::identity_profile_v2::decode_profile_document(invalid.as_bytes()).is_err());
    Ok(())
}
