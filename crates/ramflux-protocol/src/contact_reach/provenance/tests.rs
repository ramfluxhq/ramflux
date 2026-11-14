// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed owner-only provenance grammar and independent literal-domain hash coverage.
use super::*;
use crate::contact_reach::{self as wire, Operation, OperationResult};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn d(n: u8) -> String {
    crate::encode_base64url([n; 32])
}
fn proof() -> Result<ProvenanceAuthority, Box<dyn std::error::Error>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let authority = CustodyAuthority {
        publication: custody::Publication {
            record: serde_json::from_value(fixture.get("record").ok_or("native record")?.clone())?,
            compacted_ids: None,
        },
        custodian_publication: None,
    };
    let literal = serde_json::json!({"kind":"custody_authority","authority":authority,"custodian_history":[]});
    let mut hash = blake3::Hasher::new();
    hash.update(b"ramflux.contact.reach_operation.v1\0");
    hash.update(&crate::canonical_json_bytes(&literal)?);
    Ok(ProvenanceAuthority {
        proof_hash: crate::encode_base64url(hash.finalize().as_bytes()),
        authority,
        custodian_history: vec![],
    })
}
#[test]
fn cr_provenance_carrier_closed_native_hash_and_nulls() -> TestResult {
    let original = proof()?;
    original.validate()?;
    let literal = serde_json::json!({"kind":"reach_provenance","snapshot_id":d(1),"proof_hash":original.proof_hash});
    let operation: Operation =
        wire::decode(&crate::canonical_json_bytes(&literal)?, wire::MAX_FRAME_BYTES)?;
    assert_eq!(
        serde_json::to_value(&operation)?,
        literal,
        "owner proof operation has exactly the pinned selector fields"
    );
    let mut unknown = literal.clone();
    unknown
        .as_object_mut()
        .ok_or("operation object")?
        .insert("account_anchor".into(), serde_json::json!(d(2)));
    assert!(
        wire::decode::<Operation>(&crate::canonical_json_bytes(&unknown)?, wire::MAX_FRAME_BYTES)
            .is_err(),
        "the proof operation cannot become an arbitrary account-key lookup"
    );
    for field in ["snapshot_id", "proof_hash"] {
        let mut missing = literal.clone();
        missing.as_object_mut().ok_or("operation object")?.remove(field);
        assert!(
            wire::decode::<Operation>(
                &crate::canonical_json_bytes(&missing)?,
                wire::MAX_FRAME_BYTES
            )
            .is_err(),
            "both owner proof selectors are required"
        );
    }
    let mut missing = serde_json::to_value(&original)?;
    missing
        .get_mut("authority")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("native tuple")?
        .remove("custodian_publication");
    assert!(
        wire::decode::<ProvenanceAuthority>(
            &crate::canonical_json_bytes(&missing)?,
            wire::MAX_REPLY_BYTES
        )
        .is_err(),
        "native null custodian is explicit and covered by the full tuple hash"
    );
    let mut swapped = original.clone();
    swapped.authority.publication.compacted_ids = Some(vec![d(4)]);
    assert!(
        swapped.validate().is_err(),
        "compaction evidence substitution changes the full provenance hash even with the same record head"
    );
    for reason in [
        wire::Reason::ForeignSnapshotInvalid,
        wire::Reason::ForeignSnapshotExpired,
        wire::Reason::CustodyRefused,
        wire::Reason::ForeignCapacity,
    ] {
        operation.validate_result(&OperationResult::Error {
            reason,
            retry_after_ms: None,
            current_revision: None,
        })?;
    }
    assert!(
        operation
            .validate_result(&OperationResult::Error {
                reason: wire::Reason::ForeignRateLimited,
                retry_after_ms: Some(1000),
                current_revision: None
            })
            .is_err(),
        "provenance cannot invent a rate-hint result outside its closed error set"
    );
    Ok(())
}
