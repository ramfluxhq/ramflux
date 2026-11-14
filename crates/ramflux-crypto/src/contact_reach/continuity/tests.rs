// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Existing signing bytes, chained possession and independent retained-key/time floors.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn key(seed: u8) -> String {
    crate::public_key_base64url_from_seed([seed; 32])
}
fn rotation(old: u8, new: u8, at: u64) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut value = wire::NodeKeyRotation {
        node_id: "peer.example".into(),
        old_node_public_key: key(old),
        new_node_public_key: key(new),
        rotated_at: at,
        signature: String::new(),
    };
    value.signature = crate::sign_protocol_object_with_seed(&value, [old; 32])?;
    Ok(serde_json::to_value(value)?)
}
#[test]
fn cr_node_rotations_bind_original_old_key_transcript_and_retained_suffix() -> TestResult {
    let proofs = vec![rotation(1, 2, 100)?, rotation(2, 3, 200)?];
    let old = key(1);
    let current = key(3);
    let context = NodeContinuityContext {
        node: "peer.example",
        old_key: &old,
        current_key: &current,
        minimum_rotated_at: 0,
        now: 300,
    };
    verify_node_continuity(&proofs, context)?;
    let middle = key(2);
    verify_node_continuity(
        &proofs,
        NodeContinuityContext { old_key: &middle, minimum_rotated_at: 100, ..context },
    )?;
    let mut invalid = proofs.clone();
    invalid.first_mut().ok_or("first rotation")?.as_object_mut().ok_or("proof")?.insert(
        "signature".into(),
        crate::sign_canonical_bytes_with_seed(
            &ramflux_protocol::custody::signing_bytes(
                "invented.rotation.domain",
                &proofs.first().ok_or("first proof")?,
            )?,
            [1; 32],
        )
        .into(),
    );
    assert!(
        verify_node_continuity(&invalid, context).is_err(),
        "a different domain cannot replace original signed_bytes"
    );
    assert!(
        verify_node_continuity(&[], context).is_err(),
        "new key possession alone cannot replace a retained key"
    );
    assert!(
        verify_node_continuity(
            &proofs,
            NodeContinuityContext { minimum_rotated_at: 100, ..context }
        )
        .is_err(),
        "the anchored suffix must be newer than the retained rotation floor"
    );
    Ok(())
}
#[test]
fn cr_node_rotations_refuse_retired_keys_forks_wrong_nodes_and_future_time() -> TestResult {
    let old = key(1);
    let current = key(3);
    let context = NodeContinuityContext {
        node: "peer.example",
        old_key: &old,
        current_key: &current,
        minimum_rotated_at: 0,
        now: 300,
    };
    for proofs in [
        vec![rotation(1, 2, 100)?, rotation(1, 3, 200)?],
        vec![rotation(1, 2, 100)?, rotation(2, 1, 200)?, rotation(1, 3, 250)?],
        vec![rotation(1, 2, 200)?, rotation(2, 3, 100)?],
        vec![rotation(1, 3, 301)?],
    ] {
        assert!(
            verify_node_continuity(&proofs, context).is_err(),
            "a valid individual signature cannot authorize an invalid chain or time"
        );
    }
    let proofs = vec![rotation(1, 3, 100)?];
    assert!(
        verify_node_continuity(&proofs, NodeContinuityContext { node: "other.example", ..context })
            .is_err(),
        "node identity is part of every existing rotation signature"
    );
    Ok(())
}
