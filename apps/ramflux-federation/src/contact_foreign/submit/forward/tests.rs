// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native sender and federation signatures; network/publication acceptance is separate.
use super::*;
use crate::contact_foreign::test_support::{TestResult, node, submission};
#[test]
fn cr_submit_signs_the_complete_native_submission_without_resealing() -> TestResult {
    let request = submission()?;
    let node = node();
    let before = ramflux_protocol::canonical_json_bytes(&request.submission)?;
    let forward =
        signed(&request, &node).map_err(|reason| format!("native forward: {reason:?}"))?;
    assert_eq!(
        ramflux_protocol::canonical_json_bytes(&forward.submission)?,
        before,
        "the federation signer must preserve the sender's complete original envelope/route/cost"
    );
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(&forward)?,
        &forward.signature,
        &node.node_public_key,
    )?;
    assert_eq!(
        forward,
        signed(&request, &node).map_err(|reason| format!("exact retry: {reason:?}"))?,
        "retrying the same frozen submission must preserve the exact deterministic forward bytes"
    );
    let mut changed = forward;
    changed.submission.envelope.encrypted_payload.push('A');
    assert!(
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&changed)?,
            &changed.signature,
            &node.node_public_key,
        )
        .is_err(),
        "a changed sealed payload cannot borrow the federation signature"
    );
    let mut wrong = node;
    wrong.node_signing_seed = [15; 32];
    assert!(
        matches!(signed(&request, &wrong), Err(Reason::ForeignUnavailable)),
        "misconfigured node signing material must refuse before dispatch"
    );
    Ok(())
}
