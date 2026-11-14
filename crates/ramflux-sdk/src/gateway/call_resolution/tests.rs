// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{CallOperationAction, CallSubmitOutcome, PendingCalls};
use ramflux_protocol::{CallResolution, CallResolutionState, CallSubmitContext, encode_base64url};
use tokio::time::{Duration, Instant};

fn context(call: u8, request: u8) -> CallSubmitContext {
    CallSubmitContext {
        version: 1,
        call_ref: encode_base64url([call; 16]),
        start_digest: encode_base64url([call; 32]),
        request_id: format!("request-{request}"),
        envelope_id: format!("envelope-{request}"),
        session_id: "session".into(),
        session_generation: encode_base64url([19; 32]),
    }
}

#[tokio::test(start_paused = true)]
async fn pending_caps_expiry_and_retirement_preserve_existing_operations()
-> Result<(), crate::SdkError> {
    let mut pending = PendingCalls::default();
    let deadline = Instant::now() + Duration::from_secs(10);
    for request in 0..8 {
        pending.install(context(1, request), deadline)?;
    }
    assert!(
        pending.install(context(1, 8), deadline).is_err(),
        "ninth same-call operation bypassed its cap"
    );
    for call in 2..=57 {
        pending.install(context(call, 0), deadline)?;
    }
    assert!(
        pending.install(context(58, 0), deadline).is_err(),
        "sixty-fifth session operation bypassed its cap"
    );
    let first = context(1, 0);
    let decision = CallResolution {
        context: first.clone(),
        state: CallResolutionState::Ringing,
        media_allowed: true,
        wake_resolved: false,
    };
    pending.observe(decision.clone());
    pending.observe(decision);
    assert!(
        pending.decision(&first)?.is_some(),
        "capacity refusal or duplicate erased an existing exact decision"
    );
    pending.retire(&first);
    assert!(
        pending.decision(&first).is_err(),
        "retired operation still authorized its old decision"
    );
    tokio::time::advance(Duration::from_secs(11)).await;
    pending.install(context(58, 0), Instant::now() + Duration::from_secs(10))?;
    assert!(
        pending.decision(&context(1, 1)).is_err(),
        "expired operation remained in the pending table"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn contradictory_decisions_and_late_writer_results_never_release_media()
-> Result<(), crate::SdkError> {
    let mut pending = PendingCalls::default();
    let context = context(1, 0);
    let deadline = Instant::now() + Duration::from_secs(10);
    pending.install(context.clone(), deadline)?;
    let decision = CallResolution {
        context: context.clone(),
        state: CallResolutionState::Answered,
        media_allowed: true,
        wake_resolved: true,
    };
    pending.observe(decision.clone());
    let outcome = CallSubmitOutcome {
        context: context.clone(),
        decision: decision.clone(),
        action: CallOperationAction::Answer,
        deadline,
    };
    assert!(outcome.permits_media(), "exact answered positive control was refused");
    let mut conflict = decision;
    conflict.media_allowed = false;
    pending.observe(conflict);
    assert!(
        pending.decision(&context).is_err(),
        "conflicting flags did not stick to their pending operation"
    );
    tokio::time::advance(Duration::from_secs(11)).await;
    assert!(
        !outcome.permits_media(),
        "delayed account writer applied an operation after its original deadline"
    );
    Ok(())
}
