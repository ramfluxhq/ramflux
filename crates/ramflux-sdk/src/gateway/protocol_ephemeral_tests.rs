// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK `ephemeral_result` outcome/reason coupling is enforced when received bytes are decoded.

use super::GatewayServerFrame;
use ramflux_protocol::ephemeral::{
    EphemeralDropReason, EphemeralSubmitResult, RESULT_ACCEPTED_WITH_REASON,
    RESULT_DROPPED_WITHOUT_REASON,
};

fn refusal(bytes: &[u8]) -> Option<String> {
    let error = serde_json::from_slice::<GatewayServerFrame>(bytes).err()?.to_string();
    Some(error.split(" at line ").next().unwrap_or_default().to_owned())
}

#[test]
fn ephemeral_result_coupling_is_refused_at_decode() {
    let dropped_bare =
        br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"dropped"}"#;
    let dropped_null =
        br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"dropped","reason":null}"#;
    let accepted_reason = br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"accepted","reason":"offline"}"#;
    assert_eq!(refusal(dropped_bare).as_deref(), Some(RESULT_DROPPED_WITHOUT_REASON));
    assert_eq!(refusal(dropped_null).as_deref(), Some(RESULT_DROPPED_WITHOUT_REASON));
    assert_eq!(refusal(accepted_reason).as_deref(), Some(RESULT_ACCEPTED_WITH_REASON));
    let unknown = br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"dropped","reason":"nope"}"#;
    assert!(refusal(unknown).is_some_and(|e| e.starts_with("unknown variant `nope`")));
    let outcome = br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"maybe"}"#;
    assert!(refusal(outcome).is_some_and(|e| e.starts_with("unknown variant `maybe`")));
}

#[test]
fn ephemeral_result_valid_pairs_round_trip_bytes() -> Result<(), serde_json::Error> {
    let accepted = br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"accepted"}"#;
    let dropped = br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"dropped","reason":"rate_limited"}"#;
    for (bytes, result) in [
        (&accepted[..], EphemeralSubmitResult::accepted()),
        (&dropped[..], EphemeralSubmitResult::dropped(EphemeralDropReason::RateLimited)),
    ] {
        let frame: GatewayServerFrame = serde_json::from_slice(bytes)?;
        assert_eq!(
            frame,
            GatewayServerFrame::EphemeralResult { envelope_id: "e1".to_owned(), result }
        );
        assert_eq!(serde_json::to_vec(&frame)?, bytes);
    }
    Ok(())
}
