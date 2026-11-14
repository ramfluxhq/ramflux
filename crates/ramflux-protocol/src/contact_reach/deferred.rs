// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed refusals while dependent modules retain their own release gates.
use super::{MAX_FRAME_BYTES, OperationResult, Reason};

#[derive(serde::Deserialize)]
struct FrameType {
    frame_type: String,
}

#[must_use]
pub fn ephemeral_frame(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_FRAME_BYTES
        && crate::parse_i_json::<FrameType>(bytes)
            .is_ok_and(|value| value.frame_type == "contact_reach_ephemeral")
}

#[must_use]
pub const fn unavailable() -> OperationResult {
    OperationResult::Error {
        reason: Reason::FeatureDisabled,
        retry_after_ms: None,
        current_revision: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_deferred_ephemeral_is_recognized_without_a_new_request_grammar() {
        assert!(
            ephemeral_frame(br#"{"frame_type":"contact_reach_ephemeral","unknown_payload":null}"#),
            "any proposed volatile frame stays closed before payload interpretation"
        );
        assert!(
            !ephemeral_frame(br#"{"frame_type":"ephemeral"}"#),
            "ordinary non-reach typing retains its existing owner"
        );
        assert!(!super::super::enabled(), "dependent modules must land before reach activation");
    }
}
