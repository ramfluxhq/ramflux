// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::expect_used, reason = "independent wire assertions")]
use super::*;
use crate::router_store::publication::tests::entry;
fn independent_size(envelope: &ramflux_protocol::Envelope) -> usize {
    let row = serde_json::json!({"inbox_seq":u64::MAX,"target_delivery_id":envelope.target_delivery_id,"envelope":envelope});
    [serde_json::json!({"frame_type":"deliver","entry":row}),
        serde_json::json!({"frame_type":"deliver","incarnation_id":"ffffffffffffffffffffffffffffffff","entry":row,"retain_until":i64::MIN}),
        serde_json::json!({"frame_type":"entry","incarnation_id":"ffffffffffffffffffffffffffffffff","record":{"entry":row,"retain_until":i64::MIN}})]
        .iter().map(|frame|serde_json::to_vec(frame).expect("wire JSON").len()).max().expect("three frames")
}
#[test]
fn downstream_entry_bound_matches_actual_wire_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let mut envelope = entry(1).envelope;
    envelope.encrypted_payload.clear();
    envelope.ext.ext.insert("escaped_metadata".into(), serde_json::json!("\"\\\n".repeat(30)));
    let base = independent_size(&envelope);
    for over in [false, true] {
        envelope.encrypted_payload = "x".repeat(ENTRY_FRAME_BYTE_CAP - base + usize::from(over));
        let actual = independent_size(&envelope);
        assert_eq!(single_entry_frame_size(&envelope)?, actual);
        assert_eq!(actual, ENTRY_FRAME_BYTE_CAP + usize::from(over));
        assert_eq!(check_entry_bound(&envelope).is_err(), over);
    }
    Ok(())
}
