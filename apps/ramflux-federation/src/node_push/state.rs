// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Applies an `ok` reply to the push state file: `dir` members and the key set (relayed, not verified).
use ramflux_node_core::push_handoff::{
    CentralClass, KeysetDoc, PushCentralState, PushPolicy, PushQuota, Served, TtlMax,
};
use serde_json::Value;

/// Largest key set document the node keeps (6144 bytes serialised, A3.1).
const MAX_DOC_LEN: usize = 6144;
/// Largest decoded key set body (A3.1).
const MAX_BODY_BYTES: usize = 4096;
/// Largest integer the seq may carry (2^53 - 1).
const MAX_SEQ: u64 = (1 << 53) - 1;

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// Returns the state with the `dir` of an `ok` reply applied. Absent members keep the old value,
/// except `served`, which is all `false` when absent (A6.4).
pub(crate) fn apply_ok(mut state: PushCentralState, reply: &Value) -> PushCentralState {
    if let Some(dir) = reply.get("dir") {
        state.served = dir
            .get("served")
            .and_then(|value| serde_json::from_value::<Served>(value.clone()).ok())
            .unwrap_or(Served { apns: false, apns_voip: false, fcm: false });
        if let Some(classes) = dir.get("classes").and_then(Value::as_array) {
            state.classes = classes
                .iter()
                .filter_map(|class| serde_json::from_value::<CentralClass>(class.clone()).ok())
                .collect();
        }
        if let Some(ttl) = dir
            .get("ttl_max_s")
            .and_then(|value| serde_json::from_value::<TtlMax>(value.clone()).ok())
        {
            state.ttl_max_s = ttl;
        }
        if let Some(policy) = dir
            .get("policy")
            .and_then(|value| serde_json::from_value::<PushPolicy>(value.clone()).ok())
        {
            state.policy = policy;
        }
        if let Some(quota) = dir
            .get("quota")
            .and_then(|value| serde_json::from_value::<PushQuota>(value.clone()).ok())
        {
            state.quota = Some(quota);
        }
    }
    if let Some(doc) =
        reply.get("ks").and_then(|value| serde_json::from_value::<KeysetDoc>(value.clone()).ok())
        && let Some(seq) = keyset_seq(&doc)
        && seq > state.ks_seq
    {
        state.ks_seq = seq;
        state.ks = Some(doc);
    }
    state.updated_at_ms = now_ms();
    state
}

/// The `seq` of a key set document, read from its unverified body (the node never verifies it).
/// Returns `None` for documents over the size bounds or with a malformed body.
fn keyset_seq(doc: &KeysetDoc) -> Option<u64> {
    let serialised = serde_json::to_vec(doc).ok()?;
    if serialised.len() > MAX_DOC_LEN {
        return None;
    }
    let body = ramflux_protocol::decode_base64url(&doc.body).ok()?;
    if body.len() > MAX_BODY_BYTES {
        return None;
    }
    let value: Value = ramflux_protocol::parse_i_json(&body).ok()?;
    let seq = value.get("seq")?.as_u64()?;
    (1..=MAX_SEQ).contains(&seq).then_some(seq)
}
