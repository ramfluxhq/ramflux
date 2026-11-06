// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validate router authority before forwarding a capable reply.
use super::{Retired, Value};
pub(super) fn page(
    value: &Value,
    target: &str,
    after: u64,
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    let issued = value["issued_inbox_seq"].as_u64().ok_or(Retired)?;
    let settled = value["settled_through_seq"].as_u64().ok_or(Retired)?;
    let covered = value["covered_through_seq"].as_u64().ok_or(Retired)?;
    anyhow::ensure!(
        value["target_delivery_id"] == target
            && value["after_inbox_seq"] == after
            && after <= covered
            && settled <= issued
            && covered <= issued
            && value["more"] == (covered < issued),
        Retired
    );
    let entries = value["entries"].as_array().ok_or(Retired)?;
    let losses = value["known_losses"].as_array().ok_or(Retired)?;
    anyhow::ensure!(entries.len() <= limit && losses.len() <= 64, Retired);
    let mut previous = after;
    for record in entries {
        let seq = record["entry"]["inbox_seq"].as_u64().ok_or(Retired)?;
        anyhow::ensure!(
            record["entry"]["target_delivery_id"] == target
                && seq > previous
                && seq <= covered
                && record["retain_until"].as_i64().is_some(),
            Retired
        );
        previous = seq;
    }
    previous = after;
    for loss in losses {
        let from = loss["from_seq"].as_u64().ok_or(Retired)?;
        let to = loss["to_seq"].as_u64().ok_or(Retired)?;
        anyhow::ensure!(
            from > previous
                && to >= from
                && to <= covered
                && serde_json::from_value::<ramflux_node_core::PageReason>(loss["reason"].clone())
                    .is_ok(),
            Retired
        );
        anyhow::ensure!(
            entries
                .iter()
                .all(|r| r["entry"]["inbox_seq"].as_u64().is_some_and(|s| s < from || s > to)),
            Retired
        );
        previous = to;
    }
    if !value["oversize_next"].is_null() {
        anyhow::ensure!(value["oversize_next"].as_u64() == covered.checked_add(1), Retired);
    }
    let bytes = serde_json::to_vec(value)?;
    anyhow::ensure!(bytes.len() <= ramflux_node_core::PAGE_BYTE_CAP, Retired);
    Ok(bytes)
}
pub(super) fn point(value: &Value, target: &str, seq: u64) -> anyhow::Result<Vec<u8>> {
    match value["frame_type"].as_str() {
        Some("entry") => anyhow::ensure!(
            value["record"]["entry"]["target_delivery_id"] == target
                && value["record"]["entry"]["inbox_seq"] == seq
                && value["record"]["retain_until"].as_i64().is_some(),
            Retired
        ),
        Some("entry_too_large") => anyhow::ensure!(
            value["inbox_seq"] == seq && value["retain_until"].as_i64().is_some(),
            Retired
        ),
        Some("entry_gone") => anyhow::ensure!(
            value["inbox_seq"] == seq
                && value["observed_issued_inbox_seq"].as_u64().is_some_and(|i| i >= seq)
                && value.get("retain_until").is_none()
                && serde_json::from_value::<ramflux_node_core::EntryGoneReason>(
                    value["reason"].clone()
                )
                .is_ok(),
            Retired
        ),
        _ => return Err(Retired.into()),
    }
    let bytes = serde_json::to_vec(value)?;
    anyhow::ensure!(bytes.len() <= ramflux_node_core::ENTRY_FRAME_BYTE_CAP, Retired);
    Ok(bytes)
}
pub(super) fn batch(value: &Value, target: &str, seqs: &[u64]) -> anyhow::Result<()> {
    anyhow::ensure!(value["cursor"]["target_delivery_id"] == target, Retired);
    let results = value["results"].as_array().ok_or(Retired)?;
    anyhow::ensure!(results.len() == seqs.len(), Retired);
    for (row, seq) in results.iter().zip(seqs) {
        anyhow::ensure!(row["inbox_seq"] == *seq, Retired);
        match row["outcome"].as_str() {
            Some("acked" | "already_settled" | "not_found" | "invalid_seq") => {
                anyhow::ensure!(row["reason"].is_null(), Retired);
            }
            Some("rejected") => anyhow::ensure!(
                matches!(row["reason"].as_str(), Some("ack_backpressure_retry" | "invalid_seq")),
                Retired
            ),
            _ => return Err(Retired.into()),
        }
    }
    Ok(())
}
