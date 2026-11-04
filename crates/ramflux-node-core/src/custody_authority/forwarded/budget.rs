// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Foreign pin quotas and LRU eviction preserve durable references and denial floors.
use super::{FOREIGN, storage};
use crate::NodeCoreError;
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("foreign_pin_metadata_v1");
const MAX_ANCHORS: usize = 4096;
const MAX_PEER: usize = 256;
const MAX_BYTES: usize = 16 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Meta {
    peer: String,
    touched: u64,
}
fn capacity() -> NodeCoreError {
    NodeCoreError::Capacity { resource: "foreign custody pins" }
}
fn denial(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Object(o) => o.iter().any(|(k, v)| {
            (["revoked_ids", "fenced_ranges", "conflicts"].contains(&k.as_str())
                && v.as_array().is_none_or(|a| !a.is_empty())
                && v.as_object().is_none_or(|o| !o.is_empty()))
                || denial(v)
        }),
        serde_json::Value::Array(a) => a.iter().any(denial),
        _ => false,
    }
}
fn protected(bytes: &[u8]) -> Result<bool, NodeCoreError> {
    let state: super::CustodyAccountState = serde_json::from_slice(bytes).map_err(storage)?;
    // Retain every evolved head; only pristine genesis pins may be evicted.
    let value = serde_json::to_value(&state.pins).map_err(storage)?;
    Ok(state
        .pins
        .accepted_epoch_floor(&state.publication.record.body.account_anchor)
        .is_some_and(|e| ramflux_protocol::custody::decode_epoch(e).ok() != Some((1, 1)))
        || denial(&value))
}
pub(super) fn insert(
    tx: &redb::WriteTransaction,
    peer: &str,
    anchor: &str,
    bytes: &[u8],
    now: u64,
) -> Result<(), NodeCoreError> {
    insert_bounded(tx, peer, anchor, bytes, now, MAX_ANCHORS, MAX_PEER, MAX_BYTES)
}
#[expect(
    clippy::too_many_arguments,
    reason = "testable quota policy at one atomic transaction boundary"
)]
fn insert_bounded(
    tx: &redb::WriteTransaction,
    peer: &str,
    anchor: &str,
    bytes: &[u8],
    now: u64,
    max_anchors: usize,
    max_peer: usize,
    max_bytes: usize,
) -> Result<(), NodeCoreError> {
    if peer.len() > 256 || bytes.len() > max_bytes {
        return Err(capacity());
    }
    let mut rows = Vec::new();
    {
        let table = tx.open_table(FOREIGN).map_err(storage)?;
        let metadata = tx.open_table(META).map_err(storage)?;
        for row in table.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let meta = metadata
                .get(key.value())
                .map_err(storage)?
                .map(|v| serde_json::from_slice::<Meta>(v.value()).map_err(storage))
                .transpose()?
                .unwrap_or(Meta { peer: "legacy".into(), touched: 0 });
            rows.push((key.value().to_owned(), value.value().to_vec(), meta));
        }
    }
    let owner = rows
        .iter()
        .find(|(k, _, _)| k == anchor)
        .map_or(peer, |(_, _, m)| m.peer.as_str())
        .to_owned();
    let mut removals = Vec::new();
    loop {
        let others: Vec<_> =
            rows.iter().filter(|(k, _, _)| k != anchor && !removals.contains(k)).collect();
        let peer_full = others.iter().filter(|(_, _, m)| m.peer == owner).count() >= max_peer;
        if others.len() < max_anchors
            && !peer_full
            && others.iter().map(|(_, v, _)| v.len()).sum::<usize>().saturating_add(bytes.len())
                <= max_bytes
        {
            break;
        }
        let mut candidates: Vec<_> =
            others.into_iter().filter(|(_, _, m)| !peer_full || m.peer == owner).collect();
        candidates.sort_by_key(|(_, _, m)| m.touched);
        let mut victim = None;
        for (key, value, _) in candidates {
            if protected(value)? {
                continue;
            }
            // Receipts are written in the same transaction as every forwarded durable inbox row.
            let prefix = format!("v3/{}/", ramflux_protocol::encode_base64url(key));
            let table =
                tx.open_table(crate::ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE).map_err(storage)?;
            if table
                .range(prefix.as_str()..)
                .map_err(storage)?
                .next()
                .transpose()
                .map_err(storage)?
                .is_some_and(|(k, _)| k.value().starts_with(&prefix))
            {
                continue;
            }
            victim = Some(key.clone());
            break;
        }
        removals.push(victim.ok_or_else(capacity)?);
    }
    let mut table = tx.open_table(FOREIGN).map_err(storage)?;
    let mut metadata = tx.open_table(META).map_err(storage)?;
    for key in removals {
        table.remove(key.as_str()).map_err(storage)?;
        metadata.remove(key.as_str()).map_err(storage)?;
    }
    table.insert(anchor, bytes).map_err(storage)?;
    let touched =
        rows.iter().map(|(_, _, m)| m.touched).max().unwrap_or(0).saturating_add(1).max(now);
    metadata
        .insert(
            anchor,
            serde_json::to_vec(&Meta { peer: owner, touched }).map_err(storage)?.as_slice(),
        )
        .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn state(anchor: &str) -> Result<Vec<u8>> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
        ))?;
        let mut publication: crate::CustodyPublication = serde_json::from_value(
            serde_json::json!({"record":fixture["record"],"compacted_ids":null}),
        )?;
        publication.record.body.account_anchor = anchor.into();
        Ok(serde_json::to_vec(&super::super::CustodyAccountState {
            publication,
            pins: ramflux_crypto::custody::AuthorityPins::default(),
        })?)
    }
    fn database() -> Result<(std::path::PathBuf, redb::Database)> {
        let path = std::env::temp_dir().join(format!(
            "rf-pin-budget-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let db = redb::Database::create(&path)?;
        Ok((path, db))
    }
    fn referenced(tx: &redb::WriteTransaction, anchor: &str) -> Result {
        let key = format!("v3/{}/entry/target", ramflux_protocol::encode_base64url(anchor));
        tx.open_table(crate::ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?
            .insert(key.as_str(), b"receipt".as_slice())?;
        Ok(())
    }
    #[test]
    fn foreign_pin_store_evicts_unreferenced_lru_and_keeps_referenced_pins() -> Result {
        let (path, db) = database()?;
        let tx = db.begin_write()?;
        for anchor in ["protected", "old", "recent"] {
            insert_bounded(&tx, "peer", anchor, &state(anchor)?, 1, 3, 3, 100_000)?;
        }
        referenced(&tx, "protected")?;
        insert_bounded(&tx, "peer", "new", &state("new")?, 1, 3, 3, 100_000)?;
        let table = tx.open_table(FOREIGN)?;
        assert!(table.get("old")?.is_none());
        for anchor in ["protected", "recent", "new"] {
            assert!(table.get(anchor)?.is_some());
        }
        drop(table);
        tx.commit()?;
        drop(db);
        std::fs::remove_file(path)?;
        Ok(())
    }
    #[test]
    fn one_peer_cannot_exhaust_foreign_pin_store_for_others() -> Result {
        let (path, db) = database()?;
        let tx = db.begin_write()?;
        for anchor in ["a1", "a2"] {
            insert_bounded(&tx, "A", anchor, &state(anchor)?, 1, 4, 2, 100_000)?;
            referenced(&tx, anchor)?;
        }
        assert!(matches!(
            insert_bounded(&tx, "A", "a3", &state("a3")?, 1, 4, 2, 100_000),
            Err(NodeCoreError::Capacity { .. })
        ));
        insert_bounded(&tx, "B", "b1", &state("b1")?, 1, 4, 2, 100_000)?;
        assert!(tx.open_table(FOREIGN)?.get("b1")?.is_some());
        tx.commit()?;
        drop(db);
        std::fs::remove_file(path)?;
        Ok(())
    }
    #[test]
    fn full_foreign_pin_store_returns_classified_retryable_refusal() -> Result {
        let (path, db) = database()?;
        let tx = db.begin_write()?;
        insert_bounded(&tx, "A", "a", &state("a")?, 1, 1, 1, 100_000)?;
        referenced(&tx, "a")?;
        assert!(matches!(
            insert_bounded(&tx, "B", "b", &state("b")?, 1, 1, 1, 100_000),
            Err(NodeCoreError::Capacity { resource: "foreign custody pins" })
        ));
        assert!(tx.open_table(FOREIGN)?.get("a")?.is_some());
        tx.commit()?;
        // The total byte budget independently refuses an oversized replacement.
        let tx = db.begin_write()?;
        assert!(matches!(
            insert_bounded(&tx, "A", "a", &state("a")?, 1, 2, 2, 1),
            Err(NodeCoreError::Capacity { .. })
        ));
        drop(tx);
        drop(db);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
