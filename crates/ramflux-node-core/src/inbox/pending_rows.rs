// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Preserve the historical snapshot array while maintaining ordered live rows.
use super::{BTreeMap, InboxEntry};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
type Rows = BTreeMap<String, BTreeMap<u64, InboxEntry>>;
pub(super) fn serialize<S: Serializer>(rows: &Rows, serializer: S) -> Result<S::Ok, S::Error> {
    let arrays: BTreeMap<_, Vec<_>> =
        rows.iter().map(|(target, entries)| (target, entries.values().collect())).collect();
    arrays.serialize(serializer)
}
pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Rows, D::Error> {
    let arrays = BTreeMap::<String, Vec<InboxEntry>>::deserialize(deserializer)?;
    Ok(arrays
        .into_iter()
        .map(|(target, entries)| {
            (target, entries.into_iter().map(|entry| (entry.inbox_seq, entry)).collect())
        })
        .collect())
}
