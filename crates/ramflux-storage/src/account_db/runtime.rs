// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account runtime persistence facade.

mod acknowledgements;
mod config;
mod control;
mod operations;
mod outbox;
mod schema;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccountOutboxEntry {
    pub sequence: i64,
    pub table_name: String,
    pub change_kind: String,
    pub row_id: i64,
    #[serde(default)]
    pub keys: serde_json::Value,
}
