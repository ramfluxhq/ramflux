// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compact local consent metadata, independent of cached public device manifests.
use super::{Control, Decision, invalid};
use crate::prelude::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Default, Deserialize, Serialize)]
pub(super) struct Metadata {
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub issued_at: i64,
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs_reply: Option<Decision>,
}
impl Metadata {
    pub fn from_control(control: &Control) -> Self {
        Self {
            nonce: control.body.nonce.clone(),
            issued_at: control.body.issued_at,
            note: control.body.note.clone(),
            needs_reply: None,
        }
    }
    pub fn read(row: &ramflux_storage::ContactRequestRecord) -> Result<Self, SdkError> {
        let value: serde_json::Value = serde_json::from_slice(&row.request_json)?;
        if value.get("body").is_some() {
            let control: Control = serde_json::from_value(value)?;
            Ok(Self::from_control(&control))
        } else {
            Ok(serde_json::from_value(value)?)
        }
    }
    pub fn valid_for(&self, requester: &str, id: &str) -> Result<bool, SdkError> {
        Ok(!self.nonce.is_empty() && super::wire::request_id(requester, &self.nonce)? == id)
    }
    pub fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 1024 {
            return Err(invalid("contact metadata exceeds its budget"));
        }
        Ok(bytes)
    }
}
