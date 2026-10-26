// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incremental response accounting: each candidate row is encoded once before insertion.
use super::{LocalBusFrame, SdkError, Value, body, local_bus_response};
pub(super) struct Budget {
    used: usize,
    limit: usize,
    count: usize,
    servers: bool,
}
impl Budget {
    pub(super) fn new(
        request: &LocalBusFrame,
        field: &str,
        limit: usize,
        reserve: usize,
    ) -> Result<Self, SdkError> {
        Ok(Self {
            used: serde_json::to_vec(&local_bus_response(request, body(field, &[], None)))?
                .len()
                .saturating_add(reserve),
            limit,
            count: 0,
            servers: field == "server_details",
        })
    }
    pub(super) fn admit(&mut self, row: &Value) -> Result<bool, SdkError> {
        let mut bytes = serde_json::to_vec(row)?.len() + usize::from(self.count > 0);
        if self.servers
            && let Some(id) = row.get("id")
        {
            bytes += serde_json::to_vec(id)?.len() + usize::from(self.count > 0);
        }
        if self.used.saturating_add(bytes) > self.limit {
            return Ok(false);
        }
        self.used += bytes;
        self.count += 1;
        Ok(true)
    }
}
