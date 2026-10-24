// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded account-owned forwarding work awaiting envelope preparation outside SQL transactions.
use super::{Carrier, invalid, key};
use crate::{RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub(crate) struct SurfaceLogicalJob {
    pub carrier: Carrier,
    pub group_epoch: Option<u64>,
    pub created_at: i64,
    pub attempts: u32,
    pub next_at: i64,
}
impl RamfluxClient {
    pub(super) fn queue_surface_logical(
        &self,
        kind: &str,
        id: &str,
        carrier: &Carrier,
        epoch: Option<u64>,
    ) -> Result<(), SdkError> {
        if !matches!(kind, "forward_job" | "receipt_job") {
            return Err(invalid("invalid surface forwarding kind"));
        }
        let db = self.account_db()?;
        let record = key(kind, id);
        if db.load_actor_state::<SurfaceLogicalJob>(&record)?.is_some() {
            return Ok(());
        }
        let job = SurfaceLogicalJob {
            carrier: carrier.clone(),
            group_epoch: epoch,
            created_at: crate::prelude::now_unix_timestamp(),
            attempts: 0,
            next_at: 0,
        };
        let mut count = 0;
        let mut bytes = serde_json::to_vec(&job)?.len();
        for prefix in ["surface/forward_job/", "surface/receipt_job/"] {
            let rows = db.surface_history_page::<SurfaceLogicalJob>(prefix, prefix, 65)?;
            count += rows.len();
            for row in rows {
                bytes = bytes.saturating_add(serde_json::to_vec(&row)?.len());
            }
        }
        if count >= 64 || bytes > 8 * 1024 * 1024 {
            return Err(SdkError::InboundPending("surface forwarding backpressure".into()));
        }
        db.persist_actor_state(&record, &job)?;
        Ok(())
    }
}
