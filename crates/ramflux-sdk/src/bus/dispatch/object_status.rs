// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared read-only upload reconciliation used by actor and reader routes.

use crate::prelude::*;

pub(super) const OBJECT_PUT_STATE_RESUMABLE: &str = "resumable";

pub(in crate::bus) fn upload_status(
    client: &RamfluxClient,
    request: &LocalBusFrame,
    session_written: Option<usize>,
) -> Result<serde_json::Value, SdkError> {
    let body: LocalBusObjectPutStatusRequest = serde_json::from_value(request.body.clone())?;
    let record = client.object_operation(&body.object_id)?;
    let last_error = record
        .as_ref()
        .filter(|record| record.operation_id == body.operation_id)
        .and_then(|record| record.last_error.clone());
    let (state, terminal, resume_offset) = match record {
        Some(record) if record.operation_id == body.operation_id => {
            match record.state.as_str() {
                OBJECT_OPERATION_COMMITTED => {
                    (OBJECT_OPERATION_COMMITTED.to_owned(), record.terminal_result, None)
                }
                OBJECT_OPERATION_FAILED => (OBJECT_OPERATION_FAILED.to_owned(), None, None),
                // pending / local_committed: the finish/commit phase. Keep the raw state so the
                // A2 finish reconcile is unchanged; expose an offset only if a session survives.
                _ => (record.state, None, session_written),
            }
        }
        // No matching durable record: a live/rehydrated chunk-phase spool is `resumable`.
        _ => match session_written {
            Some(written) => (OBJECT_PUT_STATE_RESUMABLE.to_owned(), None, Some(written)),
            None => (OBJECT_OPERATION_UNKNOWN.to_owned(), None, None),
        },
    };
    let mut response = serde_json::json!({
        "object_id": body.object_id,
        "operation_id": body.operation_id,
        "state": state,
        "terminal": terminal,
        "last_error": last_error,
    });
    if let Some(offset) = resume_offset
        && let Some(map) = response.as_object_mut()
    {
        map.insert("resume_offset".to_owned(), serde_json::json!(offset));
    }
    Ok(response)
}
