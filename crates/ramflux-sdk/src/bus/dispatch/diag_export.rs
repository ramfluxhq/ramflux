// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `diag.export` and `diag.snapshot` return the SDK part of a diagnostics bundle (C-10).

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::diag::export;
use crate::prelude::*;

pub(crate) fn dispatch_diag_export(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let data_root = &state.config.data_root;
    match request.method.as_str() {
        "diag.export" => {
            let since_ms = request.body.get("since_ms").and_then(serde_json::Value::as_u64);
            Ok(local_bus_ok(export::export(data_root, since_ms)))
        }
        "diag.snapshot" => Ok(local_bus_ok(export::snapshot(data_root))),
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}
