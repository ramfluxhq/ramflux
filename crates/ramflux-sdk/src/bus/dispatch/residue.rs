// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `diag.residue` reads one marker from the request body and returns locations.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::diag::{ResidueDiagnostic, ResidueDirectory, diagnose_plaintext_residue};
use crate::prelude::*;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const MAX_MARKER_TEXT: usize = 8192;
const SCAN_BUDGET: Duration = Duration::from_secs(30);

pub(crate) fn dispatch_residue(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    match request.method.as_str() {
        "diag.residue" => scan(request, state, account_id),
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn scan(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let encoded = request
        .body
        .get("marker_base64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SdkError::LocalBus("residue marker is missing".into()))?;
    if encoded.is_empty() || encoded.len() > MAX_MARKER_TEXT {
        return Err(SdkError::LocalBus("residue marker is invalid".into()));
    }
    let mut marker = Marker(
        ramflux_protocol::decode_base64url(encoded)
            .map_err(|_| SdkError::LocalBus("residue marker is invalid".into()))?,
    );
    let account = local_bus_account(state, account_id)?;
    let directories = [
        ResidueDirectory {
            path: object_put_account_dir(&state.config.data_root, account_id),
            scope: "account",
        },
        ResidueDirectory { path: object_get_spool_dir(&state.config.data_root), scope: "shared" },
    ];
    let mut diagnostic = ResidueDiagnostic {
        account_id,
        marker: &mut marker.0,
        data_root: &state.config.data_root,
        directories: &directories,
        deadline: Instant::now() + SCAN_BUDGET,
    };
    let report = diagnose_plaintext_residue(&account.client, &mut diagnostic);
    Ok(local_bus_ok(report?))
}

struct Marker(Vec<u8>);

impl Drop for Marker {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
