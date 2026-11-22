// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use super::*;
use crate::cli::{TransferExportProbeAction, TransferExportProbeCommand};

pub(crate) async fn handle(
    socket: PathBuf,
    command: TransferExportProbeCommand,
) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(&socket).await?;
    let (method, body) = match command.action {
        TransferExportProbeAction::Write { directory } => (
            "itest.transfer_export.write",
            serde_json::json!({ "account": command.account, "directory": directory }),
        ),
        TransferExportProbeAction::Fresh => (
            "itest.transfer_export.fresh",
            serde_json::json!({ "account": command.account }),
        ),
        TransferExportProbeAction::Open { file, key_file, expected_root, clean_copy } => (
            "itest.transfer_export.open",
            serde_json::json!({
                "file": file,
                "key_file": key_file,
                "expected_root": expected_root,
                "clean_copy": clean_copy,
            }),
        ),
    };
    print_json(&bus.request(Some(command.account), "itest", method, body).await?)
}
