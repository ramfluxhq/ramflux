// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use super::*;
use zeroize::Zeroize;

pub(crate) async fn handle(socket: PathBuf, command: DiagCommand) -> Result<(), RfError> {
    match command.action {
        DiagAction::Residue(residue) => scan_residue(socket, residue).await,
    }
}

async fn scan_residue(socket: PathBuf, residue: ResidueArgs) -> Result<(), RfError> {
    let marker = Marker(crate::cli::read_marker_file(&residue.marker_file)?);
    let mut bus = LocalBusClient::connect(&socket).await?;
    let response = bus
        .request(
            Some(residue.account),
            "diag",
            "diag.residue",
            serde_json::json!({
                "marker_base64": ramflux_protocol::encode_base64url(&marker.0),
            }),
        )
        .await;
    print_json(&response?)
}

struct Marker(Vec<u8>);

impl Drop for Marker {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
