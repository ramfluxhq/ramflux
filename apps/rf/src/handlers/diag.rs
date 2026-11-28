// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use super::*;
use zeroize::Zeroize;

pub(crate) async fn handle(socket: PathBuf, command: DiagCommand) -> Result<(), RfError> {
    match command.action {
        DiagAction::Residue(residue) => scan_residue(socket, residue).await,
        DiagAction::Export(args) => export_bundle(socket, args).await,
        DiagAction::Snapshot => snapshot(socket).await,
    }
}

async fn export_bundle(socket: PathBuf, args: ExportArgs) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(&socket).await?;
    let body = match args.since_ms {
        Some(since_ms) => serde_json::json!({ "since_ms": since_ms }),
        None => serde_json::json!({}),
    };
    let response = bus.request(None, "diag", "diag.export", body).await;
    print_json(&response?)
}

async fn snapshot(socket: PathBuf) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(&socket).await?;
    let response = bus.request(None, "diag", "diag.snapshot", serde_json::json!({})).await;
    print_json(&response?)
}

async fn scan_residue(socket: PathBuf, residue: ResidueArgs) -> Result<(), RfError> {
    let marker = Marker(crate::cli::read_marker_file(&residue.marker_file)?);
    let mut bus = LocalBusClient::connect(&socket).await?;
    let mut encoded = SecretString(ramflux_protocol::encode_base64url(&marker.0));
    let mut body = SecretBody(serde_json::json!({
        "marker_base64": encoded.0.clone(),
    }));
    let response = bus.request(Some(residue.account), "diag", "diag.residue", body.0.clone()).await;
    encoded.wipe();
    body.wipe();
    print_json(&response?)
}

struct Marker(Vec<u8>);

impl Drop for Marker {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SecretString(String);

impl SecretString {
    fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.wipe();
    }
}

struct SecretBody(serde_json::Value);

impl SecretBody {
    fn wipe(&mut self) {
        let Some(serde_json::Value::String(text)) = self.0.get_mut("marker_base64") else {
            return;
        };
        text.zeroize();
    }
}

impl Drop for SecretBody {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sent_marker_encoding_is_zeroized() {
        let encoded = ramflux_protocol::encode_base64url(b"b11canarymarker");
        let mut secret = SecretString(encoded.clone());
        let mut body = SecretBody(serde_json::json!({ "marker_base64": encoded.clone() }));
        secret.wipe();
        body.wipe();
        assert_eq!(secret.0.len(), 0, "the base64url string is cleared");
        assert!(!secret.0.contains(encoded.as_str()));
        let field =
            body.0.get("marker_base64").and_then(serde_json::Value::as_str).expect("test: field");
        assert_eq!(field.len(), 0, "the json marker value is cleared");
        assert!(!body.0.to_string().contains(&encoded));
    }
}
