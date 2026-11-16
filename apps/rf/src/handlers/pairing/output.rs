// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed CLI outcome categories. A failure prints one typed class line (an allow-listed code or
//! an HTTP status); free-form diagnostic text, tokens and identifiers never reach stderr.
use super::{LocalResult, Outcome, RfError};
pub(super) fn code(value: Option<&str>) -> i32 {
    match value {
        None => 0,
        Some("Busy" | "PublicationPending") => 3,
        Some("SasMismatch") => 4,
        Some("PrimaryRequired") => 5,
        Some("UpdateRequired") => 6,
        Some("VaultUnavailable") => 7,
        Some(_) => 2,
    }
}
pub(super) fn outcome(result: &LocalResult) -> i32 {
    match &result.outcome {
        Outcome::Begin { .. } => 0,
        Outcome::Update { value } => code(value.result.as_deref()),
        Outcome::FullStatus { value } => code(value.result.map(
            ramflux_protocol::custody::pairing::full_transfer::FullError::legacy_update_result,
        )),
        Outcome::Error { error } => code(Some(&error.code)),
    }
}
/// A short typed class for a failed pairing command, safe to print: a closed code name or an
/// HTTP status. Everything else collapses to the error kind's name.
pub(super) fn class(error: &RfError) -> String {
    use ramflux_sdk::SdkError;
    let name_of = |debug: String| -> String {
        debug.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').take(48).collect()
    };
    match error {
        RfError::Sdk(SdkError::PairingCode(code)) => (*code).to_owned(),
        RfError::Sdk(SdkError::PairingField(field)) => format!("PairingField {field}"),
        RfError::Sdk(SdkError::GatewayWriterBusy) => "GatewayWriterBusy".to_owned(),
        RfError::Sdk(SdkError::LocalBusRefused { code, message, .. }) => {
            let code = bounded(code);
            match http_status(message) {
                Some(status) => format!("{code}: pairing HTTPS status {status}"),
                None => code,
            }
        }
        RfError::Sdk(SdkError::LocalBus(message)) => http_status(message).map_or_else(
            || "LocalBus".to_owned(),
            |status| format!("pairing HTTPS status {status}"),
        ),
        RfError::Sdk(other) => name_of(format!("{other:?}")),
        other => name_of(format!("{other:?}")),
    }
}
fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .take(64)
        .collect()
}
/// `"... pairing HTTPS status 400 Bad Request"` yields `"400 Bad Request"`; nothing else passes.
fn http_status(message: &str) -> Option<String> {
    let rest = message.split("pairing HTTPS status ").nth(1)?;
    let status: String =
        rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == ' ').take(40).collect();
    let digits = status.chars().take_while(char::is_ascii_digit).count();
    (digits == 3).then_some(status.trim().to_owned())
}
pub(super) fn failure(error: RfError) -> RfError {
    if !matches!(error, RfError::PairingExit { .. }) {
        eprintln!("Pairing error: {}", class(&error));
    }
    let exit = match error {
        RfError::PairingExit { .. } => return error,
        RfError::Sdk(ramflux_sdk::SdkError::GatewayWriterBusy) => 3,
        RfError::Sdk(ramflux_sdk::SdkError::PairingCode(code)) => code_category(code),
        RfError::Sdk(ramflux_sdk::SdkError::LocalBusRefused { code, .. }) => code_category(&code),
        _ => 1,
    };
    RfError::PairingExit { code: exit }
}
fn code_category(value: &str) -> i32 {
    match value {
        "Busy" | "busy" | "GatewayWriterBusy" | "PublicationPending" => 3,
        "SasMismatch" => 4,
        "PrimaryRequired" => 5,
        "UpdateRequired" => 6,
        "VaultUnavailable" | "CustodyVaultUnavailable" => 7,
        _ => 2,
    }
}

/// One compact JSON record. Public output cannot interleave terminal input or diagnostics.
pub(super) fn print(value: &serde_json::Value) -> Result<(), RfError> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
