// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed CLI outcome categories; diagnostic text and identifiers never reach stderr.
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
pub(super) fn failure(error: RfError) -> RfError {
    let exit = match error {
        RfError::PairingExit { .. } => return error,
        RfError::Sdk(ramflux_sdk::SdkError::PairingCode(code)) => code_category(code),
        RfError::Sdk(ramflux_sdk::SdkError::LocalBusRefused { code, .. }) => code_category(&code),
        _ => 1,
    };
    RfError::PairingExit { code: exit }
}
fn code_category(value: &str) -> i32 {
    match value {
        "Busy" | "busy" | "PublicationPending" => 3,
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
