// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed CLI outcome categories. A failure prints one typed class line (an allow-listed code,
//! a fixed passphrase-policy sentence, or an HTTP status). Free-form diagnostic text, tokens
//! and identifiers never reach stderr. The passphrase sentence never includes the passphrase.
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
/// Error codes the CLI may name. Anything else prints the fixed category `unknown`.
const KNOWN_CODES: &[&str] = &[
    "Busy",
    "Expired",
    "Retired",
    "WrongRole",
    "WrongContext",
    "Replay",
    "HeadChanged",
    "PrimaryRequired",
    "SasMismatch",
    "PublicationPending",
    "TransferFloorsTooLarge",
    "TransferCapacity",
    "UpdateRequired",
    "VaultUnavailable",
    "NotFound",
    "InvalidInput",
    "UntrustedPeer",
    "LeaseExpired",
    "ChunkMismatch",
    "SchemaMismatch",
    "ManifestMismatch",
    "local_bus_error",
    "NetworkingPending",
    "NoNodeSelected",
    "AccountNotOpen",
    "CustodyVaultUnavailable",
    "CustodyExpired",
    "CustodySetupInvalid",
    "CustodyAccountConflict",
    "DataRootInUse",
    "GatewayWriterBusy",
    "Unsupported",
    "AuthorityUnavailable",
    "PrincipalIdTaken",
    "ChallengeUnknown",
    "ChallengeExpired",
    "BindingRefused",
    "SessionRequired",
    "SessionExpired",
    "Capacity",
    "PersistenceUnavailable",
    "HomeMigration",
    "AbortedRetrySafe",
    "CapacityRetryAfter",
    "IdempotencyConflict",
    "PayloadTooLarge",
    "FrameLimit",
];
/// The fixed category for a code outside the allowlist.
const UNKNOWN: &str = "unknown";
/// Longest local-bus code the CLI echoes after `unknown`.
const MAX_ECHOED_CODE: usize = 64;

fn known(code: &str) -> &'static str {
    KNOWN_CODES.iter().find(|candidate| **candidate == code).copied().unwrap_or(UNKNOWN)
}

/// A local-bus refusal: a listed code prints its text; an unlisted plain identifier prints
/// `unknown (<code>)`; anything else prints `unknown`. The free-text message is never printed.
fn refused_class(code: &str) -> String {
    let listed = known(code);
    if listed != UNKNOWN {
        listed.to_owned()
    } else if is_echoable_code(code) {
        format!("{UNKNOWN} ({code})")
    } else {
        UNKNOWN.to_owned()
    }
}

fn is_echoable_code(code: &str) -> bool {
    code.len() <= MAX_ECHOED_CODE
        && code.bytes().next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && code.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// A short typed class for a failed pairing command, safe to print: an allow-listed code name,
/// the fixed passphrase-policy sentence, or `HTTP <status>` for a pairing HTTPS refusal, else
/// `unknown`, or `unknown (<code>)` for an unlisted local-bus refusal code. No received text is
/// echoed.
pub(super) fn class(error: &RfError) -> String {
    use ramflux_sdk::SdkError;
    match error {
        RfError::Sdk(SdkError::PairingCode(code)) => known(code).to_owned(),
        RfError::Sdk(SdkError::PassphrasePolicy(error)) => error.user_message(),
        RfError::Sdk(SdkError::GatewayWriterBusy) => "GatewayWriterBusy".to_owned(),
        RfError::Sdk(SdkError::LocalBusRefused { code, message, .. }) => http_status(message)
            .map_or_else(|| refused_class(code), |status| format!("HTTP {status}")),
        RfError::Sdk(SdkError::LocalBus(message)) => http_status(message)
            .map_or_else(|| UNKNOWN.to_owned(), |status| format!("HTTP {status}")),
        RfError::Sdk(SdkError::CustodyNetwork(code) | SdkError::CustodyAdmission { code, .. }) => {
            known(code.reason_code()).to_owned()
        }
        _ => UNKNOWN.to_owned(),
    }
}
/// `"... pairing HTTPS status 400 <anything>"` yields 400. Exactly three digits, then end of
/// text or a space, in 100..=599; the suffix is dropped.
fn http_status(message: &str) -> Option<u16> {
    let rest = message.split("pairing HTTPS status ").nth(1)?;
    let digits: String = rest.chars().take(3).collect();
    let after = rest.chars().nth(3);
    if digits.len() != 3 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !matches!(after, None | Some(' ')) {
        return None;
    }
    digits.parse::<u16>().ok().filter(|status| (100..=599).contains(status))
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
        RfError::Sdk(
            ramflux_sdk::SdkError::CustodyNetwork(code)
            | ramflux_sdk::SdkError::CustodyAdmission { code, .. },
        ) => code_category(code.reason_code()),
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
