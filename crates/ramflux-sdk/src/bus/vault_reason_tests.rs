// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wire contract of the bounded vault reason codes: error body, custody frames and decoders.
use crate::{SdkError, bus::io::local_bus_error_body, custody::CustodyVaultReason as R};

pub(crate) type Row = (R, &'static str, &'static str, bool, Option<u64>, Option<&'static str>);
pub(crate) const ROWS: [Row; 9] = [
    (R::Missing, "vault_missing", "CustodyVaultUnavailable", false, None, None),
    (
        R::InitPending,
        "vault_init_pending",
        "CustodyVaultUnavailable",
        false,
        None,
        Some("rf_vault_init"),
    ),
    (
        R::ImportPending,
        "vault_import_pending",
        "CustodyVaultUnavailable",
        false,
        None,
        Some("provisioning_import_retry"),
    ),
    (R::Corrupt, "vault_corrupt", "CustodyVaultUnavailable", false, None, None),
    (R::Permission, "vault_permission", "CustodyVaultUnavailable", false, None, None),
    (R::Locked, "vault_locked", "CustodyVaultUnavailable", false, None, None),
    (R::Busy, "vault_busy", "CustodyVaultUnavailable", true, Some(1_000), None),
    (
        R::PrimaryUnavailable,
        "vault_primary_unavailable",
        "CustodyVaultUnavailable",
        false,
        None,
        None,
    ),
    (R::ModeMismatch, "vault_mode_mismatch", "CustodySetupInvalid", false, None, None),
];

fn check_row(row: &Row) {
    let (reason, text, code, retryable, retry_after, remedy) = *row;
    let body = local_bus_error_body(&SdkError::CustodyVault(reason));
    assert_eq!(body.code, code, "{text} code");
    assert_eq!(body.reason_code.as_deref(), Some(text), "{text} reason");
    assert_eq!(body.message, text, "{text} message shows only the reason code");
    assert_eq!(body.retry_after_ms, retry_after, "{text} retry_after_ms");
    let details = body.details.as_deref().cloned().unwrap_or_default();
    assert_eq!(details["retryable"], serde_json::json!(retryable), "{text} retryable");
    assert_eq!(details.get("remedy").and_then(serde_json::Value::as_str), remedy, "{text} remedy");
    // The wire round trip reconstructs exactly this reason from the serialized body.
    let wire: serde_json::Value = serde_json::to_value(&body).unwrap_or_default();
    let decoded = R::from_wire(
        wire["code"].as_str().unwrap_or_default(),
        wire.get("reason_code").and_then(serde_json::Value::as_str),
    );
    assert_eq!(decoded, Some(reason), "{text} round trip");
}

#[test]
fn custody_vault_reason_codes_survive_bus_roundtrip() {
    check_row(&ROWS[0]);
    check_row(&ROWS[1]);
    check_row(&ROWS[2]);
    check_row(&ROWS[3]);
    check_row(&ROWS[4]);
    check_row(&ROWS[5]);
    check_row(&ROWS[6]);
    check_row(&ROWS[7]);
    check_row(&ROWS[8]);
    // The unit variant is unchanged: no reason, no details.
    let unit = local_bus_error_body(&SdkError::CustodyVaultUnavailable);
    assert_eq!(unit.code, "CustodyVaultUnavailable");
    assert!(unit.reason_code.is_none() && unit.details.is_none() && unit.retry_after_ms.is_none());
    let json = serde_json::to_value(&unit).unwrap_or_default();
    assert!(json.get("reason_code").is_none(), "the unit variant serializes no reason_code");
}

#[test]
fn custody_vault_reason_decoding_rejects_unknown_and_mismatched_wire_values() {
    assert_eq!(R::from_wire("CustodyVaultUnavailable", Some("vault_future_reason")), None);
    assert_eq!(R::from_wire("CustodyVaultUnavailable", None), None);
    assert_eq!(R::from_wire("CustodySetupInvalid", None), None);
    assert_eq!(R::from_wire("CustodySetupInvalid", Some("vault_busy")), None);
    assert_eq!(R::from_wire("CustodyVaultUnavailable", Some("vault_mode_mismatch")), None);
    assert_eq!(R::from_wire("Other", Some("vault_missing")), None);
    assert_eq!(
        R::from_wire("CustodySetupInvalid", Some("vault_mode_mismatch")),
        Some(R::ModeMismatch)
    );
}
