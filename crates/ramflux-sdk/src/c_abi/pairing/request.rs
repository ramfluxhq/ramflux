// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One closed DTO family; the ABI adapter adds no pairing state or secret JSON fields.
use super::super::{CAbiError, CAbiResult, RamfluxErrorCode};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    local_dto::{
        Approve, Begin, Cancel, Confirm, FullTransferBegin, Join, LocalResult, Outcome, Prepare,
        StatusRequest, TransferAffirm,
    },
};
use serde::Serialize;
fn invalid() -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, "invalid pairing request")
}
fn decode<T: PairingWire + Serialize>(bytes: &[u8]) -> CAbiResult<serde_json::Value> {
    let value = T::from_wire_bytes(bytes).map_err(|_| invalid())?;
    if value.to_wire_bytes().map_err(|_| invalid())?.as_slice() != bytes {
        return Err(invalid());
    }
    serde_json::to_value(value).map_err(|_| invalid())
}
pub(super) fn body(method: &str, bytes: &[u8]) -> CAbiResult<serde_json::Value> {
    match method {
        "device.pair.begin" => decode::<Begin>(bytes),
        "device.transfer.begin" => decode::<FullTransferBegin>(bytes),
        "device.pair.join" | "device.transfer.join" => decode::<Join>(bytes),
        "device.pair.confirm" | "device.transfer.confirm" => decode::<Confirm>(bytes),
        "device.pair.approve" => decode::<Approve>(bytes),
        "device.pair.cancel" | "device.transfer.cancel" => decode::<Cancel>(bytes),
        "device.pair.status" | "device.transfer.status" => decode::<StatusRequest>(bytes),
        "device.transfer.prepare" => decode::<Prepare>(bytes),
        "device.transfer.affirm" => decode::<TransferAffirm>(bytes),
        _ => Err(invalid()),
    }
}
pub(super) fn refusal(code: &str) -> CAbiResult<LocalResult> {
    let code = ramflux_protocol::custody::pairing::full_transfer::FullError::from_code(code)
        .map_or(code, |error| error.legacy_update_result());
    let mut result = LocalResult {
        schema: "ramflux.pairing.LocalResult.v2".into(),
        version: 2,
        outcome: Outcome::Error {
            error: ramflux_protocol::custody::pairing::native::Failure {
                schema: "ramflux.pairing.Failure.v2".into(),
                version: 2,
                code: code.into(),
                retry_after_ms: None,
            },
        },
    };
    if result.validate().is_err() {
        if let Outcome::Error { error } = &mut result.outcome {
            error.code = "InvalidInput".into();
        }
    }
    result.validate().map_err(|_| invalid())?;
    Ok(result)
}
