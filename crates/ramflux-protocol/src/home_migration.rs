// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cooperative born-v3 home changes over the exporter-bound custody connection.
mod control;
mod messages;
mod records;
use crate::{ProtocolError, canonical_json_bytes, custody, domain};
pub use control::*;
pub use messages::*;
pub use records::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_MESSAGE_BYTES: usize = 8192;
pub const MAX_RESOLVE_BYTES: usize = 1024 * 1024;
pub const MAX_CHAIN_RECORDS: usize = 64;
pub const MAX_CONTROL_BYTES: usize = 64 * 1024;
pub const MAX_FRAME_BYTES: usize = custody::MAX_CUSTODY_FRAME_BYTES;
pub const SKEW_SECONDS: u64 = 300;
pub const MAX_SEAL_DELAY: u64 = 600;
pub const MAX_COMMIT_DELAY: u64 = 600;
pub const FORWARD_SECONDS: u64 = 86400;

pub(crate) fn invalid(reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidIdentityRecord(reason)
}
/// Decode original bounded I-JSON bytes; nullable fields must be explicit.
/// # Errors
/// Rejects duplicate/unknown/missing fields, unsafe numbers, depth and byte overflow.
pub fn decode<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, ProtocolError> {
    let value: T = custody::decode(bytes, limit.min(MAX_FRAME_BYTES))?;
    safe_numbers(&serde_json::to_value(&value)?)?;
    Ok(value)
}
fn safe_numbers(value: &Value) -> Result<(), ProtocolError> {
    match value {
        Value::Number(n) if n.as_u64().is_none_or(|n| n > crate::MAX_SAFE_JSON_INTEGER) => {
            return Err(invalid("unsafe migration integer"));
        }
        Value::Array(values) => {
            for value in values {
                safe_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for (name, value) in values {
                if let Value::String(text) = value {
                    let max = if matches!(name.as_str(), "gateway_tcp_addr" | "federation_endpoint")
                    {
                        2048
                    } else {
                        256
                    };
                    if text.len() > max {
                        return Err(invalid("migration identifier exceeds budget"));
                    }
                }
                safe_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
#[derive(Serialize)]
struct Transcript<'a, T> {
    schema: &'a str,
    domain: &'a str,
    body: &'a T,
    signers: &'a [Signer],
}

/// Role/key metadata is part of the signature, with schema equal to the type's domain.
/// # Errors
/// Rejects a substituted schema/domain, role order or unsupported message version.
pub fn signing_bytes<T: Message>(message: &Signed<T>) -> Result<Vec<u8>, ProtocolError> {
    if message.schema != T::DOMAIN
        || message.domain != T::DOMAIN
        || message.signers.iter().map(|s| s.role).ne(T::ROLES.iter().copied())
        || serde_json::to_value(&message.body)?.get("version").and_then(Value::as_u64) != Some(1)
    {
        return Err(invalid("migration schema, version or signer role mismatch"));
    }
    safe_numbers(&serde_json::to_value(&message.body)?)?;
    canonical_json_bytes(&Transcript {
        schema: &message.schema,
        domain: &message.domain,
        body: &message.body,
        signers: &message.signers,
    })
}
/// Hash a whole signed message, retaining every signature.
/// # Errors
/// Returns schema or canonicalization failures.
pub fn message_hash<T: Message>(message: &Signed<T>) -> Result<String, ProtocolError> {
    signing_bytes(message)?;
    custody::framed_hash(domain::CUSTODY_OBJECT_HASH, message)
}
/// Hash a composite committed home, including its old-home commit proof.
/// # Errors
/// Returns canonicalization failures.
pub fn record_hash(record: &HomeRecord) -> Result<String, ProtocolError> {
    custody::framed_hash(domain::HOME_RECORD_HASH, record)
}
/// Hash the complete canonical delivery map, never a client-chosen roster subset.
/// # Errors
/// Returns canonicalization failures.
pub fn delivery_map_hash(map: &[DeliveryMapEntry]) -> Result<String, ProtocolError> {
    custody::framed_hash(domain::HOME_DELIVERY_MAP, &map)
}

#[cfg(test)]
mod tests;
