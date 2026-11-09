// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

const BODY_250KB: usize = 250 * 1024;

fn inject_compact_object_pad(
    envelope: &ramflux_protocol::Envelope,
    object: &str,
    pad: serde_json::Value,
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut sidecar: serde_json::Value =
        serde_json::from_slice(compact.sidecar).map_err(|error| invalid(&error.to_string()))?;
    sidecar[object]["pad"] = pad;
    let rebuilt = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    let mut out = envelope.clone();
    out.encrypted_payload = ramflux_protocol::encode_base64url(&rebuilt);
    Ok(out)
}

fn unknown_field(result: Result<SdkDmEncryptedEnvelope, SdkError>) -> Result<(), SdkError> {
    match result {
        Err(SdkError::InboundRejected(message))
            if message == "candidate outer envelope has unknown fields" =>
        {
            Ok(())
        }
        other => Err(invalid(&format!("exact unknown-field error, got {other:?}"))),
    }
}

fn sealed_250kb() -> Result<GatewayInboxEntry, SdkError> {
    let a = Fixture::new("alice", 101)?;
    let b = Fixture::new("bob", 102)?;
    seal(&a, &b, message("nested-pad", "c"), &vec![0x5a; BODY_250KB])
}

#[test]
fn sdk_decode_refuses_ciphertext_pad_on_real_250kb_envelope() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let entry = sealed_250kb()?;
    let padded = inject_compact_object_pad(
        &entry.envelope,
        "ciphertext",
        serde_json::json!("p".repeat(100 * 1024)),
    )?;
    unknown_field(decode(&padded))
}

#[test]
fn sdk_decode_refuses_x3dh_pad_on_real_250kb_envelope() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let entry = sealed_250kb()?;
    let padded = inject_compact_object_pad(&entry.envelope, "x3dh", serde_json::json!("x"))?;
    unknown_field(decode(&padded))
}

#[test]
fn sdk_decode_refuses_source_principal_commitment_over_identifier_cap() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let entry = sealed_250kb()?;
    let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut sidecar: serde_json::Value =
        serde_json::from_slice(compact.sidecar).map_err(|error| invalid(&error.to_string()))?;
    let cap = ramflux_protocol::message::outer::MAX_IDENTIFIER_BYTES;
    sidecar["source_principal_commitment"] = serde_json::json!("c".repeat(cap));
    let allowed = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    let mut envelope = entry.envelope.clone();
    envelope.encrypted_payload = ramflux_protocol::encode_base64url(&allowed);
    decode(&envelope)?;
    sidecar["source_principal_commitment"] = serde_json::json!("c".repeat(cap + 1));
    let over = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    envelope.encrypted_payload = ramflux_protocol::encode_base64url(&over);
    match decode(&envelope) {
        Err(SdkError::InboundRejected(message)) if message == "identifier exceeds 256 bytes" => {
            Ok(())
        }
        other => Err(invalid(&format!("exact identifier error, got {other:?}"))),
    }
}

fn rewrite_sidecar(
    envelope: &ramflux_protocol::Envelope,
    edit: impl FnOnce(&mut serde_json::Value),
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut sidecar: serde_json::Value =
        serde_json::from_slice(compact.sidecar).map_err(|error| invalid(&error.to_string()))?;
    edit(&mut sidecar);
    let rebuilt = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    let mut out = envelope.clone();
    out.encrypted_payload = ramflux_protocol::encode_base64url(&rebuilt);
    out.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        out.encrypted_payload.as_bytes(),
    );
    Ok(out)
}

#[test]
fn sdk_decode_refuses_non_empty_legacy_ciphertext_on_real_250kb_envelope() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let entry = sealed_250kb()?;
    decode(&entry.envelope)?;
    let padded = rewrite_sidecar(&entry.envelope, |sidecar| {
        sidecar["ciphertext"]["ciphertext"] = serde_json::json!(vec![0_u8; 200 * 1024]);
    })?;
    match decode(&padded) {
        Err(SdkError::InboundRejected(message))
            if message == "compact candidate sidecar ciphertext field must be empty" =>
        {
            Ok(())
        }
        other => Err(invalid(&format!("exact non-empty ciphertext error, got {other:?}"))),
    }
}

#[test]
fn sdk_decode_refuses_top_level_pad_on_real_250kb_envelope() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let entry = sealed_250kb()?;
    let padded = rewrite_sidecar(&entry.envelope, |sidecar| {
        sidecar["pad"] = serde_json::json!("p".repeat(100 * 1024));
    })?;
    unknown_field(decode(&padded))
}
