// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared immutable-error classification and authenticated retry admission.
use crate::prelude::*;
/// Checks immutable signature encoding independently of a possibly incomplete directory cache.
pub(crate) fn wire_signature_error(entry: &GatewayInboxEntry) -> Option<SdkError> {
    match ramflux_protocol::decode_base64url(&entry.envelope.signed.signature) {
        Ok(bytes) if bytes.len() == 64 => None,
        Ok(bytes) => {
            Some(SdkError::Crypto(ramflux_crypto::CryptoError::InvalidSignatureLength(bytes.len())))
        }
        Err(source) => {
            Some(SdkError::Protocol(ramflux_protocol::ProtocolError::InvalidBase64Url {
                field: "signature",
                source,
            }))
        }
    }
}

/// Directory response failures do not prove that immutable message bytes are invalid.
pub(crate) fn lookup_error(error: SdkError, context: &str) -> SdkError {
    match error {
        SdkError::Json(_) | SdkError::Protocol(_) | SdkError::Crypto(_) => {
            SdkError::InboundPending(context.into())
        }
        other => other,
    }
}

pub(crate) fn deterministic(error: &SdkError) -> Option<&'static str> {
    match error {
        SdkError::Crypto(
            ramflux_crypto::CryptoError::VerifyFailed
            | ramflux_crypto::CryptoError::InvalidSignatureLength(_)
            | ramflux_crypto::CryptoError::AeadFailed
            | ramflux_crypto::CryptoError::KeyCommitmentMismatch
            | ramflux_crypto::CryptoError::CommitmentMismatch,
        ) => Some("authentication_failed"),
        SdkError::Json(_) | SdkError::Protocol(_) => Some("schema_invalid"),
        SdkError::InboundRejected(_) => Some("routing_rejected"),
        _ => None,
    }
}

pub(crate) fn set_failure_policy(
    client: &RamfluxClient,
    local: &str,
    entry: &GatewayInboxEntry,
    key: &str,
    bytes: &[u8],
    at: i64,
) -> Result<bool, SdkError> {
    let verified_source = client.authenticated_device_identity(entry).ok();
    let authenticated = verified_source.is_some();
    let opened = if authenticated { client.open_routed(entry, local).ok() } else { None };
    let legacy_group = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&bytes).ok())
        .filter(|g| g.schema == "ramflux.sdk.group_sender_key.message.v1" && g.version == 1)
        .map(|g| g.group_id);
    let group =
        opened.as_ref().and_then(|o| o.routing.group_id.as_deref()).or(legacy_group.as_deref());
    let related = if let Some(group) = group {
        client
            .group_state(group)
            .is_ok_and(|state| state.members.contains(&entry.envelope.source_device_id))
    } else {
        verified_source
            .as_ref()
            .map(|source| {
                client.pair_recovery_pending(&client.local_device_identity(local)?, source)
            })
            .transpose()?
            .unwrap_or(false)
            || client.friend_link_peer_is_accepted(&entry.envelope.source_principal_id)?
            || client
                .device_branch
                .as_ref()
                .is_some_and(|b| b.principal_id == entry.envelope.source_principal_id)
    };
    let missing_manifest = client
        .account_db()?
        .client_record("device", &entry.envelope.source_device_id)?
        .is_none_or(|record| record.get("x25519_identity_public").is_none());
    let (class, subject) = if !authenticated || missing_manifest {
        ("manifest", entry.envelope.source_device_id.as_str())
    } else if let Some(group) = group {
        ("group", group)
    } else {
        ("none", "")
    };
    Ok(client.account_db()?.set_verified_inbox_failure_policy(
        key,
        bytes,
        ramflux_storage::InboxFailurePolicy {
            verified_source: verified_source.as_ref(),
            trusted: authenticated && related,
            dependency: (class, subject),
            at,
        },
    )?)
}

/// Admits a retry under the verified source's budget without charging a fallback claimed identity.
pub(crate) fn defer_entry(
    client: &RamfluxClient,
    local: &str,
    entry: &GatewayInboxEntry,
    key: &str,
    bytes: &[u8],
    at: i64,
) -> Result<bool, SdkError> {
    Ok(set_failure_policy(client, local, entry, key, bytes, at)?
        && client.account_db()?.defer_inbox_entry(key, bytes, at)? != 0)
}
