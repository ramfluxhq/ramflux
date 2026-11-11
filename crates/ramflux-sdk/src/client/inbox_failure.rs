// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared immutable-error classification and authenticated retry admission.
use crate::client::identity_authority::HeadUse;
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
        SdkError::DirectoryAuthorityUnavailable { root, source } => {
            SdkError::DirectoryAuthorityUnavailable {
                root,
                source: Box::new(lookup_error(*source, context)),
            }
        }
        SdkError::Json(_) | SdkError::Protocol(_) | SdkError::Crypto(_) => {
            SdkError::InboundPending(context.into())
        }
        other => other,
    }
}

pub(crate) fn deterministic(error: &SdkError) -> Option<&'static str> {
    match error {
        SdkError::DirectoryAuthorityUnavailable { source, .. } => deterministic(source),
        SdkError::GeneratedRefused { code, .. } => Some(code.as_str()),
        SdkError::ReplayMismatch => Some("replay_mismatch"),
        SdkError::EditConflict { .. } => Some("edit_conflict"),
        SdkError::Crypto(
            ramflux_crypto::CryptoError::VerifyFailed
            | ramflux_crypto::CryptoError::InvalidSignatureLength(_)
            | ramflux_crypto::CryptoError::AeadFailed
            | ramflux_crypto::CryptoError::KeyCommitmentMismatch
            | ramflux_crypto::CryptoError::CommitmentMismatch
            | ramflux_crypto::CryptoError::ReportCommitmentMismatch
            | ramflux_crypto::CryptoError::ReportCommitmentMissing
            | ramflux_crypto::CryptoError::MissingCollapseKey,
        ) => Some("authentication_failed"),
        SdkError::Protocol(ramflux_protocol::ProtocolError::IJson(_)) => Some("i_json_rejected"),
        SdkError::Json(_) | SdkError::Protocol(_) => Some("schema_invalid"),
        SdkError::InboundRejected(_) | SdkError::CallControlReceiptCapacity { .. } => {
            Some("routing_rejected")
        }
        _ => None,
    }
}

/// Owned verified-sender policy; pass `.policy()` into `ReceiveFailure`.
pub(crate) struct VerifiedInboxFailure {
    verified_source: Option<ramflux_crypto::RootQualifiedDeviceRef>,
    trusted: bool,
    class: &'static str,
    subject: String,
    at: i64,
}

impl VerifiedInboxFailure {
    #[must_use]
    pub(crate) fn policy(&self) -> ramflux_storage::InboxFailurePolicy<'_> {
        ramflux_storage::InboxFailurePolicy {
            verified_source: self.verified_source.as_ref(),
            trusted: self.trusted,
            dependency: (self.class, self.subject.as_str()),
            at: self.at,
        }
    }
}

/// Builds the verified sender policy used by both client retry admission and the P08 adapter.
pub(crate) fn verified_failure_policy(
    client: &RamfluxClient,
    local: &str,
    entry: &GatewayInboxEntry,
    at: i64,
) -> Result<VerifiedInboxFailure, SdkError> {
    let verified_source =
        client.authenticated_device_identity(HeadUse::NewAuthorization, entry).ok();
    let authenticated = verified_source.is_some();
    let opened = if authenticated { client.open_routed(entry, local).ok() } else { None };
    let legacy_group = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&bytes).ok())
        .filter(|g| g.schema == "ramflux.sdk.group_sender_key.message.v1" && g.version == 1)
        .map(|g| g.group_id);
    let group =
        opened.as_ref().and_then(|o| o.routing.group_id.as_deref()).or(legacy_group.as_deref());
    let db = client.account_db()?;
    let source_record =
        verified_source.as_ref().and_then(|source| db.client_device_record(source).ok().flatten());
    let verified_principal = source_record
        .as_ref()
        .and_then(|record| record["principal_id"].as_str())
        .filter(|principal| *principal == entry.envelope.source_principal_id);
    let related = if let Some(group) = group {
        verified_source.as_ref().is_some_and(|source| {
            db.has_root_bound_group_membership(group, source).unwrap_or(false)
        })
    } else {
        verified_source.as_ref().is_some_and(|source| {
            client
                .local_device_identity(local)
                .and_then(|local| client.pair_recovery_pending(&local, source))
                .unwrap_or(false)
        }) || verified_principal.is_some_and(|principal| {
            client.friend_link_peer_is_accepted(principal).unwrap_or(false)
                || client
                    .device_branch
                    .as_ref()
                    .is_some_and(|branch| branch.principal_id == principal)
        })
    };
    // A failed cache lookup is a dependency miss, not a second failure that wedges the inbox.
    let missing_manifest =
        source_record.as_ref().is_none_or(|record| record.get("x25519_identity_public").is_none());
    let target_dependency = if let Some(opened) = opened.as_ref() {
        missing_generated_target(client, &opened.body)?
    } else { None };
    let (class, subject) = if !authenticated || missing_manifest {
        (
            "manifest",
            verified_source.as_ref().map_or_else(
                || entry.envelope.source_device_id.clone(),
                |source| source.storage_key().to_owned(),
            ),
        )
    } else if let Some(subject) = target_dependency {
        ("message_target", subject)
    } else if let Some(group) = group {
        ("group", group.to_owned())
    } else {
        ("none", String::new())
    };
    Ok(VerifiedInboxFailure {
        verified_source,
        trusted: authenticated && related,
        class,
        subject,
        at,
    })
}

fn missing_generated_target(client: &RamfluxClient, bytes: &[u8]) -> Result<Option<String>, SdkError> {
    use ramflux_protocol::message as g;
    let Ok((_, content)) = RamfluxClient::decode_generated_inner(bytes) else { return Ok(None); };
    let references = match content.value {
        Some(g::content::Value::Edit(value)) => value.target.into_iter().collect::<Vec<_>>(),
        Some(g::content::Value::Reaction(value)) => value.target.into_iter().collect(),
        Some(g::content::Value::SelfSync(value)) => value.read_through.into_iter().chain(value.pin).collect(),
        _ => Vec::new(),
    };
    for reference in references {
        let id = ramflux_protocol::encode_base64url(&reference.id);
        if client.direct_message_by_id(&id)?.is_none() && !client.account_db()?.message_is_deleted(&id)? {
            return Ok(Some(format!("{}/{id}", reference.conversation_id)));
        }
    }
    Ok(None)
}

pub(crate) fn set_failure_policy(
    client: &RamfluxClient,
    local: &str,
    entry: &GatewayInboxEntry,
    key: &str,
    bytes: &[u8],
    at: i64,
) -> Result<bool, SdkError> {
    let built = verified_failure_policy(client, local, entry, at)?;
    Ok(client.account_db()?.set_verified_inbox_failure_policy(key, bytes, built.policy())?)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_refusal_codes_are_stable() {
        assert_eq!(deterministic(&SdkError::ReplayMismatch), Some("replay_mismatch"));
        assert_eq!(
            deterministic(&SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed)),
            Some("authentication_failed")
        );
        assert_eq!(
            deterministic(&SdkError::Crypto(ramflux_crypto::CryptoError::ReportCommitmentMismatch)),
            Some("authentication_failed")
        );
        assert_eq!(deterministic(&SdkError::InboundRejected("x".into())), Some("routing_rejected"));
        assert_eq!(deterministic(&SdkError::IdentityRootMissing), None);
    }
}
