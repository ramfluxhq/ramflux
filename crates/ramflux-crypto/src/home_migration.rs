// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Role-bound home-migration signatures. Signature validity alone grants no node admission.
mod history;
mod time;
use crate::{CryptoError, DeviceBranch, custody::VerifiedRecord};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
pub use history::*;
use ramflux_protocol::{
    custody::{CustodyKind, object_hash},
    encode_base64url,
    home_migration::{
        Authorization, MAX_MESSAGE_BYTES, Message, Role, SKEW_SECONDS, Signed, Signer, SignerKey,
        signing_bytes,
    },
};
use serde_json::Value;
pub use time::*;

pub(crate) fn reject(reason: &'static str) -> CryptoError {
    CryptoError::IdentityAuthority(reason)
}
fn key(text: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes: [u8; 32] =
        binary(text, 32)?.try_into().map_err(|_| reject("migration key length"))?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| reject("migration key invalid"))?;
    if key.is_weak() {
        return Err(reject("migration key weak"));
    }
    Ok(key)
}
fn binary(text: &str, length: usize) -> Result<Vec<u8>, CryptoError> {
    let raw = ramflux_protocol::decode_base64url(text)?;
    if raw.len() != length || encode_base64url(&raw) != text {
        return Err(reject("migration binary noncanonical"));
    }
    Ok(raw)
}
fn structure(value: &Value) -> Result<(), CryptoError> {
    match value {
        Value::Object(map) => {
            for (name, value) in map {
                if let Value::String(text) = value {
                    if name.ends_with("_hash")
                        || name.ends_with("_key")
                        || name == "account_anchor"
                        || name == "migration_id"
                        || name == "nonce"
                        || name == "admission_id"
                    {
                        binary(text, 32)?;
                    } else if text.is_empty()
                        || text.len() > 2048
                        || text.chars().any(char::is_control)
                    {
                        return Err(reject("migration identifier invalid"));
                    }
                }
                structure(value)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                structure(item)?;
            }
        }
        Value::Number(number)
            if number.as_u64().is_none_or(|n| n > ramflux_protocol::MAX_SAFE_JSON_INTEGER) =>
        {
            return Err(reject("migration integer unsafe"));
        }
        _ => {}
    }
    Ok(())
}
/// Verify exact domains, role order, key kinds and every signature; no authority is inferred.
/// # Errors
/// Rejects malformed/oversized messages, wrong roles and invalid signatures.
pub fn verify_signatures<T: Message>(message: &Signed<T>) -> Result<(), CryptoError> {
    let bytes = signing_bytes(message)?;
    if ramflux_protocol::canonical_json_bytes(message)?.len() > MAX_MESSAGE_BYTES
        || message.signatures.len() != T::ROLES.len()
    {
        return Err(reject("migration message size or signature count"));
    }
    structure(
        &serde_json::to_value(&message.body).map_err(ramflux_protocol::ProtocolError::from)?,
    )?;
    for (signer, sig) in message.signers.iter().zip(&message.signatures) {
        if !matches!(
            (&signer.role, &signer.key),
            (Role::Management, SignerKey::MasterCertifiedCustody { .. })
                | (Role::Actor, SignerKey::BranchV3 { .. })
                | (Role::Node, SignerKey::Node { .. })
        ) {
            return Err(reject("migration signer key kind mismatch"));
        }
        let signature = Signature::from_slice(&binary(sig, 64)?)
            .map_err(|_| reject("migration signature length"))?;
        key(signer.key.public_key())?
            .verify_strict(&bytes, &signature)
            .map_err(|_| CryptoError::VerifyFailed)?;
    }
    Ok(())
}
pub(crate) fn sign_with_keys<T: Message>(
    body: T,
    signers: Vec<Signer>,
    keys: &[&SigningKey],
) -> Result<Signed<T>, CryptoError> {
    let mut message = Signed {
        schema: T::DOMAIN.into(),
        domain: T::DOMAIN.into(),
        body,
        signers,
        signatures: Vec::new(),
    };
    if message.signers.len() != keys.len()
        || message
            .signers
            .iter()
            .zip(keys)
            .any(|(s, k)| s.key.public_key() != encode_base64url(k.verifying_key().to_bytes()))
    {
        return Err(reject("migration signing key mismatch"));
    }
    let bytes = signing_bytes(&message)?;
    message.signatures = keys.iter().map(|k| encode_base64url(k.sign(&bytes).to_bytes())).collect();
    verify_signatures(&message)?;
    Ok(message)
}
/// Sign a node-role message using the configured node identity key.
/// # Errors
/// Rejects another role family, malformed bodies and invalid node identifiers.
pub fn sign_node<T: Message>(
    body: T,
    node_id: &str,
    key: &SigningKey,
) -> Result<Signed<T>, CryptoError> {
    if T::ROLES != [Role::Node] || node_id.is_empty() || node_id.len() > 256 {
        return Err(reject("migration node signer role"));
    }
    sign_with_keys(
        body,
        vec![Signer {
            role: Role::Node,
            key: SignerKey::Node {
                node_id: node_id.into(),
                public_key: encode_base64url(key.verifying_key().to_bytes()),
            },
        }],
        &[key],
    )
}
/// Authenticate a node message with an independently retained node pin.
/// # Errors
/// Rejects a supplied replacement key, another node and invalid message signatures.
pub fn verify_node<T: Message>(
    message: &Signed<T>,
    node_id: &str,
    node_key: &str,
) -> Result<(), CryptoError> {
    verify_signatures(message)?;
    if message.signers.as_slice()
        != [Signer {
            role: Role::Node,
            key: SignerKey::Node { node_id: node_id.into(), public_key: node_key.into() },
        }]
    {
        return Err(reject("migration node pin mismatch"));
    }
    Ok(())
}
fn actor_signer(
    reference: &ramflux_protocol::custody::DeviceRef,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<Signer, CryptoError> {
    let branch = authority.authorize(reference, "register", now)?;
    if now < branch.not_before || now > branch.expires_at {
        return Err(reject("migration actor lease expired"));
    }
    let entry = authority
        .envelope()
        .body
        .devices
        .iter()
        .find(|d| d.device_id == reference.device_id)
        .ok_or_else(|| reject("migration actor unavailable"))?;
    let cert =
        entry.branch_certificate.as_ref().ok_or_else(|| reject("migration actor revoked"))?;
    Ok(Signer {
        role: Role::Actor,
        key: SignerKey::BranchV3 {
            device_ref: reference.clone(),
            branch_certificate_hash: object_hash(cert)?,
            public_key: branch.branch_signing_public_key.clone(),
        },
    })
}
pub(crate) fn authorization_signers(
    body: &Authorization,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<Vec<Signer>, CryptoError> {
    let record = authority.envelope();
    let cert = &record.body.master_certificate;
    if record.body.account_anchor != body.account_anchor
        || object_hash(record)? != body.authority_record_hash
        || object_hash(cert)? != body.management_certificate_hash
        || cert.body.custody_kind != CustodyKind::LocalHuman
        || record.body.principal_kind != ramflux_protocol::PrincipalKind::Human
    {
        return Err(reject("migration current custody authority mismatch"));
    }
    authorization_bounds(body, now)?;
    Ok(vec![
        Signer {
            role: Role::Management,
            key: SignerKey::MasterCertifiedCustody {
                account_anchor: body.account_anchor.clone(),
                master_certificate_hash: body.management_certificate_hash.clone(),
                authority_record_hash: body.authority_record_hash.clone(),
                public_key: cert.body.self_signing_public_key.clone(),
            },
        },
        actor_signer(&body.actor, authority, now)?,
    ])
}
/// Verify management and actor authority against the receiving node's current verified record.
/// # Errors
/// Rejects a stale head, wrong manager, revoked/expired actor and time-bound violations.
pub fn verify_authorization(
    message: &Signed<Authorization>,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    verify_signatures(message)?;
    if message.signers != authorization_signers(&message.body, authority, now)? {
        return Err(reject("migration authorization signer mismatch"));
    }
    Ok(())
}
/// Sign a Prepare or Control with its current v3 actor; no primary key is loaded.
/// # Errors
/// Rejects wrong families, device/key mismatch and unavailable current authority.
pub fn sign_actor<T: Message>(
    body: T,
    branch: &DeviceBranch,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<Signed<T>, CryptoError> {
    if T::ROLES != [Role::Actor] {
        return Err(reject("migration actor signer role"));
    }
    let value = serde_json::to_value(&body).map_err(ramflux_protocol::ProtocolError::from)?;
    let reference: ramflux_protocol::custody::DeviceRef = serde_json::from_value(
        value
            .get("actor")
            .or_else(|| value.get("requester"))
            .cloned()
            .ok_or_else(|| reject("migration actor absent"))?,
    )
    .map_err(ramflux_protocol::ProtocolError::from)?;
    let signer = actor_signer(&reference, authority, now)?;
    if branch.device_id != reference.device_id
        || branch.device_epoch != reference.device_epoch
        || branch.principal_id != authority.envelope().body.principal_id
    {
        return Err(reject("migration actor ownership mismatch"));
    }
    sign_with_keys(body, vec![signer], &[&branch.signing_key])
}
/// Verify Prepare/Control actor identity against current local authority.
/// # Errors
/// Rejects stale records, wrong signers, invalid signatures or expired requests.
pub fn verify_actor<T: Message>(
    message: &Signed<T>,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    verify_signatures(message)?;
    let value =
        serde_json::to_value(&message.body).map_err(ramflux_protocol::ProtocolError::from)?;
    let reference = serde_json::from_value(
        value
            .get("actor")
            .or_else(|| value.get("requester"))
            .cloned()
            .ok_or_else(|| reject("migration actor absent"))?,
    )
    .map_err(ramflux_protocol::ProtocolError::from)?;
    if message.signers != [actor_signer(&reference, authority, now)?]
        || value.get("authority_record_hash").and_then(Value::as_str)
            != Some(object_hash(authority.envelope())?.as_str())
    {
        return Err(reject("migration actor current head mismatch"));
    }
    let issued = value
        .get("issued_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| reject("migration time missing"))?;
    let expires = value
        .get("expires_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| reject("migration expiry missing"))?;
    if issued > now.saturating_add(SKEW_SECONDS)
        || expires <= issued
        || expires - issued > 300
        || now > expires
    {
        return Err(reject("migration request expired"));
    }
    Ok(())
}
