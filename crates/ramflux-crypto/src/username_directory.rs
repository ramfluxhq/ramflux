// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant username cryptography. Signers are borrowed only for an authorized ceremony.
//! No seeds, keys, custody records or existing transcripts are created or exported here.
//! Signature verification establishes key ownership; current heads, pins, time, replay and
//! publication authorization remain the responsibility of the directory/home/client parts.
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ramflux_protocol::{domain, encode_base64url, username_directory as wire};
use wire::{Signed, SigningBody, Wire};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Codec(#[from] wire::CodecError),
    #[error(transparent)]
    Crypto(#[from] crate::CryptoError),
    #[error("username root commitment mismatch")]
    RootCommitment,
    #[error("username center identity mismatch")]
    CenterId,
}
fn root_binding(key: &VerifyingKey, commitment: &str) -> Result<(), Error> {
    if key.is_weak() || crate::identity_root_commitment(key) != commitment {
        return Err(Error::RootCommitment);
    }
    Ok(())
}
fn center_binding(actual: &str, pinned: &str) -> Result<(), Error> {
    if actual != pinned {
        return Err(Error::CenterId);
    }
    Ok(())
}
fn sign<T: SigningBody>(key: &SigningKey, body: T) -> Result<Signed<T>, Error>
where
    Signed<T>: Wire,
{
    let signature = encode_base64url(key.sign(&wire::signing_bytes(&body)?).to_bytes());
    let result = Signed { body, signature };
    wire::encode(&result)?;
    Ok(result)
}
fn verify<T: SigningBody>(key: &VerifyingKey, signed: &Signed<T>) -> Result<(), Error>
where
    Signed<T>: Wire,
{
    wire::encode(signed)?;
    if key.is_weak() {
        return Err(crate::CryptoError::VerifyFailed.into());
    }
    crate::verify_canonical_signature(
        &wire::signing_bytes(&signed.body)?,
        &signed.signature,
        &encode_base64url(key.to_bytes()),
    )?;
    Ok(())
}
/// Sign one complete binding using a transient root/master authority.
/// # Errors
/// Rejects invalid fields or a commitment unrelated to the signer.
pub fn sign_binding(
    key: &SigningKey,
    body: wire::UsernameBindingBody,
) -> Result<wire::UsernameBinding, Error> {
    root_binding(&key.verifying_key(), &body.principal_commitment)?;
    sign(key, body)
}
/// Verify a binding against an independently authenticated root/master key.
/// # Errors
/// Rejects malformed bindings, root substitution and invalid signatures.
pub fn verify_binding(key: &VerifyingKey, value: &wire::UsernameBinding) -> Result<(), Error> {
    root_binding(key, &value.body.principal_commitment)?;
    verify(key, value)
}
/// Sign a detached v2 profile without modifying the native `DeviceSet` profile.
/// # Errors
/// Rejects invalid fields or an unrelated signer.
pub fn sign_profile(
    key: &SigningKey,
    body: wire::IdentityProfileV2Body,
) -> Result<wire::SignedIdentityProfileV2, Error> {
    root_binding(&key.verifying_key(), &body.principal_commitment)?;
    sign(key, body)
}
/// Verify a detached v2 profile against the authenticated root/master key.
/// # Errors
/// Rejects invalid fields, root substitution and invalid signatures.
pub fn verify_profile(
    key: &VerifyingKey,
    value: &wire::SignedIdentityProfileV2,
) -> Result<(), Error> {
    root_binding(key, &value.body.principal_commitment)?;
    verify(key, value)
}
/// Sign a complete operation, including its signed binding and both `ProfileRef`s.
/// # Errors
/// Rejects malformed operations, unrelated roots or forged nested bindings.
pub fn sign_operation(
    key: &SigningKey,
    body: wire::UsernameOperationBody,
) -> Result<wire::UsernameOperation, Error> {
    root_binding(&key.verifying_key(), &body.principal_commitment)?;
    if let Some(binding) = &body.binding {
        verify_binding(&key.verifying_key(), binding)?;
    }
    sign(key, body)
}
/// Verify the operation and its nested binding under the same authenticated root.
/// # Errors
/// Rejects malformed operations, root substitution or either invalid signature.
pub fn verify_operation(key: &VerifyingKey, value: &wire::UsernameOperation) -> Result<(), Error> {
    root_binding(key, &value.body.principal_commitment)?;
    verify(key, value)?;
    if let Some(binding) = &value.body.binding {
        verify_binding(key, binding)?;
    }
    Ok(())
}
/// Sign a receipt with the existing center node key after publication authorization.
/// # Errors
/// Rejects malformed data or a center different from the configured identity.
pub fn sign_receipt(
    key: &SigningKey,
    center: &str,
    body: wire::DirectoryReceiptBody,
) -> Result<wire::DirectoryReceipt, Error> {
    center_binding(&body.center_id, center)?;
    sign(key, body)
}
/// Verify a receipt against an independently pinned center identity and key.
/// # Errors
/// Rejects malformed receipts, center substitution and invalid signatures.
pub fn verify_receipt(
    key: &VerifyingKey,
    center: &str,
    value: &wire::DirectoryReceipt,
) -> Result<(), Error> {
    center_binding(&value.body.center_id, center)?;
    verify(key, value)
}
/// Sign a resolve result with the existing center node key after publication authorization.
/// # Errors
/// Rejects malformed data or an unrelated center identity.
pub fn sign_resolve(
    key: &SigningKey,
    center: &str,
    body: wire::DirectoryResolveBody,
) -> Result<wire::DirectoryResolve, Error> {
    center_binding(&body.center_id, center)?;
    sign(key, body)
}
/// Verify a resolve result against the pinned center; nonce/freshness are caller policy.
/// # Errors
/// Rejects malformed results, center substitution and invalid signatures.
pub fn verify_resolve(
    key: &VerifyingKey,
    center: &str,
    value: &wire::DirectoryResolve,
) -> Result<(), Error> {
    center_binding(&value.body.center_id, center)?;
    verify(key, value)
}
fn framed<T: Wire>(tag: &str, value: &T) -> Result<String, Error> {
    wire::encode(value)?;
    ramflux_protocol::custody::framed_hash(tag, value)
        .map_err(|e| crate::CryptoError::from(e).into())
}
/// Hash the complete signed binding, including its signature.
/// # Errors
/// Rejects malformed or oversized bindings.
pub fn binding_hash(value: &wire::UsernameBinding) -> Result<String, Error> {
    framed(domain::USERNAME_BINDING_HASH, value)
}
/// Hash the complete signed operation, including its nested signed binding.
/// # Errors
/// Rejects malformed or oversized operations.
pub fn operation_hash(value: &wire::UsernameOperation) -> Result<String, Error> {
    framed(domain::USERNAME_OPERATION_HASH, value)
}
/// Hash the complete checkpoint, including typed keys and both row images.
/// # Errors
/// Rejects malformed or oversized checkpoint records.
pub fn checkpoint_hash(value: &wire::Checkpoint) -> Result<String, Error> {
    framed(domain::USERNAME_CHECKPOINT, value)
}
/// Hash the complete signed v2 document; an absent profile has no document hash.
/// # Errors
/// Rejects malformed or oversized profiles.
pub fn profile_hash_v2(value: &wire::SignedIdentityProfileV2) -> Result<String, Error> {
    framed(domain::USERNAME_PROFILE_HASH, value)
}
/// Hash a complete legacy v1 document without changing its flat signing grammar.
/// # Errors
/// Rejects invalid v1 fields or noncanonical signature encodings.
pub fn profile_hash_v1(value: &ramflux_protocol::SignedIdentityProfile) -> Result<String, Error> {
    ramflux_protocol::identity_profile_signing_bytes(value).map_err(crate::CryptoError::from)?;
    let signature =
        ramflux_protocol::decode_base64url(&value.signature).map_err(crate::CryptoError::from)?;
    if signature.len() != 64 || encode_base64url(&signature) != value.signature {
        return Err(crate::CryptoError::VerifyFailed.into());
    }
    ramflux_protocol::custody::framed_hash(domain::USERNAME_PROFILE_HASH, value)
        .map_err(|e| crate::CryptoError::from(e).into())
}
/// Hash the exact plaintext file bytes, with the existing no-NUL grammar.
/// Decoding, signed size/type checks and upload policy belong to the avatar pipeline.
#[must_use]
pub fn avatar_hash(plaintext: &[u8]) -> String {
    crate::blake3_256_base64url(domain::AVATAR_CONTENT, plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn corpus() -> Result<Value, serde_json::Error> {
        serde_json::from_str(include_str!(
            "../../../scripts/reference/username_directory/crypto_vectors.json"
        ))
    }
    fn string<'a>(v: &'a Value, field: &str) -> &'a str {
        v[field].as_str().unwrap_or("")
    }
    fn bytes(v: &Value, field: &str) -> Result<Vec<u8>, crate::CryptoError> {
        Ok(ramflux_protocol::decode_base64url(string(v, field))?)
    }
    fn key(v: &Value, field: &str) -> Result<VerifyingKey, crate::CryptoError> {
        crate::verifying_key_from_base64url(string(v, field))
    }
    fn mutation(value: &Value, case: &Value) -> Result<Value, &'static str> {
        let mut value = value.clone();
        let path = case["path"].as_array().ok_or("missing mutation path")?;
        let mut slot = &mut value;
        for part in path {
            slot = if let Some(index) = part.as_u64() {
                slot.get_mut(usize::try_from(index).map_err(|_| "index overflow")?)
            } else {
                slot.get_mut(part.as_str().ok_or("invalid key")?)
            }
            .ok_or("missing mutation target")?;
        }
        *slot = case["replacement"].clone();
        Ok(value)
    }
    fn verify_case(
        kind: &str,
        bytes: &[u8],
        key: &VerifyingKey,
        center: &str,
    ) -> Result<(), Error> {
        match kind {
            "UsernameBinding" => verify_binding(key, &wire::decode(bytes)?),
            "SignedIdentityProfileV2" => verify_profile(key, &wire::decode(bytes)?),
            "UsernameOperation" => verify_operation(key, &wire::decode(bytes)?),
            "DirectoryReceipt" => verify_receipt(key, center, &wire::decode(bytes)?),
            "DirectoryResolve" => verify_resolve(key, center, &wire::decode(bytes)?),
            _ => Err(Error::CenterId),
        }
    }
    fn sign_case(
        kind: &str,
        bytes: &[u8],
        key: &SigningKey,
        center: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        macro_rules! signed_case {
            ($ty:ty, $sign:ident $(,$center:expr)?) => {{
                let value: $ty = wire::decode(bytes)?;
                let transcript = wire::signing_bytes(&value.body)?;
                let signed = $sign(key, $($center,)? value.body)?;
                Ok((wire::encode(&signed)?, transcript))
            }};
        }
        match kind {
            "UsernameBinding" => signed_case!(wire::UsernameBinding, sign_binding),
            "SignedIdentityProfileV2" => signed_case!(wire::SignedIdentityProfileV2, sign_profile),
            "UsernameOperation" => signed_case!(wire::UsernameOperation, sign_operation),
            "DirectoryReceipt" => signed_case!(wire::DirectoryReceipt, sign_receipt, center),
            "DirectoryResolve" => signed_case!(wire::DirectoryResolve, sign_resolve, center),
            _ => Err(Error::CenterId),
        }
    }
    #[test]
    fn username_root_signatures_and_independent_vectors() -> TestResult {
        let vectors = corpus()?;
        let cases = vectors["signatures"].as_array().ok_or("missing signatures")?;
        assert_eq!(cases.len(), 13);
        let center = string(&vectors, "center_id");
        let alternate = key(&vectors, "alternate_key")?;
        let mut negative_count = 0;
        for case in cases {
            let name = string(case, "name");
            let kind = string(case, "type");
            let data = string(case, "wire").as_bytes();
            let public = key(case, "key")?;
            verify_case(kind, data, &public, center)?;
            let seed: [u8; 32] = bytes(case, "seed")?.try_into().map_err(|_| "seed length")?;
            let signer = SigningKey::from_bytes(&seed);
            let (document, transcript) = sign_case(kind, data, &signer, center)?;
            assert_eq!(document, data, "signature golden {name}");
            assert_eq!(transcript, bytes(case, "preimage")?, "complete transcript {name}");
            let value: Value = serde_json::from_slice(data)?;
            for change in case["tamper"].as_array().ok_or("missing tamper cases")? {
                assert_eq!(string(change, "error"), "VerifyFailed");
                let body = mutation(&value["body"], change)?;
                let changed =
                    ramflux_protocol::custody::signing_bytes(string(case, "domain"), &body)?;
                assert!(
                    matches!(
                        crate::verify_canonical_signature(
                            &changed,
                            string(&value, "signature"),
                            string(case, "key")
                        ),
                        Err(crate::CryptoError::VerifyFailed)
                    ),
                    "unbound {name}: {}",
                    change["path"]
                );
                negative_count += 1;
            }
            let wrong = verify_case(kind, data, &alternate, center);
            if matches!(kind, "DirectoryReceipt" | "DirectoryResolve") {
                assert!(
                    matches!(wrong, Err(Error::Crypto(crate::CryptoError::VerifyFailed))),
                    "center key substitution {name}"
                );
                assert!(
                    matches!(
                        verify_case(kind, data, &public, "other.example"),
                        Err(Error::CenterId)
                    ),
                    "center identity substitution {name}"
                );
            } else {
                assert!(matches!(wrong, Err(Error::RootCommitment)), "root substitution {name}");
            }
            let mut forged = value.clone();
            forged["signature"] = Value::String(encode_base64url([0_u8; 64]));
            assert!(
                matches!(
                    verify_case(
                        kind,
                        &ramflux_protocol::canonical_json_bytes(&forged)?,
                        &public,
                        center
                    ),
                    Err(Error::Crypto(crate::CryptoError::VerifyFailed))
                ),
                "signature forgery {name}"
            );
            let wrong_domain = ramflux_protocol::custody::signing_bytes(
                "ramflux.wrong.domain.v1",
                &value["body"],
            )?;
            assert!(matches!(
                crate::verify_canonical_signature(
                    &wrong_domain,
                    string(&value, "signature"),
                    string(case, "key")
                ),
                Err(crate::CryptoError::VerifyFailed)
            ));
        }
        assert!(negative_count == 224, "every signed field has a negative vector");
        assert!(!wire::enabled());
        Ok(())
    }
    #[test]
    fn username_hash_preimages_and_every_field() -> TestResult {
        let vectors = corpus()?;
        let cases = vectors["hashes"].as_array().ok_or("missing hash cases")?;
        assert_eq!(cases.len(), 19);
        let mut fields = 0;
        for case in cases {
            let name = string(case, "name");
            let domain = string(case, "domain");
            let preimage = bytes(case, "preimage")?;
            assert_eq!(
                encode_base64url(blake3::hash(&preimage).as_bytes()),
                string(case, "hash"),
                "raw preimage {name}"
            );
            if string(case, "mode") == "raw" {
                let raw = bytes(case, "raw")?;
                let actual = if name == "root_commitment" {
                    crate::identity_root_commitment(&key(&vectors, "root_key")?)
                } else {
                    avatar_hash(&raw)
                };
                assert_eq!(actual, string(case, "hash"), "no NUL {name}");
                let mut nul = domain.as_bytes().to_vec();
                nul.push(0);
                nul.extend_from_slice(&raw);
                assert_ne!(
                    encode_base64url(blake3::hash(&nul).as_bytes()),
                    actual,
                    "F must not replace raw grammar"
                );
            } else {
                let data = string(case, "wire").as_bytes();
                let actual = if name == "binding" {
                    binding_hash(&wire::decode(data)?)
                } else if name == "operation" {
                    operation_hash(&wire::decode(data)?)
                } else if name.starts_with("checkpoint_") {
                    checkpoint_hash(&wire::decode(data)?)
                } else if name == "profile_v1" {
                    profile_hash_v1(&serde_json::from_slice(data)?)
                } else {
                    profile_hash_v2(&wire::decode(data)?)
                }?;
                assert_eq!(actual, string(case, "hash"), "typed slot {name}");
                let value: Value = serde_json::from_slice(data)?;
                let mut complete = domain.as_bytes().to_vec();
                complete.push(0);
                complete.extend_from_slice(data);
                assert_eq!(complete, preimage, "framed complete signed document {name}");
                for change in case["mutations"].as_array().ok_or("missing hash mutations")? {
                    let changed = mutation(&value, change)?;
                    let actual = ramflux_protocol::custody::framed_hash(domain, &changed)?;
                    assert_eq!(
                        actual,
                        string(change, "hash"),
                        "independent changed hash {name}: {}",
                        change["path"]
                    );
                    assert_ne!(actual, string(case, "hash"));
                    fields += 1;
                }
            }
        }
        assert!(fields > 1000, "all checkpoint keys, images, nested signatures and fields");
        let legacy: ramflux_protocol::SignedIdentityProfile =
            serde_json::from_str(string(&vectors["legacy"], "wire"))?;
        assert_eq!(
            ramflux_protocol::identity_profile_signing_bytes(&legacy)?,
            bytes(&vectors["legacy"], "preimage")?
        );
        crate::verify_identity_profile(&key(&vectors, "root_key")?, &legacy)?;
        Ok(())
    }
    type FieldMutation = (&'static str, Value, &'static str);
    fn binding_mutations() -> Vec<FieldMutation> {
        use serde_json::json;
        let m = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
        let other = encode_base64url([19_u8; 32]);
        vec![
            ("/body/name", json!("alice2"), "VerifyFailed"),
            ("/body/node", json!("other.example"), "VerifyFailed"),
            ("/body/principal_commitment", json!(other), "RootCommitment"),
            ("/body/epoch", json!(m - 2), "VerifyFailed"),
        ]
    }
    fn profile_mutations() -> Vec<FieldMutation> {
        use serde_json::json;
        let m = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
        let other = encode_base64url([19_u8; 32]);
        vec![
            ("/body/schema", json!("ramflux.identity.profile.v3"), "schema"),
            ("/body/principal_id", json!("other-principal"), "VerifyFailed"),
            ("/body/principal_commitment", json!(other), "RootCommitment"),
            ("/body/kind", json!("bot"), "VerifyFailed"),
            ("/body/display_name", json!("Alice"), "VerifyFailed"),
            ("/body/bio", json!("Other bio"), "VerifyFailed"),
            ("/body/avatar", Value::Null, "VerifyFailed"),
            ("/body/avatar/content_hash", json!(other), "VerifyFailed"),
            ("/body/avatar/media_type", json!("image/png"), "VerifyFailed"),
            ("/body/avatar/size", json!(524_287), "VerifyFailed"),
            ("/body/avatar/relay_ref", json!(other), "VerifyFailed"),
            ("/body/epoch", json!(m - 2), "VerifyFailed"),
        ]
    }
    fn operation_mutations() -> Vec<FieldMutation> {
        use serde_json::json;
        let m = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
        let other = encode_base64url([19_u8; 32]);
        vec![
            ("/body/action", json!("claim"), "profile"),
            ("/body/operation_id", json!(other), "VerifyFailed"),
            ("/body/principal_commitment", json!(other), "binding"),
            ("/body/expected_epoch", json!(m - 3), "next_epoch"),
            ("/body/next_epoch", json!(m - 2), "next_epoch"),
            ("/body/expected_profile/version", json!(1), "expected_profile"),
            ("/body/expected_profile/epoch", json!(m - 3), "profile"),
            ("/body/expected_profile/hash", json!(other), "VerifyFailed"),
            ("/body/profile/version", json!(1), "profile"),
            ("/body/profile/epoch", json!(m - 2), "profile"),
            ("/body/profile/hash", json!(other), "VerifyFailed"),
            ("/body/old_name", json!("alice2"), "old_name"),
            ("/body/binding", Value::Null, "old_name"),
            ("/body/binding/body/name", json!("alice2"), "old_name"),
            ("/body/binding/body/node", json!("other.example"), "VerifyFailed"),
            ("/body/binding/body/principal_commitment", json!(other), "binding"),
            ("/body/binding/body/epoch", json!(m - 2), "binding"),
            ("/body/binding/signature", json!(encode_base64url([0_u8; 64])), "VerifyFailed"),
            ("/body/discoverable", json!(true), "VerifyFailed"),
            ("/body/issued_at", json!(m - 10_000_012), "expires_at"),
            ("/body/expires_at", json!(m - 10_000_000 + 289), "expires_at"),
        ]
    }
    fn receipt_mutations() -> Vec<FieldMutation> {
        use serde_json::json;
        let m = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
        let other = encode_base64url([19_u8; 32]);
        vec![
            ("/body/center_id", json!("other.example"), "CenterId"),
            ("/body/operation_id", json!(other), "VerifyFailed"),
            ("/body/operation_hash", json!(other), "VerifyFailed"),
            ("/body/principal_commitment", json!(other), "VerifyFailed"),
            ("/body/epoch", json!(m - 2), "VerifyFailed"),
            ("/body/state", json!("aborted"), "VerifyFailed"),
            ("/body/binding_hash", json!(other), "VerifyFailed"),
            ("/body/profile/version", json!(1), "profile"),
            ("/body/profile/epoch", json!(m - 2), "VerifyFailed"),
            ("/body/profile/hash", json!(other), "VerifyFailed"),
            ("/body/discoverable", json!(true), "VerifyFailed"),
            ("/body/committed_at", json!(m - 10_000_000 - 86_401), "VerifyFailed"),
            ("/body/expires_at", json!(m - 10_000_000 + 59), "VerifyFailed"),
        ]
    }
    fn resolve_mutations() -> Vec<FieldMutation> {
        use serde_json::json;
        let m = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
        let other = encode_base64url([19_u8; 32]);
        vec![
            ("/body/center_id", json!("other.example"), "CenterId"),
            ("/body/name", json!("alice2"), "VerifyFailed"),
            ("/body/node", json!("other.example"), "VerifyFailed"),
            ("/body/principal_commitment", json!(other), "VerifyFailed"),
            ("/body/epoch", json!(m - 2), "VerifyFailed"),
            ("/body/binding_hash", json!(other), "VerifyFailed"),
            ("/body/profile/version", json!(1), "profile"),
            ("/body/profile/epoch", json!(m - 2), "VerifyFailed"),
            ("/body/profile/hash", json!(other), "VerifyFailed"),
            ("/body/request_nonce", json!(other), "VerifyFailed"),
            ("/body/issued_at", json!(m - 10_000_000 - 1), "expires_at"),
            ("/body/expires_at", json!(m - 10_000_000 + 59), "VerifyFailed"),
        ]
    }
    #[test]
    fn username_typed_verifiers_reject_each_field() -> TestResult {
        let vectors = corpus()?;
        let cases = vectors["signatures"].as_array().ok_or("missing signatures")?;
        // Each tuple is one changed field and its fixed, specific public-verifier error.
        let groups = vec![
            ("binding", binding_mutations()),
            ("profile_9007199254740990", profile_mutations()),
            ("operation", operation_mutations()),
            ("receipt", receipt_mutations()),
            ("resolve", resolve_mutations()),
        ];
        let mut fields = 0;
        for (name, mutations) in groups {
            let case =
                cases.iter().find(|c| string(c, "name") == name).ok_or("missing signed case")?;
            let original: Value = serde_json::from_str(string(case, "wire"))?;
            for (path, replacement, expected) in mutations {
                let mut value = original.clone();
                *value.pointer_mut(path).ok_or("missing signed field")? = replacement;
                let result = verify_case(
                    string(case, "type"),
                    &ramflux_protocol::canonical_json_bytes(&value)?,
                    &key(case, "key")?,
                    string(&vectors, "center_id"),
                );
                let matched = match &result {
                    Err(Error::Crypto(crate::CryptoError::VerifyFailed)) => {
                        expected == "VerifyFailed"
                    }
                    Err(Error::RootCommitment) => expected == "RootCommitment",
                    Err(Error::CenterId) => expected == "CenterId",
                    Err(Error::Codec(wire::CodecError::Field(field))) => *field == expected,
                    _ => false,
                };
                assert!(matched, "{name}{path} expected {expected}, got {result:?}");
                fields += 1;
            }
        }
        assert_eq!(fields, 62);
        Ok(())
    }

    #[test]
    fn username_nested_binding_and_signer_rejections() -> TestResult {
        let vectors = corpus()?;
        let cases = vectors["signatures"].as_array().ok_or("missing signatures")?;
        let case =
            cases.iter().find(|v| string(v, "name") == "operation").ok_or("missing operation")?;
        let mut operation: wire::UsernameOperation = wire::decode(string(case, "wire").as_bytes())?;
        let public = key(&vectors, "root_key")?;
        let signer = SigningKey::from_bytes(&[17; 32]);
        operation.body.binding.as_mut().ok_or("missing binding")?.signature =
            encode_base64url([0_u8; 64]);
        assert!(matches!(
            sign_operation(&signer, operation.body.clone()),
            Err(Error::Crypto(crate::CryptoError::VerifyFailed))
        ));
        // A valid outer root signature must never hide an invalid nested binding signature.
        operation.signature =
            encode_base64url(signer.sign(&wire::signing_bytes(&operation.body)?).to_bytes());
        assert!(matches!(
            verify_operation(&public, &operation),
            Err(Error::Crypto(crate::CryptoError::VerifyFailed))
        ));
        let wrong = SigningKey::from_bytes(&[31; 32]);
        let binding = operation.body.binding.as_ref().ok_or("missing binding")?;
        assert!(matches!(sign_binding(&wrong, binding.body.clone()), Err(Error::RootCommitment)));
        let profile: wire::SignedIdentityProfileV2 =
            wire::decode(string(&cases[0], "wire").as_bytes())?;
        assert!(matches!(sign_profile(&wrong, profile.body), Err(Error::RootCommitment)));
        assert!(matches!(sign_operation(&wrong, operation.body), Err(Error::RootCommitment)));
        for kind in ["DirectoryReceipt", "DirectoryResolve"] {
            let c =
                cases.iter().find(|v| string(v, "type") == kind).ok_or("missing center record")?;
            assert!(matches!(
                sign_case(kind, string(c, "wire").as_bytes(), &wrong, "other.example"),
                Err(Error::CenterId)
            ));
        }
        let weak = VerifyingKey::from_bytes(&[0_u8; 32])?;
        assert!(matches!(
            verify_profile(&weak, &wire::decode(string(&cases[0], "wire").as_bytes())?),
            Err(Error::RootCommitment)
        ));
        Ok(())
    }
    use wire::*;
    fn roundtrip(kind: &str, bytes: &[u8]) -> Result<Vec<u8>, wire::CodecError> {
        match kind {
            "UsernameBindingBody" => encode(&decode::<UsernameBindingBody>(bytes)?),
            "ProfileRef" => encode(&decode::<ProfileRef>(bytes)?),
            "AvatarRef" => encode(&decode::<AvatarRef>(bytes)?),
            "IdentityProfileV2Body" => encode(&decode::<IdentityProfileV2Body>(bytes)?),
            "UsernameOperationBody" => encode(&decode::<UsernameOperationBody>(bytes)?),
            "DirectoryReceiptBody" => encode(&decode::<DirectoryReceiptBody>(bytes)?),
            "DirectoryResolveBody" => encode(&decode::<DirectoryResolveBody>(bytes)?),
            "ReceiptDecision" => encode(&decode::<ReceiptDecision>(bytes)?),
            "RootRow" => encode(&decode::<RootRow>(bytes)?),
            "NameRow" => encode(&decode::<NameRow>(bytes)?),
            "SkeletonRow" => encode(&decode::<SkeletonRow>(bytes)?),
            "HoldKey" => encode(&decode::<HoldKey>(bytes)?),
            "HoldRow" => encode(&decode::<HoldRow>(bytes)?),
            "OperationKey" => encode(&decode::<OperationKey>(bytes)?),
            "OperationRow" => encode(&decode::<OperationRow>(bytes)?),
            "OperationOwnerRow" => encode(&decode::<OperationOwnerRow>(bytes)?),
            "DueRow" => encode(&decode::<DueRow>(bytes)?),
            "CounterRow" => encode(&decode::<CounterRow>(bytes)?),
            "CheckpointDelta" => encode(&decode::<CheckpointDelta>(bytes)?),
            "Checkpoint" => encode(&decode::<Checkpoint>(bytes)?),
            "HomeRevalidateRequest" => encode(&decode::<HomeRevalidateRequest>(bytes)?),
            "HomeRevalidateResult" => encode(&decode::<HomeRevalidateResult>(bytes)?),
            "DirectoryFailure" => encode(&decode::<DirectoryFailure>(bytes)?),
            "UsernameBinding" => encode(&decode::<UsernameBinding>(bytes)?),
            "SignedIdentityProfileV2" => encode(&decode::<SignedIdentityProfileV2>(bytes)?),
            "UsernameOperation" => encode(&decode::<UsernameOperation>(bytes)?),
            "DirectoryReceipt" => encode(&decode::<DirectoryReceipt>(bytes)?),
            "DirectoryResolve" => encode(&decode::<DirectoryResolve>(bytes)?),
            "Replacement" => encode(&decode::<Replacement>(bytes)?),
            "DueKey" => encode(&decode::<DueKey>(bytes)?),
            "CounterKey" => encode(&decode::<CounterKey>(bytes)?),
            "ServeCandidate" => encode(&decode::<ServeCandidate>(bytes)?),
            _ => Err(wire::CodecError::Field("unknown test type")),
        }
    }

    #[test]
    fn username_crypto_entry_rejects_every_schema_rule() -> TestResult {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../scripts/reference/username_directory/wire_vectors.json"
        ))?;
        let cases = corpus["invalid"].as_array().ok_or("missing schema negatives")?;
        assert_eq!(cases.len(), 563);
        let mut fields = 0;
        for case in cases {
            let error = roundtrip(string(case, "type"), string(case, "wire").as_bytes());
            if string(case, "field") == "!i_json" {
                assert!(matches!(
                    error,
                    Err(wire::CodecError::Protocol(ramflux_protocol::ProtocolError::IJson(_)))
                ));
            } else if string(case, "field").is_empty() {
                assert!(error.is_err(), "{}", case["name"]);
            } else {
                assert!(
                    matches!(error,Err(wire::CodecError::Field(field)) if field==string(case,"field")),
                    "specific rule {}: {:?}",
                    case["name"],
                    error
                );
                fields += 1;
            }
        }
        assert!(fields >= 277);
        Ok(())
    }
}
