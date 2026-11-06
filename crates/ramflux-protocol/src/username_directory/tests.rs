// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    wire: String,
    #[serde(default)]
    bytes: usize,
    #[serde(default)]
    field: String,
}
#[derive(Deserialize)]
struct Legacy {
    profile: String,
    signing: String,
    native: String,
}
#[derive(Deserialize)]
struct Corpus {
    valid: Vec<Case>,
    invalid: Vec<Case>,
    legacy: Legacy,
    transcripts: std::collections::BTreeMap<String, String>,
}
fn corpus() -> Result<Corpus, serde_json::Error> {
    serde_json::from_str(include_str!(
        "../../../../scripts/reference/username_directory/wire_vectors.json"
    ))
}
fn roundtrip(kind: &str, bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
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
        _ => Err(CodecError::Field("unknown test type")),
    }
}

#[test]
fn username_canonical_domains_and_maxima() -> Result<(), Box<dyn std::error::Error>> {
    assert!(!enabled());
    let vectors = corpus()?;
    for case in &vectors.valid {
        if let Some(expected) = vectors.transcripts.get(&case.name) {
            let bytes = case.wire.as_bytes();
            let actual = match case.kind.as_str() {
                "UsernameBinding" => signing_bytes(&decode::<UsernameBinding>(bytes)?.body)?,
                "SignedIdentityProfileV2" => {
                    signing_bytes(&decode::<SignedIdentityProfileV2>(bytes)?.body)?
                }
                "UsernameOperation" => signing_bytes(&decode::<UsernameOperation>(bytes)?.body)?,
                "DirectoryReceipt" => signing_bytes(&decode::<DirectoryReceipt>(bytes)?.body)?,
                "DirectoryResolve" => signing_bytes(&decode::<DirectoryResolve>(bytes)?.body)?,
                _ => return Err(std::io::Error::other("unknown transcript kind").into()),
            };
            assert_eq!(actual, expected.as_bytes(), "{} frozen E transcript", case.name);
        }
    }
    assert_eq!(DirectoryFailure::new(DirectoryCode::Capacity, 0).retry_after_ms, Some(1000));
    assert_eq!(
        DirectoryFailure::new(DirectoryCode::RateLimited, u64::MAX).retry_after_ms,
        Some(60000)
    );
    assert_eq!(DirectoryCode::AuthenticationRequired.http_status(), 401);
    for case in vectors.valid {
        let bytes = roundtrip(&case.kind, case.wire.as_bytes())
            .map_err(|e| std::io::Error::other(format!("{}: {e}", case.name)))?;
        assert_eq!(bytes, case.wire.as_bytes(), "{} identity", case.name);
        assert_eq!(bytes.len(), case.bytes, "{} maximum", case.name);
    }
    for case in vectors.invalid {
        let result = roundtrip(&case.kind, case.wire.as_bytes());
        assert!(result.is_err(), "accepted negative {}", case.name);
        if case.field == "!i_json" {
            assert!(
                matches!(result, Err(CodecError::Protocol(crate::ProtocolError::IJson(_)))),
                "{} safe-integer parser rejection: {result:?}",
                case.name
            );
        } else if !case.field.is_empty() {
            assert!(
                matches!(result,Err(CodecError::Field(field)) if field==case.field),
                "{} specific rejection: {result:?}",
                case.name
            );
        }
    }
    let sources: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../scripts/reference/username_directory/oracle_sources.json"
    ))?;
    for (name, domain) in [
        ("USERNAME_BINDING", crate::domain::USERNAME_BINDING),
        ("IDENTITY_PROFILE_V2", crate::domain::IDENTITY_PROFILE_V2),
        ("USERNAME_OPERATION", crate::domain::USERNAME_OPERATION),
        ("USERNAME_OPERATION_HASH", crate::domain::USERNAME_OPERATION_HASH),
        ("USERNAME_CHECKPOINT", crate::domain::USERNAME_CHECKPOINT),
        ("USERNAME_PROFILE_HASH", crate::domain::USERNAME_PROFILE_HASH),
        ("USERNAME_BINDING_HASH", crate::domain::USERNAME_BINDING_HASH),
        ("USERNAME_RECEIPT", crate::domain::USERNAME_RECEIPT),
        ("USERNAME_RESOLVE", crate::domain::USERNAME_RESOLVE),
        ("AVATAR_CONTENT", crate::domain::AVATAR_CONTENT),
    ] {
        assert_eq!(sources["domains"][name].as_str(), Some(domain), "{name}");
    }
    for c in "abcdefghijklmnopqrstuvwxyz0123456789_".chars() {
        let name = c.to_string().repeat(5);
        let expected = match c {
            'm' => "rn".repeat(5),
            '0' => "O".repeat(5),
            '1' => "l".repeat(5),
            _ => name.clone(),
        };
        assert_eq!(crate::identity_name::username_comparison_key(&name)?, expected);
    }
    assert_eq!(normalize_username("  ALICE  ")?, "alice");
    assert_eq!(normalize_bio(" Cafe\u{301} ")?, "Café");
    Ok(())
}

#[test]
fn username_v1_native_profile_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let vectors = corpus()?;
    let legacy = vectors.legacy;
    let profile: crate::SignedIdentityProfile = crate::parse_i_json(legacy.profile.as_bytes())?;
    assert_eq!(crate::identity_profile_signing_bytes(&profile)?, legacy.signing.as_bytes());
    assert_eq!(crate::canonical_json_bytes(&profile)?, legacy.profile.as_bytes());
    let native: crate::custody::Profile = crate::parse_i_json(legacy.native.as_bytes())?;
    assert_eq!(crate::canonical_json_bytes(&native)?, legacy.native.as_bytes());
    let document = crate::identity_profile_v2::decode_profile_document(legacy.profile.as_bytes())?;
    assert!(matches!(document, crate::identity_profile_v2::IdentityProfileDocument::V1(_)));
    assert_eq!(document.encode()?, legacy.profile.as_bytes());
    let v2 = vectors
        .valid
        .iter()
        .find(|c| c.kind == "SignedIdentityProfileV2")
        .ok_or_else(|| std::io::Error::other("missing v2 fixture"))?;
    let parsed = crate::identity_profile_v2::decode_profile_document(v2.wire.as_bytes())?;
    assert!(matches!(parsed, crate::identity_profile_v2::IdentityProfileDocument::V2(_)));
    assert_eq!(parsed.encode()?, v2.wire.as_bytes());
    let invalid =
        v2.wire.replace(crate::domain::IDENTITY_PROFILE_V2, "ramflux.identity.profile.v9");
    assert!(crate::identity_profile_v2::decode_profile_document(invalid.as_bytes()).is_err());
    Ok(())
}
