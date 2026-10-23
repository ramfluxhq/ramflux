// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::relay::{
    OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS, OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS,
    ObjectRelayCapability, RelayTokenIssueBody, relay_token_mac, validate_object_permission,
    validate_relay_token, validate_relay_token_issue_body,
};

use crate::relay::test_support::{test_object_permission, test_relay_token};

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn relay_token_and_permission_allow_bounded_future_issued_at() -> Result<(), String> {
    let service_key = b"relay-clock-skew-test-key";
    let now = 1_000;
    let issued_at = now + 30;
    let expires_at = now + 300;
    let token = test_relay_token(service_key, ObjectRelayCapability::Get, issued_at, expires_at)?;
    let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

    validate_relay_token(&token, service_key, ObjectRelayCapability::Get, now)
        .map_err(|source| source.to_string())?;
    validate_object_permission(&permission, ObjectRelayCapability::Get, now)
        .map_err(|source| source.to_string())?;
    Ok(())
}

#[test]
fn relay_token_and_permission_reject_future_issued_at_beyond_leeway() -> Result<(), String> {
    let service_key = b"relay-clock-skew-test-key";
    let now = 1_000;
    let issued_at = now + OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS + 1;
    let expires_at = issued_at + 300;
    let token = test_relay_token(service_key, ObjectRelayCapability::Get, issued_at, expires_at)?;
    let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

    assert!(validate_relay_token(&token, service_key, ObjectRelayCapability::Get, now).is_err());
    assert!(validate_object_permission(&permission, ObjectRelayCapability::Get, now).is_err());
    Ok(())
}

#[test]
fn relay_token_and_permission_reject_expired_without_leeway() -> Result<(), String> {
    let service_key = b"relay-clock-skew-test-key";
    let now = 1_000;
    let issued_at = now - 30;
    let expires_at = now;
    let token = test_relay_token(service_key, ObjectRelayCapability::Get, issued_at, expires_at)?;
    let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

    assert!(validate_relay_token(&token, service_key, ObjectRelayCapability::Get, now).is_err());
    assert!(validate_object_permission(&permission, ObjectRelayCapability::Get, now).is_err());
    Ok(())
}

#[test]
fn relay_token_v2_rejects_wrong_issuer_audience_and_capability() -> Result<(), String> {
    let service_key = b"relay-token-v2-key";
    let now = 1_000;
    let token = test_relay_token(service_key, ObjectRelayCapability::Get, now, now + 300)?;

    let mut wrong_issuer = token.clone();
    wrong_issuer.issuer_service = "router".to_owned();
    wrong_issuer.mac =
        relay_token_mac(service_key, &wrong_issuer).map_err(|source| source.to_string())?;
    assert!(
        validate_relay_token(&wrong_issuer, service_key, ObjectRelayCapability::Get, now).is_err()
    );

    let mut wrong_audience = token.clone();
    wrong_audience.audience_service = "ramflux-router".to_owned();
    wrong_audience.mac =
        relay_token_mac(service_key, &wrong_audience).map_err(|source| source.to_string())?;
    assert!(
        validate_relay_token(&wrong_audience, service_key, ObjectRelayCapability::Get, now)
            .is_err()
    );

    let mut multi_capability = token;
    multi_capability.capabilities.push(ObjectRelayCapability::Ack);
    multi_capability.mac =
        relay_token_mac(service_key, &multi_capability).map_err(|source| source.to_string())?;
    assert!(
        validate_relay_token(&multi_capability, service_key, ObjectRelayCapability::Get, now)
            .is_err()
    );
    Ok(())
}

#[test]
fn relay_token_v2_rejects_forged_and_expired_tokens() -> Result<(), String> {
    let service_key = b"relay-token-v2-key";
    let now = 1_000;
    let mut forged = test_relay_token(service_key, ObjectRelayCapability::Get, now, now + 300)?;
    forged.object_id = "forged-object".to_owned();
    assert!(validate_relay_token(&forged, service_key, ObjectRelayCapability::Get, now).is_err());

    let expired = test_relay_token(service_key, ObjectRelayCapability::Get, now - 600, now - 1)?;
    assert!(validate_relay_token(&expired, service_key, ObjectRelayCapability::Get, now).is_err());
    Ok(())
}

#[test]
fn relay_token_issue_body_enforces_ttl_and_permission_binding() -> Result<(), String> {
    let now = 1_000;
    let permission = test_object_permission(ObjectRelayCapability::Get, now, now + 300)?;
    let body = RelayTokenIssueBody {
        object_id: permission.object_id.clone(),
        manifest_hash: permission.manifest_hash.clone(),
        chunk_id: "chunk_relay_clock_skew".to_owned(),
        recipient_device_hash: permission.grantee_device_hash.clone(),
        owner_signing_key_id: permission.owner_signing_key_id.clone(),
        owner_public_key: permission.owner_public_key.clone(),
        capability: ObjectRelayCapability::Get,
        delete_after_ack: false,
        issued_at: now,
        expires_at: now + OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS,
        object_permission_envelope: permission.clone(),
    };
    validate_relay_token_issue_body(&body, now).map_err(|source| source.to_string())?;

    let mut long_ttl = body.clone();
    long_ttl.expires_at = now + OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS + 1;
    assert!(validate_relay_token_issue_body(&long_ttl, now).is_err());

    let mut mismatched = body;
    mismatched.recipient_device_hash = "other_recipient".to_owned();
    assert!(validate_relay_token_issue_body(&mismatched, now).is_err());
    Ok(())
}
