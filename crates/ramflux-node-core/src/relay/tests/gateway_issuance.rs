// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::relay::{
    OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS, OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS,
    ObjectRelayCapability, RelayTokenIssueBody, relay_token_mac, validate_object_permission,
    validate_relay_token_issue_body,
};

use crate::relay::test_support::test_object_permission;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn deferred_issuer_permission_allow_bounded_future_issued_at() -> Result<(), String> {
    let now = 1_000;
    let issued_at = now + 30;
    let expires_at = now + 300;
    let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

    validate_object_permission(&permission, ObjectRelayCapability::Get, now)
        .map_err(|source| source.to_string())?;
    Ok(())
}

#[test]
fn deferred_issuer_permission_reject_future_issued_at_beyond_leeway() -> Result<(), String> {
    let now = 1_000;
    let issued_at = now + OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS + 1;
    let expires_at = issued_at + 300;
    let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

    assert!(validate_object_permission(&permission, ObjectRelayCapability::Get, now).is_err());
    Ok(())
}

#[test]
fn deferred_issuer_permission_reject_expired_without_leeway() -> Result<(), String> {
    let now = 1_000;
    let issued_at = now - 30;
    let expires_at = now;
    let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

    assert!(validate_object_permission(&permission, ObjectRelayCapability::Get, now).is_err());
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

#[test]
fn deferred_gateway_token_golden_preserves_base64url_bytes() -> Result<(), crate::NodeCoreError> {
    let token = crate::relay::RelayToken {
        token_version: 2,
        token_id: "token-golden".into(),
        object_id: "object-golden".into(),
        manifest_hash: "manifest-golden".into(),
        chunk_id: "chunk-golden".into(),
        recipient_device_hash: "recipient-golden".into(),
        owner_signing_key_id: "owner-key-golden".into(),
        owner_public_key: "owner-public-golden".into(),
        issuer_service: "ramflux-gateway".into(),
        audience_service: "ramflux-relay".into(),
        capabilities: vec![ObjectRelayCapability::Get],
        delete_after_ack: false,
        issued_at: 1_700_000_000,
        expires_at: 1_700_000_300,
        nonce: "nonce-golden".into(),
        mac: String::new(),
    };
    assert_eq!(
        relay_token_mac(b"golden-service-key", &token)?,
        "N7X_3SD5SWTvAq3R53gDwsei_4V33QgjAfdd_nVOe1o"
    );
    Ok(())
}
