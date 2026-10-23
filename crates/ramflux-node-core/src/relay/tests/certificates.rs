// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::relay::{
    GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS, GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS,
    GatewayCertificateRevocation, NodeCoreError, OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS,
    ObjectRelayCapability, apply_gateway_certificate_revocation, gateway_certificate_is_renewal_of,
    gateway_certificate_matches_revocation, gateway_certificate_request_signing_bytes,
    gateway_issuer_certificate_signing_bytes, issue_gateway_issuer_certificate,
    verify_gateway_certificate_request, verify_gateway_issuer_certificate,
    verify_relay_token_v3_with_certificate,
};

use crate::relay::test_support::{
    V3_ATTESTATION_KEY_ID, V3_AUDIENCE_NODE, V3_GATEWAY_INSTANCE, V3_ISSUER_NODE, V3_ISSUER_SEED,
    V3_OWNER_SEED, V3_ROOT_KEY_ID, V3_ROOT_SEED, v3_certificate, v3_certificate_request,
    v3_get_token_for_cert, v3_pk, v3_resign_token, v3_sign,
};

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn v3_certificate_valid_chain_accepts() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);
    let cert = v3_certificate(now, |_cert| {})?;
    verify_gateway_issuer_certificate(&cert, &root_pk, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v3_certificate_rejects_wrong_node_or_instance() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);
    let wrong_node = v3_certificate(now, |cert| cert.node_id = "node-z".to_owned())?;
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &wrong_node,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    let wrong_instance = v3_certificate(now, |cert| cert.gateway_instance_id = "gw-z".to_owned())?;
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &wrong_instance,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_certificate_rejects_expired_not_yet_valid_and_revoked() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);

    let expired = v3_certificate(now, |cert| {
        cert.not_before = now - 100;
        cert.not_after = now - 1;
    })?;
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &expired,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    let not_yet = v3_certificate(now, |cert| {
        cert.not_before = now + 1_000;
        cert.not_after = now + 2_000;
        cert.issued_at = now + 1_000;
    })?;
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &not_yet,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    let inverted = v3_certificate(now, |cert| {
        cert.not_before = now + 100;
        cert.not_after = now + 10;
        cert.issued_at = now + 10;
    })?;
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &inverted,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // issued_at outside the validity window (below not_before and above not_after).
    let issued_before = v3_certificate(now, |cert| {
        cert.not_before = now - 50;
        cert.not_after = now + 50;
        cert.issued_at = now - 100;
    })?;
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &issued_before,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    let issued_after = v3_certificate(now, |cert| {
        cert.not_before = now - 50;
        cert.not_after = now + 50;
        cert.issued_at = now + 100;
    })?;
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &issued_after,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    let revoked = v3_certificate(now, |cert| cert.revoked_at = Some(now - 1))?;
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &revoked,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_certificate_rejects_root_signature_tamper() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);

    // Tamper a signed field without re-signing -> root signature invalid.
    let mut tampered = v3_certificate(now, |_cert| {})?;
    tampered.attestation_public_key = v3_pk(V3_OWNER_SEED);
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &tampered,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Certificate signed by a key that is not the pinned node root -> rejected.
    let mut wrong_root = v3_certificate(now, |_cert| {})?;
    wrong_root.node_root_signature = v3_sign(
        &gateway_issuer_certificate_signing_bytes(&wrong_root).map_err(|e| e.to_string())?,
        V3_OWNER_SEED,
    );
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &wrong_root,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_token_with_certificate_accepts_valid_chain() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);
    let (token, _grant) = v3_get_token_for_cert(now)?;
    let cert = v3_certificate(now, |_cert| {})?;
    verify_relay_token_v3_with_certificate(
        &token,
        &cert,
        &root_pk,
        ObjectRelayCapability::Get,
        V3_AUDIENCE_NODE,
        now,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v3_token_with_certificate_rejects_wrong_cert_key_id_or_issuer() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);
    let (token, _grant) = v3_get_token_for_cert(now)?;

    // Certificate id does not match the token's issuer_certificate_id.
    let wrong_cert_id = v3_certificate(now, |cert| cert.cert_id = "cert-z".to_owned())?;
    assert!(matches!(
        verify_relay_token_v3_with_certificate(
            &token,
            &wrong_cert_id,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Attestation key id does not match the token.
    let wrong_key_id = v3_certificate(now, |cert| cert.attestation_key_id = "att-z".to_owned())?;
    assert!(matches!(
        verify_relay_token_v3_with_certificate(
            &token,
            &wrong_key_id,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Certificate for a different node than the token's issuer node.
    let wrong_node = v3_certificate(now, |cert| cert.node_id = "node-z".to_owned())?;
    assert!(matches!(
        verify_relay_token_v3_with_certificate(
            &token,
            &wrong_node,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Certificate whose attestation key does not match the key that actually signed the token.
    let wrong_attestation_key = v3_certificate(now, |cert| {
        cert.attestation_public_key = v3_pk(V3_OWNER_SEED);
    })?;
    assert!(matches!(
        verify_relay_token_v3_with_certificate(
            &token,
            &wrong_attestation_key,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_token_certificate_rejects_frame_replacement_and_tamper() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);
    let (token, _grant) = v3_get_token_for_cert(now)?;
    let expected = token.issuer_certificate.clone();

    // Sanity: the embedded certificate equals the expected certificate -> valid chain.
    verify_relay_token_v3_with_certificate(
        &token,
        &expected,
        &root_pk,
        ObjectRelayCapability::Get,
        V3_AUDIENCE_NODE,
        now,
    )
    .map_err(|e| e.to_string())?;

    // Frame replacement: a different (still root-valid) certificate is presented as expected.
    let other = v3_certificate(now, |cert| cert.cert_id = "cert-other".to_owned())?;
    assert!(matches!(
        verify_relay_token_v3_with_certificate(
            &token,
            &other,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Embedded certificate tampered without re-signing the token: the embedded/expected
    // comparison fails (canonical differs).
    let mut tampered = token.clone();
    tampered.issuer_certificate.attestation_public_key = v3_pk(V3_OWNER_SEED);
    assert!(matches!(
        verify_relay_token_v3_with_certificate(
            &tampered,
            &expected,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Even if the caller passes the tampered embedded certificate as expected (comparison
    // matches), the tampered certificate no longer verifies against the pinned node root.
    let expected_tampered = tampered.issuer_certificate.clone();
    assert!(matches!(
        verify_relay_token_v3_with_certificate(
            &tampered,
            &expected_tampered,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Embedded certificate names a different node than the token's issuer_node_id (embedded ==
    // expected, token re-signed), caught by the root-bound certificate verification.
    let mut mismatched = v3_get_token_for_cert(now)?.0;
    mismatched.issuer_certificate = v3_certificate(now, |cert| cert.node_id = "node-z".to_owned())?;
    v3_resign_token(&mut mismatched)?;
    let mismatched_expected = mismatched.issuer_certificate.clone();
    assert!(matches!(
        verify_relay_token_v3_with_certificate(
            &mismatched,
            &mismatched_expected,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_certificate_request_and_issue_valid_chain() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);
    let request = v3_certificate_request(now, |_r| {})?;
    verify_gateway_certificate_request(&request, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
        .map_err(|e| e.to_string())?;

    let cert = issue_gateway_issuer_certificate(
        &request,
        V3_ROOT_KEY_ID,
        V3_ROOT_SEED,
        "cert-issued-1",
        now,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(cert.cert_id, "cert-issued-1");
    assert_eq!(cert.issued_at, now);
    assert_eq!(cert.node_id, V3_ISSUER_NODE);
    assert_eq!(cert.gateway_instance_id, V3_GATEWAY_INSTANCE);
    assert_eq!(cert.attestation_public_key, v3_pk(V3_ISSUER_SEED));
    assert_eq!(cert.attestation_key_id, V3_ATTESTATION_KEY_ID);
    assert_eq!(cert.node_root_signing_key_id, V3_ROOT_KEY_ID);
    assert!(cert.revoked_at.is_none());

    // The issued certificate verifies under the T2 verifier against the node root.
    verify_gateway_issuer_certificate(&cert, &root_pk, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v3_certificate_request_rejects_wrong_attestation_key_and_tamper() -> Result<(), String> {
    let now = 1_000_000;

    // Request signed by a key other than its declared attestation key.
    let mut wrong_key = v3_certificate_request(now, |_r| {})?;
    wrong_key.request_signature = v3_sign(
        &gateway_certificate_request_signing_bytes(&wrong_key).map_err(|e| e.to_string())?,
        V3_OWNER_SEED,
    );
    assert!(matches!(
        verify_gateway_certificate_request(&wrong_key, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Tamper a field / nonce without re-signing -> attestation signature invalid.
    let mut tampered = v3_certificate_request(now, |_r| {})?;
    tampered.request_nonce = "forged_nonce".to_owned();
    assert!(
        verify_gateway_certificate_request(&tampered, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
            .is_err()
    );
    Ok(())
}

#[test]
fn v3_certificate_request_rejects_wrong_node_instance_and_window() -> Result<(), String> {
    let now = 1_000_000;
    let request = v3_certificate_request(now, |_r| {})?;
    assert!(matches!(
        verify_gateway_certificate_request(&request, "node-z", V3_GATEWAY_INSTANCE, now),
        Err(NodeCoreError::Unauthorized(_))
    ));
    assert!(matches!(
        verify_gateway_certificate_request(&request, V3_ISSUER_NODE, "gw-z", now),
        Err(NodeCoreError::Unauthorized(_))
    ));

    let inverted = v3_certificate_request(now, |r| {
        r.not_before = now + 100;
        r.not_after = now + 10;
    })?;
    assert!(matches!(
        verify_gateway_certificate_request(&inverted, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now),
        Err(NodeCoreError::Unauthorized(_))
    ));

    let expired = v3_certificate_request(now, |r| {
        r.not_before = now - 100;
        r.not_after = now - 1;
    })?;
    assert!(matches!(
        verify_gateway_certificate_request(&expired, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    let future_requested_at = v3_certificate_request(now, |r| {
        r.requested_at = now + OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS + 1;
    })?;
    assert!(matches!(
        verify_gateway_certificate_request(
            &future_requested_at,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    // Stale request: requested_at older than the max age is rejected and is not issued.
    let stale = v3_certificate_request(now, |r| {
        r.requested_at = now - GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS - 1;
    })?;
    assert!(matches!(
        verify_gateway_certificate_request(&stale, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now),
        Err(NodeCoreError::TtlExpired { .. })
    ));
    assert!(matches!(
        issue_gateway_issuer_certificate(&stale, V3_ROOT_KEY_ID, V3_ROOT_SEED, "cert-stale", now),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    // Boundary: requested_at exactly at the max age is still accepted.
    let at_max_age = v3_certificate_request(now, |r| {
        r.requested_at = now - GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS;
    })?;
    verify_gateway_certificate_request(&at_max_age, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v3_issue_rejects_future_not_before_and_over_max_window() -> Result<(), String> {
    let now = 1_000_000;

    // not_before in the future: the certificate would not be active at issuance (issued_at=now
    // outside window).
    let future_not_before = v3_certificate_request(now, |r| {
        r.not_before = now + 100;
        r.not_after = now + 200;
    })?;
    assert!(matches!(
        issue_gateway_issuer_certificate(
            &future_not_before,
            V3_ROOT_KEY_ID,
            V3_ROOT_SEED,
            "cert-x",
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // not_after beyond the hard maximum TTL.
    let over_max = v3_certificate_request(now, |r| {
        r.not_before = now - 10;
        r.not_after = now + GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS + 1;
    })?;
    assert!(matches!(
        issue_gateway_issuer_certificate(&over_max, V3_ROOT_KEY_ID, V3_ROOT_SEED, "cert-x", now),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Boundary: exactly the maximum TTL is accepted and the issued cert verifies.
    let root_pk = v3_pk(V3_ROOT_SEED);
    let at_max = v3_certificate_request(now, |r| {
        r.not_before = now - 10;
        r.not_after = now + GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS;
    })?;
    let cert =
        issue_gateway_issuer_certificate(&at_max, V3_ROOT_KEY_ID, V3_ROOT_SEED, "cert-max", now)
            .map_err(|e| e.to_string())?;
    verify_gateway_issuer_certificate(&cert, &root_pk, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v3_issued_certificate_root_tamper_and_revocation() -> Result<(), String> {
    let now = 1_000_000;
    let root_pk = v3_pk(V3_ROOT_SEED);
    let request = v3_certificate_request(now, |_r| {})?;
    let cert =
        issue_gateway_issuer_certificate(&request, V3_ROOT_KEY_ID, V3_ROOT_SEED, "cert-rev-1", now)
            .map_err(|e| e.to_string())?;

    // Root signature tamper: mutate a signed field without re-signing.
    let mut tampered = cert.clone();
    tampered.attestation_public_key = v3_pk(V3_OWNER_SEED);
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &tampered,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Certificate signed by a non-root key is rejected.
    let mut wrong_root = cert.clone();
    wrong_root.node_root_signature = v3_sign(
        &gateway_issuer_certificate_signing_bytes(&wrong_root).map_err(|e| e.to_string())?,
        V3_OWNER_SEED,
    );
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &wrong_root,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Revocation binds by all identity fields; a mismatch does not apply.
    let mismatched = GatewayCertificateRevocation {
        cert_id: "cert-other".to_owned(),
        attestation_key_id: V3_ATTESTATION_KEY_ID.to_owned(),
        node_id: V3_ISSUER_NODE.to_owned(),
        gateway_instance_id: V3_GATEWAY_INSTANCE.to_owned(),
        revoked_at: now,
    };
    assert!(!gateway_certificate_matches_revocation(&cert, &mismatched));
    assert!(apply_gateway_certificate_revocation(&cert, &mismatched).is_err());

    // A matching revocation stamps revoked_at and the certificate then fails closed.
    let revocation = GatewayCertificateRevocation {
        cert_id: cert.cert_id.clone(),
        attestation_key_id: cert.attestation_key_id.clone(),
        node_id: cert.node_id.clone(),
        gateway_instance_id: cert.gateway_instance_id.clone(),
        revoked_at: now,
    };
    assert!(gateway_certificate_matches_revocation(&cert, &revocation));
    let revoked =
        apply_gateway_certificate_revocation(&cert, &revocation).map_err(|e| e.to_string())?;
    assert_eq!(revoked.revoked_at, Some(now));
    assert!(matches!(
        verify_gateway_issuer_certificate(
            &revoked,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_certificate_renewal_binding() -> Result<(), String> {
    let now = 1_000_000;
    let request = v3_certificate_request(now, |_r| {})?;
    let previous =
        issue_gateway_issuer_certificate(&request, V3_ROOT_KEY_ID, V3_ROOT_SEED, "cert-prev", now)
            .map_err(|e| e.to_string())?;

    // A fresh cert id for the same gateway with a not-earlier not_after is a renewal.
    let renew_request = v3_certificate_request(now, |r| {
        r.not_before = now - 5;
        r.not_after = now + 7_200;
    })?;
    let next = issue_gateway_issuer_certificate(
        &renew_request,
        V3_ROOT_KEY_ID,
        V3_ROOT_SEED,
        "cert-next",
        now,
    )
    .map_err(|e| e.to_string())?;
    assert!(gateway_certificate_is_renewal_of(&previous, &next));

    // Same cert id is not a renewal.
    let mut same_id = next.clone();
    same_id.cert_id = previous.cert_id.clone();
    assert!(!gateway_certificate_is_renewal_of(&previous, &same_id));

    // A different node/instance is not a renewal.
    let mut other_node = next.clone();
    other_node.node_id = "node-z".to_owned();
    assert!(!gateway_certificate_is_renewal_of(&previous, &other_node));
    Ok(())
}
