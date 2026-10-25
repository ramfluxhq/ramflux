// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lease consent is checked against current registry membership and the live session's actor.
use super::*;
use ramflux_node_core::{DeviceManifestEntry, DeviceManifestResponse};
use ramflux_protocol::{CallEndpoint, VoiceAllocationRequest, VoiceLeaseConsent};
fn identity(
    name: &str,
    seed: u8,
) -> anyhow::Result<(CallEndpoint, DeviceManifestResponse, ramflux_crypto::DeviceBranch)> {
    let root = ramflux_crypto::create_identity_root(name, [seed; 32]);
    let device =
        ramflux_crypto::create_device_branch(name, &format!("{name}-device"), 1, [seed + 1; 32]);
    let public = ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let commitment = ramflux_crypto::blake3_256_base64url("test-root", public.as_bytes());
    let manifest = DeviceManifestResponse {
        principal_id: name.into(),
        principal_commitment: commitment.clone(),
        root_public_key: public.clone(),
        devices: vec![DeviceManifestEntry {
            principal_id: name.into(),
            principal_commitment: commitment,
            device_id: device.device_id.clone(),
            device_epoch: 1,
            branch_public_key: ramflux_protocol::encode_base64url(
                device.signing_key.verifying_key().to_bytes(),
            ),
            target_delivery_id: name.into(),
            branch_proof: ramflux_crypto::authorize_device_branch(
                &root,
                &device,
                "ramflux-node",
                vec!["device.delivery.bind".into()],
                1,
                20000,
            )?,
            prekey_bundle: ramflux_crypto::create_prekey_bundle(
                &device,
                &ramflux_crypto::X25519KeyPair::from_seed([seed + 2; 32]),
                "spk",
                &ramflux_crypto::X25519KeyPair::from_seed([seed + 3; 32]),
                None,
                None,
            )?,
            branch_authorized_event_id: "branch".into(),
        }],
    };
    Ok((
        CallEndpoint {
            principal_id: name.into(),
            root_public_key: public,
            device_id: device.device_id.clone(),
        },
        manifest,
        device,
    ))
}
fn runtime(endpoint: &CallEndpoint, key: &ramflux_crypto::DeviceBranch) -> GatewaySessionRuntime {
    GatewaySessionRuntime {
        principal_id: endpoint.principal_id.clone(),
        device_id: endpoint.device_id.clone(),
        branch_public_key: ramflux_protocol::encode_base64url(
            key.signing_key.verifying_key().to_bytes(),
        ),
        session_id: "session".into(),
        resume_token: "resume".into(),
        target_delivery_id: endpoint.principal_id.clone(),
    }
}
#[test]
fn only_the_consented_callee_session_can_claim_callee_relay_secrets() -> anyhow::Result<()> {
    let (caller, a, ka) = identity("alice", 1)?;
    let (callee, b, kb) = identity("bob", 5)?;
    let scope = VoiceAllocationRequest {
        call_id: ramflux_protocol::encode_base64url([1; 16]),
        caller: caller.clone(),
        callee: callee.clone(),
    };
    let mut consent = VoiceLeaseConsent {
        scope: scope.clone(),
        lease_id: ramflux_protocol::encode_base64url([2; 16]),
        expires_at: 1000,
        signature: String::new(),
    };
    consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::voice_lease_consent_bytes(&consent)?,
        &kb,
    );
    let accept = VoiceLeaseRequest::Accept { consent: Box::new(consent.clone()) };
    assert!(validate_authority(&accept, &runtime(&callee, &kb), &a, &b, 100).is_ok());
    assert!(validate_authority(&accept, &runtime(&caller, &ka), &a, &b, 100).is_err());
    let renew = VoiceLeaseRequest::Renew { consent: Box::new(consent) };
    assert!(validate_authority(&renew, &runtime(&caller, &ka), &a, &b, 100).is_ok());
    assert!(validate_authority(&renew, &runtime(&callee, &kb), &a, &b, 100).is_err());
    Ok(())
}
#[test]
fn forged_replayed_or_revoked_device_consents_cannot_authorize_a_voice_lease() -> anyhow::Result<()>
{
    let (caller, a, _) = identity("alice", 1)?;
    let (callee, b, kb) = identity("bob", 5)?;
    let mut consent = VoiceLeaseConsent {
        scope: VoiceAllocationRequest {
            call_id: ramflux_protocol::encode_base64url([1; 16]),
            caller,
            callee: callee.clone(),
        },
        lease_id: ramflux_protocol::encode_base64url([2; 16]),
        expires_at: 1000,
        signature: String::new(),
    };
    consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::voice_lease_consent_bytes(&consent)?,
        &kb,
    );
    for field in 0..5 {
        let mut changed = consent.clone();
        match field {
            0 => changed.signature = "forged".into(),
            1 => changed.lease_id = ramflux_protocol::encode_base64url([3; 16]),
            2 => changed.scope.call_id = ramflux_protocol::encode_base64url([4; 16]),
            3 => changed.expires_at = 99,
            _ => changed.expires_at = 20000,
        };
        assert!(
            validate_authority(
                &VoiceLeaseRequest::Accept { consent: Box::new(changed) },
                &runtime(&callee, &kb),
                &a,
                &b,
                100
            )
            .is_err()
        );
    }
    let request = VoiceLeaseRequest::Accept { consent: Box::new(consent) };
    for changed in 0..3 {
        let mut manifest = b.clone();
        match changed {
            0 => manifest.devices.clear(),
            1 => {
                manifest.devices[0].branch_public_key =
                    ramflux_crypto::public_key_base64url_from_seed([99; 32])
            }
            _ => {
                manifest.root_public_key = ramflux_crypto::public_key_base64url_from_seed([98; 32])
            }
        };
        assert!(validate_authority(&request, &runtime(&callee, &kb), &a, &manifest, 100).is_err());
    }
    Ok(())
}
