// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A client envelope cannot replace the authenticated gateway session's sender or authority.
use crate::GatewaySessionRuntime;
pub(crate) fn bind_source(
    runtime: &GatewaySessionRuntime,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<ramflux_protocol::Envelope> {
    if envelope.source_principal_id != runtime.principal_id
        || envelope.source_device_id != runtime.source_identity.device_id()
        || envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
            != Some(runtime.source_identity.root_commitment())
    {
        anyhow::bail!("submit source differs from authenticated session");
    }
    ramflux_node_core::check_entry_bound(envelope)?;
    let mut envelope = envelope.clone();
    envelope.ext.ext.remove("source_device_authority");

    ramflux_protocol::message::outer::refuse_live_bridge(&envelope)
        .map_err(|error| anyhow::anyhow!(error))?;

    ramflux_protocol::verify_envelope_sender_signature(&envelope, &runtime.branch_public_key)?;
    // The router resolves the current signed set for every submission.
    // A session-open snapshot must never be propagated as current authority.
    Ok(envelope)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn authority(
        principal: &str,
        device: &str,
        root_seed: u8,
        public_key: String,
        epoch: u64,
    ) -> anyhow::Result<ramflux_node_core::DeviceAuthKeyResponse> {
        let root = ramflux_crypto::create_identity_root(principal, [root_seed; 32]);
        let agreement = ramflux_crypto::X25519KeyPair::from_seed([9; 32]);
        let keys = ramflux_crypto::device_key_commitments(
            &public_key,
            &ramflux_protocol::encode_base64url(agreement.public),
        )?;
        let record = ramflux_crypto::sign_device_set(
            &root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: 1,
                devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                    device_id: device.into(),
                    device_epoch: epoch,
                    signing_key_commitment: keys.0,
                    agreement_key_commitment: keys.1,
                    status: ramflux_protocol::DeviceSetStatus::Active,
                    revoked_at: None,
                }],
            },
        )?;
        Ok(ramflux_node_core::DeviceAuthKeyResponse {
            custody_authority: None,
            root_public_key: Some(ramflux_protocol::encode_base64url(
                root.signing_key.verifying_key().to_bytes(),
            )),
            signed_device_set: Some(record),
            principal_id: principal.into(),
            device_id: device.into(),
            device_epoch: epoch,
            branch_public_key: public_key,
            target_delivery_id: "source-delivery".into(),
            revoked: false,
        })
    }
    #[test]
    fn submit_binds_principal_device_root_signature_and_strips_client_authority()
    -> anyhow::Result<()> {
        let branch = ramflux_crypto::create_device_branch("alice", "shared", 1, [2; 32]);
        let authority = authority(
            "alice",
            "shared",
            1,
            ramflux_crypto::public_key_base64url_from_seed(&[2; 32]),
            1,
        )?;
        let runtime = GatewaySessionRuntime {
            call_session_generation: None,
            session_push: None,
            ephemeral: false,
            push_limit: 256,
            source_identity: authority.authenticated_device_identity()?,
            session_id: "session".into(),
            resume_token: "resume".into(),
            principal_id: "alice".into(),
            device_id: "shared".into(),
            target_delivery_id: "source-delivery".into(),
            branch_public_key: authority.branch_public_key.clone(),
            device_epoch: 1,
            supports_forward_ack: false,
            ephemeral_rate: std::sync::Arc::default(),
        };
        let mut envelope = ramflux_node_core::test_support::federation_fixtures::envelope(
            "one",
            "peer",
            ramflux_protocol::DeliveryClass::Message,
        );
        envelope.source_device_id = "shared".into();
        envelope.signed.signing_key_id = "shared".into();
        envelope.ttl = 600;
        envelope.created_at = 1000;
        envelope.ext.ext.insert(
            "source_root_commitment".into(),
            serde_json::json!(runtime.source_identity.root_commitment()),
        );
        envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
            &branch,
        );
        envelope
            .ext
            .ext
            .insert("source_device_authority".into(), serde_json::json!({"forged":true}));
        assert!(!bind_source(&runtime, &envelope)?.ext.ext.contains_key("source_device_authority"));
        for refused in [
            ramflux_protocol::DeliveryClass::OpaqueEvent,
            ramflux_protocol::DeliveryClass::NotificationWake,
            ramflux_protocol::DeliveryClass::SelfDeviceControl,
        ] {
            let mut wrong_class = envelope.clone();
            wrong_class.delivery_class = refused.clone();
            let error = bind_source(&runtime, &wrong_class)
                .err()
                .ok_or_else(|| anyhow::anyhow!("{refused:?} must be refused"))?;
            assert!(
                matches!(
                    error.downcast_ref::<ramflux_node_core::NodeCoreError>(),
                    Some(ramflux_node_core::NodeCoreError::DeliveryClassRefused)
                ),
                "generation 1 session ingress refuses {refused:?} with the typed class error: {error}"
            );
        }
        let mut forged = envelope.clone();
        forged.source_principal_id = "mallory".into();
        assert!(bind_source(&runtime, &forged).is_err());
        forged = envelope.clone();
        forged.source_device_id = "other".into();
        assert!(bind_source(&runtime, &forged).is_err());
        forged = envelope.clone();
        forged.ext.ext.insert("source_root_commitment".into(), serde_json::json!("other"));
        assert!(bind_source(&runtime, &forged).is_err());
        forged = envelope;
        forged.signed.signature = "invalid".into();
        assert!(bind_source(&runtime, &forged).is_err());
        Ok(())
    }
}
