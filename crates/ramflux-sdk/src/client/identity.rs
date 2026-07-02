// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub fn create_identity_root(&mut self, principal_id: &str, seed: [u8; 32]) -> IdentityRoot {
        let root = ramflux_crypto::create_identity_root(principal_id, seed);
        self.identity_root = Some(root.clone());
        root
    }

    pub fn create_device_branch(
        &mut self,
        principal_id: &str,
        device_id: &str,
        device_epoch: u64,
        seed: [u8; 32],
    ) -> DeviceBranch {
        let branch =
            ramflux_crypto::create_device_branch(principal_id, device_id, device_epoch, seed);
        self.device_branch = Some(branch.clone());
        branch
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn authorize_current_device(
        &self,
        audience: &str,
        capability_scope: Vec<String>,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<BranchProofDocument, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(ramflux_crypto::authorize_device_branch(
            root,
            branch,
            audience,
            capability_scope,
            issued_at,
            expires_at,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn x3dh_initiator(&self, input: &X3dhInitiatorInput<'_>) -> Result<X3dhOutput, SdkError> {
        Ok(ramflux_crypto::x3dh_initiator(input)?)
    }

    /// # Errors
    /// Returns an error when X3DH recipient secret derivation fails.
    pub fn x3dh_recipient(&self, input: &X3dhRecipientInput<'_>) -> Result<X3dhOutput, SdkError> {
        Ok(ramflux_crypto::x3dh_recipient(input)?)
    }

    /// # Errors
    /// Returns an error when the initiator session keys cannot be derived.
    pub fn init_dm_initiator_session(
        &self,
        root_seed: [u8; 32],
        local_device_id_hash: [u8; 32],
        remote_device_id_hash: [u8; 32],
        bootstrap_transcript_hash: [u8; 32],
    ) -> Result<ramflux_crypto::DmSession, SdkError> {
        Ok(ramflux_crypto::DmSession::initiator(
            root_seed,
            local_device_id_hash,
            remote_device_id_hash,
            bootstrap_transcript_hash,
        )?)
    }

    /// # Errors
    /// Returns an error when the recipient session keys cannot be derived.
    pub fn init_dm_recipient_session(
        &self,
        root_seed: [u8; 32],
        local_device_id_hash: [u8; 32],
        remote_device_id_hash: [u8; 32],
        bootstrap_transcript_hash: [u8; 32],
    ) -> Result<ramflux_crypto::DmSession, SdkError> {
        Ok(ramflux_crypto::DmSession::recipient(
            root_seed,
            local_device_id_hash,
            remote_device_id_hash,
            bootstrap_transcript_hash,
        )?)
    }

    /// # Errors
    /// Returns an error when prekey material cannot be created, persisted, or published.
    pub fn initialize_and_publish_prekey_bundle(
        &self,
        principal_commitment: &str,
        device_id: &str,
        target_delivery_id: &str,
        device_seed: [u8; 32],
        prekey_http_url: Option<&str>,
    ) -> Result<(), SdkError> {
        let bundle = self.create_and_store_prekey_bundle(device_id, device_seed)?;
        if let Some(url) = prekey_http_url {
            self.register_mvp1_identity_for_prekey(
                url,
                principal_commitment,
                device_id,
                target_delivery_id,
                &format!("session_for_{device_id}"),
            )?;
            sdk_publish_prekey_bundle(url, device_id, &bundle)?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when prekey material cannot be created, persisted, or published through the
    /// authenticated production gateway session.
    pub async fn initialize_and_publish_prekey_bundle_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        principal_commitment: &str,
        device_id: &str,
        target_delivery_id: &str,
        device_seed: [u8; 32],
    ) -> Result<(), SdkError> {
        let bundle = self.create_and_store_prekey_bundle(device_id, device_seed)?;
        let request = self.mvp1_identity_registration_request(
            device_id,
            target_delivery_id,
            &engine.session().session_id,
            principal_commitment,
        )?;
        let response = engine.register_identity(request).await?;
        if !response.session_bound {
            return Err(SdkError::GatewaySessionRejected(
                "identity registration did not bind the gateway session".to_owned(),
            ));
        }
        engine.publish_prekey_bundle(device_id, &bundle).await?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when prekey material cannot be created, persisted, or published before
    /// opening the authenticated gateway session.
    pub async fn initialize_and_publish_prekey_bundle_via_gateway_request(
        &self,
        gateway: &GatewaySessionConfig,
        principal_commitment: &str,
        device_id: &str,
        target_delivery_id: &str,
        device_seed: [u8; 32],
    ) -> Result<(), SdkError> {
        let bundle = self.create_and_store_prekey_bundle(device_id, device_seed)?;
        let request = self.mvp1_identity_registration_request(
            device_id,
            target_delivery_id,
            &format!("pre_session_for_{device_id}"),
            principal_commitment,
        )?;
        let response: SdkIdentityRegistrationResponse =
            sdk_gateway_post_json(gateway, "/mvp1/identity/register", &request).await?;
        if !response.session_bound {
            return Err(SdkError::GatewaySessionRejected(
                "identity registration did not bind the gateway session".to_owned(),
            ));
        }
        let _response: SdkPrekeyResponse = sdk_gateway_post_json(
            gateway,
            "/mvp1/prekey/publish",
            &SdkPrekeyPublishRequest { device_id: device_id.to_owned(), bundle },
        )
        .await?;
        Ok(())
    }

    fn create_and_store_prekey_bundle(
        &self,
        device_id: &str,
        device_seed: [u8; 32],
    ) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let identity_seed = x3dh_private_seed("ramflux.sdk.x3dh.identity.v1", &device_seed);
        let signed_prekey_seed =
            x3dh_private_seed("ramflux.sdk.x3dh.signed_prekey.v1", &device_seed);
        let identity = X25519KeyPair::from_seed(identity_seed);
        let signed_prekey = X25519KeyPair::from_seed(signed_prekey_seed);
        let signed_prekey_id = format!("{device_id}:signed:1");
        let bundle = ramflux_crypto::create_prekey_bundle(
            branch,
            &identity,
            &signed_prekey_id,
            &signed_prekey,
            None,
            None,
        )?;
        let state = SdkX3dhPrivateState {
            device_id: device_id.to_owned(),
            identity_seed,
            signed_prekey_id,
            signed_prekey_seed,
            bundle: bundle.clone(),
        };
        let event_id = format!("x3dh.prekey.private:{device_id}");
        self.append_event(&event_id, "x3dh.prekey.private", &serde_json::to_vec(&state)?)?;
        self.set_projection_checkpoint(&x3dh_private_checkpoint_name(device_id), &event_id)?;
        Ok(bundle)
    }

    pub(crate) fn register_mvp1_identity_for_prekey(
        &self,
        gateway_url: &str,
        principal_commitment: &str,
        device_id: &str,
        target_delivery_id: &str,
        session_id: &str,
    ) -> Result<(), SdkError> {
        let request = self.mvp1_identity_registration_request(
            device_id,
            target_delivery_id,
            session_id,
            principal_commitment,
        )?;
        let _response: serde_json::Value =
            sdk_http_post_json(gateway_url, "/mvp1/identity/register", &request)?;
        Ok(())
    }

    pub(crate) fn mvp1_identity_registration_request(
        &self,
        device_id: &str,
        target_delivery_id: &str,
        session_id: &str,
        principal_commitment: &str,
    ) -> Result<SdkIdentityRegisterRequest, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let now = now_unix_timestamp();
        let proof = ramflux_crypto::authorize_device_branch(
            root,
            branch,
            "ramflux-node",
            vec!["device.delivery.bind".to_owned()],
            now,
            now.saturating_add(3_600),
        )?;
        Ok(SdkIdentityRegisterRequest {
            root_public_key: ramflux_protocol::encode_base64url(
                root.signing_key.verifying_key().to_bytes(),
            ),
            principal_commitment: principal_commitment.to_owned(),
            branch_public_key: ramflux_protocol::encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            proof,
            target_delivery_id: target_delivery_id.to_owned(),
            gateway_id: "ramflux-gateway".to_owned(),
            session_id: session_id.to_owned(),
            push_alias_hash: Some(format!("push_alias_for_{device_id}")),
            now,
            registration_pow: None,
            source_ip_hash: None,
        })
    }
}
