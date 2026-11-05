// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned pair-material requests and local sealing after conditional actor admission.

use super::{
    GatewayDirectMessage, GatewaySessionConfig, RamfluxClient, Route, SdkDeviceManifestResponse,
    SdkDmEncryptedEnvelope, SdkDmX3dhHeader, SdkError, SealPair, invalid,
};

pub(crate) struct SendMaterialRequest {
    pub root: Option<String>,
    pub prekey: Option<String>,
}
pub(crate) struct SendMaterial {
    pub manifest: Option<(String, SdkDeviceManifestResponse)>,
    pub bundle: Option<ramflux_crypto::PrekeyBundle>,
}

impl RamfluxClient {
    pub(crate) fn routed_send_material_request(
        &self,
        config: &GatewaySessionConfig,
        message: &GatewayDirectMessage,
    ) -> Result<SendMaterialRequest, SdkError> {
        let local = self.local_device_identity(&config.device_id)?;
        self.require_pair_device_active(&local)?;
        let recipient = Self::qualified_recipient(message)?;
        let remote = self.device_identity(&recipient)?;
        let authority = self
            .require_cached_root_authority(
                &remote,
                crate::client::identity_authority::HeadUse::NewAuthorization,
            )
            .is_ok();
        let pair = self.active_pair(&local, &remote)?;
        let reusable = if let Some((session, _)) = pair {
            let inactive = self
                .account_db()?
                .actor_state_exists(&format!("backup/inactive-pair/{}", session.session_id))?;
            let header = self.account_db()?.load_actor_state::<SdkDmX3dhHeader>(&format!(
                "dm-pair/bootstrap/{}",
                session.session_id
            ))?;
            !inactive
                && header.is_none_or(|header| {
                    header.bootstrap_ordering_version == Some(2)
                        && header.bootstrap_sequence.is_some()
                })
        } else {
            false
        };
        Ok(SendMaterialRequest {
            root: (!authority).then(|| remote.root_commitment().to_owned()),
            prekey: if authority && reusable {
                None
            } else {
                Some(remote.storage_key().to_owned())
            },
        })
    }

    pub(super) fn prepared_send_pair(
        &self,
        config: &GatewaySessionConfig,
        message: &GatewayDirectMessage,
        material: SendMaterial,
    ) -> Result<super::send_candidate::SendPair, SdkError> {
        if let Some((root, manifest)) = material.manifest {
            self.accept_fetched_device_manifest(manifest, &root, "background-outbox")?;
        }
        let local = self.local_device_identity(&config.device_id)?;
        self.require_pair_device_active(&local)?;
        let recipient = Self::qualified_recipient(message)?;
        let remote = self.device_identity(&recipient)?;
        let pair = match self.sendable_pair(&local, &remote)? {
            Some(pair) => pair,
            None => self.new_send_pair(
                &local,
                message,
                material.bundle.ok_or_else(|| invalid("prepared recipient prekey missing"))?,
            )?,
        };
        Ok(pair)
    }

    pub(crate) fn seal_routed_prepared(
        &self,
        config: &GatewaySessionConfig,
        message: &GatewayDirectMessage,
        body: &[u8],
        route: Route,
        material: SendMaterial,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let (mut session, header, bundle) = self.prepared_send_pair(config, message, material)?;
        let local = self.local_device_identity(&config.device_id)?;
        let recipient = Self::qualified_recipient(message)?;
        self.bind_outgoing_delivery(&local, message, &route.kind)?;
        self.seal_routed_with_route(
            message,
            body,
            route,
            SealPair {
                local: &config.device_id,
                remote: &recipient,
                session: &mut session,
                header,
                bundle,
            },
        )
    }
}
