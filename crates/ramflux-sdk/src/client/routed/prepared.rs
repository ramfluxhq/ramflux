// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned pair-material requests and local sealing after conditional actor admission.

use super::{
    GatewayDirectMessage, GatewaySessionConfig, RamfluxClient, Route, SdkDeviceManifestResponse,
    SdkDmX3dhHeader, SdkError, SealPair, invalid,
};
use crate::client::identity_authority::HeadUse;

pub(crate) struct SendMaterialRequest {
    pub root: Option<String>,
    pub prekey: Option<String>,
}
#[derive(Clone)]
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
        let authority =
            self.require_cached_root_authority(HeadUse::NewAuthorization, &remote).is_ok();
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
        kind: ramflux_protocol::message::KindId,
    ) -> Result<super::send_candidate::SendPair, SdkError> {
        if let Some((root, manifest)) = material.manifest {
            self.accept_fetched_device_manifest(manifest, &root, "background-outbox")?;
        }
        let _ = Self::candidate_target_plan(|| self.dm_selection_request(message, kind))?;
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
    ) -> Result<super::SealedRouted, SdkError> {
        let (mut session, header, bundle) = self.prepared_send_pair(
            config,
            message,
            material,
            crate::client::target_selection::kind_id_for_route(&route.kind),
        )?;
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

impl RamfluxClient {
    /// Exact generated durable carrier, kept behind the inactive profile until module activation.
    /// It has one schema, raw I, and native authority; no alternate carrier is selected on failure.
    pub(crate) fn seal_generated_routed_prepared(
        &self,
        config: &GatewaySessionConfig,
        message: &GatewayDirectMessage,
        body: &[u8],
        route: Route,
        material: SendMaterial,
    ) -> Result<super::SealedRouted, SdkError> {
        use prost::Message as _;
        use ramflux_protocol::message as g;
        if !crate::client::target_selection::schema_v1_selected() {
            return Err(invalid("generated durable profile is not selected"));
        }
        let local = self.owned_device_identity()?;
        self.current_custody_authority(local.root_commitment(), crate::custody::network_now()?)?
            .ok_or(SdkError::NetworkingPending)?;
        let parsed = super::generated_transport::generated_plaintext(body)?;
        if parsed.routing.kind != route.kind
            || parsed.routing.conversation_id != message.conversation_id
            || parsed.routing.group_id != route.group_id
        {
            return Err(invalid("generated send route differs from exact Inner"));
        }
        let inner = g::Inner::decode(body).map_err(|_| invalid("generated Inner malformed"))?;
        if inner.kind == 12 {
            Self::require_self_sync_floor_bootstrap()?;
        }
        if inner.kind == 8
            && g::Control::decode(inner.body.as_slice())
                .is_ok_and(|control| control.operation == 11)
        {
            Self::require_a2i_binding_authority()?;
        }
        self.account_db()?.write_transaction(|| {
            let (mut session, header, bundle) = self.prepared_send_pair(
                config,
                message,
                material,
                crate::client::target_selection::kind_id_for_route(&route.kind),
            )?;
            if route.kind == super::Kind::Direct {
                self.capture_own_authored_direct(message, body)?;
            }
            let recipient = Self::qualified_recipient(message)?;
            self.bind_outgoing_delivery(&local, message, &route.kind)?;
            self.seal_routed_with_route_in(
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
                Some((g::outer::CANDIDATE_ENVELOPE_SCHEMA, 2)),
            )
        })
    }
}
