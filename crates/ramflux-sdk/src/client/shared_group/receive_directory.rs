// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit directory inputs for authenticated shared-group receive; no task owns an account DB.

use crate::client::routed::{Kind, Routing};
use crate::prelude::*;
use ramflux_protocol::group_state::GroupStateActor;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GroupDirectoryRequest {
    pub root: String,
    pub url: Option<String>,
}
pub(crate) struct GroupDirectoryPlan {
    pub actor_root: String,
    pub actor: GroupStateActor,
    pub addition: Option<GroupDirectoryRequest>,
}
pub(crate) struct GroupDirectoryEvidence {
    pub actor: SdkDeviceManifestResponse,
    pub addition: Option<(GroupDirectoryRequest, SdkDeviceManifestResponse)>,
}
impl GroupDirectoryRequest {
    pub(crate) async fn fetch(
        self,
        gateway: &GatewaySessionConfig,
    ) -> Result<(Self, SdkDeviceManifestResponse), SdkError> {
        let manifest = if let Some(url) = &self.url {
            let manifest = crate::prekey::http_async::get::<Option<SdkDeviceManifestResponse>>(
                url,
                &format!("/mvp1/device-manifest/{}", self.root),
                gateway.timeout,
            )
            .await?
            .ok_or_else(|| SdkError::InboundPending("group manifest unavailable".into()))?;
            crate::client::contact::verify_device_manifest(&manifest, &self.root)?;
            crate::client::identity_authority::ready_manifest(manifest, now_unix_timestamp())
        } else {
            crate::client::contact::fetch_verified_device_manifest(gateway, &self.root).await?
        };
        Ok((self, manifest))
    }
}
impl RamfluxClient {
    pub(crate) fn group_receive_directory_plan(
        &self,
        entry: &GatewayInboxEntry,
        route: &Routing,
        body: &[u8],
    ) -> Result<Option<GroupDirectoryPlan>, SdkError> {
        self.group_directory_plan(entry, route, body, true)
    }
    pub(crate) fn confirm_group_receive_directory_plan(
        &self,
        entry: &GatewayInboxEntry,
        route: &Routing,
        body: &[u8],
    ) -> Result<Option<GroupDirectoryPlan>, SdkError> {
        self.group_directory_plan(entry, route, body, false)
    }
    fn group_directory_plan(
        &self,
        entry: &GatewayInboxEntry,
        route: &Routing,
        body: &[u8],
        charge: bool,
    ) -> Result<Option<GroupDirectoryPlan>, SdkError> {
        if route.kind != Kind::GroupControl {
            return Ok(None);
        }
        self.contact_route_gate(entry, route, body)?;
        self.confirm_routed_context(route, entry)?;
        if let Ok(packet) = ramflux_protocol::parse_i_json::<super::GroupControlPacket>(body)
            && packet.schema == super::controls::CONTROL_SCHEMA
        {
            if body.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES
                || route.group_id.as_deref() != Some(packet.group())
            {
                return Err(super::invalid("group control routing or byte budget mismatch"));
            }
            let state = self.group_control_base(&packet)?;
            if route.conversation_id != state.view().conversation_id {
                return Err(super::invalid("group control conversation mismatch"));
            }
            self.admit_group_control(&state, entry, &packet)?;
            let actor_root = self.group_directory_actor_root(packet.actor(), entry, charge)?;
            let addition = self.group_control_addition_request(&packet, &state)?;
            return Ok(Some(GroupDirectoryPlan {
                actor_root,
                actor: packet.actor().clone(),
                addition,
            }));
        }
        let Some(state) = super::bootstrap::decode_packet(body)? else { return Ok(None) };
        if route.group_id.as_deref() != Some(state.view().group_id.as_str())
            || route.conversation_id != state.view().conversation_id
        {
            return Err(super::invalid("group state routing mismatch"));
        }
        match self.group_snapshot_requires_consent(&state) {
            Ok(_)
            | Err(SdkError::Crypto(ramflux_crypto::CryptoError::Protocol(
                ramflux_protocol::ProtocolError::GroupTransferRequiresSync,
            ))) => {}
            Err(error) => return Err(error),
        }
        Ok(Some(GroupDirectoryPlan {
            actor_root: self.group_directory_actor_root(&state.snapshot().issuer, entry, charge)?,
            actor: state.snapshot().issuer.clone(),
            addition: None,
        }))
    }
    fn group_directory_actor_root(
        &self,
        actor: &GroupStateActor,
        entry: &GatewayInboxEntry,
        charge: bool,
    ) -> Result<String, SdkError> {
        if charge {
            self.group_actor_manifest_request(actor, entry)
        } else {
            self.confirm_group_actor_transport(actor, entry)?;
            Ok(actor.identity.root_commitment.clone())
        }
    }
    fn group_control_addition_request(
        &self,
        packet: &super::GroupControlPacket,
        state: &ramflux_crypto::VerifiedGroupState,
    ) -> Result<Option<GroupDirectoryRequest>, SdkError> {
        if let super::GroupControlBody::Request { request, federation } = &packet.body {
            ramflux_crypto::verify_group_change_request(request, now_unix_timestamp())?;
            if self.owned_device_identity()?.root_commitment()
                != state.creator().identity.root_commitment
                || request.genesis_hash != state.genesis_hash()?
            {
                return Err(StorageError::GroupPermissionDenied.into());
            }
            if let ramflux_protocol::GroupStateChange::Add { member, .. } = &request.change
                && ramflux_crypto::validate_group_change_request(
                    state,
                    request,
                    now_unix_timestamp(),
                )
                .is_ok()
            {
                return self
                    .group_addition_directory_request(
                        packet.group(),
                        &member.root_commitment,
                        federation.as_ref(),
                    )
                    .map(Some);
            }
        }
        Ok(None)
    }
    pub(super) fn group_addition_directory_request(
        &self,
        group: &str,
        root: &str,
        federation: Option<&LocalBusFederationRoute>,
    ) -> Result<GroupDirectoryRequest, SdkError> {
        let saved;
        let route = if let Some(route) = federation {
            Some(route)
        } else {
            saved = self.shared_group_federation_route(group, root)?;
            saved.as_ref()
        };
        let url = route
            .map(|route| {
                route
                    .recipient_prekey_url
                    .clone()
                    .ok_or_else(|| super::invalid("federated addition requires prekey directory"))
            })
            .transpose()?;
        Ok(GroupDirectoryRequest { root: root.to_owned(), url })
    }
    pub(super) fn prepared_group_addition_manifest(
        lookup: &GroupDirectoryRequest,
        directory: &GroupDirectoryEvidence,
    ) -> Result<SdkDeviceManifestResponse, SdkError> {
        let manifest = directory
            .addition
            .as_ref()
            .filter(|(request, _)| request == lookup)
            .map(|(_, manifest)| manifest.clone())
            .ok_or_else(|| {
                SdkError::InboundPending("group addition directory changed before commit".into())
            })?;
        crate::client::contact::verify_device_manifest(&manifest, &lookup.root)?;
        Ok(manifest)
    }

    pub(super) async fn fetch_group_addition_manifest(
        &self,
        gateway: &GatewaySessionConfig,
        group: &str,
        root: &str,
        federation: Option<&LocalBusFederationRoute>,
    ) -> Result<SdkDeviceManifestResponse, SdkError> {
        if let Some(federation) = federation {
            let url = federation
                .recipient_prekey_url
                .clone()
                .ok_or_else(|| super::invalid("federated addition requires prekey directory"))?;
            let expected = root.to_owned();
            tokio::task::spawn_blocking(move || {
                crate::client::contact::fetch_verified_device_manifest_from_url(&url, &expected)
            })
            .await
            .map_err(|error| {
                SdkError::InboundPending(format!("federation manifest worker: {error}"))
            })?
        } else {
            self.shared_group_manifest(gateway, group, root).await
        }
    }
    pub(super) async fn verify_group_actor_directory(
        &self,
        gateway: &GatewaySessionConfig,
        actor: &GroupStateActor,
        entry: &GatewayInboxEntry,
        directory: Option<&GroupDirectoryEvidence>,
    ) -> Result<(), SdkError> {
        if let Some(directory) = directory {
            self.accept_group_actor_manifest(actor, entry, &directory.actor)
        } else {
            self.verify_group_actor_source(gateway, actor, entry).await
        }
    }
    pub(super) async fn verify_shared_group_directory(
        &self,
        gateway: &GatewaySessionConfig,
        state: &ramflux_crypto::VerifiedGroupState,
        entry: &GatewayInboxEntry,
        directory: Option<&GroupDirectoryEvidence>,
    ) -> Result<(), SdkError> {
        if directory.is_none() {
            return self.verify_shared_group_source(gateway, state, entry).await;
        }
        self.verify_group_actor_directory(gateway, &state.snapshot().issuer, entry, directory)
            .await?;
        self.ensure_shared_group_device(state, &self.authenticated_device_identity(entry)?)
    }
}
