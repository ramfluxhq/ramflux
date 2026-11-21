// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated surface transport controls; account-owned forwarding preserves original wire bytes.
use super::{Carrier, Payload, PayloadKind, SurfaceSender, invalid};
#[cfg(test)]
use crate::client::identity_authority::HeadUse;
use crate::own_device_sync::SdkOwnDeviceGroupSnapshot;
use crate::prekey::SdkDeviceManifestResponse;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlKind {
    Peer,
    Own,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SurfaceControl {
    pub kind: ControlKind,
    pub carrier_base64: String,
    pub group_epoch: Option<u64>,
    pub context: Option<OwnContext>,
    pub manifests: Vec<SdkDeviceManifestResponse>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnContext {
    pub(crate) conversation_id: String,
    pub(crate) participants: Vec<String>,
    pub(crate) group: Option<SdkOwnDeviceGroupSnapshot>,
    pub(crate) friend: Option<ramflux_storage::FriendLinkRecord>,
}
impl SurfaceControl {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, SdkError> {
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(invalid("surface control byte budget exceeded"));
        }
        if !matches!(
            g::validation::scan_message("Surface", bytes, g::registry::COMPILED_LAYER),
            Ok(g::validation::ScanOutcome::Supported)
        ) {
            return Ok(None);
        }
        let value = g::Surface::decode(bytes).map_err(|_| invalid("invalid typed Surface"))?;
        let Some(g::surface::Payload::Delivery(delivery)) = value.payload else {
            return Ok(None);
        };
        Ok(Some(Self::from_generated(&delivery)?))
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let bytes =
            g::Surface { payload: Some(g::surface::Payload::Delivery(self.to_generated()?)) }
                .encode_to_vec();
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(invalid("surface control byte budget exceeded"));
        }
        Ok(bytes)
    }
}
impl RamfluxClient {
    pub(crate) fn surface_control_packet(
        &self,
        carrier: &Carrier,
        kind: ControlKind,
        group_epoch: Option<u64>,
    ) -> Result<SurfaceControl, SdkError> {
        self.surface_control_packet_inner(carrier, kind, group_epoch, true)
    }
    pub(super) fn live_surface_control_packet(
        &self,
        carrier: &Carrier,
        group_epoch: Option<u64>,
    ) -> Result<SurfaceControl, SdkError> {
        // Suppress context only during preparation, after the current targets are known.
        self.surface_control_packet_inner(carrier, ControlKind::Own, group_epoch, true)
    }
    fn surface_control_packet_inner(
        &self,
        carrier: &Carrier,
        kind: ControlKind,
        group_epoch: Option<u64>,
        include_context: bool,
    ) -> Result<SurfaceControl, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let manifests = if kind == ControlKind::Own {
            self.own_surface_signer_manifests(carrier)?
        } else {
            Vec::new()
        };
        let context = if kind == ControlKind::Own && include_context {
            let thread = self
                .account_db()?
                .client_record("conversation", &carrier.conversation_id)?
                .ok_or_else(|| invalid("surface conversation missing"))?;
            let group = if let Some(id) = thread["group_id"].as_str() {
                Some(
                    self.own_device_group_snapshot(id, &local.device_id)?
                        .ok_or_else(|| invalid("own-device group access unavailable"))?,
                )
            } else {
                None
            };
            let participants: Vec<String> =
                thread["participants"].as_array().map_or_else(Vec::new, |ids| {
                    ids.iter().filter_map(Value::as_str).map(str::to_owned).collect()
                });
            let friend = if group.is_none() {
                let peer = participants.iter().find(|id| *id != &local.principal_id);
                if let Some(peer) = peer {
                    let direct = self.account_db()?.friend_link_for_peer(peer)?;
                    if direct.is_some() {
                        direct
                    } else {
                        let identity = self.account_db()?.client_record("identity", peer)?;
                        identity
                            .as_ref()
                            .and_then(|v| v["contact_identity_commitment"].as_str())
                            .map(|c| Ok::<_, SdkError>(self.account_db()?.friend_link_for_peer(c)?))
                            .transpose()?
                            .flatten()
                    }
                } else {
                    None
                }
            } else {
                None
            };
            Some(OwnContext {
                conversation_id: carrier.conversation_id.clone(),
                participants,
                group,
                friend,
            })
        } else {
            None
        };
        Ok(SurfaceControl {
            kind,
            carrier_base64: ramflux_protocol::encode_base64url(carrier.bytes()?),
            group_epoch,
            context,
            manifests,
        })
    }
    fn own_surface_signer_manifests(
        &self,
        carrier: &Carrier,
    ) -> Result<Vec<SdkDeviceManifestResponse>, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let mut manifests = Vec::new();
        let mut principals = vec![carrier.sender_principal_id.clone()];
        if let Payload::ActionReceipt { original, .. } = carrier.payload()? {
            principals.push(original.sender_principal_id);
        }
        principals.sort();
        principals.dedup();
        for principal in principals {
            if principal == local.principal_id {
                continue;
            }
            let manifest = self
                .account_db()?
                .load_actor_state::<SdkDeviceManifestResponse>(&format!(
                    "identity/manifest/{principal}"
                ))?
                .ok_or_else(|| invalid("forwarded surface signer manifest missing"))?;
            manifests.push(manifest);
        }
        Ok(manifests)
    }
    #[cfg(test)]
    pub(crate) fn receive_surface_control(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        group: Option<&str>,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        if SurfaceControl::decode(body)?.is_none() {
            return Ok(false);
        }
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        self.receive_surface_control_from(entry, &source, conversation, group, body)
    }
    pub(in crate::client) fn receive_surface_control_from(
        &self,
        entry: &GatewayInboxEntry,
        source_identity: &ramflux_crypto::RootQualifiedDeviceRef,
        conversation: &str,
        group: Option<&str>,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        self.receive_surface_control_scoped(
            entry,
            source_identity,
            (conversation, group, None),
            body,
            None,
        )
    }
    pub(in crate::client) fn receive_surface_control_scoped(
        &self,
        entry: &GatewayInboxEntry,
        source_identity: &ramflux_crypto::RootQualifiedDeviceRef,
        scope: (&str, Option<&str>, Option<&str>),
        body: &[u8],
        expires_at: Option<i64>,
    ) -> Result<bool, SdkError> {
        let (conversation, group, logical_message) = scope;
        let Some(control) = SurfaceControl::decode(body)? else {
            return Ok(false);
        };
        let bytes = ramflux_protocol::decode_base64url(&control.carrier_base64)
            .map_err(|_| invalid("invalid surface control carrier encoding"))?;
        let carrier =
            Carrier::decode(&bytes)?.ok_or_else(|| invalid("surface control carrier missing"))?;
        if carrier.conversation_id != conversation {
            return Err(invalid("surface control conversation mismatch"));
        }
        if source_identity.device_id() != entry.envelope.source_device_id {
            return Err(invalid("surface source identity mismatch"));
        }
        let source = self
            .account_db()?
            .client_device_record(source_identity)?
            .ok_or_else(|| invalid("surface control has no authenticated device owner"))?;
        let principal = source["principal_id"]
            .as_str()
            .ok_or_else(|| invalid("surface control source owner missing"))?;
        if principal != entry.envelope.source_principal_id {
            return Err(invalid("surface control source principal mismatch"));
        }
        if let Some(context) = &control.context {
            self.validate_own_context_namespace(context)?;
        }
        if control.kind == ControlKind::Own {
            self.authorize_owned_surface_source(&source)?;
            for manifest in &control.manifests {
                crate::client::contact::verify_device_manifest(
                    manifest,
                    &manifest.principal_commitment,
                )?;
                self.persist_identity_directory(manifest)?;
            }
        } else if control.context.is_some()
            || !control.manifests.is_empty()
            || carrier.sender_device_id != entry.envelope.source_device_id
            || carrier.sender_principal_id != principal
        {
            return Err(invalid("peer surface control source or context mismatch"));
        }
        let signer = self.verified_surface_signer(&carrier)?;
        self.verify_surface_carrier(&carrier, &signer, &carrier.sender_device_id)?;
        if control.kind == ControlKind::Own {
            if let Some(context) = &control.context {
                if context.conversation_id != conversation
                    || context.group.as_ref().map(|g| g.group_id.as_str()) != group
                {
                    return Err(invalid("own surface routing context mismatch"));
                }
                if let Some(group) = &context.group {
                    let epoch = control
                        .group_epoch
                        .ok_or_else(|| invalid("own surface group epoch missing"))?;
                    if epoch < group.local_joined_epoch
                        || epoch > group.group_epoch
                        || self
                            .account_db()?
                            .group_member_joined_epoch_metadata(
                                &group.group_id,
                                &local_device(self)?,
                            )?
                            .is_some_and(|floor| epoch < floor)
                    {
                        return Err(invalid("own surface snapshot is below the joined epoch"));
                    }
                }
                self.import_surface_context(context)?;
            } else {
                self.require_existing_own_surface_context(
                    conversation,
                    group,
                    control.group_epoch,
                    &entry.envelope.source_device_id,
                )?;
            }
            self.bootstrap_owned_surface(&carrier)?;
        } else {
            self.authorize_surface_peer_context(
                conversation,
                group,
                principal,
                &entry.envelope.source_device_id,
                control.group_epoch,
            )?;
        }
        self.project_surface_control(entry, &carrier, &control, logical_message, expires_at)
    }
    fn project_surface_control(
        &self,
        entry: &GatewayInboxEntry,
        carrier: &Carrier,
        control: &SurfaceControl,
        logical_message: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<bool, SdkError> {
        let conversation = carrier.conversation_id.as_str();
        let signer = self.verified_surface_signer(carrier)?;
        let bytes = carrier.bytes()?;
        let message = match logical_message {
            Some(message) => message.to_owned(),
            None => Self::surface_timeline_id(carrier)?,
        };
        let sender = SurfaceSender {
            principal: &signer,
            device: &carrier.sender_device_id,
            envelope_id: &entry.envelope.envelope_id,
            expires_at: Some(expires_at.unwrap_or_else(|| {
                entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl))
            })),
            group_epoch: control.group_epoch,
        };
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let outbound = control.kind == ControlKind::Own
            && carrier.sender_principal_id == local.principal_id
            && carrier.payload_kind == PayloadKind::Action;
        // The generated receiver writes the exact Inner after this native transition.
        // Native history restores application state independently of message projection.
        self.project_surface_message(conversation, &message, sender, &bytes, outbound)
            .map(|outcome| outcome.is_some())
    }
    pub(crate) fn surface_timeline_id(carrier: &Carrier) -> Result<String, SdkError> {
        Ok(format!(
            "routed:surface:{}",
            ramflux_protocol::hash_base64url(
                "ramflux.surface.timeline.v1",
                &ramflux_protocol::canonical_json_bytes(&(
                    &carrier.surface_reference()?,
                    &carrier.sender_principal_id,
                    &carrier.message_id
                ))?
            )
        ))
    }
    fn verified_surface_signer(&self, carrier: &Carrier) -> Result<String, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if carrier.sender_device_id == local.device_id
            && carrier.sender_principal_id == local.principal_id
        {
            return Ok(local.principal_id.clone());
        }
        self.surface_signer_record(&carrier.sender_principal_id, &carrier.sender_device_id)?;
        Ok(carrier.sender_principal_id.clone())
    }
}

fn local_device(client: &RamfluxClient) -> Result<String, SdkError> {
    Ok(client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id.clone())
}
