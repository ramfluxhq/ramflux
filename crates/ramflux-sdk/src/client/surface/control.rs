// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated surface transport controls; account-owned forwarding preserves original wire bytes.
use super::{Carrier, Payload, PayloadKind, SurfaceSender, invalid};
use crate::own_device_sync::SdkOwnDeviceGroupSnapshot;
use crate::prekey::SdkDeviceManifestResponse;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub(crate) const CONTROL_PREFIX: &[u8] = b"ramflux.surface.control.v1\n";
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
    pub(super) conversation_id: String,
    pub(super) participants: Vec<String>,
    pub(super) group: Option<SdkOwnDeviceGroupSnapshot>,
    pub(super) friend: Option<ramflux_storage::FriendLinkRecord>,
}
impl SurfaceControl {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut bytes = CONTROL_PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
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
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let mut manifests = Vec::new();
        let context = if kind == ControlKind::Own {
            let thread = self
                .account_db()?
                .client_record("conversation", &carrier.conversation_id)?
                .ok_or_else(|| invalid("surface conversation missing"))?;
            let group = if let Some(id) = thread["group_id"].as_str() {
                Some(
                    self.own_device_group_snapshots(&local.device_id)?
                        .into_iter()
                        .find(|g| g.group_id == id)
                        .ok_or_else(|| invalid("own-device group access unavailable"))?,
                )
            } else {
                None
            };
            let participants: Vec<String> =
                thread["participants"].as_array().map_or_else(Vec::new, |ids| {
                    ids.iter().filter_map(Value::as_str).map(str::to_owned).collect()
                });
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
    pub(crate) fn receive_surface_control(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        group: Option<&str>,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(raw) = body.strip_prefix(CONTROL_PREFIX) else {
            return Ok(false);
        };
        if body.len() > 2 * 1024 * 1024 {
            return Err(invalid("surface control byte budget exceeded"));
        }
        let control: SurfaceControl = ramflux_protocol::parse_i_json(raw)
            .map_err(|_| SdkError::InboundRejected("invalid surface control JSON".into()))?;
        let bytes = ramflux_protocol::decode_base64url(&control.carrier_base64)
            .map_err(|_| invalid("invalid surface control carrier encoding"))?;
        let carrier =
            Carrier::decode(&bytes)?.ok_or_else(|| invalid("surface control carrier missing"))?;
        if carrier.conversation_id != conversation {
            return Err(invalid("surface control conversation mismatch"));
        }
        let source = self
            .account_db()?
            .client_record("device", &entry.envelope.source_device_id)?
            .ok_or_else(|| invalid("surface control has no authenticated device owner"))?;
        let principal = source["principal_id"]
            .as_str()
            .ok_or_else(|| invalid("surface control source owner missing"))?;
        if principal != entry.envelope.source_principal_id {
            return Err(invalid("surface control source principal mismatch"));
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
            let context =
                control.context.as_ref().ok_or_else(|| invalid("own surface context missing"))?;
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
                        .group_member_joined_epoch(&group.group_id, &local_device(self)?)?
                        .is_some_and(|floor| epoch < floor)
                {
                    return Err(invalid("own surface snapshot is below the joined epoch"));
                }
            }
            self.import_surface_context(context, &entry.envelope.source_device_id)?;
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
        self.project_surface_control(entry, group, &carrier, &control)
    }
    fn project_surface_control(
        &self,
        entry: &GatewayInboxEntry,
        group: Option<&str>,
        carrier: &Carrier,
        control: &SurfaceControl,
    ) -> Result<bool, SdkError> {
        let conversation = carrier.conversation_id.as_str();
        let signer = self.verified_surface_signer(carrier)?;
        let bytes = carrier.bytes()?;
        let message = Self::surface_timeline_id(carrier)?;
        let sender = SurfaceSender {
            principal: &signer,
            device: &carrier.sender_device_id,
            envelope_id: &entry.envelope.envelope_id,
            expires_at: Some(
                entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl)),
            ),
            group_epoch: control.group_epoch,
        };
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let outbound = control.kind == ControlKind::Own
            && carrier.sender_principal_id == local.principal_id
            && carrier.payload_kind == PayloadKind::Action;
        let outcome = self
            .project_surface_message(conversation, &message, sender, &bytes, outbound)?
            .ok_or_else(|| invalid("surface projection absent"))?;
        if carrier.payload_kind == PayloadKind::ActionReceipt {
            return Ok(true);
        }
        if self.direct_message_by_id(&message)?.is_none() {
            let metadata = ramflux_storage::MessageMetadata::default();
            self.send_direct_message_with_metadata(
                conversation,
                &message,
                &carrier.sender_device_id,
                entry.envelope.encrypted_payload.as_bytes(),
                &metadata,
            )?;
            let routing = crate::client::routed::Routing {
                kind: if group.is_some() {
                    crate::client::routed::Kind::GroupMessage
                } else {
                    crate::client::routed::Kind::Direct
                },
                conversation_id: conversation.into(),
                group_id: group.map(str::to_owned),
                message_id: message.clone(),
                attachments: false,
            };
            self.account_db()?
                .persist_actor_state(&format!("routed/message-metadata/{message}"), &routing)?;
        }
        self.account_db()?.replace_surface_message_content(
            conversation,
            &message,
            outcome.fallback_text.as_bytes(),
        )?;
        Ok(true)
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
        if carrier.sender_device_id == local.device_id {
            return Ok(local.principal_id.clone());
        }
        self.account_db()?
            .client_record("device", &carrier.sender_device_id)?
            .and_then(|v| v["principal_id"].as_str().map(str::to_owned))
            .ok_or_else(|| invalid("original surface signer owner missing"))
    }
}

fn local_device(client: &RamfluxClient) -> Result<String, SdkError> {
    Ok(client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id.clone())
}
