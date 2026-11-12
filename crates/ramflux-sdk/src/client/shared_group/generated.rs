// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed native group adapters; a generated arm selects one concrete native type.
use super::{GroupControlBody, GroupControlPacket, TransferBody, TransferControl, invalid};
use crate::{LocalBusFederationRoute, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use serde::{Serialize, de::DeserializeOwned};

fn leaf<T: DeserializeOwned + Serialize>(bytes: Option<&[u8]>) -> Result<T, SdkError> {
    let bytes = bytes.ok_or_else(|| invalid("native group field missing"))?;
    if bytes.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES {
        return Err(invalid("native group field exceeds its byte budget"));
    }
    let value = ramflux_protocol::parse_i_json(bytes)?;
    if ramflux_protocol::canonical_json_bytes(&value)? != bytes {
        return Err(invalid("native group field must retain canonical signed bytes"));
    }
    Ok(value)
}

fn device(
    value: Option<&g::TransferDevice>,
) -> Result<super::transfer_wire::TransferDevice, SdkError> {
    let value = value.ok_or_else(|| invalid("group transfer device missing"))?;
    if value.root.is_empty() || value.device.is_empty() {
        return Err(invalid("group transfer device empty"));
    }
    Ok(super::transfer_wire::TransferDevice {
        root: value.root.clone(),
        device: value.device.clone(),
    })
}

fn transfer(value: &g::TransferControl) -> Result<TransferControl, SdkError> {
    let body = match value.body.as_ref().and_then(|body| body.value.as_ref()) {
        Some(g::transfer_body::Value::Probe(wrapper)) => {
            let probe = wrapper.probe.as_ref().ok_or_else(|| invalid("transfer probe missing"))?;
            TransferBody::Probe {
                probe: Box::new(super::transfer_wire::TransferProbe {
                    id: probe.id.clone(),
                    actor: leaf(probe.actor.as_ref().map(|leaf| leaf.canonical.as_slice()))?,
                    creator: leaf(probe.creator.as_ref().map(|leaf| leaf.canonical.as_slice()))?,
                    base: leaf(probe.base.as_ref().map(|leaf| leaf.canonical.as_slice()))?,
                    required: probe
                        .required
                        .iter()
                        .map(|value| device(Some(value)))
                        .collect::<Result<_, _>>()?,
                    issued_at: probe.issued_at,
                    expires_at: probe.expires_at,
                }),
            }
        }
        Some(g::transfer_body::Value::Head(wrapper)) => {
            let reply = wrapper.reply.as_ref().ok_or_else(|| invalid("transfer head missing"))?;
            TransferBody::Head {
                reply: Box::new(super::transfer_wire::TransferHead {
                    proposal: reply.proposal.clone(),
                    actor: leaf(reply.actor.as_ref().map(|leaf| leaf.canonical.as_slice()))?,
                    requested_hash: reply.requested_hash.clone(),
                    head: leaf(reply.head.as_ref().map(|leaf| leaf.canonical.as_slice()))?,
                    acceptance: reply
                        .acceptance
                        .as_ref()
                        .map(|value| leaf(Some(&value.canonical)).map(Box::new))
                        .transpose()?,
                    requires_sync: reply.requires_sync,
                    target: device(reply.target.as_ref())?,
                    additional_targets: reply
                        .additional_targets
                        .iter()
                        .map(|value| device(Some(value)))
                        .collect::<Result<_, _>>()?,
                    cancelled: reply.cancelled,
                    cancel_ack: reply.cancel_ack,
                    issued_at: reply.issued_at,
                    expires_at: reply.expires_at,
                }),
            }
        }
        None => return Err(invalid("group transfer body missing")),
    };
    Ok(TransferControl { body, signature: value.signature.clone() })
}

pub(super) fn from_generated(value: &g::GroupStateControl) -> Result<GroupControlPacket, SdkError> {
    if value.schema != super::controls::CONTROL_SCHEMA {
        return Err(invalid("native group control schema mismatch"));
    }
    let body = match value.body.as_ref().and_then(|body| body.value.as_ref()) {
        Some(g::group_control_body::Value::Request(value)) => GroupControlBody::Request {
            request: leaf(value.request.as_ref().map(|leaf| leaf.canonical.as_slice()))?,
            federation: value.federation.as_ref().map(|route| LocalBusFederationRoute {
                federation_url: route.federation_url.clone(),
                source_node_id: route.source_node_id.clone(),
                target_node_id: route.target_node_id.clone(),
                required_capability: route.required_capability.clone(),
                admin_token: route.admin_token.clone(),
                recipient_prekey_url: route.recipient_prekey_url.clone(),
            }),
        },
        Some(g::group_control_body::Value::Result(value)) => GroupControlBody::Result {
            result: leaf(value.result.as_ref().map(|leaf| leaf.canonical.as_slice()))?,
        },
        Some(g::group_control_body::Value::DeviceSet(value)) => GroupControlBody::DeviceSet {
            group_id: value.group_id.clone(),
            actor: leaf(value.actor.as_ref().map(|leaf| leaf.canonical.as_slice()))?,
            device_set_epoch: value.device_set_epoch,
        },
        Some(g::group_control_body::Value::Transfer(value)) => GroupControlBody::Transfer {
            control: Box::new(transfer(
                value.control.as_ref().ok_or_else(|| invalid("group transfer missing"))?,
            )?),
        },
        None => return Err(invalid("native group control body missing")),
    };
    Ok(GroupControlPacket::new(body))
}

pub(super) struct Decoded {
    pub packet: GroupControlPacket,
    pub supported: bool,
}

pub(super) fn decode(bytes: &[u8]) -> Result<Option<Decoded>, SdkError> {
    if crate::client::target_selection::schema_v1_selected()
        && let Ok(inner) = g::Inner::decode(bytes)
        && inner.kind == 8
    {
        let control = g::Control::decode(inner.body.as_slice())
            .map_err(|_| invalid("generated group control malformed"))?;
        if let Some(g::control::Payload::GroupState(value)) = control.payload.as_ref() {
            crate::client::generated_control::validate_control_native(&control)?;
            let scanned = g::validation::scan_inner(bytes)
                .map_err(|_| invalid("generated group Inner malformed"))?;
            return Ok(Some(Decoded {
                packet: from_generated(value)?,
                supported: scanned.outcome == g::validation::ScanOutcome::Supported,
            }));
        }
        return Ok(None);
    }
    // Dormant pre-activation callers still provide this one concrete native packet.
    // LAST removes the legacy live wire admission; no schema string selects another codec.
    Ok(ramflux_protocol::parse_i_json::<GroupControlPacket>(bytes)
        .ok()
        .filter(|packet| packet.schema == super::controls::CONTROL_SCHEMA)
        .map(|packet| Decoded { packet, supported: true }))
}

impl crate::RamfluxClient {
    pub(crate) fn authorize_generated_group_control_body(
        &self,
        entry: &crate::GatewayInboxEntry,
        route: &crate::client::routed::Routing,
        bytes: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(decoded) = decode(bytes)? else {
            return Ok(false);
        };
        self.authorize_native_group_control_packet(entry, route, &decoded.packet)?;
        Ok(true)
    }

    pub(super) fn authorize_native_group_control_packet(
        &self,
        entry: &crate::GatewayInboxEntry,
        route: &crate::client::routed::Routing,
        packet: &GroupControlPacket,
    ) -> Result<(), SdkError> {
        use crate::client::identity_authority::{HeadUse, NativeOperation};
        if route.kind != crate::client::routed::Kind::GroupControl
            || route.group_id.as_deref() != Some(packet.group())
        {
            return Err(invalid("generated group control route mismatch"));
        }
        let state = self.group_control_base(packet)?;
        if state.view().conversation_id != route.conversation_id {
            return Err(invalid("generated group control conversation mismatch"));
        }
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        self.require_native_operation(&source, NativeOperation::Group)?;
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Group)?;
        self.admit_group_control(&state, entry, packet)
    }
}

#[cfg(test)]
mod tests;
