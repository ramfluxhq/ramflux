// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed group controls preserve native signed proof leaves without a JSON carrier.
use super::{GroupControlBody, GroupControlPacket, TransferBody, TransferControl};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;

fn device(value: &super::transfer_wire::TransferDevice) -> g::TransferDevice {
    g::TransferDevice { root: value.root.clone(), device: value.device.clone() }
}
fn actor(
    value: &ramflux_protocol::group_state::GroupStateActor,
) -> Result<g::NativeGroupActor, SdkError> {
    Ok(g::NativeGroupActor { canonical: ramflux_protocol::canonical_json_bytes(value)? })
}
fn snapshot(
    value: &ramflux_protocol::group_state::GroupStateSnapshot,
) -> Result<g::NativeGroupSnapshot, SdkError> {
    Ok(g::NativeGroupSnapshot { canonical: ramflux_protocol::canonical_json_bytes(value)? })
}
pub(super) fn transfer(value: &TransferControl) -> Result<g::TransferControl, SdkError> {
    let body = match &value.body {
        TransferBody::Probe { probe } => g::transfer_body::Value::Probe(g::TransferBodyProbe {
            probe: Some(g::TransferProbe {
                id: probe.id.clone(),
                actor: Some(actor(&probe.actor)?),
                creator: Some(actor(&probe.creator)?),
                base: Some(snapshot(&probe.base)?),
                required: probe.required.iter().map(device).collect(),
                issued_at: probe.issued_at,
                expires_at: probe.expires_at,
            }),
        }),
        TransferBody::Head { reply } => g::transfer_body::Value::Head(g::TransferBodyHead {
            reply: Some(g::TransferHead {
                proposal: reply.proposal.clone(),
                actor: Some(actor(&reply.actor)?),
                requested_hash: reply.requested_hash.clone(),
                head: Some(snapshot(&reply.head)?),
                acceptance: reply
                    .acceptance
                    .as_ref()
                    .map(|value| {
                        Ok::<_, SdkError>(g::NativeGroupTransferAcceptance {
                            canonical: ramflux_protocol::canonical_json_bytes(value)?,
                        })
                    })
                    .transpose()?,
                requires_sync: reply.requires_sync,
                target: Some(device(&reply.target)),
                additional_targets: reply.additional_targets.iter().map(device).collect(),
                cancelled: reply.cancelled,
                cancel_ack: reply.cancel_ack,
                issued_at: reply.issued_at,
                expires_at: reply.expires_at,
            }),
        }),
    };
    Ok(g::TransferControl {
        body: Some(g::TransferBody { value: Some(body) }),
        signature: value.signature.clone(),
    })
}
impl GroupControlPacket {
    pub(crate) fn to_generated(&self) -> Result<g::GroupStateControl, SdkError> {
        let body = match &self.body {
            GroupControlBody::Request { request, federation } => {
                g::group_control_body::Value::Request(g::GroupControlBodyRequest {
                    request: Some(g::NativeGroupChangeRequest {
                        canonical: ramflux_protocol::canonical_json_bytes(request)?,
                    }),
                    federation: federation.as_ref().map(|value| g::LocalBusFederationRoute {
                        federation_url: String::new(),
                        source_node_id: value.source_node_id.clone(),
                        target_node_id: value.target_node_id.clone(),
                        required_capability: value.required_capability.clone(),
                        admin_token: None,
                        recipient_prekey_url: None,
                    }),
                })
            }
            GroupControlBody::Result { result } => {
                g::group_control_body::Value::Result(g::GroupControlBodyResult {
                    result: Some(g::NativeGroupChangeResult {
                        canonical: ramflux_protocol::canonical_json_bytes(result)?,
                    }),
                })
            }
            GroupControlBody::DeviceSet { group_id, actor: source, device_set_epoch } => {
                g::group_control_body::Value::DeviceSet(g::GroupControlBodyDeviceSet {
                    group_id: group_id.clone(),
                    actor: Some(actor(source)?),
                    device_set_epoch: *device_set_epoch,
                })
            }
            GroupControlBody::Transfer { control } => {
                g::group_control_body::Value::Transfer(g::GroupControlBodyTransfer {
                    control: Some(transfer(control)?),
                })
            }
        };
        Ok(g::GroupStateControl {
            schema: self.schema.clone(),
            body: Some(g::GroupControlBody { value: Some(body) }),
        })
    }
}
impl RamfluxClient {
    pub(crate) fn generated_group_control_inner(
        &self,
        packet: &GroupControlPacket,
    ) -> Result<Vec<u8>, SdkError> {
        let state = self.group_control_base(packet)?;
        let control = crate::client::generated_control::control_from_payload(
            g::control::Payload::GroupState(packet.to_generated()?),
        )?;
        self.generated_snapshot_inner(&state, &control)
    }
}
