// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed Surface carriers reuse the native state machine, with the v1 protobuf signing view.
use super::{
    Carrier, ControlKind, OwnContext, Payload, PayloadKind, SnapshotProof, SurfaceControl, invalid,
};
use crate::SdkError;
use prost::Message as _;
use ramflux_protocol::message as g;

use crate::client::generated_fields as shape;

impl SurfaceControl {
    pub(crate) fn to_generated(&self) -> Result<g::SurfaceDelivery, SdkError> {
        let bytes = ramflux_protocol::decode_base64url(&self.carrier_base64)
            .map_err(|_| invalid("surface carrier encoding"))?;
        let carrier = Carrier::decode(&bytes)?.ok_or_else(|| invalid("surface carrier missing"))?;
        Ok(g::SurfaceDelivery {
            kind: Some(g::SurfaceControlKind {
                value: Some(match self.kind {
                    ControlKind::Peer => {
                        g::surface_control_kind::Value::Peer(g::SurfaceControlKindPeer {})
                    }
                    ControlKind::Own => {
                        g::surface_control_kind::Value::Own(g::SurfaceControlKindOwn {})
                    }
                }),
            }),
            carrier: Some(carrier.to_generated()?),
            group_epoch: self.group_epoch,
            context: self.context.as_ref().map(g::OwnContext::try_from).transpose()?,
            manifests: self
                .manifests
                .iter()
                .map(g::NativeDeviceManifest::try_from)
                .collect::<Result<_, _>>()?,
        })
    }

    pub(crate) fn from_generated(value: &g::SurfaceDelivery) -> Result<Self, SdkError> {
        let kind = match value.kind.as_ref().and_then(|kind| kind.value.as_ref()) {
            Some(g::surface_control_kind::Value::Peer(_)) => ControlKind::Peer,
            Some(g::surface_control_kind::Value::Own(_)) => ControlKind::Own,
            None => return Err(invalid("surface delivery kind missing")),
        };
        let carrier = Carrier::from_generated(
            value.carrier.as_ref().ok_or_else(|| invalid("surface carrier missing"))?,
        )?;
        Ok(Self {
            kind,
            carrier_base64: ramflux_protocol::encode_base64url(carrier.bytes()?),
            group_epoch: value.group_epoch,
            context: value.context.as_ref().map(OwnContext::try_from).transpose()?,
            manifests: value
                .manifests
                .iter()
                .map(crate::client::task::generated::manifest::generated_manifest_fields)
                .collect::<Result<_, _>>()?,
        })
    }
}

pub(crate) fn event(
    value: &ramflux_protocol::A2uiConversationEvent,
) -> Result<g::SurfaceEvent, SdkError> {
    Ok(serde_json::from_value(shape::convert(
        "SurfaceEvent",
        &serde_json::to_value(value)?,
        true,
    )?)?)
}

pub(super) fn native_event(value: &g::SurfaceEvent) -> Result<Vec<u8>, SdkError> {
    let native = shape::convert("SurfaceEvent", &serde_json::to_value(value)?, false)?;
    let bytes = ramflux_protocol::canonical_json_bytes(&native)?;
    ramflux_protocol::A2uiConversationEvent::from_wire_bytes(&bytes)?;
    Ok(bytes)
}

fn action(value: &ramflux_protocol::A2uiSurfaceAction) -> Result<g::SurfaceAction, SdkError> {
    Ok(serde_json::from_value(shape::convert(
        "SurfaceAction",
        &serde_json::to_value(value)?,
        true,
    )?)?)
}

fn native_action(value: &g::SurfaceAction) -> Result<Vec<u8>, SdkError> {
    let native = shape::convert("SurfaceAction", &serde_json::to_value(value)?, false)?;
    let bytes = ramflux_protocol::canonical_json_bytes(&native)?;
    ramflux_protocol::A2uiSurfaceAction::from_wire_bytes(&bytes)?;
    Ok(bytes)
}

fn snapshot(value: &SnapshotProof) -> Result<g::SurfaceSnapshotProof, SdkError> {
    let event = if value.wire_base64.is_empty() {
        None
    } else {
        Some(event(&ramflux_protocol::A2uiConversationEvent::from_wire_bytes(
            &ramflux_protocol::decode_base64url(&value.wire_base64)
                .map_err(|_| invalid("snapshot event encoding"))?,
        )?)?)
    };
    let checkpoint = if value.checkpoint_base64.is_empty() {
        None
    } else {
        let bytes = ramflux_protocol::decode_base64url(&value.checkpoint_base64)
            .map_err(|_| invalid("snapshot checkpoint encoding"))?;
        let native = ramflux_protocol::parse_i_json::<serde_json::Value>(&bytes)?;
        Some(serde_json::from_value(shape::convert("SurfaceCheckpoint", &native, true)?)?)
    };
    Ok(g::SurfaceSnapshotProof {
        event,
        checkpoint,
        surface_hash: value.surface_hash.clone(),
        metadata: value
            .metadata
            .as_ref()
            .map(|metadata| {
                Ok::<_, SdkError>(serde_json::from_value(shape::convert(
                    "SurfaceResyncMetadata",
                    metadata,
                    true,
                )?)?)
            })
            .transpose()?,
        author_device_id: value.author_device_id.clone(),
    })
}

fn native_snapshot(value: &g::SurfaceSnapshotProof) -> Result<SnapshotProof, SdkError> {
    Ok(SnapshotProof {
        wire_base64: value
            .event
            .as_ref()
            .map(native_event)
            .transpose()?
            .map(ramflux_protocol::encode_base64url)
            .unwrap_or_default(),
        checkpoint_base64: value
            .checkpoint
            .as_ref()
            .map(|checkpoint| {
                let native =
                    shape::convert("SurfaceCheckpoint", &serde_json::to_value(checkpoint)?, false)?;
                Ok::<_, SdkError>(ramflux_protocol::encode_base64url(
                    ramflux_protocol::canonical_json_bytes(&native)?,
                ))
            })
            .transpose()?
            .unwrap_or_default(),
        surface_hash: value.surface_hash.clone(),
        metadata: value
            .metadata
            .as_ref()
            .map(|metadata| {
                shape::convert("SurfaceResyncMetadata", &serde_json::to_value(metadata)?, false)
            })
            .transpose()?,
        author_device_id: value.author_device_id.clone(),
    })
}

impl Carrier {
    pub(crate) fn to_generated(&self) -> Result<g::SurfaceCarrier, SdkError> {
        if let Some(value) = self.retained_generated()? {
            return Ok(value);
        }
        self.rebuilt_generated()
    }

    fn rebuilt_generated(&self) -> Result<g::SurfaceCarrier, SdkError> {
        let payload = match self.payload()? {
            Payload::Event(value) => g::surface_carrier::Payload::Event(event(&value)?),
            Payload::Action(value) => g::surface_carrier::Payload::Action(action(&value)?),
            Payload::ActionReceipt { original, .. } => {
                g::surface_carrier::Payload::ActionReceipt(Box::new(original.to_generated()?))
            }
        };
        Ok(g::SurfaceCarrier {
            schema: self.schema.clone(),
            content_type: self.content_type.clone(),
            posted_at: self.posted_at,
            updated_at: self.updated_at,
            conversation_id: self.conversation_id.clone(),
            surface_id: self.surface_id.clone(),
            message_id: self.message_id.clone(),
            sender_principal_id: self.sender_principal_id.clone(),
            sender_device_id: self.sender_device_id.clone(),
            author_principal_id: self.author_principal_id.clone(),
            signature: self.signature.clone(),
            snapshot: self.snapshot.as_ref().map(snapshot).transpose()?,
            payload: Some(payload),
        })
    }

    pub(crate) fn from_generated(value: &g::SurfaceCarrier) -> Result<Self, SdkError> {
        let mut result = Self::native_view(value)?;
        result.retain_generated_encoding(value)?;
        Ok(result)
    }

    fn native_view(value: &g::SurfaceCarrier) -> Result<Self, SdkError> {
        let (kind, body) = match value
            .payload
            .as_ref()
            .ok_or_else(|| invalid("Surface payload missing"))?
        {
            g::surface_carrier::Payload::Event(event) => (PayloadKind::Event, native_event(event)?),
            g::surface_carrier::Payload::Action(action) => {
                (PayloadKind::Action, native_action(action)?)
            }
            g::surface_carrier::Payload::ActionReceipt(inner) => {
                if matches!(inner.payload, Some(g::surface_carrier::Payload::ActionReceipt(_))) {
                    return Err(invalid("nested Surface action receipt"));
                }
                (PayloadKind::ActionReceipt, Self::from_generated(inner)?.bytes()?)
            }
        };
        let result = Self {
            typed: None,
            schema: value.schema.clone(),
            content_type: value.content_type.clone(),
            posted_at: value.posted_at,
            updated_at: value.updated_at,
            payload_kind: kind,
            conversation_id: value.conversation_id.clone(),
            surface_id: value.surface_id.clone(),
            message_id: value.message_id.clone(),
            sender_principal_id: value.sender_principal_id.clone(),
            sender_device_id: value.sender_device_id.clone(),
            author_principal_id: value.author_principal_id.clone(),
            wire_base64: ramflux_protocol::encode_base64url(body),
            signature: value.signature.clone(),
            snapshot: value.snapshot.as_ref().map(native_snapshot).transpose()?,
        };
        result.payload()?;
        Ok(result)
    }

    fn representation_hash(&self) -> Result<String, SdkError> {
        Ok(ramflux_protocol::hash_base64url(
            "ramflux.surface.native_view.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &self.schema,
                &self.content_type,
                self.posted_at,
                self.updated_at,
                &self.payload_kind,
                &self.conversation_id,
                &self.surface_id,
                &self.message_id,
                &self.sender_principal_id,
                &self.sender_device_id,
                &self.author_principal_id,
                &self.wire_base64,
                &self.signature,
                &self.snapshot,
            ))?,
        ))
    }

    pub(super) fn retain_generated_encoding(
        &mut self,
        value: &g::SurfaceCarrier,
    ) -> Result<(), SdkError> {
        self.typed = None;
        if self.rebuilt_generated()? != *value {
            let bytes = value.encode_to_vec();
            if bytes.len() > super::carrier::MAX_CARRIER_BYTES {
                return Err(invalid("retained typed Surface exceeds byte budget"));
            }
            self.typed = Some(super::carrier::TypedEncoding {
                fingerprint: self.representation_hash()?,
                encoded: ramflux_protocol::encode_base64url(bytes),
            });
        }
        Ok(())
    }

    fn retained_generated(&self) -> Result<Option<g::SurfaceCarrier>, SdkError> {
        const MAX_ENCODED: usize = super::carrier::MAX_CARRIER_BYTES * 4 / 3 + 4;
        let Some(retained) = &self.typed else {
            return Ok(None);
        };
        let fingerprint = self.representation_hash()?;
        if retained.fingerprint != fingerprint {
            return Ok(None);
        }
        if retained.encoded.len() > MAX_ENCODED {
            return Err(invalid("retained typed Surface exceeds byte budget"));
        }
        let bytes = ramflux_protocol::decode_base64url(&retained.encoded)
            .map_err(|_| invalid("retained typed Surface encoding invalid"))?;
        if g::validation::scan_message("SurfaceCarrier", &bytes, g::registry::COMPILED_LAYER)
            .map_err(|_| invalid("retained typed Surface grammar invalid"))?
            != g::validation::ScanOutcome::Supported
        {
            return Err(invalid("retained typed Surface fields unsupported"));
        }
        let value = g::SurfaceCarrier::decode(bytes.as_slice())
            .map_err(|_| invalid("retained typed Surface missing"))?;
        // The retained bytes are not authority for different projected fields, even
        // when a damaged private store supplies a matching cache fingerprint.
        if Self::native_view(&value)?.representation_hash()? != fingerprint {
            return Err(invalid("retained typed Surface differs from native projection"));
        }
        Ok(Some(value))
    }

    pub(super) fn typed_signing(&self) -> Result<Vec<u8>, SdkError> {
        let mut unsigned = self.to_generated()?;
        unsigned.signature.clear();
        crate::client::task::generated::typed_transcript(
            "SurfaceCarrier",
            &unsigned.encode_to_vec(),
        )
    }
}
