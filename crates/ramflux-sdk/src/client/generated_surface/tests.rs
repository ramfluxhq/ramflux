// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::message::{
    CreateSurfaceCommand, DeleteSurfaceCommand, DeleteSurfaceReason, DeleteSurfaceReasonCompleted,
    JsonValue, PatchSurfaceCommand, QualifiedDevice, StreamAppendCommand, Surface, SurfaceAction,
    SurfaceCarrier, SurfaceCommand, SurfaceCommandCreateSurface, SurfaceCommandDeleteSurface,
    SurfaceCommandPatchSurface, SurfaceCommandStreamAppend, SurfaceCommandUpdateComponents,
    SurfaceCommandUpdateDataModel, SurfaceControlKind, SurfaceControlKindPeer, SurfaceDelivery,
    SurfaceEvent, SurfaceHistoryExport, SurfacePatchOp, SurfacePatchOpInsertBlock,
    SurfacePatchOpRemoveBlock, SurfacePatchOpReplaceBlock, SurfacePatchOpSetActions,
    SurfacePatchOpSetFallbackText, SurfaceResyncRequest, SurfaceType, SurfaceTypeMessageCard,
    UpdateComponentsCommand, UpdateDataModelCommand, content, delete_surface_reason, json_value,
    surface, surface_carrier, surface_command, surface_control_kind, surface_patch_op,
    surface_type,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn author() -> QualifiedDevice {
    QualifiedDevice { account_anchor: "anchor".into(), device_id: "device".into(), device_epoch: 1 }
}

fn stream() -> GeneratedEventStream {
    GeneratedEventStream::new("c1", author())
}

fn json_text() -> JsonValue {
    JsonValue { value: Some(json_value::Value::Text("x".into())) }
}

fn signed_carrier(payload: surface_carrier::Payload) -> SurfaceCarrier {
    SurfaceCarrier {
        conversation_id: "c1".into(),
        surface_id: "s1".into(),
        sender_principal_id: "alice".into(),
        author_principal_id: "alice".into(),
        signature: "sig-alice".into(),
        payload: Some(payload),
        ..Default::default()
    }
}

fn delivery(payload: surface_carrier::Payload) -> Surface {
    Surface {
        payload: Some(surface::Payload::Delivery(SurfaceDelivery {
            kind: Some(SurfaceControlKind {
                value: Some(surface_control_kind::Value::Peer(SurfaceControlKindPeer {})),
            }),
            carrier: Some(signed_carrier(payload)),
            ..Default::default()
        })),
    }
}

fn event(command: surface_command::Value) -> Surface {
    delivery(surface_carrier::Payload::Event(SurfaceEvent {
        schema: "surface.v1".into(),
        conversation_id: "c1".into(),
        version: 1,
        command: Some(SurfaceCommand { value: Some(command) }),
    }))
}

fn create() -> Surface {
    event(surface_command::Value::CreateSurface(SurfaceCommandCreateSurface {
        value: Some(CreateSurfaceCommand {
            surface_id: "s1".into(),
            surface_type: Some(SurfaceType {
                value: Some(surface_type::Value::MessageCard(SurfaceTypeMessageCard {})),
            }),
            catalog: "cat".into(),
            catalog_version: "1".into(),
            fallback_text: "hi".into(),
            ..Default::default()
        }),
    }))
}

fn action_carrier() -> SurfaceCarrier {
    signed_carrier(surface_carrier::Payload::Action(SurfaceAction {
        conversation_id: "c1".into(),
        surface_id: "s1".into(),
        action_id: "act-1".into(),
        surface_hash: "hash".into(),
        ..Default::default()
    }))
}

fn round_trip(surface: Surface, event_id: &[u8]) -> TestResult {
    RamfluxClient::validate_generated_surface(&surface)?;
    let encoded =
        RamfluxClient::encode_generated_surface(&mut stream(), event_id.to_vec(), surface)?;
    let (_, decoded) = RamfluxClient::decode_generated_inner(&encoded)?;
    assert!(matches!(decoded.value, Some(content::Value::Surface(_))));
    Ok(())
}

fn commands_and_patches() -> TestResult {
    round_trip(create(), b"surf-create")?;
    round_trip(
        event(surface_command::Value::UpdateComponents(SurfaceCommandUpdateComponents {
            value: Some(UpdateComponentsCommand {
                surface_id: "s1".into(),
                base_surface_hash: "a".into(),
                new_surface_hash: "b".into(),
                components: vec![json_text()],
                ..Default::default()
            }),
        })),
        b"surf-components",
    )?;
    round_trip(
        event(surface_command::Value::UpdateDataModel(SurfaceCommandUpdateDataModel {
            value: Some(UpdateDataModelCommand {
                surface_id: "s1".into(),
                base_surface_hash: "a".into(),
                new_surface_hash: "b".into(),
                ..Default::default()
            }),
        })),
        b"surf-data",
    )?;
    round_trip(
        event(surface_command::Value::DeleteSurface(SurfaceCommandDeleteSurface {
            value: Some(DeleteSurfaceCommand {
                surface_id: "s1".into(),
                reason: Some(DeleteSurfaceReason {
                    value: Some(delete_surface_reason::Value::Completed(
                        DeleteSurfaceReasonCompleted {},
                    )),
                }),
            }),
        })),
        b"surf-delete",
    )?;
    let ops = vec![
        SurfacePatchOp {
            value: Some(surface_patch_op::Value::ReplaceBlock(SurfacePatchOpReplaceBlock {
                component: Some(json_text()),
            })),
        },
        SurfacePatchOp {
            value: Some(surface_patch_op::Value::InsertBlock(SurfacePatchOpInsertBlock {
                index: 1,
                component: Some(json_text()),
            })),
        },
        SurfacePatchOp {
            value: Some(surface_patch_op::Value::RemoveBlock(SurfacePatchOpRemoveBlock {
                component_id: "c1".into(),
            })),
        },
        SurfacePatchOp {
            value: Some(surface_patch_op::Value::SetActions(SurfacePatchOpSetActions {
                actions: vec![json_text()],
            })),
        },
        SurfacePatchOp {
            value: Some(surface_patch_op::Value::SetFallbackText(SurfacePatchOpSetFallbackText {
                fallback_text: "bye".into(),
            })),
        },
    ];
    assert_eq!(ops.len(), 5);
    round_trip(
        event(surface_command::Value::PatchSurface(SurfaceCommandPatchSurface {
            value: Some(PatchSurfaceCommand {
                surface_id: "s1".into(),
                base_surface_hash: "a".into(),
                new_surface_hash: "b".into(),
                ops,
            }),
        })),
        b"surf-patch",
    )?;
    round_trip(
        event(surface_command::Value::StreamAppend(SurfaceCommandStreamAppend {
            value: Some(StreamAppendCommand {
                surface_id: "s1".into(),
                component_id: "c1".into(),
                text_delta: "x".into(),
                r#final: true,
            }),
        })),
        b"surf-append",
    )?;
    Ok(())
}

fn action_receipt_and_resync() -> TestResult {
    let action = action_carrier();
    RamfluxClient::authorize_generated_surface_action_signer("alice", &action)?;
    round_trip(
        delivery(surface_carrier::Payload::Action(SurfaceAction {
            conversation_id: "c1".into(),
            surface_id: "s1".into(),
            action_id: "act-1".into(),
            surface_hash: "hash".into(),
            ..Default::default()
        })),
        b"surf-action",
    )?;
    round_trip(
        delivery(surface_carrier::Payload::ActionReceipt(Box::new(action.clone()))),
        b"surf-receipt",
    )?;
    round_trip(
        Surface {
            payload: Some(surface::Payload::ResyncRequest(SurfaceResyncRequest {
                kind: "full".into(),
                conversation_id: "c1".into(),
                surface_ref: "ref".into(),
                author: "alice".into(),
                surface_id: "s1".into(),
                ..Default::default()
            })),
        },
        b"surf-resync",
    )?;
    round_trip(
        Surface {
            payload: Some(surface::Payload::OwnHistory(SurfaceHistoryExport {
                controls: vec![SurfaceDelivery {
                    kind: Some(SurfaceControlKind {
                        value: Some(surface_control_kind::Value::Peer(SurfaceControlKindPeer {})),
                    }),
                    carrier: Some(action.clone()),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        },
        b"surf-history",
    )?;

    let mut forged = action.clone();
    forged.signature.clear();
    assert!(RamfluxClient::authorize_generated_surface_action_signer("alice", &forged).is_err());
    let forged_receipt = delivery(surface_carrier::Payload::ActionReceipt(Box::new(forged)));
    assert!(RamfluxClient::validate_generated_surface(&forged_receipt).is_err());
    Ok(())
}

#[test]
fn every_surface_command_patch_action_receipt_and_resync_round_trips() -> TestResult {
    commands_and_patches()?;
    action_receipt_and_resync()?;
    Ok(())
}
