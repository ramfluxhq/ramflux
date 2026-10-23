// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use ramflux_protocol::*;
use serde_json::json;
pub fn snapshot() -> CreateSurfaceCommand {
    CreateSurfaceCommand {
        surface_id: "s".into(),
        surface_type: SurfaceType::StatusPanel,
        catalog: "ramflux.basic.v1".into(),
        catalog_version: "1.0.0".into(),
        fallback_text: "Working".into(),
        fallback_markdown: None,
        components: vec![json!({"id":"text","kind":"text","text":""})],
        data_model: serde_json::Map::default(),
        allowed_actions: vec![json!({"name":"approve"})],
    }
}
pub fn event(version: u64, command: A2uiCommand) -> A2uiConversationEvent {
    A2uiConversationEvent {
        schema: A2uiConversationSchema::V2,
        conversation_id: "c".into(),
        version,
        command,
    }
}
pub fn created() -> SurfaceState {
    SurfaceState::default().apply(&event(1, A2uiCommand::CreateSurface(snapshot()))).unwrap()
}
pub fn stream(version: u64, text: &str, final_: bool) -> A2uiConversationEvent {
    event(
        version,
        A2uiCommand::StreamAppend(StreamAppendCommand {
            surface_id: "s".into(),
            component_id: "text".into(),
            text_delta: text.into(),
            final_,
        }),
    )
}
pub fn patch(
    state: &SurfaceState,
    ops: Vec<SurfacePatchOp>,
    after: &CreateSurfaceCommand,
) -> A2uiConversationEvent {
    event(
        state.version() + 1,
        A2uiCommand::PatchSurface(PatchSurfaceCommand {
            surface_id: "s".into(),
            base_surface_hash: state.hash().unwrap().into(),
            ops,
            new_surface_hash: surface_snapshot_hash(after).unwrap(),
        }),
    )
}
pub fn close(version: u64) -> A2uiConversationEvent {
    event(
        version,
        A2uiCommand::DeleteSurface(DeleteSurfaceCommand {
            surface_id: "s".into(),
            reason: Some(DeleteSurfaceReason::Completed),
        }),
    )
}
pub fn action(state: &SurfaceState) -> A2uiSurfaceAction {
    let values = json!({"approved":true});
    A2uiSurfaceAction {
        schema: A2uiActionSchema::V2,
        conversation_id: "c".into(),
        surface_id: "s".into(),
        version: state.version(),
        surface_hash: state.hash().unwrap().into(),
        action_id: "approve".into(),
        args_hash: surface_args_hash(&values).unwrap(),
        values,
    }
}
