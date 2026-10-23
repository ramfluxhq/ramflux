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
pub fn event(version: u64, command: A2uiConversationCommand) -> A2uiConversationEvent {
    let command = serde_json::to_value(command).unwrap();
    A2uiConversationEvent::from_wire_bytes(&serde_json::to_vec(&json!({"schema":A2UI_CONVERSATION_SCHEMA,"conversationId":"c","version":version,"command":command})).unwrap()).unwrap()
}
pub fn edit_event(
    event: &A2uiConversationEvent,
    edit: impl FnOnce(&mut serde_json::Value),
) -> A2uiConversationEvent {
    let mut value = serde_json::to_value(event).unwrap();
    edit(&mut value);
    A2uiConversationEvent::from_wire_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
}
pub fn edit_action(
    action: &A2uiSurfaceAction,
    edit: impl FnOnce(&mut serde_json::Value),
) -> A2uiSurfaceAction {
    let mut value = serde_json::to_value(action).unwrap();
    edit(&mut value);
    A2uiSurfaceAction::from_wire_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
}
pub fn created() -> SurfaceState {
    SurfaceState::default()
        .apply(&event(1, A2uiConversationCommand::CreateSurface(snapshot())))
        .unwrap()
}
pub fn stream(version: u64, text: &str, final_: bool) -> A2uiConversationEvent {
    event(
        version,
        A2uiConversationCommand::StreamAppend(StreamAppendCommand {
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
        A2uiConversationCommand::PatchSurface(PatchSurfaceCommand {
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
        A2uiConversationCommand::DeleteSurface(DeleteSurfaceCommand {
            surface_id: "s".into(),
            reason: Some(DeleteSurfaceReason::Completed),
        }),
    )
}
pub fn action(state: &SurfaceState) -> A2uiSurfaceAction {
    let values = json!({"approved":true});
    A2uiSurfaceAction::from_wire_bytes(&serde_json::to_vec(&json!({"schema":A2UI_ACTION_SCHEMA,"conversationId":"c","surfaceId":"s","version":state.version(),"surfaceHash":state.hash().unwrap(),"actionId":"approve","argsHash":surface_args_hash(&values).unwrap(),"values":values})).unwrap()).unwrap()
}
