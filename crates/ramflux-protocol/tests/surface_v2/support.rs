// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub use ramflux_protocol::surface_v2::*;
pub use serde_json::{Value, json};
pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub fn block(id: &str, text: &str) -> SurfaceBlock {
    SurfaceBlock {
        id: id.to_owned(),
        kind: SurfaceBlockKind::Text,
        version: 1,
        redacted: false,
        data: json!({"text":text}),
    }
}
pub fn definition(id: &str) -> SurfaceActionDefinition {
    SurfaceActionDefinition {
        id: id.to_owned(),
        label: "Go".to_owned(),
        risk: SurfaceActionRisk::High,
        disabled_reason: None,
    }
}
pub fn create() -> SurfaceEvent {
    SurfaceEvent::Create {
        surface_id: "s".to_owned(),
        version: 1,
        blocks: vec![block("b", "hello")],
        actions: vec![definition("go")],
        fallback_text: "fallback".to_owned(),
    }
}
pub fn state() -> Result<SurfaceState, SurfaceReject> {
    SurfaceState::default().apply(&create())
}
pub fn patch(
    state: &SurfaceState,
    ops: Vec<SurfacePatchOp>,
) -> Result<SurfaceEvent, SurfaceReject> {
    Ok(SurfaceEvent::Patch {
        surface_id: "s".to_owned(),
        version: state.version() + 1,
        base_hash: state.hash().ok_or(SurfaceReject::NotCreated)?,
        ops,
    })
}
pub fn append(version: u64, delta: &str, final_: bool) -> SurfaceEvent {
    SurfaceEvent::StreamAppend {
        surface_id: "s".to_owned(),
        version,
        block_id: "b".to_owned(),
        text_delta: delta.to_owned(),
        final_,
    }
}
pub fn action(state: &SurfaceState) -> Result<SurfaceAction, SurfaceReject> {
    let values = json!({"choice":"yes"});
    Ok(SurfaceAction {
        schema: SurfaceActionSchema::V1,
        surface_id: "s".to_owned(),
        version: state.version(),
        surface_hash: state.hash().ok_or(SurfaceReject::NotCreated)?,
        action_id: "go".to_owned(),
        args_hash: surface_args_hash(&values)?,
        values,
    })
}
pub fn content(
    blocks: Vec<SurfaceBlock>,
    actions: Vec<SurfaceActionDefinition>,
) -> Result<SurfaceContent, SurfaceReject> {
    SurfaceContent::new("s".to_owned(), "fallback".to_owned(), blocks, actions)
}
