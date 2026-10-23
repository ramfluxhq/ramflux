// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::support::*;
use ramflux_protocol::*;
use serde_json::json;
fn rejects(content: CreateSurfaceCommand, error: SurfaceReject) {
    assert_eq!(
        SurfaceState::default().apply(&event(1, A2uiConversationCommand::CreateSurface(content))),
        Err(error)
    );
}
fn limit(limit: SurfaceLimit) -> SurfaceReject {
    SurfaceReject::LimitExceeded { limit }
}
#[test]
fn snapshot_limits_and_identifiers_have_typed_rejections() {
    let mut c = snapshot();
    c.fallback_text = " ".into();
    rejects(c, SurfaceReject::MissingFallback);
    let mut c = snapshot();
    c.surface_id.clear();
    rejects(c, SurfaceReject::InvalidIdentifier);
    let mut c = snapshot();
    c.fallback_text = "a".repeat(MAX_SURFACE_TEXT_CHARS + 1);
    rejects(c, limit(SurfaceLimit::TextCharacters));
    let mut c = snapshot();
    c.components = vec![c.components[0].clone(); 65];
    rejects(c, limit(SurfaceLimit::Blocks));
    let mut c = snapshot();
    c.allowed_actions = vec![json!("a"); 17];
    rejects(c, limit(SurfaceLimit::Actions));
    let mut c = snapshot();
    c.components.push(c.components[0].clone());
    rejects(c, SurfaceReject::DuplicateBlock);
    let mut c = snapshot();
    c.allowed_actions.push(c.allowed_actions[0].clone());
    rejects(c, SurfaceReject::DuplicateAction);
    let mut c = snapshot();
    c.allowed_actions = vec![json!({"id":"a","name":"b"})];
    rejects(c, SurfaceReject::InvalidIdentifier);
    let mut c = snapshot();
    c.data_model.insert("unsafe".into(), json!(MAX_SAFE_JSON_INTEGER + 1));
    let wire = json!({"schema":A2UI_CONVERSATION_SCHEMA,"conversationId":"c","version":1,"command":A2uiConversationCommand::CreateSurface(c)});
    assert!(matches!(
        A2uiConversationEvent::from_wire_bytes(&serde_json::to_vec(&wire).unwrap()),
        Err(ProtocolError::IJson(_))
    ));
    let mut c = snapshot();
    let mut nested = json!(true);
    for _ in 0..66 {
        nested = json!([nested]);
    }
    c.data_model.insert("deep".into(), nested);
    rejects(c, limit(SurfaceLimit::NestingDepth));
}
#[test]
fn scalar_and_utf8_stream_budgets_are_distinct() {
    let state = created();
    assert!(state.apply(&stream(2, &"é".repeat(2048), false)).is_ok());
    assert_eq!(
        state.apply(&stream(2, &"é".repeat(2049), false)),
        Err(limit(SurfaceLimit::TextDeltaBytes))
    );
    let mut c = snapshot();
    c.components[0]["text"] = json!("x".repeat(MAX_SURFACE_TEXT_CHARS));
    let full = SurfaceState::default()
        .apply(&event(1, A2uiConversationCommand::CreateSurface(c)))
        .unwrap();
    assert_eq!(full.apply(&stream(2, "x", false)), Err(limit(SurfaceLimit::TextCharacters)));
    assert!(full.apply(&stream(2, "", true)).is_ok());
}
#[test]
fn total_data_bytes_and_operation_batches_are_bounded() {
    let mut c = snapshot();
    c.components = (0..4).map(|i| json!({"id":format!("c{i}"),"text":"x".repeat(16384)})).collect();
    rejects(c, limit(SurfaceLimit::DataBytes));
    let state = created();
    let ops = vec![SurfacePatchOp::SetActions { actions: vec![] }; 65];
    assert_eq!(
        state.apply(&patch(&state, ops, state.content().unwrap())),
        Err(limit(SurfaceLimit::PatchOperations))
    );
    let mut c = snapshot();
    c.data_model.insert("escaped".into(), json!("\n".repeat(16384)));
    c.data_model.insert("escaped2".into(), json!("\n".repeat(16384)));
    rejects(c, limit(SurfaceLimit::DataBytes));
}
#[test]
fn retirement_tombstones_have_a_finite_budget() {
    let mut state = created();
    for i in 0..MAX_SURFACE_FINALIZED_BLOCKS {
        let id = format!("final{i}");
        let mut after = state.content().unwrap().clone();
        after.components = vec![json!({"id":id,"text":""})];
        state = state
            .apply(&patch(
                &state,
                vec![
                    SurfacePatchOp::RemoveBlock {
                        component_id: state.content().unwrap().components[0]["id"]
                            .as_str()
                            .unwrap()
                            .into(),
                    },
                    SurfacePatchOp::InsertBlock {
                        index: 0,
                        component: after.components[0].clone(),
                    },
                ],
                &after,
            ))
            .unwrap();
        let append = edit_event(&stream(state.version() + 1, "", true), |v| {
            v["command"]["componentId"] = json!(id);
        });
        state = state.apply(&append).unwrap();
    }
    let mut after = state.content().unwrap().clone();
    after.components = vec![json!({"id":"text","text":""})];
    state = state
        .apply(&patch(
            &state,
            vec![
                SurfacePatchOp::ReplaceBlock {
                    component: state.content().unwrap().components[0].clone(),
                },
                SurfacePatchOp::RemoveBlock { component_id: "final63".into() },
                SurfacePatchOp::InsertBlock { index: 0, component: after.components[0].clone() },
            ],
            &after,
        ))
        .unwrap();
    assert_eq!(
        state.apply(&stream(state.version() + 1, "", true)),
        Err(limit(SurfaceLimit::FinalizedBlocks))
    );
}

#[test]
fn exact_jcs_data_budget_is_accepted_then_one_stream_byte_is_rejected() {
    let mut content = snapshot();
    content.components = (0..4)
        .map(|i| json!({"id":if i==0{"text".into()}else{format!("c{i}")},"text":"x".repeat(16000)}))
        .collect();
    let used = canonical_json_bytes(&content).unwrap().len();
    let mut remaining = MAX_SURFACE_DATA_BYTES - used;
    for component in &mut content.components {
        let text = component["text"].as_str().unwrap();
        let count = (MAX_SURFACE_TEXT_CHARS - text.len()).min(remaining);
        component["text"] = json!(format!("{text}{}", "x".repeat(count)));
        remaining -= count;
    }
    assert_eq!(remaining, 0);
    // Append to a component whose scalar budget still has room, isolating total data bytes.
    content.components.swap(0, 3);
    content.components[0]["id"] = json!("text");
    content.components[3]["id"] = json!("c3");
    let state = SurfaceState::default()
        .apply(&event(1, A2uiConversationCommand::CreateSurface(content)))
        .unwrap();
    assert_eq!(state.apply(&stream(2, "x", false)), Err(limit(SurfaceLimit::DataBytes)));
}

#[test]
fn actions_and_fallback_are_inside_the_whole_snapshot_cap() {
    let mut content = snapshot();
    content.allowed_actions =
        (0..16).map(|i| json!({"name":format!("a{i}"),"label":"x".repeat(5000)})).collect();
    rejects(content, limit(SurfaceLimit::DataBytes));
    let mut content = snapshot();
    content.fallback_text = "𐀀".repeat(16384);
    rejects(content, limit(SurfaceLimit::DataBytes));
    let mut content = snapshot();
    content.fallback_markdown = Some("𐀀".repeat(16384));
    rejects(content, limit(SurfaceLimit::DataBytes));
}
