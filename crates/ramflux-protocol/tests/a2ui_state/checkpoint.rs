// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::support::{close, created, patch, stream};
use ramflux_protocol::{A2uiConversationEvent, SurfacePatchOp, SurfaceReject, SurfaceState};
use serde_json::json;
#[test]
fn private_checkpoint_preserves_version_hash_close_and_removed_stream_finality() {
    let state = created().apply(&stream(2, "final", true)).unwrap();
    let mut content = state.content().unwrap().clone();
    content.components.clear();
    let removed = state
        .apply(&patch(
            &state,
            vec![SurfacePatchOp::RemoveBlock { component_id: "text".into() }],
            &content,
        ))
        .unwrap();
    let wire = removed.checkpoint_bytes().unwrap();
    let restored = SurfaceState::from_checkpoint_bytes(&wire).unwrap();
    assert_eq!(restored, removed);
    assert!(A2uiConversationEvent::from_wire_bytes(&wire).is_err());
    let content = state.content().unwrap();
    let reinsert = patch(
        &restored,
        vec![SurfacePatchOp::InsertBlock { index: 0, component: content.components[0].clone() }],
        content,
    );
    let inserted = restored.apply(&reinsert).unwrap();
    assert_eq!(inserted.apply(&stream(5, "x", false)), Err(SurfaceReject::BlockClosed));
    let closed = inserted.apply(&close(5)).unwrap();
    let saved = SurfaceState::from_checkpoint_bytes(&closed.checkpoint_bytes().unwrap()).unwrap();
    assert_eq!(saved, closed);
    assert_eq!(saved.apply(&close(6)), Err(SurfaceReject::Closed));
}
#[test]
fn invalid_checkpoint_schema_and_inconsistent_text_are_rejected() {
    let state = created().apply(&stream(2, "final", true)).unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&state.checkpoint_bytes().unwrap()).unwrap();
    for field in ["schema", "version"] {
        let mut changed = value.clone();
        changed[field] = if field == "schema" { json!("unknown") } else { json!(0) };
        assert!(
            SurfaceState::from_checkpoint_bytes(&serde_json::to_vec(&changed).unwrap()).is_err()
        );
    }
    let mut changed = value.clone();
    changed["final_text"][0]["text"] = json!("different");
    assert_eq!(
        SurfaceState::from_checkpoint_bytes(&serde_json::to_vec(&changed).unwrap()),
        Err(SurfaceReject::BlockClosed)
    );
    let mut changed = value;
    let duplicate = changed["final_text"][0].clone();
    changed["final_text"].as_array_mut().unwrap().push(duplicate);
    assert_eq!(
        SurfaceState::from_checkpoint_bytes(&serde_json::to_vec(&changed).unwrap()),
        Err(SurfaceReject::DuplicateBlock)
    );
    let empty = SurfaceState::default();
    assert_eq!(
        SurfaceState::from_checkpoint_bytes(&empty.checkpoint_bytes().unwrap()).unwrap(),
        empty
    );
}
