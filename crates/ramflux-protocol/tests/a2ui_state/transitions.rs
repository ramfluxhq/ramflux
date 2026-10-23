// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::support::*;
use ramflux_protocol::*;
use serde_json::json;
#[test]
fn lifecycle_versions_close_and_stream_final_are_terminal() {
    let empty = SurfaceState::default();
    assert_eq!(empty.apply(&close(1)), Err(SurfaceReject::NotCreated));
    assert_eq!(empty.validate_action(&action(&created())), Err(SurfaceReject::NotCreated));
    let state = created();
    assert_eq!(
        state.apply(&stream(1, "", false)),
        Err(SurfaceReject::Version { expected: 2, actual: 1 })
    );
    assert_eq!(
        state.apply(&stream(3, "", false)),
        Err(SurfaceReject::Version { expected: 2, actual: 3 })
    );
    assert_eq!(
        state.apply(&event(2, A2uiCommand::CreateSurface(snapshot()))),
        Err(SurfaceReject::AlreadyCreated)
    );
    let finished = state.apply(&stream(2, "hello", true)).unwrap();
    assert_eq!(finished.content().unwrap().components[0]["text"], "hello");
    assert_eq!(finished.apply(&stream(3, "!", false)), Err(SurfaceReject::BlockClosed));
    let closed = finished.apply(&close(3)).unwrap();
    assert!(closed.is_closed());
    assert_eq!(closed.hash(), finished.hash());
    assert_eq!(closed.apply(&stream(4, "", false)), Err(SurfaceReject::Closed));
    assert_eq!(closed.validate_action(&action(&closed)), Err(SurfaceReject::Closed));
}
#[test]
fn bindings_conflicts_result_hash_and_operation_rejects_are_atomic() {
    let state = created();
    let original = state.clone();
    let mut wrong = stream(2, "x", false);
    wrong.conversation_id = "other".into();
    assert_eq!(state.apply(&wrong), Err(SurfaceReject::WrongSurface));
    if let A2uiCommand::StreamAppend(c) = &mut wrong.command {
        c.surface_id = "other".into();
    }
    wrong.conversation_id = "c".into();
    assert_eq!(state.apply(&wrong), Err(SurfaceReject::WrongSurface));
    let mut p = patch(&state, vec![], state.content().unwrap());
    if let A2uiCommand::PatchSurface(c) = &mut p.command {
        c.base_surface_hash = "wrong".into();
    }
    assert_eq!(state.apply(&p), Err(SurfaceReject::Conflict));
    if let A2uiCommand::PatchSurface(c) = &mut p.command {
        c.base_surface_hash = state.hash().unwrap().into();
        c.new_surface_hash = "wrong".into();
    }
    assert_eq!(state.apply(&p), Err(SurfaceReject::ResultHashMismatch));
    for (op, error) in [
        (
            SurfacePatchOp::RemoveBlock { component_id: "missing".into() },
            SurfaceReject::UnknownBlock,
        ),
        (
            SurfacePatchOp::ReplaceBlock { component: json!({"id":"missing"}) },
            SurfaceReject::UnknownBlock,
        ),
        (
            SurfacePatchOp::InsertBlock { index: 2, component: json!({"id":"new"}) },
            SurfaceReject::InvalidInsertPosition,
        ),
        (
            SurfacePatchOp::InsertBlock { index: 0, component: json!({"id":"text"}) },
            SurfaceReject::DuplicateBlock,
        ),
        (
            SurfacePatchOp::InsertBlock { index: 0, component: json!({}) },
            SurfaceReject::InvalidIdentifier,
        ),
    ] {
        assert_eq!(state.apply(&patch(&state, vec![op], state.content().unwrap())), Err(error));
    }
    let mut no_text = snapshot();
    no_text.components[0] = json!({"id":"text","kind":"progress","value":1.0});
    let no_text =
        SurfaceState::default().apply(&event(1, A2uiCommand::CreateSurface(no_text))).unwrap();
    assert_eq!(no_text.apply(&stream(2, "x", false)), Err(SurfaceReject::BlockNotStreamable));
    let mut unknown = stream(2, "x", false);
    if let A2uiCommand::StreamAppend(c) = &mut unknown.command {
        c.component_id = "missing".into();
    }
    assert_eq!(state.apply(&unknown), Err(SurfaceReject::UnknownBlock));
    assert_eq!(state, original);
}
#[test]
fn action_checks_bind_every_field_and_disabled_reason() {
    let state = created();
    let valid = action(&state);
    assert_eq!(state.validate_action(&valid), Ok(()));
    for field in 0..6 {
        let mut a = valid.clone();
        let error = match field {
            0 => {
                a.conversation_id = "other".into();
                SurfaceReject::WrongSurface
            }
            1 => {
                a.surface_id = "other".into();
                SurfaceReject::WrongSurface
            }
            2 => {
                a.version += 1;
                SurfaceReject::Stale
            }
            3 => {
                a.surface_hash = "wrong".into();
                SurfaceReject::Stale
            }
            4 => {
                a.action_id = "other".into();
                SurfaceReject::UnknownAction
            }
            _ => {
                a.values = json!({"approved":false});
                SurfaceReject::ArgumentsHashMismatch
            }
        };
        assert_eq!(state.validate_action(&a), Err(error));
    }
    let mut content = snapshot();
    content.allowed_actions[0]["disabledReason"] = json!("waiting");
    let disabled =
        SurfaceState::default().apply(&event(1, A2uiCommand::CreateSurface(content))).unwrap();
    assert_eq!(disabled.validate_action(&action(&disabled)), Err(SurfaceReject::DisabledAction));
}
#[test]
fn existing_update_commands_share_the_snapshot_hash() {
    let state = created();
    let mut after = state.content().unwrap().clone();
    after.components = vec![json!({"id":"next","text":"next"})];
    let state = state
        .apply(&event(
            2,
            A2uiCommand::UpdateComponents(UpdateComponentsCommand {
                surface_id: "s".into(),
                base_surface_hash: state.hash().unwrap().into(),
                components: after.components.clone(),
                remove_component_ids: vec!["text".into()],
                new_surface_hash: surface_snapshot_hash(&after).unwrap(),
            }),
        ))
        .unwrap();
    after.data_model.insert("progress".into(), json!(1.0));
    let state = state
        .apply(&event(
            3,
            A2uiCommand::UpdateDataModel(UpdateDataModelCommand {
                surface_id: "s".into(),
                base_surface_hash: state.hash().unwrap().into(),
                data_patch: after.data_model.clone(),
                new_surface_hash: surface_snapshot_hash(&after).unwrap(),
            }),
        ))
        .unwrap();
    assert_eq!(state.content(), Some(&after));
}
#[test]
fn patch_chains_round_trip_identically_across_1024_mutations() {
    for seed in 0..32 {
        let mut state = created();
        for step in 0..32 {
            let mut after = state.content().unwrap().clone();
            let ops = match step % 4 {
                0 => {
                    after.components[0] = json!({"id":"text","text":format!("{seed}:{step}")});
                    vec![SurfacePatchOp::ReplaceBlock { component: after.components[0].clone() }]
                }
                1 => {
                    let c = json!({"id":"extra","text":"x"});
                    after.components.insert(1, c.clone());
                    vec![SurfacePatchOp::InsertBlock { index: 1, component: c }]
                }
                2 => {
                    after.components.remove(1);
                    vec![SurfacePatchOp::RemoveBlock { component_id: "extra".into() }]
                }
                _ => {
                    after.allowed_actions =
                        vec![json!({"name":"approve","label":format!("{seed}:{step}")})];
                    vec![SurfacePatchOp::SetActions { actions: after.allowed_actions.clone() }]
                }
            };
            let event = patch(&state, ops, &after);
            let ordinary = serde_json::from_slice(&serde_json::to_vec(&event).unwrap()).unwrap();
            let canonical = serde_json::from_slice(&canonical_json_bytes(&event).unwrap()).unwrap();
            let next = state.apply(&event).unwrap();
            assert_eq!(next, state.apply(&ordinary).unwrap());
            assert_eq!(next, state.apply(&canonical).unwrap());
            assert_eq!(next.hash(), Some(surface_snapshot_hash(&after).unwrap().as_str()));
            state = next;
        }
    }
}
#[test]
fn finalized_identity_cannot_be_reopened_by_removing_and_reinserting_it() {
    let state = created().apply(&stream(2, "", true)).unwrap();
    let after = state.content().unwrap().clone();
    let state = state
        .apply(&patch(
            &state,
            vec![
                SurfacePatchOp::RemoveBlock { component_id: "text".into() },
                SurfacePatchOp::InsertBlock { index: 0, component: after.components[0].clone() },
            ],
            &after,
        ))
        .unwrap();
    assert_eq!(state.apply(&stream(4, "again", false)), Err(SurfaceReject::BlockClosed));
}

#[test]
fn nested_text_and_data_model_removal_follow_documented_semantics() {
    let mut content = snapshot();
    content.components[0] = json!({"id":"text","data":{"text":"a"}});
    content.data_model.insert("old".into(), json!({"value":1}));
    let state =
        SurfaceState::default().apply(&event(1, A2uiCommand::CreateSurface(content))).unwrap();
    let state = state.apply(&stream(2, "b", false)).unwrap();
    assert_eq!(state.content().unwrap().components[0]["data"]["text"], "ab");
    let mut after = state.content().unwrap().clone();
    after.data_model.remove("old");
    after.data_model.insert("new".into(), json!({"value":2}));
    let update = UpdateDataModelCommand {
        surface_id: "s".into(),
        base_surface_hash: state.hash().unwrap().into(),
        data_patch: json!({"old":null,"new":{"value":2}}).as_object().unwrap().clone(),
        new_surface_hash: surface_snapshot_hash(&after).unwrap(),
    };
    assert_eq!(
        state.apply(&event(3, A2uiCommand::UpdateDataModel(update))).unwrap().content(),
        Some(&after)
    );
}
