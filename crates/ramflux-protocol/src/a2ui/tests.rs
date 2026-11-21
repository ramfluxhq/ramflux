// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real protocol transitions, canonical-byte admission and continuity controls.
use super::*;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn frame(state: &SurfaceState) -> EventFrame {
    EventFrame {
        schema: EVENT_SCHEMA.into(),
        conversation_id: "conversation".into(),
        surface_version: state.version() + 1,
        base_surface_hash: state.hash().map(str::to_owned),
        new_surface_hash: String::new(),
        fallback_text: None,
        close_reason: None,
        a2ui: None,
        append_text: None,
        resync: None,
        final_: None,
        closed: None,
        metadata: None,
    }
}
fn create() -> Result<SurfaceState, Reject> {
    let state = SurfaceState::default();
    let mut f = frame(&state);
    f.fallback_text = Some("A message".into());
    f.a2ui = Some(MutationMessage::new(Mutation::CreateSurface(CreateSurface {
        surface_id: "surface".into(),
        catalog_id: CATALOG_ID.into(),
        send_data_model: None,
        components: Some(vec![json!({"id":"root","component":"Text","text":{"@path":"/text"}})]),
        data_model: Some(json!({"text":"hello"})),
        metadata: None,
    })));
    state.apply(&SurfaceEvent::from_wire_bytes(&state.prepare_event(f)?.wire_bytes()?)?)
}
fn append(state: &SurfaceState, final_: bool) -> Result<SurfaceState, Reject> {
    let mut f = frame(state);
    f.append_text = Some(AppendText {
        surface_id: "surface".into(),
        path: "/text".into(),
        delta: " world".into(),
        final_,
    });
    state.apply(&SurfaceEvent::from_wire_bytes(&state.prepare_event(f)?.wire_bytes()?)?)
}
#[test]
fn finality_survives_reopen_and_all_ordinary_replacement_paths() -> TestResult {
    let state = append(&create()?, true)?;
    let reopened = SurfaceState::from_checkpoint_bytes(&state.checkpoint_bytes()?)?;
    assert_eq!(state, reopened, "checkpoint must restore the identical signed base and finality");
    for state in [&state, &reopened] {
        for (path, value) in [
            ("/text", json!("changed")),
            ("/text", json!(null)),
            ("/", json!({"text":"changed"})),
            ("/", json!(null)),
        ] {
            let mut f = frame(state);
            f.a2ui = Some(MutationMessage::new(Mutation::UpdateDataModel(UpdateDataModel {
                surface_id: "surface".into(),
                path: Some(path.into()),
                value,
            })));
            assert!(
                state.prepare_event(f).is_err(),
                "ordinary replacement/deletion must preserve every committed text"
            );
        }
        assert!(append(state, false).is_err(), "a final pointer must refuse appends");
    }
    Ok(())
}
#[test]
fn self_consistent_higher_version_resync_cannot_erase_or_alter_known_finality() -> TestResult {
    let state = append(&create()?, true)?;
    let reopened = SurfaceState::from_checkpoint_bytes(&state.checkpoint_bytes()?)?;
    for known in [&state, &reopened] {
        for altered in [false, true] {
            let mut f = known.resync_frame()?;
            f.surface_version += 1;
            let mut snapshot = known.content().ok_or("missing state")?.clone();
            if altered {
                snapshot.data_model = json!({"text":"forged"});
                snapshot.final_ = vec![FinalRecord {
                    pointer: "/text".into(),
                    text_hash: crate::hash_base64url("ramflux.a2ui.final_text.v2", b"forged"),
                }];
            } else {
                snapshot.final_.clear();
            }
            f.final_ = Some(snapshot.final_.clone());
            f.resync = Some(Resync {
                a2ui: MutationMessage::new(Mutation::CreateSurface(snapshot.create())),
            });
            f.new_surface_hash = snapshot.hash()?;
            let event = SurfaceEvent::from_wire_bytes(&f.wire_bytes()?)?;
            assert!(
                SurfaceState::validate_proof(&event).is_ok(),
                "control: incoming proof must be self-consistent against empty context"
            );
            assert_eq!(
                known.apply(&event),
                Err(Reject::Integrity),
                "known finality must reject a self-consistent replacement without mutating state"
            );
            assert_eq!(
                known.hash(),
                state.hash(),
                "failed replacement cannot change the known state"
            );
        }
    }
    Ok(())
}
#[test]
fn bootstrap_accepts_missed_create_then_requires_exact_next_sequence() -> TestResult {
    let author = append(&create()?, false)?;
    let mut resync = author.resync_frame()?;
    resync.surface_version = 19;
    let bootstrap =
        SurfaceState::default().apply(&SurfaceEvent::from_wire_bytes(&resync.wire_bytes()?)?)?;
    assert_eq!(
        bootstrap.version(),
        19,
        "a missed create must bootstrap the signed snapshot version"
    );
    let next = append(&bootstrap, false)?;
    assert_eq!(next.version(), 20, "the first delta must consume exactly N+1");
    let mut wrong = frame(&bootstrap);
    wrong.surface_version = 21;
    wrong.append_text = Some(AppendText {
        surface_id: "surface".into(),
        path: "/text".into(),
        delta: String::new(),
        final_: false,
    });
    assert_eq!(
        bootstrap.prepare_event(wrong),
        Err(Reject::Version { expected: 20, actual: 21 }),
        "a skipped version must be rejected"
    );
    for version in [0, crate::MAX_SAFE_JSON_INTEGER + 1] {
        resync.surface_version = version;
        assert!(resync.wire_bytes().is_err(), "bootstrap version must be positive and JSON-safe");
    }
    Ok(())
}
#[test]
fn rollback_equal_version_close_and_noncanonical_bytes_are_refused() -> TestResult {
    let state = create()?;
    let mut resync = state.resync_frame()?;
    resync.new_surface_hash = "different".into();
    assert_eq!(
        state.apply(&SurfaceEvent::from_wire_bytes(&resync.wire_bytes()?)?),
        Err(Reject::Conflict),
        "equal-version replacements must bind the identical hash"
    );
    let mut close = frame(&state);
    close.a2ui = Some(MutationMessage::new(Mutation::DeleteSurface(DeleteSurface {
        surface_id: "surface".into(),
    })));
    let closed =
        state.apply(&SurfaceEvent::from_wire_bytes(&state.prepare_event(close)?.wire_bytes()?)?)?;
    assert!(closed.is_closed(), "deleteSurface must commit terminal close");
    assert!(
        closed
            .apply(&SurfaceEvent::from_wire_bytes(&state.resync_frame()?.wire_bytes()?)?)
            .is_err(),
        "known closed state cannot bootstrap or reopen"
    );
    let bytes = serde_json::to_vec_pretty(&state.resync_frame()?)?;
    assert_eq!(
        SurfaceEvent::from_wire_bytes(&bytes),
        Err(Reject::Encoding),
        "JCS inequality must be rejected from original bytes"
    );
    Ok(())
}
#[test]
fn final_record_order_duplicates_arrays_and_checkpoint_tampering_are_refused() -> TestResult {
    let state = append(&create()?, true)?;
    let mut f = state.resync_frame()?;
    let record = state.content().and_then(|s| s.final_.first()).ok_or("missing finality")?.clone();
    f.final_ = Some(vec![record.clone(), record]);
    assert!(
        SurfaceState::validate_proof(&SurfaceEvent::from_wire_bytes(&f.wire_bytes()?)?).is_err(),
        "duplicate finality must fail even before stateful replacement"
    );
    assert!(
        JsonPointer::parse("/items/0/text")?.text(&json!({"items":[{"text":"unsafe"}]})).is_err(),
        "stream pointers cannot traverse array indices"
    );
    assert!(JsonPointer::parse("/text~2").is_err(), "noncanonical RFC6901 escapes must be refused");
    let mut checkpoint: serde_json::Value = serde_json::from_slice(&state.checkpoint_bytes()?)?;
    checkpoint["dataModel"]["text"] = json!("tampered");
    assert!(
        SurfaceState::from_checkpoint_bytes(&crate::canonical_json_bytes(&checkpoint)?).is_err(),
        "checkpoint text must match its final commitment"
    );
    Ok(())
}
#[test]
fn metadata_is_committed_and_empty_metadata_is_not_an_alias() -> TestResult {
    let state = create()?;
    let mut s = state.content().ok_or("missing snapshot")?.clone();
    let before = s.hash()?;
    s.metadata =
        Some(Metadata { extensions: serde_json::from_value(json!({"example":"present"}))? });
    assert_ne!(before, s.hash()?, "surface metadata must participate in the signed commitment");
    let mut f = state.resync_frame()?;
    f.metadata = Some(Metadata { extensions: serde_json::Map::default() });
    assert!(f.wire_bytes().is_err(), "empty metadata cannot introduce an alternate state encoding");
    Ok(())
}

#[test]
fn locale_sensitive_button_checks_are_refused_for_en_and_zh_cn_but_display_is_allowed() -> TestResult
{
    let base: EventFrame = serde_json::from_slice(include_bytes!(
        "../../fixtures/protocol/v1/a2ui_surface/create.event.json"
    ))?;
    // Admission takes original bytes and no ambient locale. Both host settings must therefore
    // receive the same typed refusal, including when the formatter is nested under length.
    for locale in ["en", "zh-CN"] {
        for function in ["formatDate", "formatNumber", "formatCurrency", "pluralize"] {
            let args = match function {
                "formatDate" => json!({"value":"2026-11-14T00:00:00Z","format":"MMMM"}),
                "formatNumber" => json!({"value":1000}),
                "formatCurrency" => json!({"value":1000,"currency":"USD"}),
                _ => json!({"value":1,"one":"item","other":"items"}),
            };
            let rendered_args = args
                .as_object()
                .ok_or("formatter args")?
                .iter()
                .map(|(key, value)| {
                    serde_json::to_string(value).map(|value| format!("{key}:{value}"))
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(",");
            let program = format!("${{{function}({rendered_args})}}");
            for form in ["direct", "program", "bound_program"] {
                let mut frame = base.clone();
                let Some(MutationMessage { mutation: Mutation::CreateSurface(create), .. }) =
                    &mut frame.a2ui
                else {
                    return Err("fixture create".into());
                };
                if form == "bound_program" {
                    create
                        .data_model
                        .as_mut()
                        .and_then(serde_json::Value::as_object_mut)
                        .ok_or("model")?
                        .insert("program".into(), json!(program));
                }
                let value = match form {
                    "direct" => json!({"@call":function,"args":args}),
                    "program" => json!({"@call":"formatString","args":{"value":program}}),
                    _ => json!({"@call":"formatString","args":{"value":{"@path":"/program"}}}),
                };
                let button = create
                    .components
                    .as_mut()
                    .ok_or("components")?
                    .iter_mut()
                    .find(|c| c.get("id").and_then(serde_json::Value::as_str) == Some("button"))
                    .ok_or("button")?;
                button["@checks"] =
                    json!([{"condition":{"@call":"length","args":{"value":value,"min":5}}}]);
                assert_eq!(
                    SurfaceState::default().prepare_event(frame),
                    Err(Reject::LocaleDependentCheck),
                    "{locale}: {function} in {form} must never gate an action through host locale"
                );
            }
        }
    }
    let mut frame = base;
    let Some(MutationMessage { mutation: Mutation::CreateSurface(create), .. }) = &mut frame.a2ui
    else {
        return Err("fixture create".into());
    };
    let label = create
        .components
        .as_mut()
        .ok_or("components")?
        .iter_mut()
        .find(|c| c.get("id").and_then(serde_json::Value::as_str) == Some("label"))
        .ok_or("label")?;
    label["text"] =
        json!({"@call":"formatDate","args":{"value":"2026-11-14T00:00:00Z","format":"MMMM"}});
    assert!(
        SurfaceState::default().prepare_event(frame).is_ok(),
        "the same locale formatter must remain valid in display-only bindings"
    );
    Ok(())
}

#[test]
fn repeated_large_binding_obeys_the_expanded_tree_byte_cap() -> TestResult {
    let mut frame = frame(&SurfaceState::default());
    frame.fallback_text = Some("Repeated display".into());
    frame.a2ui = Some(MutationMessage::new(Mutation::CreateSurface(CreateSurface {
        surface_id: "surface".into(),
        catalog_id: CATALOG_ID.into(),
        send_data_model: None,
        metadata: None,
        components: Some(vec![
            json!({"id":"root","component":"List","children":{"componentId":"item","path":"/items"}}),
            json!({"id":"item","component":"Text","text":{"@path":"/large"}}),
        ]),
        data_model: Some(json!({"items":vec![json!({});16],"large":"x".repeat(4096)})),
    })));
    assert_eq!(
        SurfaceState::default().prepare_event(frame.clone()),
        Err(Reject::Limit),
        "small signed state cannot expand into more than 64 KiB of component values"
    );
    let Some(MutationMessage { mutation: Mutation::CreateSurface(create), .. }) = &mut frame.a2ui
    else {
        return Err("create".into());
    };
    create.data_model = Some(json!({"items":vec![json!({});16],"large":"x".repeat(1024)}));
    assert!(
        SurfaceState::default().prepare_event(frame).is_ok(),
        "control: bounded repetition must remain valid"
    );
    Ok(())
}

#[test]
fn date_time_owned_inputs_accept_iso_minute_precision_and_compare_offsets_as_instants() -> TestResult
{
    let base: EventFrame = serde_json::from_slice(include_bytes!(
        "../../fixtures/protocol/v1/a2ui_surface/create.event.json"
    ))?;
    for (date, time, value, min, max) in [
        (false, true, "12:30", "10:00:00Z", "14:00:00Z"),
        (true, true, "2026-06-22T12:30", "2026-06-22T12:30:00+01:00", "2026-06-22T12:30:00Z"),
        (true, true, "2026-06-22T13:30:00+01:00", "2026-06-22T12:30:00Z", "2026-06-22T12:30:00Z"),
    ] {
        let mut frame = base.clone();
        let Some(MutationMessage { mutation: Mutation::CreateSurface(create), .. }) =
            &mut frame.a2ui
        else {
            return Err("fixture create".into());
        };
        create.data_model = Some(json!({"note":value,"text":"Hello"}));
        let input = create
            .components
            .as_mut()
            .and_then(|components| {
                components
                    .iter_mut()
                    .find(|c| c.get("id").and_then(serde_json::Value::as_str) == Some("input"))
            })
            .ok_or("input")?;
        let map = input.as_object_mut().ok_or("input object")?;
        map.insert("component".into(), json!("DateTimeInput"));
        map.insert("enableDate".into(), json!(date));
        map.insert("enableTime".into(), json!(time));
        map.insert("min".into(), json!(min));
        map.insert("max".into(), json!(max));
        let state = SurfaceState::default().apply(&SurfaceEvent::from_wire_bytes(
            &SurfaceState::default().prepare_event(frame)?.wire_bytes()?,
        )?)?;
        let mut action: ActionFrame = serde_json::from_slice(include_bytes!(
            "../../fixtures/protocol/v1/a2ui_surface/submit.action.json"
        ))?;
        action.surface_hash = state.hash().ok_or("hash")?.into();
        action.a2ui.action.context.insert("note".into(), json!(value));
        action.args_hash = action.arguments_hash()?;
        assert!(
            state.validate_action(&SurfaceAction::from_wire_bytes(&action.wire_bytes()?)?).is_ok(),
            "ISO date/time witness must use deterministic bounds: {value}"
        );
        action.a2ui.action.context.insert("note".into(), json!("invalid"));
        action.args_hash = action.arguments_hash()?;
        assert!(
            state.validate_action(&SurfaceAction::from_wire_bytes(&action.wire_bytes()?)?).is_err(),
            "invalid date/time raw input must not pass the author witness check"
        );
    }
    Ok(())
}

#[test]
fn maximum_author_literal_context_allows_action_frame_overhead() -> TestResult {
    let mut snapshot = SurfaceSnapshot {
        surface_id: "s".into(),
        catalog_id: CATALOG_ID.into(),
        fallback_text: "Save".into(),
        metadata: None,
        components: vec![
            json!({"id":"root","component":"Button","child":"label","action":{"event":{"name":"submit","context":{"large":""}}}}),
            json!({"id":"label","component":"Text","text":"Save"}),
        ],
        data_model: json!({}),
        final_: Vec::new(),
        closed: false,
    };
    let overhead = crate::canonical_json_bytes(&snapshot)?.len();
    snapshot.components.first_mut().ok_or("button")?["action"]["event"]["context"]["large"] =
        json!("x".repeat(MAX_STATE_BYTES.checked_sub(overhead).ok_or("state overhead")?));
    let mut frame: EventFrame = serde_json::from_slice(include_bytes!(
        "../../fixtures/protocol/v1/a2ui_surface/create.event.json"
    ))?;
    frame.conversation_id = "c".repeat(256);
    frame.fallback_text = Some("Save".into());
    frame.a2ui = Some(MutationMessage::new(Mutation::CreateSurface(snapshot.create())));
    let state = SurfaceState::default().apply(&SurfaceEvent::from_wire_bytes(
        &SurfaceState::default().prepare_event(frame)?.wire_bytes()?,
    )?)?;
    assert_eq!(
        crate::canonical_json_bytes(state.content().ok_or("state")?)?.len(),
        MAX_STATE_BYTES,
        "control state uses the design's full canonical state budget"
    );
    let context = snapshot
        .components
        .first()
        .and_then(|c| c.pointer("/action/event/context"))
        .and_then(serde_json::Value::as_object)
        .ok_or("context")?
        .clone();
    let mut action = ActionFrame {
        schema: ACTION_SCHEMA.into(),
        conversation_id: "c".repeat(256),
        surface_version: 1,
        surface_hash: state.hash().ok_or("hash")?.into(),
        source_instance: Vec::new(),
        args_hash: String::new(),
        task_binding: None,
        a2ui: ActionMessage {
            version: "1.0".into(),
            action: Action {
                name: "submit".into(),
                surface_id: "s".into(),
                source_component_id: "root".into(),
                timestamp: "2026-11-16T00:00:00Z".into(),
                context,
                user_message: None,
                metadata: None,
            },
        },
    };
    action.args_hash = action.arguments_hash()?;
    let wire = action.wire_bytes()?;
    assert!(wire.len() > MAX_STATE_BYTES, "action framing is outside the signed state budget");
    state.validate_action(&SurfaceAction::from_wire_bytes(&wire)?)?;
    Ok(())
}
