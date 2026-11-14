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
    f.metadata = Some(Metadata { extensions: Default::default() });
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
            let mut frame = base.clone();
            let Some(MutationMessage { mutation: Mutation::CreateSurface(create), .. }) =
                &mut frame.a2ui
            else {
                return Err("fixture must create a surface".into());
            };
            let components = create.components.as_mut().ok_or("fixture components")?;
            let button = components
                .iter_mut()
                .find(|c| c.get("id").and_then(serde_json::Value::as_str) == Some("button"))
                .ok_or("fixture button")?;
            button["@checks"] = json!([{"condition":{"@call":"length","args":{"value":{"@call":function,"args":args},"min":5}}}]);
            assert_eq!(
                SurfaceState::default().prepare_event(frame),
                Err(Reject::LocaleDependentCheck),
                "{locale}: {function} must never gate an action through host locale"
            );
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
