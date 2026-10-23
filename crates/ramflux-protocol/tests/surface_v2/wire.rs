// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::support::*;

#[test]
fn versioned_events_actions_and_content_round_trip_strictly() -> TestResult {
    let base = state()?;
    let events = [
        create(),
        patch(
            &base,
            vec![
                SurfacePatchOp::ReplaceBlock { block: block("b", "new") },
                SurfacePatchOp::InsertBlock { index: 0, block: block("new", "") },
                SurfacePatchOp::RemoveBlock { block_id: "new".to_owned() },
                SurfacePatchOp::SetActions { actions: vec![definition("go")] },
            ],
        )?,
        append(2, "delta", true),
        SurfaceEvent::Close { surface_id: "s".to_owned(), version: 2 },
    ];
    for (event, schema) in events.into_iter().zip([
        SURFACE_CREATE_SCHEMA,
        SURFACE_PATCH_SCHEMA,
        SURFACE_STREAM_APPEND_SCHEMA,
        SURFACE_CLOSE_SCHEMA,
    ]) {
        let wire = serde_json::to_value(&event)?;
        assert_eq!(wire["schema"], schema);
        assert_eq!(serde_json::from_value::<SurfaceEvent>(wire.clone())?, event);
        let mut unknown = wire.clone();
        unknown["executable"] = json!("code");
        assert!(serde_json::from_value::<SurfaceEvent>(unknown).is_err());
        let mut unknown = wire;
        unknown["schema"] = json!("ramflux.surface.future.v2");
        assert!(serde_json::from_value::<SurfaceEvent>(unknown).is_err());
    }
    let event = serde_json::to_value(append(2, "", true))?;
    assert_eq!(event["final"], true);
    assert!(event.get("final_").is_none());
    let action = action(&base)?;
    let mut wire = serde_json::to_value(&action)?;
    assert_eq!(wire["schema"], SURFACE_ACTION_SCHEMA);
    assert_eq!(serde_json::from_value::<SurfaceAction>(wire.clone())?, action);
    wire["extra"] = json!(1);
    assert!(serde_json::from_value::<SurfaceAction>(wire).is_err());
    let content = base.content().ok_or("content")?;
    assert_eq!(serde_json::from_slice::<SurfaceContent>(&serde_json::to_vec(content)?)?, *content);
    Ok(())
}

#[test]
fn missing_fallback_unknown_fields_kinds_ops_and_action_versions_reject() -> TestResult {
    let original = serde_json::to_value(create())?;
    let mut missing = original.clone();
    missing.as_object_mut().ok_or("object")?.remove("fallback_text");
    assert!(serde_json::from_value::<SurfaceEvent>(missing).is_err());
    for pointer in ["/blocks/0", "/actions/0"] {
        let mut value = original.clone();
        value.pointer_mut(pointer).ok_or("field")?["unknown"] = json!(1);
        assert!(serde_json::from_value::<SurfaceEvent>(value).is_err());
    }
    let mut value = original;
    value["blocks"][0]["kind"] = json!("ExecuteScript");
    assert!(serde_json::from_value::<SurfaceEvent>(value).is_err());
    assert!(
        serde_json::from_value::<SurfacePatchOp>(json!({"op":"execute","code":"anything"}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<SurfacePatchOp>(
            json!({"op":"remove_block","block_id":"b","extra":true})
        )
        .is_err()
    );
    let base = state()?;
    let mut value = serde_json::to_value(action(&base)?)?;
    value["schema"] = json!("ramflux.surface.action.v2");
    assert!(serde_json::from_value::<SurfaceAction>(value).is_err());
    let mut value = serde_json::to_value(base.content().ok_or("content")?)?;
    value["streaming"] = json!(true);
    assert!(serde_json::from_value::<SurfaceContent>(value).is_err());
    let mut value = serde_json::to_value(base.content().ok_or("content")?)?;
    value["blocks"][0]["version"] = json!(2);
    assert!(serde_json::from_value::<SurfaceContent>(value).is_err());
    Ok(())
}

#[test]
fn typed_rejects_are_wire_round_trippable_and_payload_free() -> TestResult {
    for reject in [
        SurfaceReject::NotCreated,
        SurfaceReject::AlreadyCreated,
        SurfaceReject::Closed,
        SurfaceReject::WrongSurface,
        SurfaceReject::Version { expected: 2, actual: 1 },
        SurfaceReject::VersionExhausted,
        SurfaceReject::Conflict,
        SurfaceReject::Stale,
        SurfaceReject::InvalidIdentifier,
        SurfaceReject::MissingFallback,
        SurfaceReject::DuplicateBlock,
        SurfaceReject::DuplicateAction,
        SurfaceReject::UnsupportedBlockVersion,
        SurfaceReject::UnknownBlock,
        SurfaceReject::UnknownAction,
        SurfaceReject::DisabledAction,
        SurfaceReject::BlockClosed,
        SurfaceReject::BlockNotStreamable,
        SurfaceReject::InvalidInsertPosition,
        SurfaceReject::ArgumentsHashMismatch,
        SurfaceReject::Encoding,
        SurfaceReject::LimitExceeded { limit: SurfaceLimit::Blocks },
    ] {
        assert_eq!(serde_json::from_slice::<SurfaceReject>(&serde_json::to_vec(&reject)?)?, reject);
    }
    Ok(())
}

#[test]
fn debug_omits_redacted_block_bytes_canonical_cache_and_decision_values() -> TestResult {
    let redacted = SurfaceBlock { redacted: true, ..block("b", "private-block-value") };
    let content = content(vec![redacted], Vec::new())?;
    let debug = format!("{content:?}");
    assert!(!debug.contains("private-block-value"));
    assert!(!debug.contains("canonical"));
    let mut action = action(&state()?)?;
    action.values = json!({"password":"private-decision-value"});
    assert!(!format!("{action:?}").contains("private-decision-value"));
    // Redaction affects diagnostics, not the reviewed/hash-bound wire content.
    assert!(serde_json::to_string(&content)?.contains("private-block-value"));
    Ok(())
}
