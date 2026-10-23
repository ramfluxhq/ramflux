// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::support::*;

#[test]
fn lifecycle_version_and_surface_identity_rejections_are_explicit() -> TestResult {
    let empty = SurfaceState::default();
    assert_eq!(empty.apply(&append(1, "x", false)), Err(SurfaceReject::NotCreated));
    assert_eq!(empty.validate_action(&action(&state()?)?), Err(SurfaceReject::NotCreated));
    let mut invalid = create();
    if let SurfaceEvent::Create { version, .. } = &mut invalid {
        *version = 0;
    }
    assert_eq!(empty.apply(&invalid), Err(SurfaceReject::Version { expected: 1, actual: 0 }));
    let base = state()?;
    assert_eq!(base.apply(&create()), Err(SurfaceReject::AlreadyCreated));
    assert_eq!(
        base.apply(&append(1, "x", false)),
        Err(SurfaceReject::Version { expected: 2, actual: 1 })
    );
    assert_eq!(
        base.apply(&append(3, "x", false)),
        Err(SurfaceReject::Version { expected: 2, actual: 3 })
    );
    assert_eq!(
        base.apply(&SurfaceEvent::Close { surface_id: "wrong".to_owned(), version: 2 }),
        Err(SurfaceReject::WrongSurface)
    );
    let closed = base.apply(&SurfaceEvent::Close { surface_id: "s".to_owned(), version: 2 })?;
    for event in [
        create(),
        append(3, "x", false),
        patch(&closed, Vec::new())?,
        SurfaceEvent::Close { surface_id: "s".to_owned(), version: 3 },
    ] {
        assert_eq!(closed.apply(&event), Err(SurfaceReject::Closed));
    }
    assert_eq!(closed.validate_action(&action(&closed)?), Err(SurfaceReject::Closed));
    Ok(())
}

#[test]
fn all_patch_operations_are_atomic_and_conflicting_bases_reject() -> TestResult {
    let base = state()?;
    let event = patch(
        &base,
        vec![
            SurfacePatchOp::ReplaceBlock { block: block("b", "replaced") },
            SurfacePatchOp::InsertBlock { index: 0, block: block("new", "inserted") },
            SurfacePatchOp::RemoveBlock { block_id: "b".to_owned() },
            SurfacePatchOp::SetActions { actions: vec![definition("new-action")] },
        ],
    )?;
    let result = base.apply(&event)?;
    let current = result.content().ok_or("missing content")?;
    assert_eq!(current.blocks()[0].id, "new");
    assert_eq!(current.actions()[0].id, "new-action");
    assert_eq!(result.version(), 2);
    assert_ne!(result.hash(), base.hash());
    let mut bad = patch(&base, Vec::new())?;
    if let SurfaceEvent::Patch { base_hash, .. } = &mut bad {
        *base_hash = "sha256:wrong".to_owned();
    }
    assert_eq!(base.apply(&bad), Err(SurfaceReject::Conflict));
    for (op, expected) in [
        (SurfacePatchOp::ReplaceBlock { block: block("missing", "") }, SurfaceReject::UnknownBlock),
        (
            SurfacePatchOp::RemoveBlock { block_id: "missing".to_owned() },
            SurfaceReject::UnknownBlock,
        ),
        (
            SurfacePatchOp::InsertBlock { index: 9, block: block("new", "") },
            SurfaceReject::InvalidInsertPosition,
        ),
        (
            SurfacePatchOp::InsertBlock { index: 0, block: block("b", "") },
            SurfaceReject::DuplicateBlock,
        ),
    ] {
        let before = base.clone();
        let event = patch(
            &base,
            vec![SurfacePatchOp::ReplaceBlock { block: block("b", "must roll back") }, op],
        )?;
        assert_eq!(base.apply(&event), Err(expected));
        assert_eq!(base, before);
    }
    Ok(())
}

#[test]
fn stream_finality_survives_patch_replacement_and_reinsertion() -> TestResult {
    let base = state()?;
    let event = append(2, " world", false);
    let streamed = base.apply(&event)?;
    assert_eq!(streamed.content().ok_or("content")?.blocks()[0].data["text"], "hello world");
    assert!(matches!(streamed.apply(&event), Err(SurfaceReject::Version { .. })));
    let finished = streamed.apply(&append(3, "!", true))?;
    assert_eq!(finished.apply(&append(4, "no", false)), Err(SurfaceReject::BlockClosed));
    let replaced = finished.apply(&patch(
        &finished,
        vec![SurfacePatchOp::ReplaceBlock { block: block("b", "replacement") }],
    )?)?;
    assert_eq!(replaced.apply(&append(5, "no", false)), Err(SurfaceReject::BlockClosed));
    let removed = replaced.apply(&patch(
        &replaced,
        vec![SurfacePatchOp::RemoveBlock { block_id: "b".to_owned() }],
    )?)?;
    let reinserted = removed.apply(&patch(
        &removed,
        vec![SurfacePatchOp::InsertBlock { index: 0, block: block("b", "new") }],
    )?)?;
    assert_eq!(reinserted.apply(&append(7, "no", false)), Err(SurfaceReject::BlockClosed));
    let mut missing = append(2, "x", false);
    if let SurfaceEvent::StreamAppend { block_id, .. } = &mut missing {
        *block_id = "missing".to_owned();
    }
    assert_eq!(base.apply(&missing), Err(SurfaceReject::UnknownBlock));
    for block in [
        SurfaceBlock { kind: SurfaceBlockKind::Progress, ..block("b", "") },
        SurfaceBlock { data: json!({}), ..block("b", "") },
    ] {
        let nontext = base.apply(&patch(&base, vec![SurfacePatchOp::ReplaceBlock { block }])?)?;
        assert_eq!(nontext.apply(&append(3, "x", false)), Err(SurfaceReject::BlockNotStreamable));
    }
    Ok(())
}

#[test]
fn decisions_bind_current_version_content_action_and_arguments() -> TestResult {
    let base = state()?;
    let correct = action(&base)?;
    base.validate_action(&correct)?;
    for (change, expected) in [
        ("version", SurfaceReject::Stale),
        ("hash", SurfaceReject::Stale),
        ("surface", SurfaceReject::WrongSurface),
        ("action", SurfaceReject::UnknownAction),
        ("args", SurfaceReject::ArgumentsHashMismatch),
    ] {
        let mut changed = correct.clone();
        match change {
            "version" => changed.version = 0,
            "hash" => changed.surface_hash = "other".to_owned(),
            "surface" => changed.surface_id = "other".to_owned(),
            "action" => changed.action_id = "other".to_owned(),
            _ => changed.values = json!({"choice":"tampered"}),
        }
        assert_eq!(base.validate_action(&changed), Err(expected));
    }
    let updated = base.apply(&append(2, "x", false))?;
    assert_eq!(updated.validate_action(&correct), Err(SurfaceReject::Stale));
    let mut disabled = definition("go");
    disabled.disabled_reason = Some("disabled".to_owned());
    let disabled =
        base.apply(&patch(&base, vec![SurfacePatchOp::SetActions { actions: vec![disabled] }])?)?;
    assert_eq!(disabled.validate_action(&action(&disabled)?), Err(SurfaceReject::DisabledAction));
    let mut oversized = correct;
    oversized.values = json!("x".repeat(MAX_SURFACE_TEXT_CHARS + 1));
    assert_eq!(
        base.validate_action(&oversized),
        Err(SurfaceReject::LimitExceeded { limit: SurfaceLimit::TextCharacters })
    );
    Ok(())
}

#[test]
fn generated_patch_chains_round_trip_with_consistent_hashes() -> TestResult {
    for seed in 0_u64..32 {
        let mut random = seed;
        let mut direct = state()?;
        let mut decoded = direct.clone();
        for step in 0..32 {
            random = random.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let blocks = direct.content().ok_or("content")?.blocks();
            let op = match random % 4 {
                0 => SurfacePatchOp::ReplaceBlock {
                    block: block("b", &format!("seed={seed} step={step}")),
                },
                1 => SurfacePatchOp::InsertBlock {
                    index: blocks.len(),
                    block: block(&format!("b-{step}"), "added"),
                },
                2 if blocks.len() > 1 => {
                    SurfacePatchOp::RemoveBlock { block_id: blocks[1].id.clone() }
                }
                _ => {
                    SurfacePatchOp::SetActions { actions: vec![definition(&format!("go-{step}"))] }
                }
            };
            let event = patch(&direct, vec![op])?;
            let wire = ramflux_protocol::canonical_json_bytes(&event)?;
            let roundtrip: SurfaceEvent = serde_json::from_slice(&wire)?;
            direct = direct.apply(&event)?;
            decoded = decoded.apply(&roundtrip)?;
            assert_eq!(direct, decoded);
            assert_eq!(direct.hash(), decoded.hash());
            let content = direct.content().ok_or("content")?;
            let copy: SurfaceContent = serde_json::from_slice(content.canonical_bytes())?;
            assert_eq!(surface_hash(content), surface_hash(&copy));
        }
    }
    Ok(())
}
