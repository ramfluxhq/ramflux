// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::support::*;

fn reject(limit: SurfaceLimit) -> SurfaceReject {
    SurfaceReject::LimitExceeded { limit }
}

#[test]
fn block_and_action_counts_accept_exact_bounds_and_reject_excess() -> TestResult {
    let blocks: Vec<_> = (0..MAX_SURFACE_BLOCKS).map(|i| block(&format!("b-{i}"), "")).collect();
    let actions: Vec<_> = (0..MAX_SURFACE_ACTIONS).map(|i| definition(&format!("a-{i}"))).collect();
    content(blocks.clone(), actions.clone())?;
    let mut excess = blocks.clone();
    excess.push(block("extra", ""));
    assert_eq!(content(excess, Vec::new()), Err(reject(SurfaceLimit::Blocks)));
    let mut excess = actions;
    excess.push(definition("extra"));
    assert_eq!(content(Vec::new(), excess), Err(reject(SurfaceLimit::Actions)));
    let full = SurfaceState::default().apply(&SurfaceEvent::Create {
        surface_id: "s".to_owned(),
        version: 1,
        blocks,
        actions: Vec::new(),
        fallback_text: "fallback".to_owned(),
    })?;
    assert_eq!(
        full.apply(&patch(
            &full,
            vec![SurfacePatchOp::InsertBlock { index: 0, block: block("extra", "") }]
        )?),
        Err(reject(SurfaceLimit::Blocks))
    );
    let base = state()?;
    let too_many =
        vec![SurfacePatchOp::SetActions { actions: Vec::new() }; MAX_SURFACE_PATCH_OPS + 1];
    assert_eq!(base.apply(&patch(&base, too_many)?), Err(reject(SurfaceLimit::PatchOperations)));
    Ok(())
}

#[test]
fn text_limits_count_unicode_scalars_in_all_content_strings() -> TestResult {
    content(vec![block("b", &"é".repeat(MAX_SURFACE_TEXT_CHARS))], Vec::new())?;
    let long = "é".repeat(MAX_SURFACE_TEXT_CHARS + 1);
    for bad in [
        SurfaceBlock { data: json!({"nested":[long.clone()]}), ..block("b", "") },
        SurfaceBlock { id: long.clone(), ..block("b", "") },
        SurfaceBlock { data: json!({long.clone():"value"}), ..block("b", "") },
    ] {
        assert_eq!(content(vec![bad], Vec::new()), Err(reject(SurfaceLimit::TextCharacters)));
    }
    for action in [
        SurfaceActionDefinition { label: long.clone(), ..definition("go") },
        SurfaceActionDefinition { disabled_reason: Some(long.clone()), ..definition("go") },
    ] {
        assert_eq!(content(Vec::new(), vec![action]), Err(reject(SurfaceLimit::TextCharacters)));
    }
    assert_eq!(
        SurfaceContent::new("s".to_owned(), long, Vec::new(), Vec::new()),
        Err(reject(SurfaceLimit::TextCharacters))
    );
    Ok(())
}

fn data_with_encoded_length(bytes: usize) -> Value {
    // Four quoted strings: 8 quote bytes + 3 commas + 2 brackets.
    json!([
        "a".repeat(MAX_SURFACE_TEXT_CHARS),
        "a".repeat(MAX_SURFACE_TEXT_CHARS),
        "a".repeat(MAX_SURFACE_TEXT_CHARS),
        "a".repeat(bytes - 3 * MAX_SURFACE_TEXT_CHARS - 13)
    ])
}

#[test]
fn canonical_data_budget_is_aggregate_and_checked_after_stream_and_patch() -> TestResult {
    let exact = data_with_encoded_length(MAX_SURFACE_DATA_BYTES);
    assert_eq!(ramflux_protocol::canonical_json_bytes(&exact)?.len(), MAX_SURFACE_DATA_BYTES);
    content(vec![SurfaceBlock { data: exact, ..block("b", "") }], Vec::new())?;
    assert_eq!(
        content(
            vec![SurfaceBlock {
                data: data_with_encoded_length(MAX_SURFACE_DATA_BYTES + 1),
                ..block("b", "")
            }],
            Vec::new()
        ),
        Err(reject(SurfaceLimit::DataBytes))
    );
    let stream = block("b", "");
    let remaining =
        MAX_SURFACE_DATA_BYTES - ramflux_protocol::canonical_json_bytes(&stream.data)?.len();
    let padding = SurfaceBlock {
        id: "padding".to_owned(),
        kind: SurfaceBlockKind::Fallback,
        data: data_with_encoded_length(remaining),
        ..block("padding", "")
    };
    let base = SurfaceState::default().apply(&SurfaceEvent::Create {
        surface_id: "s".to_owned(),
        version: 1,
        blocks: vec![stream, padding],
        actions: Vec::new(),
        fallback_text: "fallback".to_owned(),
    })?;
    assert_eq!(base.apply(&append(2, "x", false)), Err(reject(SurfaceLimit::DataBytes)));
    assert_eq!(
        base.apply(&patch(
            &base,
            vec![SurfacePatchOp::ReplaceBlock { block: block("b", "more bytes") }]
        )?),
        Err(reject(SurfaceLimit::DataBytes))
    );
    assert_eq!(
        surface_args_hash(&data_with_encoded_length(MAX_SURFACE_DATA_BYTES + 1)),
        Err(reject(SurfaceLimit::DataBytes))
    );
    Ok(())
}

#[test]
fn stream_delta_is_bytes_and_accumulated_text_is_characters() -> TestResult {
    let base = state()?;
    let exact = "🦀".repeat(MAX_SURFACE_TEXT_DELTA_BYTES / 4);
    base.apply(&append(2, &exact, false))?;
    assert_eq!(
        base.apply(&append(2, &format!("{exact}x"), false)),
        Err(reject(SurfaceLimit::TextDeltaBytes))
    );
    let mut current =
        base.apply(&patch(&base, vec![SurfacePatchOp::ReplaceBlock { block: block("b", "") }])?)?;
    for _ in 0..4 {
        current = current.apply(&append(
            current.version() + 1,
            &"a".repeat(MAX_SURFACE_TEXT_DELTA_BYTES),
            false,
        ))?;
    }
    assert_eq!(
        current.content().ok_or("content")?.blocks()[0].data["text"]
            .as_str()
            .map(|text| text.chars().count()),
        Some(MAX_SURFACE_TEXT_CHARS)
    );
    assert_eq!(
        current.apply(&append(current.version() + 1, "x", true)),
        Err(reject(SurfaceLimit::TextCharacters))
    );
    let final_state = current.apply(&append(current.version() + 1, "", true))?;
    assert_eq!(
        final_state.apply(&append(final_state.version() + 1, "", false)),
        Err(SurfaceReject::BlockClosed)
    );
    Ok(())
}

#[test]
fn invalid_content_and_excessive_nesting_reject_before_hashing() -> TestResult {
    assert_eq!(
        SurfaceContent::new(String::new(), "fallback".to_owned(), Vec::new(), Vec::new()),
        Err(SurfaceReject::InvalidIdentifier)
    );
    assert_eq!(
        SurfaceContent::new("s".to_owned(), " \n ".to_owned(), Vec::new(), Vec::new()),
        Err(SurfaceReject::MissingFallback)
    );
    assert_eq!(content(vec![block("", "")], Vec::new()), Err(SurfaceReject::InvalidIdentifier));
    assert_eq!(content(Vec::new(), vec![definition("")]), Err(SurfaceReject::InvalidIdentifier));
    assert_eq!(
        content(vec![block("b", ""), block("b", "")], Vec::new()),
        Err(SurfaceReject::DuplicateBlock)
    );
    assert_eq!(
        content(Vec::new(), vec![definition("go"), definition("go")]),
        Err(SurfaceReject::DuplicateAction)
    );
    assert_eq!(
        content(vec![SurfaceBlock { version: 2, ..block("b", "") }], Vec::new()),
        Err(SurfaceReject::UnsupportedBlockVersion)
    );
    let mut nested = Value::Null;
    for _ in 0..MAX_SURFACE_DATA_DEPTH {
        nested = json!([nested]);
    }
    content(vec![SurfaceBlock { data: nested.clone(), ..block("b", "") }], Vec::new())?;
    assert_eq!(
        content(vec![SurfaceBlock { data: json!([nested]), ..block("b", "") }], Vec::new()),
        Err(reject(SurfaceLimit::NestingDepth))
    );
    Ok(())
}

#[test]
fn stream_finality_tombstones_and_patch_action_batches_stay_bounded() -> TestResult {
    let base = state()?;
    let actions = (0..=MAX_SURFACE_ACTIONS).map(|i| definition(&format!("a-{i}"))).collect();
    assert_eq!(
        base.apply(&patch(&base, vec![SurfacePatchOp::SetActions { actions }])?),
        Err(reject(SurfaceLimit::Actions))
    );
    let mut current = base;
    for index in 0..MAX_SURFACE_BLOCKS {
        let id = format!("block-{index}");
        let blocks = current.content().ok_or("content")?.blocks();
        current = current.apply(&patch(
            &current,
            vec![
                SurfacePatchOp::RemoveBlock { block_id: blocks[0].id.clone() },
                SurfacePatchOp::InsertBlock { index: 0, block: block(&id, "") },
            ],
        )?)?;
        current = current.apply(&SurfaceEvent::StreamAppend {
            surface_id: "s".to_owned(),
            version: current.version() + 1,
            block_id: id,
            text_delta: String::new(),
            final_: true,
        })?;
    }
    let old = current.content().ok_or("content")?.blocks()[0].id.clone();
    current = current.apply(&patch(
        &current,
        vec![
            SurfacePatchOp::RemoveBlock { block_id: old },
            SurfacePatchOp::InsertBlock { index: 0, block: block("b", "") },
        ],
    )?)?;
    assert_eq!(
        current.apply(&append(current.version() + 1, "", true)),
        Err(reject(SurfaceLimit::FinalizedBlocks))
    );
    assert_eq!(
        surface_args_hash(&Value::Array(vec![Value::Null; MAX_SURFACE_DATA_BYTES + 1])),
        Err(reject(SurfaceLimit::DataBytes))
    );
    Ok(())
}
