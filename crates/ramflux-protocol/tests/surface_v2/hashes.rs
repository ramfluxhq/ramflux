// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::support::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Golden {
    name: String,
    content: SurfaceContent,
    canonical: String,
    hash: String,
}

#[test]
fn approved_jcs_goldens_include_desktop_shape_float_and_unicode_cases() -> TestResult {
    assert_eq!(SURFACE_HASH_DOMAIN, b"ramflux.surface.v1\n");
    let goldens: Vec<Golden> = serde_json::from_str(include_str!("goldens.json"))?;
    assert_eq!(goldens.len(), 3);
    for golden in goldens {
        assert_eq!(
            golden.content.canonical_bytes(),
            golden.canonical.as_bytes(),
            "{}",
            golden.name
        );
        assert_eq!(
            ramflux_protocol::canonical_json_bytes(&golden.content)?,
            golden.canonical.as_bytes()
        );
        assert_eq!(surface_hash(&golden.content), golden.hash, "{}", golden.name);
        let roundtrip: SurfaceContent = serde_json::from_slice(golden.content.canonical_bytes())?;
        assert_eq!(surface_hash(&roundtrip), golden.hash);
    }
    Ok(())
}

#[test]
fn arguments_hash_has_an_independent_domain_and_golden() -> TestResult {
    let golden: Value = serde_json::from_str(include_str!("args-golden.json"))?;
    assert_eq!(SURFACE_ARGS_HASH_DOMAIN, b"ramflux.surface.args.v1\n");
    assert_eq!(surface_args_hash(&golden["values"])?, golden["hash"]);
    assert_eq!(
        String::from_utf8(ramflux_protocol::canonical_json_bytes(&golden["values"])?)?,
        golden["canonical"]
    );
    assert_eq!(
        surface_args_hash(&json!({"b":1.0,"a":2}))?,
        surface_args_hash(&json!({"a":2,"b":1}))?
    );
    Ok(())
}

#[test]
fn every_reviewed_field_is_bound_while_version_and_lifecycle_are_separate() -> TestResult {
    let base = content(vec![block("b", "text")], vec![definition("go")])?;
    let hash = surface_hash(&base);
    let original = serde_json::to_value(&base)?;
    for (pointer, replacement) in [
        ("/surface_id", json!("other")),
        ("/fallback_text", json!("other fallback")),
        ("/blocks/0/data/text", json!("changed")),
        ("/blocks/0/id", json!("other")),
        ("/blocks/0/kind", json!("Markdown")),
        ("/blocks/0/redacted", json!(true)),
        ("/actions/0/id", json!("other")),
        ("/actions/0/label", json!("Delete")),
        ("/actions/0/risk", json!("Low")),
        ("/actions/0/disabled_reason", json!("No")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).ok_or("missing golden field")? = replacement;
        let changed: SurfaceContent = serde_json::from_value(changed)?;
        assert_ne!(surface_hash(&changed), hash, "{pointer}");
    }
    let state = state()?;
    let next = state.apply(&patch(&state, Vec::new())?)?;
    assert_eq!(state.hash(), next.hash());
    assert_ne!(state.version(), next.version());
    let closed = next.apply(&SurfaceEvent::Close { surface_id: "s".to_owned(), version: 3 })?;
    assert_eq!(next.hash(), closed.hash());
    assert!(closed.is_closed());
    assert_eq!(serde_json::to_value(&base)?.as_object().map(serde_json::Map::len), Some(4));
    Ok(())
}
