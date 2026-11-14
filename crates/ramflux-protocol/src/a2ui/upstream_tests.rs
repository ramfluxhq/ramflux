// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable upstream validity expectations, before rf-card profile restrictions.
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const PREFIX: &str = "https://a2ui.org/specification/v1_0/";
fn load(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    assert!(bytes.len() <= 1024 * 1024, "vendored schema/case resource must remain bounded");
    Ok(serde_json::from_slice(&bytes)?)
}
fn validator(
    root: &Path,
    catalog: &str,
    name: &str,
) -> Result<jsonschema::Validator, Box<dyn std::error::Error>> {
    let mut resources = BTreeMap::new();
    for entry in std::fs::read_dir(root.join("specification/v1_0/json"))? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let value = load(&path)?;
            let id = value.get("$id").and_then(Value::as_str).ok_or("schema id")?;
            resources.insert(id.to_owned(), value);
        }
    }
    let mut catalog = load(&root.join(catalog))?;
    catalog
        .as_object_mut()
        .ok_or("catalog object")?
        .insert("$id".into(), Value::String(format!("{PREFIX}catalog.json")));
    resources.insert(format!("{PREFIX}catalog.json"), catalog);
    let schema = resources.get(&format!("{PREFIX}{name}")).ok_or("target schema")?.clone();
    let mut options = jsonschema::options().should_validate_formats(true);
    for (id, resource) in resources {
        options = options.with_resource(id, jsonschema::Resource::from_contents(resource));
    }
    Ok(options.build(&schema)?)
}
#[test]
fn all_pinned_upstream_cases_preserve_upstream_validity() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/a2ui");
    let mut cases = std::fs::read_dir(root.join("specification/v1_0/test/cases"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    cases.sort();
    let mut count = 0;
    for path in cases {
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let suite = load(&path)?;
        let name = suite.get("schema").and_then(Value::as_str).unwrap_or("agent_to_renderer.json");
        let catalog =
            if suite.get("catalog").and_then(Value::as_str) == Some("testing_catalog.json") {
                "specification/v1_0/test/testing_catalog.json"
            } else {
                "catalogs/basic/v1/catalog.json"
            };
        let validator = validator(&root, catalog, name)?;
        for test in suite.get("tests").and_then(Value::as_array).ok_or("suite tests")? {
            let data = test.get("data").ok_or("case data")?;
            let expected = test.get("valid").and_then(Value::as_bool).unwrap_or(true);
            assert_eq!(
                validator.is_valid(data),
                expected,
                "{}: {}: {:?}",
                path.display(),
                test.get("description").unwrap_or(&Value::Null),
                validator.iter_errors(data).map(|e| e.to_string()).collect::<Vec<_>>()
            );
            count += 1;
        }
    }
    assert_eq!(count, 178, "every pinned upstream JSON case must run");
    Ok(())
}

#[test]
fn rf_card_catalog_is_upstream_catalog_schema_valid_and_explicit_overrides_fail_closed()
-> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/a2ui");
    let catalog: Value = serde_json::from_str(include_str!("../../catalogs/rf-card-v1.json"))?;
    let definition = validator(&root, "catalogs/basic/v1/catalog.json", "catalog_definition.json")?;
    assert!(
        definition.is_valid(&catalog),
        "rf-card must use the upstream catalog definition: {:?}",
        definition.iter_errors(&catalog).map(|e| e.to_string()).collect::<Vec<_>>()
    );
    for function in catalog.get("functions").and_then(Value::as_object).ok_or("functions")?.values()
    {
        assert_eq!(
            function.get("allowedCallers"),
            Some(&Value::String("rendererOnly".into())),
            "every rf-card function must be renderer-only"
        );
    }
    let overrides: Value = serde_json::from_str(include_str!(
        "../../fixtures/protocol/v1/a2ui_surface/profile-overrides.json"
    ))?;
    let cases = overrides.as_array().ok_or("profile overrides")?;
    assert_eq!(cases.len(), 3, "all pinned no-root overrides must remain explicit");
    for row in cases {
        let suite = load(
            &root
                .join("specification/v1_0/test/cases")
                .join(row.get("suite").and_then(Value::as_str).ok_or("suite")?),
        )?;
        let case = suite
            .get("tests")
            .and_then(Value::as_array)
            .and_then(|cases| {
                row.get("index")
                    .and_then(Value::as_u64)
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| cases.get(index))
            })
            .ok_or("case")?;
        assert_eq!(
            case.get("description"),
            row.get("description"),
            "overrides must stay anchored to immutable upstream cases"
        );
        assert_eq!(
            case.get("valid"),
            row.get("upstreamValid"),
            "upstream validity must not be rewritten"
        );
        let create = case.get("data").and_then(|v| v.get("createSurface")).ok_or("create")?;
        let mut create = create.clone();
        create
            .as_object_mut()
            .ok_or("create object")?
            .insert("catalogId".into(), Value::String(super::CATALOG_ID.into()));
        let create: super::CreateSurface = serde_json::from_value(create)?;
        let frame = super::EventFrame {
            schema: super::EVENT_SCHEMA.into(),
            conversation_id: "conversation".into(),
            surface_version: 1,
            base_surface_hash: None,
            new_surface_hash: String::new(),
            fallback_text: Some("Profile case".into()),
            close_reason: None,
            a2ui: Some(super::MutationMessage::new(super::Mutation::CreateSurface(create))),
            append_text: None,
            resync: None,
            final_: None,
            closed: None,
            metadata: None,
        };
        assert_eq!(
            super::SurfaceState::default().prepare_event(frame).is_ok(),
            row.get("profileAccepted").and_then(Value::as_bool).ok_or("profile expectation")?,
            "profile overrides must exercise real card admission"
        );
    }
    Ok(())
}
