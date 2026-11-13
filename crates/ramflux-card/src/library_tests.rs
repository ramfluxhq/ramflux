// SPDX-License-Identifier: BSD-3-Clause
use crate::{
    CardError, CardRuntime, CardSession, CardSpec, Component, Event, EventKind, EventResult,
    EventToken, Mutation, MutationBatch, Scalar, Theme,
    runtime::tests::{guard, library, package},
};
use serde_json::Value;
struct Fixture {
    name: &'static str,
    input: &'static [u8],
    updated: &'static [u8],
    tree: &'static str,
    mount: &'static str,
    edit: &'static str,
}
macro_rules! fixture {
    ($name:literal) => {
        Fixture {
            name: $name,
            input: include_bytes!(concat!("../fixtures/", $name, ".json")),
            updated: include_bytes!(concat!("../fixtures/", $name, ".updated.json")),
            tree: include_str!(concat!("../fixtures/", $name, ".tree.json")),
            mount: include_str!(concat!("../fixtures/", $name, ".mount.json")),
            edit: include_str!(concat!("../fixtures/", $name, ".edit.json")),
        }
    };
}
const FIXTURES: [Fixture; 4] =
    [fixture!("complete_form"), fixture!("task"), fixture!("chart"), fixture!("approval")];
fn snapshot(batch: MutationBatch) -> Value {
    let mut batch = batch;
    for mutation in &mut batch.mutations {
        if let Mutation::Upsert { node, .. } = mutation {
            node.attrs.style = None;
        }
    }
    serde_json::to_value(batch).expect("test: semantic batch serialization")
}
fn expected(input: &str) -> Value {
    serde_json::from_str(input).expect("test: bounded independent snapshot")
}
fn event(session: &CardSession, key: &str, event: EventKind) -> Event {
    Event {
        token: EventToken { session: session.id(), version: session.version(), key: key.into() },
        event,
    }
}
#[test]
fn every_component_matches_tree_mount_mutation_theme_and_stale_snapshots() {
    let _guard = guard();
    let package = library();
    for fixture in &FIXTURES {
        let spec = CardSpec::parse(fixture.input).expect("test: component fixture");
        let (mut session, mount) =
            CardSession::open(spec, package.clone()).expect("test: real component renderer");
        assert_eq!(
            serde_json::to_value(session.tree().expect("test: tree").without_style())
                .expect("test: tree value"),
            expected(fixture.tree),
            "{} semantic tree",
            fixture.name
        );
        assert_eq!(snapshot(mount), expected(fixture.mount), "{} complete mount", fixture.name);
        let stale = event(&session, "old-control", EventKind::Submit);
        let updated = CardSpec::parse(fixture.updated).expect("test: update fixture");
        let edit = session.update(updated.clone()).expect("test: component update");
        assert_eq!(snapshot(edit), expected(fixture.edit), "{} exact mutations", fixture.name);
        session.enqueue(stale).expect("test: old event queue");
        assert!(
            matches!(
                session.next_event().expect("test: old token check"),
                Some(EventResult::StaleDropped)
            ),
            "{} cannot reuse old shown version",
            fixture.name
        );
        let old = session.tree().expect("test: light tree").clone();
        let mut dark = updated;
        dark.theme = Theme::Dark;
        let themed = session.update(dark).expect("test: host-selected dark theme");
        assert!(!themed.mutations.is_empty(), "{} consumes generated theme tokens", fixture.name);
        assert_eq!(
            session.tree().expect("test: dark tree").without_style(),
            old.without_style(),
            "themes cannot change business semantics"
        );
    }
}
#[test]
fn every_component_rejects_its_expansion_bound_loop_and_recursion() {
    let _guard = guard();
    for fixture in &FIXTURES {
        let mut spec = CardSpec::parse(fixture.input).expect("test: fixture");
        match spec.components.first_mut().expect("test: component") {
            Component::Form(form) => {
                form.fields = vec![form.fields.first().expect("test: field").clone(); 17];
            }
            Component::Task(task) => {
                task.steps = vec![task.steps.first().expect("test: step").clone(); 17];
            }
            Component::Chart(chart) => {
                let series = chart.series.first_mut().expect("test: series");
                series.points = vec![series.points.first().expect("test: point").clone(); 17];
            }
            Component::Approval(approval) => approval.explanation = "x".repeat(1025),
        }
        assert!(spec.validate().is_err(), "{} expansion rejected before VM", fixture.name);
        let spec = CardSpec::parse(fixture.input).expect("test: valid component");
        for (source, limit) in [
            ("export function render(){while(true){}}", "budget"),
            ("export function render(){function f(){return 1+f()}f()}", "stack"),
        ] {
            let mut vm = CardRuntime::new(&package(source), spec.clone())
                .expect("test: hostile signed renderer");
            let result = vm.render(&spec);
            assert!(
                matches!(
                    (limit, result),
                    ("budget", Err(CardError::Budget)) | ("stack", Err(CardError::Stack))
                ),
                "{} must hit {limit}",
                fixture.name
            );
        }
    }
}
fn send(
    session: &mut CardSession,
    key: &str,
    kind: EventKind,
) -> Result<Option<EventResult>, CardError> {
    session.enqueue(event(session, key, kind))?;
    session.next_event()
}
#[test]
fn complete_form_enforces_types_required_errors_disabled_and_owned_submit() {
    let _guard = guard();
    let spec = CardSpec::parse(FIXTURES.first().expect("test: form fixture").input)
        .expect("test: complete form");
    let (mut session, _) = CardSession::open(spec.clone(), library()).expect("test: form open");
    assert!(
        send(&mut session, "profile:age", EventKind::Number { value: 17 }).is_err(),
        "number minimum is enforced in Rust"
    );
    assert!(
        send(&mut session, "profile:color", EventKind::Select { value: "unknown".into() }).is_err(),
        "select cannot invent options"
    );
    for (key, kind) in [
        ("profile:name", EventKind::Text { value: String::new() }),
        ("profile:age", EventKind::Number { value: 30 }),
        ("profile:color", EventKind::Select { value: "red".into() }),
        ("profile:agree", EventKind::Toggle { value: false }),
    ] {
        assert!(
            matches!(
                send(&mut session, key, kind).expect("test: typed edit"),
                Some(EventResult::Edited { .. })
            ),
            "valid typed edit"
        );
    }
    assert!(
        matches!(
            send(&mut session, "profile:submit", EventKind::Submit)
                .expect("test: required validation"),
            Some(EventResult::Validation { .. })
        ),
        "missing required data never emits intent"
    );
    send(&mut session, "profile:name", EventKind::Text { value: "Grace".into() })
        .expect("test: required text");
    send(&mut session, "profile:agree", EventKind::Toggle { value: true })
        .expect("test: required toggle");
    let Some(EventResult::Submit { fields, .. }) =
        send(&mut session, "profile:submit", EventKind::Submit).expect("test: complete submit")
    else {
        panic!("test: owned intent required")
    };
    assert_eq!(fields.len(), 4, "only four owned fields");
    assert_eq!(fields.get("age"), Some(&Scalar::Number(30)), "number type survives intent");
    assert_eq!(fields.get("agree"), Some(&Scalar::Toggle(true)), "toggle type survives intent");
    let mut disabled = spec;
    if let Some(Component::Form(form)) = disabled.components.first_mut() {
        form.disabled = true;
    }
    session.update(disabled).expect("test: host disabled form");
    assert!(
        send(&mut session, "profile:submit", EventKind::Submit).is_err(),
        "disabled submit has no intent"
    );
    assert!(
        send(&mut session, "profile:name", EventKind::Text { value: "Eve".into() }).is_err(),
        "disabled edits rejected"
    );
}
#[test]
fn chart_bar_table_and_approval_host_boundary_are_closed() {
    let _guard = guard();
    let chart = FIXTURES.get(2).expect("test: chart fixture");
    let mut spec = CardSpec::parse(chart.input).expect("test: chart");
    if let Some(Component::Chart(chart)) = spec.components.first_mut() {
        chart.kind = crate::ChartKind::Bar;
    }
    let (session, _) = CardSession::open(spec, library()).expect("test: bounded bar chart");
    let tree = session.tree().expect("test: chart tree");
    let chart = tree.root.children.first().expect("test: chart node");
    assert_eq!(
        chart.attrs.plot.as_ref().expect("test: plot").kind,
        crate::ChartKind::Bar,
        "bar plot is explicit"
    );
    assert!(
        chart.children.iter().any(|n| n.kind == crate::NodeKind::Table),
        "chart always has complete table alternative"
    );
    let approval = FIXTURES.get(3).expect("test: approval fixture");
    let invalid = String::from_utf8(approval.input.to_vec())
        .expect("test: UTF8")
        .replace("\"request_ref\":", "\"allow\":true,\"request_ref\":");
    assert!(CardSpec::parse(invalid.as_bytes()).is_err(), "peer cannot add authority controls");
    let (session, batch) =
        CardSession::open(CardSpec::parse(approval.input).expect("test: approval"), library())
            .expect("test: approval renderer");
    assert_eq!(batch.host_slots.len(), 1, "host receives untrusted reference outside tree");
    let serialized = serde_json::to_string(&session.tree()).expect("test: approval tree");
    assert!(
        !serialized.contains("request-1") && !serialized.contains("task-1"),
        "authority references never become card controls"
    );
}
