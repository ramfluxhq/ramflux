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
        assert!(
            matches!(spec.validate(), Err(CardError::Limit(_))),
            "{} expansion rejected before VM",
            fixture.name
        );
        let spec = CardSpec::parse(fixture.input).expect("test: valid component");
        for (source, limit) in [
            ("export function render(input){ realRender(input); while(true){} }", "budget"),
            (
                "export function render(input){ realRender(input); function f(){return 1+f()}f()}",
                "stack",
            ),
        ] {
            let mut vm = CardRuntime::new(
                &package(&format!(
                    "{}\n{}",
                    include_str!("../library/form.js")
                        .replace("function render(", "function realRender(")
                        .replace("\n  render\n", "\n  realRender\n"),
                    source
                )),
                spec.clone(),
            )
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
        matches!(
            send(&mut session, "profile:age", EventKind::Number { value: 17 }),
            Ok(Some(EventResult::Validation { .. }))
        ),
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
    fn assert_no_approval_action(node: &crate::Node) {
        assert!(node.action.is_none(), "single-tap approval actions stay on the host surface");
        for child in &node.children {
            assert_no_approval_action(child);
        }
    }
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
    let input = String::from_utf8(approval.input.to_vec()).expect("test: UTF8");
    for control in ["allow", "deny", "confirm", "onTap"] {
        let invalid =
            input.replace("\"request_ref\":", &format!("\"{control}\":true,\"request_ref\":"));
        assert!(CardSpec::parse(invalid.as_bytes()).is_err(), "peer cannot add {control} controls");
    }
    let (session, batch) =
        CardSession::open(CardSpec::parse(approval.input).expect("test: approval"), library())
            .expect("test: approval renderer");
    assert_eq!(batch.host_slots.len(), 1, "host receives untrusted reference outside tree");
    let tree = session.tree().expect("test: approval tree");
    assert_no_approval_action(&tree.root);
    let serialized = serde_json::to_string(&tree).expect("test: serialized approval tree");
    assert!(
        !serialized.contains("request-1") && !serialized.contains("task-1"),
        "authority references never become card controls"
    );
}

#[test]
fn every_component_matches_exact_host_theme_style_snapshots() {
    fn styles(node: &crate::Node, result: &mut std::collections::BTreeMap<String, Value>) {
        result.insert(
            node.key.clone(),
            serde_json::to_value(&node.attrs.style).expect("test: style"),
        );
        for child in &node.children {
            styles(child, result);
        }
    }
    let _guard = guard();
    let package = library();
    let snapshots = [
        include_str!("../fixtures/complete_form.styles.json"),
        include_str!("../fixtures/task.styles.json"),
        include_str!("../fixtures/chart.styles.json"),
        include_str!("../fixtures/approval.styles.json"),
    ];
    for (fixture, snapshot) in FIXTURES.iter().zip(snapshots) {
        let expected: Value = serde_json::from_str(snapshot).expect("test: independent styles");
        let mut semantics = None;
        for theme in ["light", "dark", "contrast"] {
            let mut presentation =
                crate::Presentation::bundled("en", theme == "dark").expect("test: host theme");
            if theme == "contrast" {
                presentation.tokens =
                    serde_json::from_str(include_str!("../fixtures/contrast.tokens.json"))
                        .expect("test: additional token file");
            }
            let spec = CardSpec::parse(fixture.input)
                .expect("test: fixture")
                .with_presentation(presentation)
                .expect("test: host configuration");
            let (mut session, _) =
                CardSession::open(spec, package.clone()).expect("test: real theme render");
            let tree = session.tree().expect("test: styled tree");
            let mut actual = std::collections::BTreeMap::new();
            styles(&tree.root, &mut actual);
            assert_eq!(
                serde_json::to_value(actual).expect("test: style map"),
                *expected.get(theme).expect("test: named theme snapshot"),
                "{} {theme}",
                fixture.name
            );
            if let Some(previous) = &semantics {
                assert_eq!(&tree.without_style(), previous, "themes preserve business semantics");
            } else {
                semantics = Some(tree.without_style());
            }
            session
                .present(
                    crate::Presentation::bundled("zh-CN", theme == "dark")
                        .expect("test: Chinese locale"),
                )
                .expect("test: runtime locale switch");
            let tree = session.tree().expect("test: translated tree");
            assert!(
                serde_json::to_string(tree).expect("test: translated snapshot").len() < 65536,
                "translated component stays within the tree byte bound"
            );
        }
    }
}

#[test]
fn real_component_maxima_and_256_257_expansion_boundary() {
    let _guard = guard();
    let package = library();
    let fields:Vec<_>=(0..16).map(|index|serde_json::json!({"id":format!("f{index}"),"kind":"select","label":"Choice","binding":format!("/f{index}"),"options":(0..if index<13 {15}else{14}).map(|choice|serde_json::json!({"id":format!("o{choice}"),"label":"Option"})).collect::<Vec<_>>()})).collect();
    let model: serde_json::Map<String, Value> =
        (0..16).map(|index| (format!("f{index}"), Value::String("o0".into()))).collect();
    let mut json = serde_json::json!({"catalog":"rf-card/v1","components":[{"component":"rf.form","id":"max","title":"Maximum","submit":"save","fields":fields}],"model":model});
    let spec = CardSpec::parse(&serde_json::to_vec(&json).expect("test: boundary input"))
        .expect("test: exactly 256 expanded nodes");
    let (session, _) = CardSession::open(spec, package.clone()).expect("test: real maximum form");
    session.tree().expect("test: maximum tree").check_limits().expect("test: 256 nodes");
    drop(session);
    json.get_mut("components")
        .and_then(Value::as_array_mut)
        .and_then(|v| v.first_mut())
        .and_then(|v| v.get_mut("fields"))
        .and_then(Value::as_array_mut)
        .and_then(|v| v.last_mut())
        .and_then(|v| v.get_mut("options"))
        .and_then(Value::as_array_mut)
        .expect("test: last field options")
        .push(serde_json::json!({"id":"o14","label":"Option"}));
    assert!(matches!(
        CardSpec::parse(&serde_json::to_vec(&json).expect("test: 257 nodes")),
        Err(CardError::Limit("expanded nodes or depth"))
    ));
    for fixture in FIXTURES.iter().skip(1).take(2) {
        let mut spec = CardSpec::parse(fixture.input).expect("test: component fixture");
        match spec.components.first_mut().expect("test: component") {
            Component::Task(task) => {
                let step = task.steps.first().expect("test: step").clone();
                task.steps = (0..16)
                    .map(|index| {
                        let mut s = step.clone();
                        s.id = format!("s{index}");
                        s
                    })
                    .collect();
            }
            Component::Chart(chart) => {
                let mut series = chart.series.first().expect("test: series").clone();
                series.points = (0..16)
                    .map(|index| crate::Point { label: format!("p{index}"), value: index })
                    .collect();
                series.id = "first".into();
                let mut second = series.clone();
                second.id = "second".into();
                chart.series = vec![series, second];
            }
            _ => panic!("test: only task/chart fixtures"),
        }
        let (session, _) =
            CardSession::open(spec, package.clone()).expect("test: actual maximum component");
        let tree = session.tree().expect("test: maximum tree");
        tree.check_limits().expect("test: expansion within budget");
        assert!(serde_json::to_vec(tree).expect("test: tree bytes").len() <= 64 * 1024);
    }
}

#[test]
fn localized_validation_and_host_switch_preserve_peer_data_and_stale_fences() {
    fn find<'a>(node: &'a crate::Node, key: &str) -> Option<&'a crate::Node> {
        if node.key == key {
            return Some(node);
        }
        node.children.iter().find_map(|child| find(child, key))
    }
    let _guard = guard();
    let mut spec = CardSpec::parse(include_bytes!("../fixtures/complete_form.json"))
        .expect("test: complete form");
    spec.model.insert("name".into(), Scalar::Text(String::new()));
    let (mut session, _) = CardSession::open(spec, library()).expect("test: form open");
    let stale = event(&session, "profile:age", EventKind::Number { value: 99 });
    assert!(matches!(
        send(&mut session, "profile:submit", EventKind::Submit).expect("test: required"),
        Some(EventResult::Validation { .. })
    ));
    let presentation = crate::Presentation::bundled("zh-CN", true).expect("test: host settings");
    let required = presentation.text("form_required").to_owned();
    session.present(presentation).expect("test: switch locale and theme");

    assert_eq!(
        find(&session.tree().expect("test: tree").root, "profile:name")
            .expect("test: name")
            .attrs
            .error
            .as_deref(),
        Some(required.as_str())
    );
    session.enqueue(stale).expect("test: old event");
    assert!(matches!(
        session.next_event().expect("test: stale check"),
        Some(EventResult::StaleDropped)
    ));
    assert_eq!(
        find(&session.tree().expect("test: tree").root, "profile:age").expect("test: age").value,
        "25"
    );
}

#[test]
fn maximum_chart_and_task_share_exact_expansion_boundary() {
    let _guard = guard();
    let mut spec =
        CardSpec::parse(include_bytes!("../fixtures/chart.json")).expect("test: chart fixture");
    let Component::Chart(mut chart) = spec.components.pop().expect("test: chart") else {
        panic!("test: chart variant")
    };
    let mut series = chart.series.first().expect("test: series").clone();
    series.points = (0..16).map(|i| crate::Point { label: format!("p{i}"), value: i }).collect();
    series.id = "a".into();
    let mut second = series.clone();
    second.id = "b".into();
    chart.series = vec![series, second];
    let task_spec =
        CardSpec::parse(include_bytes!("../fixtures/task.json")).expect("test: task fixture");
    let Some(Component::Task(task)) = task_spec.components.first() else {
        panic!("test: task variant")
    };
    let mut components = Vec::new();
    for id in ["chart-a", "chart-b"] {
        let mut c = chart.clone();
        c.id = id.into();
        components.push(Component::Chart(c));
    }
    for (id, count) in [("task-a", 16), ("task-b", 16), ("task-c", 15)] {
        let mut task = task.clone();
        task.id = id.into();
        let step = task.steps.first().expect("test: step").clone();
        task.steps = (0..count)
            .map(|i| {
                let mut step = step.clone();
                step.id = format!("s{i}");
                step
            })
            .collect();
        components.push(Component::Task(task));
    }
    components.push(Component::Approval(crate::Approval {
        id: "approval".into(),
        request_ref: "request".into(),
        task_binding: None,
        explanation: String::new(),
    }));
    spec.components = components;
    spec.validate().expect("test: 256 nodes with both maximum charts and tasks");
    let (session, _) =
        CardSession::open(spec.clone(), library()).expect("test: real mixed maximum renderer");
    session.tree().expect("test: tree").check_limits().expect("test: bounded expanded tree");
    drop(session);
    let Some(Component::Approval(approval)) = spec.components.last_mut() else {
        panic!("test: approval variant")
    };
    approval.explanation = "One additional node".into();
    assert!(
        matches!(spec.validate(), Err(CardError::Limit("expanded nodes or depth"))),
        "257th expanded node is rejected before evaluation"
    );
}
