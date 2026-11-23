// SPDX-License-Identifier: BSD-3-Clause
//! Existing library regressions adapted from the removed flat rf.* profile to ABI 5.
use crate::{
    CardRuntime, CardSession, CardSpec, EventResult, HostEventKind, NodeKind,
    runtime::tests::{guard, library, package},
    session::tests::{event, send},
};
use serde_json::{Value, json};
struct Fixture {
    name: &'static str,
    input: &'static [u8],
    updated: &'static [u8],
    tree: &'static str,
    mount: &'static str,
    edit: &'static str,
}
macro_rules! fixture {
    ($n:literal) => {
        Fixture {
            name: $n,
            input: include_bytes!(concat!("../fixtures/", $n, ".json")),
            updated: include_bytes!(concat!("../fixtures/", $n, ".updated.json")),
            tree: include_str!(concat!("../fixtures/", $n, ".tree.json")),
            mount: include_str!(concat!("../fixtures/", $n, ".mount.json")),
            edit: include_str!(concat!("../fixtures/", $n, ".edit.json")),
        }
    };
}
const FIXTURES: [Fixture; 4] =
    [fixture!("complete_form"), fixture!("task"), fixture!("chart"), fixture!("approval")];
fn normalized<T: serde::Serialize>(value: T) -> Value {
    fn visit(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    if key == "session" {
                        *value = json!(1);
                    } else if key == "request_id" {
                        if let Some(s) = value.as_str()
                            && let Ok(mut token) = serde_json::from_str::<Value>(s)
                        {
                            visit(&mut token);
                            *value = Value::String(
                                serde_json::to_string(&token).expect("test: request token"),
                            );
                        }
                    } else {
                        visit(value);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value);
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value).expect("test: output serialization");
    visit(&mut value);
    value
}
fn spec(name: &str) -> CardSpec {
    let fixture = FIXTURES.iter().find(|f| f.name == name).expect("test: fixture name");
    CardSpec::parse(fixture.input).expect("test: ABI5 fixture")
}
fn rehash(spec: &mut CardSpec) {
    spec.signed_hash = spec.snapshot.hash().expect("test: signed base hash");
}
#[test]
fn every_component_matches_tree_mount_mutation_theme_and_stale_snapshots() {
    let _guard = guard();
    for fixture in &FIXTURES {
        let (mut session, mount) =
            CardSession::open(CardSpec::parse(fixture.input).expect("test: spec"), library())
                .expect("test: mount");
        assert_eq!(
            normalized(session.tree()),
            serde_json::from_str::<Value>(fixture.tree).expect("test: tree snapshot"),
            "{} native tree",
            fixture.name
        );
        assert_eq!(
            normalized(mount),
            serde_json::from_str::<Value>(fixture.mount).expect("test: mount snapshot"),
            "{} mount batch",
            fixture.name
        );
        let token = event(&session, "root", HostEventKind::Activate);
        let batch = session
            .update(CardSpec::parse(fixture.updated).expect("test: update"))
            .expect("test: commit");
        assert_eq!(
            normalized(batch),
            serde_json::from_str::<Value>(fixture.edit).expect("test: edit snapshot"),
            "{} atomic signed update",
            fixture.name
        );
        session.enqueue(token).expect("test: stale token");
        assert!(
            matches!(
                session.next_event().expect("test: stale event"),
                Some(EventResult::StaleDropped)
            ),
            "signed update fences prior events"
        );
    }
}
#[test]
fn every_component_rejects_its_expansion_bound_loop_and_recursion() {
    let _guard = guard();
    for fixture in &FIXTURES {
        let base = CardSpec::parse(fixture.input).expect("test: fixture");
        let mut oversized = base.clone();
        oversized.snapshot.components = vec![oversized.snapshot.components[0].clone(); 33];
        rehash(&mut oversized);
        assert!(oversized.validate().is_err(), "{} definition bound", fixture.name);
        for source in [
            "export function render(){while(true){}}",
            "export function render(){function f(){return 1+f()}f()}",
        ] {
            let mut vm =
                CardRuntime::new(&package(source), base.clone()).expect("test: bounded VM");
            assert!(vm.render(&base).is_err(), "{} budget/stack", fixture.name);
        }
    }
}
#[test]
fn complete_form_enforces_types_required_errors_disabled_and_owned_submit() {
    let _guard = guard();
    let mut base = spec("complete_form");
    let input =
        base.snapshot.components.iter_mut().find(|v| v["id"] == "input").expect("test: input");
    input["@checks"] = json!([{"condition":{"@call":"required","args":{"value":{"@path":"/name"}}},"message":"Name required"}]);
    rehash(&mut base);
    let state = base.state().expect("test: admitted state");
    let (mut s, _) = CardSession::open(base, library()).expect("test: form");
    for (id, value) in [("age", json!(17)), ("color", json!(["green"])), ("agree", json!("yes"))] {
        assert!(
            send(&mut s, id, HostEventKind::Input { value }).is_err(),
            "invalid type/range/options reject"
        );
    }
    send(&mut s, "input", HostEventKind::Input { value: json!("") })
        .expect("test: local invalid check value");
    let input = s
        .tree()
        .expect("test: tree")
        .nodes
        .iter()
        .find(|n| n.component_id == "input")
        .expect("test: input");
    assert_eq!(
        input.attrs["errors"],
        json!(["Name required"]),
        "input check errors share Rust evaluation"
    );
    send(&mut s, "input", HostEventKind::Input { value: json!("Grace") })
        .expect("test: valid draft");
    let EventResult::Submit { action, .. } =
        send(&mut s, "button", HostEventKind::Activate).expect("test: submit")
    else {
        panic!("test: expected resolver event")
    };
    let frame = s
        .resolved()
        .expect("test: resolver")
        .action_frame(&state, &action, "2026-11-22T00:00:00Z")
        .expect("test: frame");
    assert_eq!(frame.a2ui.action.context["name"], "Grace", "egress carries raw owned draft only");
    state
        .validate_action(
            &ramflux_protocol::a2ui::SurfaceAction::from_wire_bytes(
                &frame.wire_bytes().expect("test: original canonical action"),
            )
            .expect("test: action admission"),
        )
        .expect("test: author validates same resolver output");
}
#[test]
fn chart_bar_table_and_approval_host_boundary_are_closed() {
    let _guard = guard();
    for name in ["chart", "approval"] {
        let base = spec(name);
        let (s, batch) = CardSession::open(base, library()).expect("test: display");
        let tree = s.tree().expect("test: tree");
        if name == "chart" {
            let node = &tree.nodes[0];
            assert_eq!(node.kind, NodeKind::Chart, "Chart remains first class");
            assert_ne!(
                node.attrs["series"][0]["points"][0]["label"],
                node.attrs["series"][1]["points"][0]["label"],
                "independent series labels are retained losslessly for native table alternative"
            );
        } else {
            assert_eq!(batch.host_slots.len(), 1, "Approval exposes host request only");
            assert!(
                !tree.nodes[0].attrs.contains_key("action_ref"),
                "approval never becomes a card activation"
            );
        }
    }
}
#[test]
fn every_component_matches_exact_host_theme_style_snapshots() {
    let _guard = guard();
    for fixture in &FIXTURES {
        let base = CardSpec::parse(fixture.input).expect("test: fixture");
        let mut vm = CardRuntime::new(&library(), base.clone()).expect("test: VM");
        let original = vm.render(&base).expect("test: render");
        drop(vm);
        let presentation = crate::Presentation::bundled("zh-CN", true).expect("test: host tokens");
        let base = base.with_presentation(presentation).expect("test: independent host settings");
        let mut vm = CardRuntime::new(&library(), base.clone()).expect("test: alternate VM");
        let alternate = vm.render(&base).expect("test: alternate render");
        assert_eq!(
            original.nodes.len(),
            alternate.nodes.len(),
            "host locale/theme cannot add controls"
        );
        assert_eq!(
            original.signed_hash, alternate.signed_hash,
            "host presentation never changes signed base"
        );
        let token_snapshot: Value = serde_json::from_str(match fixture.name {
            "task" => include_str!("../fixtures/task.styles.json"),
            "chart" => include_str!("../fixtures/chart.styles.json"),
            "approval" => include_str!("../fixtures/approval.styles.json"),
            _ => include_str!("../fixtures/complete_form.styles.json"),
        })
        .expect("test: host token snapshot");
        assert_eq!(
            token_snapshot,
            json!(base.presentation().expect("test: host presentation").tokens),
            "native hosts own tokens; no peer/VM geometry"
        );
    }
}
#[test]
fn real_component_maxima_and_256_257_expansion_boundary() {
    let _guard = guard();
    let mut base = spec("complete_form");
    let table =
        base.snapshot.components.iter_mut().find(|v| v["id"] == "table").expect("test: table");
    table["rows"] = json!([{"key":"same","cells":["one"]},{"key":"same","cells":["two"]}]);
    rehash(&mut base);
    assert!(base.validate().is_err(), "Table row keys must be unique");
    let table =
        base.snapshot.components.iter_mut().find(|v| v["id"] == "table").expect("test: table");
    table["rows"] = json!([{"key":"one","cells":[]}]);
    rehash(&mut base);
    assert!(base.validate().is_err(), "Table must be rectangular");
    let mut base = spec("chart");
    base.snapshot.components[0]["series"][0]["points"] =
        json!(vec![json!({"label":"p","value":0}); 17]);
    rehash(&mut base);
    assert!(base.validate().is_err(), "Chart points stay bounded");
}
#[test]
fn localized_validation_and_host_switch_preserve_peer_data_and_stale_fences() {
    let _guard = guard();
    let (mut s, _) = CardSession::open(spec("complete_form"), library()).expect("test: form");
    send(&mut s, "input", HostEventKind::Input { value: json!("Grace") }).expect("test: draft");
    let stale = event(&s, "input", HostEventKind::Input { value: json!("stale") });
    s.present(crate::Presentation::bundled("zh-CN", true).expect("test: locale"))
        .expect("test: host switch");
    s.enqueue(stale).expect("test: queue");
    assert!(
        matches!(s.next_event().expect("test: stale"), Some(EventResult::StaleDropped)),
        "presentation advances token version"
    );
    let resolved = s.resolved().expect("test: shared locale resolver");
    let text = resolved.nodes.iter().find(|n| n.id == "more").expect("test: nested locale display");
    assert_eq!(
        text.properties["text"], "Amount US$1,234.00",
        "nested formatString uses Rust launch locale"
    );
    assert!(
        resolved.inputs.iter().any(|input| input.value == json!("Grace")),
        "presentation preserves raw draft"
    );
}
#[test]
fn maximum_chart_and_task_share_exact_expansion_boundary() {
    let _guard = guard();
    let (mut s, _) =
        CardSession::open(spec("complete_form"), library()).expect("test: full catalog");
    send(&mut s, "input", HostEventKind::Input { value: json!("Grace") })
        .expect("test: draft that conflicts with next signed base");
    assert!(
        !s.tree()
            .expect("test: tree")
            .host_slots
            .iter()
            .any(|slot| matches!(slot.request, crate::slots::SlotRequest::Image { .. })
                && slot.key.contains("more")),
        "hidden pages cannot request images"
    );
    assert!(
        send(&mut s, "date", HostEventKind::Input { value: json!("2026-11-23") }).is_err(),
        "closed Modal content has no active hit targets"
    );
    send(&mut s, "modal", HostEventKind::ModalOpen).expect("test: open host modal");
    send(&mut s, "date", HostEventKind::Input { value: json!("2026-11-23") })
        .expect("test: mounted modal input");
    send(&mut s, "tabs", HostEventKind::SelectTab { index: 1 }).expect("test: change page");
    assert!(
        !s.tree()
            .expect("test: tree")
            .host_slots
            .iter()
            .any(|slot| matches!(slot.request, crate::slots::SlotRequest::Image { .. })),
        "hidden tab cancels Image requests"
    );
    assert!(
        send(&mut s, "date", HostEventKind::Input { value: json!("2026-11-24") }).is_err(),
        "hidden Modal input refuses events"
    );
    let version = s.version();
    assert!(
        send(&mut s, "tabs", HostEventKind::SelectTab { index: 2 }).is_err(),
        "bad tab index refuses"
    );
    assert_eq!(s.version(), version, "bad event preserves committed tree");
    let mut changed = spec("complete_form");
    changed.signed_version = 2;
    changed.snapshot.data_model["name"] = json!("remote");
    rehash(&mut changed);
    s.update(changed).expect("test: signed conflict");
    assert!(s.draft_conflict(), "changed signed base discards draft with host notice");
}
