// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authoring guards execute before parsing or signing a human operation.
use super::*;
use crate::bus::runtime_tests::{account, root};
use std::sync::{Arc, atomic::AtomicBool};
#[tokio::test(flavor = "current_thread")]
async fn every_human_task_method_rejects_headless_mode_and_nonhuman_kind_before_signing()
-> Result<(), SdkError> {
    let root = root("task-authority");
    let local = account(&root, "agent", None, Arc::new(AtomicBool::new(false)))?;
    let mut state = LocalBusDaemonState {
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        accounts: BTreeMap::from([("agent".into(), local)]),
        active_account_id: Some("agent".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    for (mode, kind) in [
        (LocalBusClientMode::HeadlessAi, "human"),
        (LocalBusClientMode::AttendedCli, "headless_ai"),
    ] {
        let path = local_bus_account_manifest_path(&root, "agent");
        let mut manifest = read_local_bus_account_manifest(&path)?;
        manifest.client_mode = mode;
        manifest.kind = Some(kind.into());
        write_local_bus_account_manifest(&root, &manifest)?;
        for method in ["task.start", "task.accept", "task.decline", "task.resolve", "task.cancel"] {
            let request = LocalBusFrame::request(
                method,
                Some("agent".into()),
                "task",
                method,
                serde_json::json!({}),
            );
            let result = dispatch_task(&request, &mut state).await;
            assert!(
                matches!(
                    result,
                    Err(SdkError::TaskRefused {
                        reason: crate::TaskRefusalCode::HumanRequired,
                        ..
                    })
                ),
                "{method} must fail at authoring guard"
            );
        }
    }
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn every_documented_task_method_parses_its_exact_request_body() -> Result<(), SdkError> {
    let docs =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/conversation_tasks.md"));
    let mut methods = BTreeSet::new();
    for block in docs.split("```json\n").skip(1) {
        let value: Value = serde_json::from_str(
            block
                .split("```")
                .next()
                .ok_or_else(|| invalid("unterminated documentation example"))?
                .trim(),
        )?;
        let method = required(&value, "method")?;
        let request = LocalBusFrame::request(
            "docs",
            Some("account".into()),
            "tasks",
            method,
            value["body"].clone(),
        );
        if matches!(method, "task.get" | "task.list") {
            required(
                &request.body,
                if method == "task.get" { "task_id" } else { "conversation_id" },
            )?;
        } else {
            let body = build_event(&request, "human", request.body.clone())?;
            TaskEvent::new("thread".into(), body, sdk_device_signed_fields("device", ""))
                .map_err(|error| crate::task_refusal::protocol(&error))?;
        }
        assert!(methods.insert(method.to_owned()), "one canonical example per method");
    }
    assert_eq!(methods.len(), 9);
    Ok(())
}

#[test]
fn task_accept_has_one_shape_and_refusal_codes_do_not_depend_on_display_text()
-> Result<(), SdkError> {
    let request = LocalBusFrame::request(
        "accept",
        Some("account".into()),
        "tasks",
        "task.accept",
        json!({"task_id":"task","version":2}),
    );
    assert!(matches!(
        build_event(&request, "human", request.body.clone())?,
        TaskEventBody::Accept(_)
    ));
    assert!(build_event(&request, "human", json!({"task_id":"task","base_revision":1})).is_err());
    for (error, code) in [
        (ramflux_protocol::TaskReject::Terminal, "terminal"),
        (ramflux_protocol::TaskReject::StaleVersion { expected: 2, actual: 1 }, "stale_revision"),
    ] {
        let SdkError::TaskRefused { reason, .. } = crate::task_refusal::protocol(&error) else {
            return Err(invalid("untyped refusal"));
        };
        assert_eq!(reason.as_str(), code);
    }
    for (reason, code) in [
        (crate::TaskRefusalCode::TaskQuotaExhausted, "quota_exhausted"),
        (crate::TaskRefusalCode::NotRequester, "not_requester"),
        (crate::TaskRefusalCode::DecisionConsumed, "decision_consumed"),
    ] {
        let error = crate::task_refusal::refused(reason, "arbitrary display text");
        assert_eq!(crate::bus::io::local_bus_error_code(&error), code);
    }
    Ok(())
}

#[test]
fn terminal_result_summaries_are_bounded_and_reject_unsafe_text() -> Result<(), SdkError> {
    for summary in ["x".repeat(4097), "unsafe\u{1b}[31m".into()] {
        let body: TaskUpdate = serde_json::from_value(
            json!({"task_id":"task","version":2,"state":"done","steps":[],"result_summary":summary}),
        )?;
        assert!(
            TaskEvent::new(
                "thread".into(),
                TaskEventBody::Update(body),
                sdk_device_signed_fields("device", "")
            )
            .is_err()
        );
    }
    Ok(())
}
