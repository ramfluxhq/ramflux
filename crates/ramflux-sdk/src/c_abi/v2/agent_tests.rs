// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The agent methods cross the public C ABI (AGENT-IDENTITY-01 E6). `agent.list` is admitted under
//! the `agent` namespace and reaches the SDK; `agent.creation.decide` is a key-export class method,
//! refused at admission unless the client allows exports. Each refusal is typed: a request without
//! an account, and an account that is not open, answer with their own codes.
use super::tests::{Fixture, deadline};
use super::*;
use serde_json::{Value, json};

/// Admits one agent method through the public execute export: the admission status and, when
/// admitted, the operation id.
fn admit(fixture: &Fixture, account: Option<&str>, method: &str, body: &Value) -> (i32, u64) {
    let request = serde_json::to_vec(&json!({
        "sdk_api": "agent",
        "account_id": account,
        "method": method,
        "body": body,
        "deadline_ms": deadline(),
    }))
    .expect("test: agent request");
    let mut operation = 0;
    let status =
        ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut operation);
    (status, operation)
}

/// Admits one agent method and waits for its result.
fn run(fixture: &Fixture, account: Option<&str>, method: &str, body: &Value) -> Value {
    let (status, operation) = admit(fixture, account, method, body);
    assert_eq!(status, 0, "{method} is admitted through the public ABI");
    fixture.result(operation)
}

#[test]
fn agent_list_reaches_the_sdk_and_answers_with_typed_refusals() {
    let fixture = Fixture::open();
    let body = json!({"limit": 10});
    let no_account = run(&fixture, None, "agent.list", &body);
    assert_eq!(no_account["code"], 1, "a request without an account is refused");
    assert_eq!(no_account["response"]["error"]["code"], "CustodySetupInvalid");
    assert_eq!(no_account["response"]["method"], "agent.list", "the method reached the bus");
    let unopened = run(&fixture, Some("unopened"), "agent.list", &body);
    assert_eq!(unopened["code"], 9, "an account that is not open is refused");
    assert_eq!(unopened["response"]["error"]["code"], "NetworkingPending");
}

#[test]
fn agent_creation_decide_is_an_export_class_method_and_answers_typed_when_exports_are_allowed() {
    let body = json!({"request_id": "r", "request_hash": "h", "approved": true});
    let fixture = Fixture::open();
    let (status, _) = admit(&fixture, Some("unopened"), "agent.creation.decide", &body);
    assert_eq!(status, 12, "the default client refuses the export-class method before admission");
    let exports = Fixture::configured_exports(false, true);
    let decided = run(&exports, Some("unopened"), "agent.creation.decide", &body);
    assert_eq!(decided["code"], 9, "with exports allowed the call reaches the bus and is refused");
    assert_eq!(decided["response"]["error"]["code"], "NetworkingPending");
}
