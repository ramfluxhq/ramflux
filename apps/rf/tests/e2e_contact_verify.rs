// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! B8: `rf contact verify --mark-verified --expected-safety <stamp>` is compare-and-set through
//! real daemons, a real node and the real `rf` process.
#![cfg(all(any(unix, windows), feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    boot_stack, configure_node, create_account, exchange_contacts, rf_json, rf_json_timeout,
    start_daemon,
};
use serde_json::Value;
use std::time::Duration;

/// Every `rf` call below carries this deadline; a hung process fails the test instead of the job.
const CALL_DEADLINE: Duration = Duration::from_secs(60);

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn b8_mark_verified_requires_the_matching_expected_stamp() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let socket = alice_d.socket.as_path();
    let show_args =
        ["contact", "verify", "--account", &alice.id, "--contact", &bob.principal_commitment];

    // Show the stamp.
    let shown = rf_json_timeout(socket, &show_args, CALL_DEADLINE)?;
    assert_eq!(shown["verification_state"], "unverified", "fresh contact: {shown}");
    let stamp = shown.get("expected").filter(|value| value.is_object()).ok_or("stamp missing")?;
    let stamp_text = stamp.to_string();

    // Without the stamp the CLI refuses before any bus call.
    let mut mark_args = show_args.to_vec();
    mark_args.push("--mark-verified");
    assert!(
        rf_json_timeout(socket, &mark_args, CALL_DEADLINE).is_err(),
        "mark-verified without stamp"
    );

    // A stale stamp is a typed refusal with a nonzero exit, and the contact stays unverified.
    let mut stale = stamp.clone();
    let hash = stale["safetyNumberHash"].as_str().ok_or("stamp hash missing")?.to_owned();
    stale["safetyNumberHash"] = Value::String(format!("{hash}x"));
    let stale_text = stale.to_string();
    let mut stale_args = mark_args.clone();
    stale_args.extend(["--expected-safety", &stale_text]);
    let refused = rf_json_timeout(socket, &stale_args, CALL_DEADLINE)
        .err()
        .ok_or("stale stamp must fail")?
        .to_string();
    assert!(refused.contains("safety_material_mismatch"), "typed refusal: {refused}");
    let still = rf_json_timeout(socket, &show_args, CALL_DEADLINE)?;
    assert_eq!(still["verification_state"], "unverified", "refusal must not mark: {still}");

    // The matching stamp verifies, and the contact reads verified.
    let mut right_args = mark_args;
    right_args.extend(["--expected-safety", &stamp_text]);
    let verified = rf_json_timeout(socket, &right_args, CALL_DEADLINE)?;
    assert_eq!(verified["verificationState"], "verified", "mark result: {verified}");
    let after = rf_json(socket, &show_args)?;
    assert_eq!(after["verification_state"], "verified", "contact reads verified: {after}");
    Ok(())
}
