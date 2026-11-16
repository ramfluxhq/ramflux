// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! B8: `rf contact verify --mark-verified --expected-safety <stamp>` is compare-and-set through
//! real daemons, a real node and the real `rf` process.
#![cfg(all(any(unix, windows), feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    boot_stack, configure_node, create_account, exchange_contacts, rf_json_timeout, start_daemon,
};
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

/// Per-call cap. Each call also gets only what is left of the scenario budget.
const CALL_DEADLINE: Duration = Duration::from_secs(60);
/// Whole-scenario wall clock. It is strictly inside the 300 s nextest window for this binary
/// (`.config/nextest.toml`, 60 s period x 5), so a stuck call returns an error and the fixtures
/// (daemons, node stack, temp dirs) drop before the runner would kill the process.
const SCENARIO_DEADLINE: Duration = Duration::from_secs(200);

struct Budget(Instant);

impl Budget {
    fn call(&self, socket: &Path, args: &[&str]) -> e2e::Result<Value> {
        let left = self.remaining()?;
        rf_json_timeout(socket, args, left.min(CALL_DEADLINE))
    }

    fn remaining(&self) -> e2e::Result<Duration> {
        SCENARIO_DEADLINE
            .checked_sub(self.0.elapsed())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| "scenario deadline exceeded; fixtures dropped by early return".into())
    }
}

fn stamp_of(budget: &Budget, socket: &Path, show: &[&str]) -> e2e::Result<Value> {
    let shown = budget.call(socket, show)?;
    shown
        .get("expected")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| format!("stamp missing: {shown}").into())
}

fn state_of(budget: &Budget, socket: &Path, show: &[&str]) -> e2e::Result<String> {
    let shown = budget.call(socket, show)?;
    Ok(shown["verification_state"].as_str().ok_or("state missing")?.to_owned())
}

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn b8_mark_verified_requires_the_matching_expected_stamp() -> e2e::Result<()> {
    let budget = Budget(Instant::now());
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    let carol_d = start_daemon(&stack, "carol")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    configure_node(&carol_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    let carol = create_account(&carol_d, "Carol")?;
    budget.remaining()?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    exchange_contacts(&alice_d, &alice, &carol_d, &carol)?;
    budget.remaining()?;
    let socket = alice_d.socket.as_path();
    let show_bob =
        ["contact", "verify", "--account", &alice.id, "--contact", &bob.principal_commitment];
    let show_carol =
        ["contact", "verify", "--account", &alice.id, "--contact", &carol.principal_commitment];

    // Show the stamp.
    let shown = budget.call(socket, &show_bob)?;
    assert_eq!(shown["verification_state"], "unverified", "fresh contact: {shown}");
    let stamp = stamp_of(&budget, socket, &show_bob)?;
    let stamp_text = stamp.to_string();

    // Without the stamp the CLI refuses before any bus call.
    let mut mark_args = show_bob.to_vec();
    mark_args.push("--mark-verified");
    assert!(budget.call(socket, &mark_args).is_err(), "mark-verified without stamp");

    // A stamp copied from Bob used with --contact Carol is refused (typed), both unchanged.
    let carol_selected = [
        "contact",
        "verify",
        "--account",
        &alice.id,
        "--contact",
        &carol.principal_commitment,
        "--mark-verified",
        "--expected-safety",
        &stamp_text,
    ];
    let crossed = budget
        .call(socket, &carol_selected)
        .err()
        .ok_or("cross-contact stamp must fail")?
        .to_string();
    assert!(crossed.contains("safety_material_mismatch"), "typed refusal: {crossed}");
    assert_eq!(state_of(&budget, socket, &show_bob)?, "unverified", "bob unchanged");
    assert_eq!(state_of(&budget, socket, &show_carol)?, "unverified", "carol unchanged");

    // A stale stamp is a typed refusal with a nonzero exit, and the contact stays unverified.
    let mut stale = stamp.clone();
    let hash = stale["safetyNumberHash"].as_str().ok_or("stamp hash missing")?.to_owned();
    stale["safetyNumberHash"] = Value::String(format!("{hash}x"));
    let stale_text = stale.to_string();
    let mut stale_args = mark_args.clone();
    stale_args.extend(["--expected-safety", &stale_text]);
    let refused =
        budget.call(socket, &stale_args).err().ok_or("stale stamp must fail")?.to_string();
    assert!(refused.contains("safety_material_mismatch"), "typed refusal: {refused}");
    assert_eq!(state_of(&budget, socket, &show_bob)?, "unverified", "refusal must not mark");

    // The matching stamp verifies, and only that contact reads verified.
    let mut right_args = mark_args;
    right_args.extend(["--expected-safety", &stamp_text]);
    let verified = budget.call(socket, &right_args)?;
    assert_eq!(verified["verificationState"], "verified", "mark result: {verified}");
    assert_eq!(state_of(&budget, socket, &show_bob)?, "verified", "bob reads verified");
    assert_eq!(state_of(&budget, socket, &show_carol)?, "unverified", "carol still unverified");
    Ok(())
}
