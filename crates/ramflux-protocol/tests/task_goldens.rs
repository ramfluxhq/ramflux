// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
mod task_support;
use ramflux_protocol::*;
use std::fmt::Write as _;
use task_support::*;
#[test]
fn canonical_task_events_and_fixed_key_signatures_match_v1_goldens() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let events = vec![
        ("start", &h, start()),
        ("proposal", &a, proposal()),
        (
            "accept",
            &h,
            TaskEventBody::Accept(TaskAccept { task_id: "task".to_owned(), version: 2 }),
        ),
        (
            "decline",
            &h,
            TaskEventBody::Decline(TaskDecline { task_id: "task".to_owned(), version: 2 }),
        ),
        ("update", &a, update(3, TaskStatus::NeedsMe, vec![blocked("s", approval())])),
        (
            "cancel",
            &h,
            TaskEventBody::Cancel(TaskCancel { task_id: "task".to_owned(), version: 4 }),
        ),
        ("resolve", &h, resolve(4, approval(), TaskDecision::Resume)),
    ];
    let mut golden = String::new();
    for (name, actor, body) in events {
        let event = actor.event(body)?;
        event.verify(&actor.signer())?;
        writeln!(
            golden,
            "{name}\npublic_key={}\njcs={}\nsignature={}\nfallback={}\n",
            actor.public,
            String::from_utf8(event.signing_bytes()?)?,
            event.signed.signature,
            event.fallback_text()
        )?;
    }
    insta::assert_snapshot!("task_events_v1", golden);
    Ok(())
}
