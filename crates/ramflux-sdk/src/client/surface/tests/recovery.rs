// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hash disagreement and recipient-driven resync preserve state and bound response amplification.
use super::*;
#[test]
fn delta_requires_a_hash_and_hash_disagreement_marks_out_of_sync_without_advancing() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let before = f.human.surface_get("s", 0, None)?;
    let delta = carrier(
        &f.author,
        PayloadKind::Event,
        "v2",
        &event(
            2,
            C::StreamAppend(StreamAppendCommand {
                surface_id: "s".into(),
                component_id: "stream".into(),
                text_delta: "hello".into(),
                final_: false,
            }),
        )?,
    )?;
    let mut missing = delta.clone();
    missing.snapshot = None;
    missing.message_id = "missing".into();
    missing = f.author.sign_surface_carrier(missing)?;
    assert!(!project(&f.human, &missing, "missing")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?, before);
    let mut wrong = serde_json::to_value(&delta)?;
    wrong["snapshot"]["surface_hash"] = json!("incorrect-resulting-hash");
    let wrong = f.author.sign_surface_carrier(serde_json::from_value(wrong)?)?;
    let outcome = project(&f.human, &wrong, "wrong")?;
    assert!(!outcome.accepted);
    assert_eq!(outcome.renderer_error.ok_or("typed error")?["code"], "surface_hash_mismatch");
    let after = f.human.surface_get("s", 0, None)?;
    for field in ["snapshot", "version", "surface_hash", "hash_history"] {
        assert_eq!(before[field], after[field]);
    }
    assert_eq!(after["out_of_sync"], true);
    Ok(())
}
#[test]
fn only_original_author_answers_each_device_once_in_one_surface_window_and_recovery_converges()
-> TestResult {
    let terminals = devices::Terminals::new()?;
    let [author, sibling, human, human_two] = terminals.clients.as_slice() else {
        return Err("terminals".into());
    };
    let create =
        carrier(author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    for client in [author, sibling, human, human_two] {
        assert!(project(client, &create, "create")?.accepted);
    }
    let delta = carrier(
        author,
        PayloadKind::Event,
        "v2",
        &event(
            2,
            C::StreamAppend(StreamAppendCommand {
                surface_id: "s".into(),
                component_id: "stream".into(),
                text_delta: "new state".into(),
                final_: false,
            }),
        )?,
    )?;
    assert!(project(author, &delta, "v2")?.accepted);
    let reference = create.surface_reference()?;
    human.mark_surface_out_of_sync(&create, 2)?;
    assert!(human_two.prepare_surface_resync_request(&reference).is_err());
    let request = human.prepare_surface_resync_request(&reference)?.ok_or("request")?;
    assert!(human.prepare_surface_resync_request(&reference)?.is_none());
    let bytes = serde_json::to_vec(&request)?;
    for (i, receiver) in [author, sibling].into_iter().enumerate() {
        let entry = devices::entry(human, &format!("request-{i}"))?;
        assert!(receiver.receive_surface_resync_request(&entry, "thread", &bytes)?);
        let answer = receiver.take_surface_resync_answer(&entry)?;
        if i == 0 {
            let answer = answer.ok_or("original author response")?;
            assert!(project(human, &answer.carrier, "resync")?.accepted);
            let view = human.surface_get("s", 0, None)?;
            assert_eq!(view["out_of_sync"], false);
            assert_eq!(view["surface_hash"], author.surface_get("s", 0, None)?["surface_hash"]);
        } else {
            assert!(answer.is_none());
        }
        assert!(receiver.take_surface_resync_answer(&entry)?.is_none());
    }
    // Only the requesting device receives a reply; siblings share the surface window but each
    // can recover once. A second envelope from that same device cannot elicit another reply.
    let again = devices::entry(human_two, "request-again")?;
    assert!(author.receive_surface_resync_request(&again, "thread", &bytes)?);
    let second = author.take_surface_resync_answer(&again)?.ok_or("second device response")?;
    assert_eq!(second.destination.device, "human-two");
    assert!(project(human_two, &second.carrier, "second-resync")?.accepted);
    let duplicate = devices::entry(human_two, "request-again-duplicate")?;
    author.receive_surface_resync_request(&duplicate, "thread", &bytes)?;
    assert!(author.take_surface_resync_answer(&duplicate)?.is_none());
    assert_eq!(author.account_db()?.actor_state_usage("surface/resync_answered/")?.0, 1);
    sibling.mark_surface_out_of_sync(&create, 2)?;
    let own = sibling.prepare_surface_resync_request(&reference)?.ok_or("sibling request")?;
    let entry = devices::entry(sibling, "sibling-needs-resync")?;
    author.receive_surface_resync_request(&entry, "thread", &serde_json::to_vec(&own)?)?;
    let own_reply = author.take_surface_resync_answer(&entry)?.ok_or("own resync response")?;
    assert!(project(sibling, &own_reply.carrier, "own-resync")?.accepted);
    assert_eq!(sibling.surface_get("s", 0, None)?["out_of_sync"], false);
    let mut foreign = devices::entry(human, "wrong-principal")?;
    foreign.envelope.source_principal_id = "unrelated".into();
    assert!(author.receive_surface_resync_request(&foreign, "thread", &bytes).is_err());
    Ok(())
}
