// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Display warnings and authentication failures remain local to their public record.
use super::*;
use serde_json::{Value, json};
#[test]
fn contact_and_identity_warn_about_confusable_names_without_rejecting_non_latin_names() -> TestResult
{
    let alice = Actor::new("alice", "phone", 11, 12, 1)?;
    let impostor = Actor::new("other", "phone", 13, 14, 1)?;
    let reader = Actor::new("reader", "phone", 15, 16, 1)?;
    observe(&reader.client, &with_profile(&alice, alice.manifest()?, "Alice", 1, 1)?)?;
    observe(&reader.client, &with_profile(&impostor, impostor.manifest()?, "Alіce", 1, 1)?)?;
    let contact = reader.client.contact_entry("other")?;
    assert_eq!(contact["kind_verified"], true);
    assert_eq!(contact["display_name_confusable_with"], "alice");
    assert_eq!(contact["mixed_script"], true);
    let row = crate::bus::read_model::row(&reader.client, "identity", "other")?;
    assert_eq!(row["display_name_confusable_with"], "alice");
    assert_eq!(row["mixed_script"], true);
    for (index, name) in ["ALICE", "alice"].into_iter().enumerate() {
        let epoch = u64::try_from(index)? + 2;
        observe(
            &reader.client,
            &with_profile(&impostor, impostor.manifest()?, name, epoch, epoch)?,
        )?;
        let row = reader.client.contact_entry("other")?;
        assert_eq!(row["display_name"], name);
        assert_eq!(row["display_name_confusable_with"], "alice");
    }
    observe(&reader.client, &with_profile(&impostor, impostor.manifest()?, "John 田中", 4, 4)?)?;
    assert_eq!(reader.client.contact_entry("other")?["mixed_script"], false);
    observe(&reader.client, &with_profile(&impostor, impostor.manifest()?, "東京", 5, 5)?)?;
    let row = reader.client.contact_entry("other")?;
    assert_eq!(row["display_name_confusable_with"], Value::Null);
    assert_eq!(row["mixed_script"], false);
    assert_eq!(row["kind_verified"], true);
    Ok(())
}
#[test]
fn authenticated_public_rename_emits_one_contact_change_with_old_and_new_names() -> TestResult {
    let owner = Actor::new("owner", "phone", 21, 22, 1)?;
    let reader = Actor::new("reader", "phone", 23, 24, 1)?;
    observe(&reader.client, &with_profile(&owner, owner.manifest()?, "Old Name", 1, 1)?)?;
    let db = reader.client.account_db()?;
    let before = db.journal_bounds()?.head_seq;
    let renamed = with_profile(&owner, owner.manifest()?, "New Name", 2, 2)?;
    observe(&reader.client, &renamed)?;
    observe(&reader.client, &renamed)?;
    let rows = db.journal_after(before, 100)?;
    let events = rows
        .iter()
        .filter(|e| e.topic == "contact.changed" && e.body["reason"] == "public_profile_renamed")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body["old_display_name"], "Old Name");
    assert_eq!(events[0].body["new_display_name"], "New Name");
    assert_eq!(events[0].body["principal_id"], "owner");
    Ok(())
}
#[test]
fn profile_reads_verify_once_per_full_record_and_do_not_reuse_same_epoch_substitutions()
-> TestResult {
    let owner = Actor::new("owner", "phone", 31, 32, 1)?;
    let reader = Actor::new("reader", "phone", 33, 34, 1)?;
    let signed = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
    observe(&reader.client, &signed)?;
    reader.client.with_profile_read_scope(|| -> TestResult {
        assert_eq!(reader.client.contact_entry("owner")?["kind_verified"], true);
        assert_eq!(
            crate::bus::read_model::row(&reader.client, "identity", "owner")?["kind_verified"],
            true
        );
        assert_eq!(reader.client.profile_read_verifications(), 1);
        let mut forged = signed.signed_device_set.clone().ok_or("set")?;
        forged.profile.as_mut().ok_or("profile")?.display_name = "Forged".into();
        reader
            .client
            .account_db()?
            .persist_actor_state(&record_key(&signed.principal_commitment), &forged)?;
        assert_eq!(reader.client.contact_entry("owner")?["kind_verified"], false);
        assert_eq!(reader.client.contact_entry("owner")?["kind_verified"], false);
        assert_eq!(
            reader.client.profile_read_verifications(),
            2,
            "invalid records are also cached by exact bytes"
        );
        Ok(())
    })?;
    assert_eq!(reader.client.profile_read_verifications(), 0, "cache ends at request boundary");
    Ok(())
}
#[test]
fn corrupt_profile_unverifies_only_that_actor_and_preserves_other_directory_and_task_rows()
-> TestResult {
    let owner = Actor::new("owner", "phone", 41, 42, 1)?;
    let other = Actor::new("other", "phone", 43, 44, 1)?;
    let reader = Actor::new("reader", "phone", 45, 46, 1)?;
    mode(&other, PrincipalKind::HeadlessAi, LocalBusClientMode::HeadlessAi)?;
    let signed = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
    observe(&reader.client, &signed)?;
    observe(&reader.client, &with_profile(&other, other.manifest()?, "Agent", 1, 1)?)?;
    let db = reader.client.account_db()?;
    let mut forged = signed.signed_device_set.ok_or("set")?;
    forged.profile.as_mut().ok_or("profile")?.signature.clear();
    db.persist_actor_state(&record_key(&forged.principal_commitment), &forged)?;
    assert_eq!(
        crate::bus::read_model::row(&reader.client, "identity", "owner")?["kind_verified"],
        false
    );
    assert_eq!(
        crate::bus::read_model::row(&reader.client, "identity", "other")?["kind_verified"],
        true
    );
    db.persist_actor_state(&crate::client::task::scoped("view","thread","task")?,&json!({"task_id":"task","conversation_id":"thread","state":"active","actors":{"requester":{"principal_id":"owner","device_id":"phone","actor_kind_verified":true},"assignee":{"principal_id":"other","device_id":"phone","actor_kind_verified":false}}}))?;
    for view in [
        reader.client.task_get(Some("thread"), "task")?,
        reader.client.task_list("thread", None, "", 10)?["tasks"][0].clone(),
    ] {
        assert_eq!(view["actors"]["requester"]["actor_kind_verified"], false);
        assert_eq!(view["actors"]["assignee"]["actor_kind_verified"], true);
        assert_eq!(view["actors"]["assignee"]["actor_kind"], "headless_ai");
    }
    Ok(())
}
#[test]
fn headless_profile_cannot_mark_human_role_task_outcomes_or_expired_holds_kind_verified()
-> TestResult {
    use ramflux_protocol::{TaskAccept, TaskEvent, TaskEventBody, TaskStart};
    let agent = Actor::new("agent", "agent-device", 51, 52, 1)?;
    mode(&agent, PrincipalKind::HeadlessAi, LocalBusClientMode::HeadlessAi)?;
    let reader = Actor::new("reader", "reader-device", 53, 54, 1)?;
    observe(&reader.client, &with_profile(&agent, agent.manifest()?, "Agent", 1, 1)?)?;
    let db = reader.client.account_db()?;
    db.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"direct","participants":["agent","reader"]}),
    )?;
    let make = |id: &str, body: TaskEventBody| -> Result<_, SdkError> {
        let event = TaskEvent::new(
            "thread".into(),
            body,
            crate::prelude::sdk_device_signed_fields("agent-device", ""),
        )
        .map_err(|e| crate::task_refusal::protocol(&e))?;
        agent.client.sign_task_event(event, id.into(), None)
    };
    let start = make(
        "start",
        TaskEventBody::Start(TaskStart {
            task_id: "task".into(),
            conversation_id: "thread".into(),
            requester: "agent".into(),
            assignee: "reader".into(),
            text: "Work".into(),
            constraints: None,
        }),
    )?;
    let now = crate::time::now_unix_timestamp();
    for c in [
        start,
        make(
            "waiting",
            TaskEventBody::Accept(TaskAccept { task_id: "missing".into(), version: 2 }),
        )?,
    ] {
        assert!(!crate::client::task::carrier_kind_verified(&reader.client, &c));
        reader
            .client
            .project_task_message(
                &crate::client::task::Delivery {
                    conversation: "thread",
                    message: &c.message_id,
                    principal: "agent",
                    device: "agent-device",
                    at: now,
                },
                &c.bytes()?,
            )?
            .ok_or("outcome")?;
        assert_eq!(
            reader.client.task_message_metadata("thread", &c.message_id)?.ok_or("metadata")?["actor_kind_verified"],
            false
        );
        assert_eq!(
            reader.client.task_message_metadata("thread", &c.message_id)?.ok_or("metadata")?["actor_kind"],
            "headless_ai"
        );
        let journal = db.latest_journal_event("task.changed")?.ok_or("journal")?;
        assert_eq!(journal.body["actor_kind"], "headless_ai");
        assert_eq!(journal.body["actor_kind_verified"], false);
    }
    reader.client.retry_pending_tasks(now + 601)?;
    let journal = db.latest_journal_event("task.changed")?.ok_or("event")?;
    assert_eq!(journal.body["resync_required"], true);
    assert_eq!(journal.body["actor_kind"], "headless_ai");
    let mut missing = make(
        "unknown-device",
        TaskEventBody::Accept(TaskAccept { task_id: "missing".into(), version: 2 }),
    )?;
    missing.device_id = "not-authorized".into();
    assert_eq!(crate::client::task::carrier_actor_kind(&reader.client, &missing), None);
    assert_eq!(journal.body["actor_kind_verified"], false);
    Ok(())
}

#[test]
fn confusable_name_lookup_includes_contacts_after_the_storage_page_limit() -> TestResult {
    let owner = Actor::new("owner", "phone", 61, 62, 1)?;
    let reader = Actor::new("reader", "phone", 63, 64, 1)?;
    let db = reader.client.account_db()?;
    for index in 0..110 {
        let id = format!("a-{index:03}");
        db.persist_client_record(
            "identity",
            &id,
            &json!({"principal_id":id,"display_name":format!("Other {index}")}),
        )?;
    }
    db.persist_client_record(
        "identity",
        "z-alice",
        &json!({"principal_id":"z-alice","display_name":"Alice"}),
    )?;
    observe(&reader.client, &with_profile(&owner, owner.manifest()?, "Alіce", 1, 1)?)?;
    assert_eq!(reader.client.contact_entry("owner")?["display_name_confusable_with"], "z-alice");
    Ok(())
}
