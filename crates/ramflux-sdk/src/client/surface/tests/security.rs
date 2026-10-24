// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;

#[test]
fn invalid_signatures_never_reserve_another_senders_receipt() -> TestResult {
    let f = Fixture::new()?;
    let good = carrier(
        &f.author,
        PayloadKind::Event,
        "reserved",
        &event(1, C::CreateSurface(snapshot()))?,
    )?;
    let mut forged = good.clone();
    forged.signature = "invalid".into();
    assert!(!project(&f.human, &forged, "forged")?.accepted);
    let receipt = super::super::receipt_key(&forged)?;
    assert!(f.human.account_db()?.load_actor_state::<Value>(&receipt)?.is_none());
    assert!(project(&f.human, &good, "real")?.accepted);
    Ok(())
}
#[test]
fn deferred_group_sender_principal_comes_from_the_verified_device_record() -> TestResult {
    let f = Fixture::new()?;
    f.author.create_group("g", "author-device")?;
    f.author.add_group_member("g", "human-device", "member")?;
    f.author.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"g"}),
    )?;
    let mut forged = carrier(
        &f.human,
        PayloadKind::Event,
        "reserved",
        &event(1, C::CreateSurface(snapshot()))?,
    )?;
    forged.sender_principal_id = "author".into();
    f.author.send_direct_message("thread", "deferred-forgery", "human-device", b"encrypted")?;
    f.author.account_db()?.store_message_content("thread", "deferred-forgery", &forged.bytes()?)?;
    f.author.project_deferred_surface("thread", "deferred-forgery")?;
    let receipt = super::super::receipt_key(&forged)?;
    assert!(f.author.account_db()?.load_actor_state::<Value>(&receipt)?.is_none());
    assert_eq!(f.author.surface_list("thread", "", 100)?["surfaces"], json!([]));
    let real = carrier(
        &f.author,
        PayloadKind::Event,
        "reserved",
        &event(1, C::CreateSurface(snapshot()))?,
    )?;
    assert!(project(&f.author, &real, "real")?.accepted);
    Ok(())
}
fn signed_in(
    sender: &RamfluxClient,
    author: &str,
    conversation: &str,
    message: &str,
    fallback: &str,
) -> Result<Carrier, SdkError> {
    let mut content = snapshot();
    content.fallback_text = fallback.into();
    let command = serde_json::to_value(C::CreateSurface(content))?;
    let raw = serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.conversation.v2","conversationId":conversation,"version":1,"command":command}),
    )?;
    let mut signed =
        carrier(sender, PayloadKind::Event, message, &event(1, C::CreateSurface(snapshot()))?)?;
    signed.author_principal_id = author.into();
    signed.conversation_id = conversation.into();
    signed.wire_base64 = ramflux_protocol::encode_base64url(raw);
    sender.sign_surface_carrier(signed)
}
fn project_in(client: &RamfluxClient, signed: &Carrier) -> Result<Outcome, SdkError> {
    client
        .project_surface_message(
            &signed.conversation_id,
            &signed.message_id,
            super::super::SurfaceSender {
                principal: &signed.sender_principal_id,
                device: &signed.sender_device_id,
                envelope_id: &signed.message_id,
                expires_at: None,
                group_epoch: None,
            },
            &signed.bytes()?,
            false,
        )?
        .ok_or_else(|| super::super::invalid("surface"))
}
#[test]
fn equal_ids_are_independent_across_conversations_and_authors() -> TestResult {
    let f = Fixture::new()?;
    let a = signed_in(&f.author, "author", "thread", "a", "Author in thread")?;
    let b = signed_in(&f.human, "human", "thread", "b", "Human in thread")?;
    let c = signed_in(&f.author, "author", "another-thread", "c", "Author elsewhere")?;
    for signed in [&a, &b, &c] {
        assert!(project_in(&f.human, signed)?.accepted);
    }
    assert!(f.human.surface_get("s", 0, None).is_err(), "ambiguous id requires a scope");
    let mut references = std::collections::BTreeSet::new();
    for (signed, text) in
        [(&a, "Author in thread"), (&b, "Human in thread"), (&c, "Author elsewhere")]
    {
        let reference = f
            .human
            .resolve_surface_reference(
                "s",
                Some(&signed.conversation_id),
                Some(&signed.author_principal_id),
            )?
            .ok_or("reference")?;
        references.insert(reference.clone());
        let view = f.human.surface_get_ref(&reference, 0, None)?;
        assert_eq!(view["snapshot"]["fallbackText"], text);
        assert_eq!(view["author_principal_id"], signed.author_principal_id);
    }
    assert_eq!(references.len(), 3);
    assert_eq!(
        f.human.surface_list("thread", "", 100)?["surfaces"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        f.human.surface_list("another-thread", "", 100)?["surfaces"].as_array().map(Vec::len),
        Some(1)
    );
    Ok(())
}
#[test]
fn bad_carriers_never_change_an_authors_view_or_create_stub_surfaces() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let before = f.human.surface_get("s", 0, None)?;
    let bad = carrier(
        &f.human,
        PayloadKind::Event,
        "non-author",
        &event(2, C::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }))?,
    )?;
    assert!(!project(&f.human, &bad, "bad")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?, before);
    let other = signed_in(&f.human, "human", "thread", "unknown", "Nothing")?;
    let mut unknown = other;
    unknown.surface_id = "absent".into();
    assert!(!project(&f.human, &unknown, "unknown")?.accepted);
    assert_eq!(
        f.human.surface_list("thread", "", 100)?["surfaces"].as_array().map(Vec::len),
        Some(1)
    );
    Ok(())
}
#[test]
fn checkpoint_cannot_restore_under_another_row_or_inconsistent_view() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let reference = f
        .human
        .resolve_surface_reference("s", Some("thread"), Some("author"))?
        .ok_or("reference")?;
    let state_key = key("state", &reference);
    let record: super::super::StoredSurface =
        f.human.account_db()?.load_actor_state(&state_key)?.ok_or("record")?;
    let bytes = ramflux_protocol::decode_base64url(&record.checkpoint_base64)?;
    for (field, value) in [
        ("conversation_id", json!("other")),
        (
            "content",
            serde_json::to_value({
                let mut c = snapshot();
                c.surface_id = "other".into();
                c
            })?,
        ),
    ] {
        let mut checkpoint: Value = serde_json::from_slice(&bytes)?;
        checkpoint[field] = value;
        let mut corrupt = record.clone();
        corrupt.checkpoint_base64 =
            ramflux_protocol::encode_base64url(serde_json::to_vec(&checkpoint)?);
        f.human.account_db()?.persist_actor_state(&state_key, &corrupt)?;
        assert!(f.human.surface_state_ref(&reference).is_err());
    }
    f.human.account_db()?.persist_actor_state(&state_key, &record)?;
    let mut view = f.human.account_db()?.client_record("surface", &reference)?.ok_or("view")?;
    view["version"] = json!(99);
    f.human.account_db()?.persist_client_record("surface", &reference, &view)?;
    assert!(f.human.surface_state_ref(&reference).is_err());
    Ok(())
}

#[test]
fn retry_keeps_the_signed_snapshot_after_the_authored_version_has_advanced() -> TestResult {
    let f = Fixture::new()?;
    let mut first =
        carrier(&f.author, PayloadKind::Event, "stable", &event(1, C::CreateSurface(snapshot()))?)?;
    f.author.attach_surface_snapshot(&mut first)?;
    first = f.author.sign_surface_carrier(first)?;
    f.author.account_db()?.surface_transaction(|| {
        project(&f.author, &first, "first")?;
        f.author.retain_authored_surface(&first)
    })?;
    let next = carrier(
        &f.author,
        PayloadKind::Event,
        "next",
        &event(2, C::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }))?,
    )?;
    project(&f.author, &next, "next")?;
    let mut candidate = first.clone();
    candidate.snapshot = None;
    candidate.signature = String::new();
    let retried = f.author.reuse_authored_surface(&candidate)?.ok_or("retained carrier")?;
    assert_eq!(retried.bytes()?, first.bytes()?);
    assert!(f.author.surface_delivery_receipt(&retried)?.ok_or("receipt")?.accepted);
    candidate.wire_base64 = next.wire_base64;
    assert!(f.author.reuse_authored_surface(&candidate).is_err());
    Ok(())
}
