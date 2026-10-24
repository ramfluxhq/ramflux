// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
fn stream(
    sender: &RamfluxClient,
    message: &str,
    version: u64,
    text: &str,
) -> Result<Carrier, SdkError> {
    carrier(
        sender,
        PayloadKind::Event,
        message,
        &event(
            version,
            C::StreamAppend(StreamAppendCommand {
                surface_id: "s".into(),
                component_id: "stream".into(),
                text_delta: text.into(),
                final_: false,
            }),
        )?,
    )
}
fn pending_count(client: &RamfluxClient) -> Result<usize, SdkError> {
    Ok(client
        .account_db()?
        .surface_history_page::<Value>("surface/pending/", "surface/pending/", 100)?
        .len())
}
#[test]
fn reordered_versions_catch_up_without_redelivery_or_terminal_reject_receipts() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let two = stream(&f.author, "v2", 2, "one")?;
    let three = stream(&f.author, "v3", 3, "two")?;
    let four = carrier(
        &f.author,
        PayloadKind::Event,
        "v4",
        &event(4, C::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }))?,
    )?;
    for signed in [&three, &four] {
        f.human.send_direct_message("thread", &signed.message_id, "author-device", b"encrypted")?;
        let result = project(&f.human, signed, &signed.message_id)?;
        assert!(!result.accepted && result.retryable && result.queued);
    }
    assert_eq!(pending_count(&f.human)?, 2);
    for signed in [&two, &three, &four] {
        assert!(project(&f.author, signed, &signed.message_id)?.accepted);
    }
    assert!(project(&f.human, &two, "v2")?.accepted);
    let peer = f.human.surface_get("s", 0, None)?;
    let author = f.author.surface_get("s", 0, None)?;
    for field in ["snapshot", "version", "surface_hash", "closed", "hash_history", "out_of_sync"] {
        assert_eq!(peer[field], author[field]);
    }
    assert_eq!(pending_count(&f.human)?, 0);
    assert!(project(&f.human, &three, "redelivered-v3")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 4);
    Ok(())
}
#[test]
fn future_event_survives_restart_and_waits_for_create() -> TestResult {
    let mut f = Fixture::new()?;
    let two = stream(&f.author, "early", 2, "arrived early")?;
    f.human.send_direct_message("thread", "early", "author-device", b"encrypted")?;
    let held = project(&f.human, &two, "early")?;
    assert!(held.retryable && held.queued);
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 0);
    assert!(f.human.surface_get("s", 0, None)?["snapshot"].is_null());
    f.human = RamfluxClient::new();
    f.human.create_identity_root("human", [35; 32]);
    f.human.create_device_branch("human", "human-device", 1, [36; 32]);
    f.human.open_account_index(f.root.join("human"))?;
    f.human.unlock_account("human", b"surface-test-secret")?;
    let first =
        carrier(&f.author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    assert!(project(&f.human, &first, "create")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 2);
    assert_eq!(
        f.human.surface_get("s", 0, None)?["snapshot"]["components"][0]["text"],
        "arrived early"
    );
    assert_eq!(pending_count(&f.human)?, 0);
    Ok(())
}
#[test]
fn conflicting_pending_message_cannot_replace_the_verified_original() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let two = stream(&f.author, "v2", 2, "")?;
    let first = stream(&f.author, "future", 3, "original")?;
    let conflict = stream(&f.author, "future", 3, "replacement")?;
    f.human.send_direct_message("thread", "future", "author-device", b"encrypted")?;
    assert!(project(&f.human, &first, "future")?.queued);
    let rejected = project(&f.human, &conflict, "conflict")?;
    assert!(!rejected.accepted);
    assert_eq!(rejected.renderer_error.ok_or("error")?["code"], "message_id_conflict");
    assert!(project(&f.human, &two, "v2")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?["snapshot"]["components"][0]["text"], "original");
    Ok(())
}
#[test]
fn bounded_queue_reports_backpressure_and_rejected_gap_can_be_retried() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let two = stream(&f.author, "v2", 2, "")?;
    for version in 3..=35 {
        let id = format!("future-{version}");
        let signed = stream(&f.author, &id, version, "x")?;
        f.human.send_direct_message("thread", &id, "author-device", b"encrypted")?;
        let result = project(&f.human, &signed, &id)?;
        assert!(result.retryable);
        assert_eq!(result.queued, version < 35);
    }
    assert_eq!(pending_count(&f.human)?, 32);
    assert!(project(&f.human, &two, "v2")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 34);
    let retry = stream(&f.author, "future-35", 35, "x")?;
    assert!(project(&f.human, &retry, "retry")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 35);
    assert_eq!(pending_count(&f.human)?, 0);
    Ok(())
}

#[test]
fn expired_gap_is_visible_then_recovers_from_explicit_author_resync() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let two = stream(&f.author, "v2", 2, "one")?;
    let three = stream(&f.author, "v3", 3, "two")?;
    f.human.send_direct_message("thread", "v3", "author-device", b"encrypted")?;
    assert!(project(&f.human, &three, "v3")?.queued);
    let pending_key = super::super::pending::pending_key(&three)?;
    let mut row: Value = f.human.account_db()?.load_actor_state(&pending_key)?.ok_or("pending")?;
    row["expires_at"] = json!(0);
    f.human.account_db()?.persist_actor_state(&pending_key, &row)?;
    f.human.expire_surface_pending()?;
    assert_eq!(f.human.surface_get("s", 0, None)?["out_of_sync"], true);
    assert_eq!(pending_count(&f.human)?, 0);
    for signed in [&two, &three] {
        assert!(project(&f.author, signed, &signed.message_id)?.accepted);
    }
    let mut four = stream(&f.author, "v4", 4, "three")?;
    f.author.attach_surface_snapshot(&mut four)?;
    four = f.author.sign_surface_carrier(four)?;
    assert!(four.snapshot.is_some());
    assert!(project(&f.author, &four, "v4")?.accepted);
    let reference = four.surface_reference()?;
    let resync = f.author.prepare_surface_resync(&reference, "resync-v4")?;
    assert!(project(&f.human, &resync, "resync-v4")?.accepted);
    let recovered = f.human.surface_get("s", 0, None)?;
    assert_eq!(recovered["version"], 4);
    assert_eq!(recovered["out_of_sync"], false);
    assert_eq!(recovered["snapshot"]["components"][0]["text"], "onetwothree");
    assert_eq!(recovered["surface_hash"], f.author.surface_get("s", 0, None)?["surface_hash"]);
    assert!(project(&f.human, &two, "covered-v2")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?, recovered);
    Ok(())
}

#[test]
fn holdback_byte_budget_and_original_envelope_expiry_are_enforced() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let mut accepted = 0;
    for version in 3..=8 {
        let mut signed = stream(&f.author, &format!("large-{version}"), version, "x")?;
        let mut raw = ramflux_protocol::decode_base64url(&signed.wire_base64)?;
        raw.extend(std::iter::repeat_n(b' ', 200_000));
        signed.wire_base64 = ramflux_protocol::encode_base64url(raw);
        signed = f.author.sign_surface_carrier(signed)?;
        let held = project(&f.human, &signed, &signed.message_id)?;
        accepted += usize::from(held.queued);
    }
    assert!(accepted > 0 && accepted < 6);
    assert_eq!(pending_count(&f.human)?, accepted);
    let mut expired = stream(&f.author, "already-expired", 3, "x")?;
    expired.message_id = "expired-wire".into();
    expired = f.author.sign_surface_carrier(expired)?;
    f.human.project_surface_message(
        "thread",
        "expired",
        crate::client::surface::SurfaceSender {
            principal: "author",
            device: "author-device",
            envelope_id: "expired",
            expires_at: Some(0),
            group_epoch: None,
        },
        &expired.bytes()?,
        false,
    )?;
    f.human.expire_surface_pending()?;
    assert!(
        f.human
            .account_db()?
            .load_actor_state::<Value>(&super::super::pending::pending_key(&expired)?)?
            .is_none()
    );
    assert!(f.human.surface_delivery_receipt(&expired)?.is_none());
    Ok(())
}

#[test]
fn one_author_cannot_exhaust_another_authors_holdback_share() -> TestResult {
    let f = Fixture::new()?;
    for surface in ["s", "second"] {
        for version in 3..=34 {
            let mut signed = stream(&f.author, &format!("{surface}-{version}"), version, "x")?;
            signed.surface_id = surface.into();
            let wire = event(
                version,
                C::StreamAppend(StreamAppendCommand {
                    surface_id: surface.into(),
                    component_id: "stream".into(),
                    text_delta: "x".into(),
                    final_: false,
                }),
            )?;
            signed.wire_base64 = ramflux_protocol::encode_base64url(wire);
            signed = f.author.sign_surface_carrier(signed)?;
            assert!(project(&f.human, &signed, &signed.message_id)?.queued);
        }
    }
    assert_eq!(pending_count(&f.human)?, 64);
    let mut first = carrier(
        &f.human,
        PayloadKind::Event,
        "other-create",
        &event(1, C::CreateSurface(snapshot()))?,
    )?;
    first.author_principal_id = "human".into();
    first = f.human.sign_surface_carrier(first)?;
    assert!(project(&f.human, &first, "other-create")?.accepted);
    let mut second = stream(&f.human, "other-v2", 2, "two")?;
    second.author_principal_id = "human".into();
    let wire = ramflux_protocol::decode_base64url(&second.wire_base64)?;
    attach_reference_hash(&f.human, &mut second, &wire)?;
    second = f.human.sign_surface_carrier(second)?;
    let mut third = stream(&f.human, "other-v3", 3, "three")?;
    third.author_principal_id = "human".into();
    let wire = ramflux_protocol::decode_base64url(&third.wire_base64)?;
    attach_reference_hash(&f.human, &mut third, &wire)?;
    third = f.human.sign_surface_carrier(third)?;
    assert!(project(&f.human, &third, "other-v3")?.queued);
    assert!(project(&f.human, &second, "other-v2")?.accepted);
    let reference = first.surface_reference()?;
    let view = f.human.surface_get_ref(&reference, 0, None)?;
    assert_eq!(view["version"], 3);
    assert_eq!(view["out_of_sync"], false);
    assert_eq!(view["snapshot"]["components"][0]["text"], "twothree");
    Ok(())
}

#[test]
fn explicit_signed_resync_fills_a_gap_without_waiting_for_holdback_expiry() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let two = stream(&f.author, "v2", 2, "one")?;
    assert!(project(&f.author, &two, "two")?.accepted);
    let mut three = stream(&f.author, "v3", 3, "two")?;
    f.author.attach_surface_snapshot(&mut three)?;
    three = f.author.sign_surface_carrier(three)?;
    assert!(project(&f.author, &three, "three-author")?.accepted);
    assert!(project(&f.human, &three, "three-human")?.queued);
    let resync = f.author.prepare_surface_resync(&three.surface_reference()?, "resync-v3")?;
    assert!(project(&f.human, &resync, "resync-v3")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 3);
    assert_eq!(
        f.human.surface_get("s", 0, None)?["surface_hash"],
        f.author.surface_get("s", 0, None)?["surface_hash"]
    );
    assert_eq!(pending_count(&f.human)?, 0);
    Ok(())
}
