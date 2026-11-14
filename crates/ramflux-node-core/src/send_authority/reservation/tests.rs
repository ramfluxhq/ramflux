// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

const NOW: u64 = 1000;

fn digest(byte: u8) -> String {
    ramflux_protocol::encode_base64url([byte; 32])
}

fn acquire(root: u8, operation: u8) -> ReservationRequest {
    ReservationRequest {
        version: 1,
        request_id: digest(1),
        operation_id: digest(operation),
        recipient_root: digest(root),
        slot_id: Some(digest(root)),
        reservation_id: None,
        reservation_generation: None,
        origin_incarnation: digest(2),
        action: ReservationAction::Acquire,
    }
}

fn continue_request(
    request: &ReservationRequest,
    reply: &ReservationReply,
    action: ReservationAction,
) -> ReservationRequest {
    ReservationRequest {
        reservation_id: reply.reservation_id.clone(),
        reservation_generation: reply.reservation_generation,
        action,
        ..request.clone()
    }
}

#[test]
fn one_origin_cannot_spend_another_origins_root_quota() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let db = redb::Database::create(temp.path().join("notify.redb"))?;
    initialize(&db, 4, &["origin-b".into(), "origin-a".into()])?;
    for root in [10, 11] {
        let request = acquire(root, root);
        let reply = apply(&db, "origin-a", &request, NOW)?;
        assert_eq!(reply.phase, ReservationPhase::Reserved, "origin A lost its reserved share");
        let active = apply(
            &db,
            "origin-a",
            &continue_request(&request, &reply, ReservationAction::Activate),
            NOW,
        )?;
        assert_eq!(active.phase, ReservationPhase::Active, "activation did not commit");
    }
    let refused = apply(&db, "origin-a", &acquire(12, 12), NOW)?;
    assert_eq!(
        refused.reason,
        Some(ReservationRefusal::Capacity),
        "origin A borrowed B's capacity"
    );
    let other = apply(&db, "origin-b", &acquire(20, 20), NOW)?;
    assert_eq!(
        other.phase,
        ReservationPhase::Reserved,
        "empty holds in A blocked B's admitted share"
    );
    assert!(
        initialize(&db, 2, &["origin-a".into(), "origin-b".into()]).is_err(),
        "configuration reduced an occupied quota"
    );
    Ok(())
}

#[test]
fn activated_orphans_are_discoverable_after_ack_loss_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let path = temp.path().join("notify.redb");
    let request = acquire(10, 11);
    let activated = {
        let db = redb::Database::create(&path)?;
        initialize(&db, 2, &["origin-a".into(), "origin-b".into()])?;
        let reserved = apply(&db, "origin-a", &request, NOW)?;
        apply(
            &db,
            "origin-a",
            &continue_request(&request, &reserved, ReservationAction::Activate),
            NOW,
        )?
    };
    let db = redb::Database::open(&path)?;
    initialize(&db, 2, &["origin-a".into(), "origin-b".into()])?;
    let query = ReservationListRequest {
        version: 1,
        request_id: digest(3),
        notify_boot: digest(4),
        after_generation: None,
    };
    let mine = list(&db, "origin-a", &digest(4), &query)?;
    let row = mine.rows.first().expect("test: lost-ACK reservation must be discoverable");
    assert_eq!(
        row.reservation_id,
        activated.reservation_id.clone().expect("test: active receipt ID"),
        "restart lost reservation ownership"
    );
    assert_eq!(row.phase, ReservationPhase::Active, "reopen reset an activated reservation");
    assert!(
        list(&db, "origin-b", &digest(4), &query)?.rows.is_empty(),
        "enumeration exposed another origin's tuple"
    );
    assert_eq!(
        prune(&db, NOW + UNUSED_RESERVATION_TTL_SECONDS + 1)?,
        0,
        "a timeout guessed an active orphan empty"
    );
    let tx = db.begin_write()?;
    notify_retired(&tx, &row.reservation_id, row.reservation_generation, NOW + 120)?;
    tx.commit()?;
    apply(
        &db,
        "origin-a",
        &continue_request(&request, &activated, ReservationAction::Retire),
        NOW + 1,
    )?;
    assert_eq!(prune(&db, NOW + 119)?, 0, "component release ignored its denial horizon");
    assert_eq!(prune(&db, NOW + 120)?, 1, "fully retired root reservation was not released");
    let fresh = apply(&db, "origin-a", &acquire(12, 13), NOW + 121)?;
    assert_eq!(
        fresh.phase,
        ReservationPhase::Reserved,
        "safe root retirement imposed a lifetime recipient cap"
    );
    assert_eq!(
        apply(
            &db,
            "origin-a",
            &continue_request(&request, &activated, ReservationAction::Activate),
            NOW + 121
        )?
        .reason,
        Some(ReservationRefusal::Conflict),
        "delayed activation resurrected a retired identity"
    );
    Ok(())
}

#[test]
fn never_activated_reservation_expires_without_retry_refresh()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let db = redb::Database::create(temp.path().join("notify.redb"))?;
    initialize(&db, 1, &["origin-a".into()])?;
    let request = acquire(10, 11);
    let first = apply(&db, "origin-a", &request, NOW)?;
    let retry = apply(&db, "origin-a", &request, NOW + 29)?;
    assert_eq!(retry.expires_at, first.expires_at, "an idempotent retry extended the unused lease");
    assert_eq!(
        prune(&db, NOW + 30)?,
        1,
        "never-used reservation did not expire at the fixed boundary"
    );
    assert_eq!(
        apply(
            &db,
            "origin-a",
            &continue_request(&request, &first, ReservationAction::Activate),
            NOW + 30
        )?
        .reason,
        Some(ReservationRefusal::Conflict),
        "expired receipt authorized an origin write"
    );
    Ok(())
}

#[test]
fn fully_retired_root_share_serves_more_than_two_hundred_fifty_six_recipients()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let db = redb::Database::create(temp.path().join("notify.redb"))?;
    initialize(&db, 1, &["origin-a".into()])?;
    for number in 0..260u64 {
        let now = NOW + number * 121;
        let root =
            ramflux_crypto::blake3_256_base64url("test.recipient.root", &number.to_be_bytes());
        let request = ReservationRequest {
            recipient_root: root.clone(),
            slot_id: Some(root),
            ..acquire(10, 11)
        };
        let receipt = apply(&db, "origin-a", &request, now)?;
        assert_eq!(
            receipt.phase,
            ReservationPhase::Reserved,
            "recipient {number} hit a lifetime ceiling"
        );
        let active = apply(
            &db,
            "origin-a",
            &continue_request(&request, &receipt, ReservationAction::Activate),
            now,
        )?;
        apply(
            &db,
            "origin-a",
            &continue_request(&request, &active, ReservationAction::Retire),
            now,
        )?;
        assert_eq!(prune(&db, now + 120)?, 0, "origin deletion guessed notify empty");
        let tx = db.begin_write()?;
        notify_retired(
            &tx,
            active.reservation_id.as_deref().ok_or("test: receipt id")?,
            active.reservation_generation.ok_or("test: receipt generation")?,
            now + 120,
        )?;
        tx.commit()?;
        assert_eq!(
            prune(&db, now + 120)?,
            1,
            "all safe component acknowledgements did not release recipient {number}"
        );
    }
    Ok(())
}

#[test]
fn receipt_pages_are_bounded_and_identity_and_tuple_substitution_refuse()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let db = redb::Database::create(temp.path().join("notify.redb"))?;
    initialize(&db, 12, &["origin-a".into(), "origin-b".into()])?;
    let mut originals = Vec::new();
    for root in 10..16 {
        let request = acquire(root, root);
        let reply = apply(&db, "origin-a", &request, NOW)?;
        originals.push((request, reply));
    }
    let query = ReservationListRequest {
        version: 1,
        request_id: digest(21),
        notify_boot: digest(22),
        after_generation: None,
    };
    let page = list(&db, "origin-a", &digest(22), &query)?;
    assert_eq!(page.rows.len(), 4, "page exceeded the closed four-row contract");
    let next = list(
        &db,
        "origin-a",
        &digest(22),
        &ReservationListRequest { after_generation: page.next_generation, ..query.clone() },
    )?;
    assert_eq!(next.rows.len(), 2, "global generation cursor skipped retained receipts");
    assert!(next.next_generation.is_none(), "final page did not terminate");
    let (request, receipt) = originals.first().ok_or("test: original receipt")?;
    for changed in [
        ReservationRequest {
            origin_incarnation: digest(99),
            ..continue_request(request, receipt, ReservationAction::Activate)
        },
        ReservationRequest {
            slot_id: Some(digest(99)),
            ..continue_request(request, receipt, ReservationAction::Activate)
        },
        ReservationRequest {
            reservation_generation: receipt.reservation_generation.map(|value| value + 1),
            ..continue_request(request, receipt, ReservationAction::Activate)
        },
    ] {
        assert_eq!(
            apply(&db, "origin-a", &changed, NOW)?.reason,
            Some(ReservationRefusal::Conflict),
            "substituted tuple activated a reservation"
        );
    }
    assert_eq!(
        apply(
            &db,
            "origin-b",
            &continue_request(request, receipt, ReservationAction::Activate),
            NOW
        )?
        .reason,
        Some(ReservationRefusal::Conflict),
        "foreign origin activated another identity's tuple"
    );
    Ok(())
}

#[test]
fn reservation_wire_requires_explicit_nulls_and_closed_original_json()
-> Result<(), Box<dyn std::error::Error>> {
    let request = ReservationListRequest {
        version: 1,
        request_id: digest(0),
        notify_boot: digest(0),
        after_generation: None,
    };
    let wire = ramflux_protocol::canonical_json_bytes(&request)?;
    let expected = format!(
        "{{\"after_generation\":null,\"notify_boot\":\"{}\",\"request_id\":\"{}\",\"version\":1}}",
        digest(0),
        digest(0),
    );
    assert_eq!(wire, expected.as_bytes(), "reservation listing wire contract drifted");
    let decoded: ReservationListRequest = ramflux_protocol::parse_i_json(&wire)?;
    assert_eq!(decoded, request, "listing golden failed its strict decoder");
    for invalid in [
        format!(
            "{{\"notify_boot\":\"{}\",\"request_id\":\"{}\",\"version\":1}}",
            digest(0),
            digest(0)
        ),
        expected.replace("\"version\":1", "\"version\":1,\"extra\":null"),
        expected.replace("\"version\":1", "\"version\":1,\"version\":1"),
        expected.replace("\"version\":1", "\"version\":null"),
        expected.replace("\"after_generation\":null", "\"after_generation\":9007199254740992"),
    ] {
        assert!(
            ramflux_protocol::parse_i_json::<ReservationListRequest>(invalid.as_bytes()).is_err(),
            "missing/null/unknown/duplicate/unsafe-integer reservation wire was accepted: {invalid}"
        );
    }
    let acquire = acquire(10, 11);
    let mut value = serde_json::to_value(&acquire)?;
    let object = value.as_object_mut().ok_or("test: acquire object")?;
    for member in ["slot_id", "reservation_id", "reservation_generation"] {
        let saved = object.remove(member).ok_or("test: required acquire member")?;
        let bytes = ramflux_protocol::canonical_json_bytes(&object)?;
        assert!(
            ramflux_protocol::parse_i_json::<ReservationRequest>(&bytes).is_err(),
            "acquire omitted required nullable member {member}"
        );
        object.insert(member.into(), saved);
    }
    Ok(())
}
