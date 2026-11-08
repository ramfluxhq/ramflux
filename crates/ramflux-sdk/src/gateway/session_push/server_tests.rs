// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `capable_server_frame_codecs`: decoders for the negotiated server frames.
//!
//! Oracle: node-core builds every frame from distinct, non-default values (distinct sequence
//! and deadline sentinels, so a swap or a defaulted field is visible). The SDK decodes the
//! bytes in both producer orders, and each decoded field is compared with the same source
//! values through an explicitly constructed expected frame. Server frames are decode-only in
//! the SDK, so a re-encode comparison does not apply.
use super::{
    AckOutcome, AckResult, CapableServerFrame as S, EntryGoneReason, IncarnationId, KnownLoss,
    PageEntryRecord, PageReason, PushNackReason, ResyncReason, SessionEstablished,
    decode_server_frame,
};
use crate::{GatewayCursor, GatewayInboxEntry};
use n::SessionPushNackReason as W;
use ramflux_node_core as n;
use serde_json::{Value, json};
use std::sync::Mutex;

const E: &str = "0123456789abcdef0123456789abcdef";
const BAD_E: &str = "invalid inbox incarnation id";
const FRAMES: [&str; 12] = [
    "session_established",
    "deliver",
    "submit_accepted",
    "resume_page",
    "entry",
    "entry_too_large",
    "entry_gone",
    "ack_batch",
    "ack",
    "cursor",
    "resync",
    "nack",
];

/// A distinct valid incarnation per frame kind, so a swapped field is detected.
fn eid(n: u8) -> String {
    format!("{n:02x}{}", &E[2..])
}

fn id(n: u8) -> IncarnationId {
    IncarnationId::try_from(eid(n)).unwrap()
}

fn envelope(tag: &str) -> ramflux_protocol::Envelope {
    serde_json::from_value(json!({
        "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
        "signing_key_id":"dev","signature_alg":"ed25519","signature":"fixture",
        "envelope_id":format!("env-{tag}"),"source_principal_id":"p","source_device_id":"d",
        "target_delivery_id":format!("target-{tag}"),"delivery_class":"opaque_event",
        "priority":"normal","ttl":600,"created_at":1,"encrypted_payload":"opaque",
        "payload_hash":format!("hash-{tag}")
    }))
    .unwrap()
}

fn node_entry(seq: u64, tag: &str) -> n::InboxEntry {
    n::InboxEntry {
        inbox_seq: seq,
        target_delivery_id: format!("target-{tag}"),
        envelope: envelope(tag),
    }
}

fn sdk_entry(seq: u64, tag: &str) -> GatewayInboxEntry {
    GatewayInboxEntry {
        forwarded: false,
        inbox_seq: seq,
        target_delivery_id: format!("target-{tag}"),
        envelope: envelope(tag),
    }
}

fn node_record(seq: u64, tag: &str, retain_until: i64) -> n::PageEntryRecord {
    n::PageEntryRecord { entry: node_entry(seq, tag), retain_until }
}

fn sdk_record(seq: u64, tag: &str, retain_until: i64) -> PageEntryRecord {
    PageEntryRecord { entry: sdk_entry(seq, tag), retain_until }
}

fn node_cursor(seq: u64) -> n::InboxCursorResponse {
    n::InboxCursorResponse {
        target_delivery_id: format!("cursor-target-{seq}"),
        inbox_seq: seq,
        last_envelope_id: Some(format!("last-{seq}")),
        acked_envelope_ids: vec![format!("acked-a-{seq}"), format!("acked-b-{seq}")],
        nacked_envelope_ids: [(format!("nacked-{seq}"), ramflux_protocol::NackReason::Expired)]
            .into_iter()
            .collect(),
    }
}

fn sdk_cursor(seq: u64) -> GatewayCursor {
    GatewayCursor {
        target_delivery_id: format!("cursor-target-{seq}"),
        inbox_seq: seq,
        last_envelope_id: Some(format!("last-{seq}")),
        acked_envelope_ids: vec![format!("acked-a-{seq}"), format!("acked-b-{seq}")],
        nacked_envelope_ids: [(format!("nacked-{seq}"), ramflux_protocol::NackReason::Expired)]
            .into_iter()
            .collect(),
    }
}

fn node_result(
    seq: u64,
    outcome: n::SessionAckOutcome,
    reason: Option<&str>,
) -> n::SessionAckResult {
    n::SessionAckResult { inbox_seq: seq, outcome, reason: reason.map(Into::into) }
}

fn sdk_result(seq: u64, outcome: AckOutcome, reason: Option<&str>) -> AckResult {
    AckResult { inbox_seq: seq, outcome, reason: reason.map(Into::into) }
}

/// One node-core frame and the decoded value every field must equal.
fn case(kind: &str) -> (n::SessionPushServerFrame, S) {
    use n::SessionPushServerFrame as F;
    match kind {
        "session_established" => (
            F::SessionEstablished {
                session: n::SessionPushEstablishedFrame {
                    session: n::GatewaySessionEstablishedFrame {
                        session_id: "sess-1".into(),
                        gateway_id: "gw-1".into(),
                        accepted_cursor: Some(node_cursor(41)),
                        resume_token: "token-1".into(),
                        resume_window_seconds: 77,
                    },
                    capabilities: vec![
                        ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into(),
                        "second.capability".into(),
                    ],
                    inbox_incarnation_id: eid(0x11),
                },
            },
            S::SessionEstablished {
                session: SessionEstablished {
                    session_id: "sess-1".into(),
                    gateway_id: "gw-1".into(),
                    accepted_cursor: Some(sdk_cursor(41)),
                    resume_token: "token-1".into(),
                    resume_window_seconds: 77,
                    capabilities: vec![
                        ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into(),
                        "second.capability".into(),
                    ],
                    inbox_incarnation_id: id(0x11),
                },
            },
        ),
        "deliver" => (
            F::Deliver {
                entry: node_entry(101, "d"),
                incarnation_id: eid(0x12),
                retain_until: 1_111,
            },
            S::Deliver {
                entry: sdk_entry(101, "d"),
                incarnation_id: id(0x12),
                retain_until: 1_111,
            },
        ),
        "submit_accepted" => (
            F::SubmitAccepted {
                incarnation_id: eid(0x13),
                envelope_id: "env-sa".into(),
                target_delivery_id: "target-sa".into(),
                inbox_seq: 202,
            },
            S::SubmitAccepted {
                incarnation_id: id(0x13),
                envelope_id: "env-sa".into(),
                target_delivery_id: "target-sa".into(),
                inbox_seq: 202,
            },
        ),
        "resume_page" => (resume_page_case(), resume_page_expected()),
        "entry" => (
            F::Entry { incarnation_id: eid(0x15), record: Box::new(node_record(31, "e", 5_555)) },
            S::Entry { incarnation_id: id(0x15), record: Box::new(sdk_record(31, "e", 5_555)) },
        ),
        "entry_too_large" => (
            F::EntryTooLarge { incarnation_id: eid(0x16), inbox_seq: 32, retain_until: 6_666 },
            S::EntryTooLarge { incarnation_id: id(0x16), inbox_seq: 32, retain_until: 6_666 },
        ),
        "entry_gone" => (
            F::EntryGone {
                incarnation_id: eid(0x17),
                inbox_seq: 33,
                observed_issued_inbox_seq: 34,
                reason: n::EntryGoneReason::AckWindowOverflow,
            },
            S::EntryGone {
                incarnation_id: id(0x17),
                inbox_seq: 33,
                observed_issued_inbox_seq: 34,
                reason: EntryGoneReason::AckWindowOverflow,
            },
        ),
        "ack_batch" => (
            F::AckBatch {
                incarnation_id: eid(0x18),
                cursor: node_cursor(42),
                results: vec![
                    node_result(51, n::SessionAckOutcome::Acked, None),
                    node_result(52, n::SessionAckOutcome::Rejected, Some("ack_backpressure_retry")),
                ],
            },
            S::AckBatch {
                incarnation_id: id(0x18),
                cursor: sdk_cursor(42),
                results: vec![
                    sdk_result(51, AckOutcome::Acked, None),
                    sdk_result(52, AckOutcome::Rejected, Some("ack_backpressure_retry")),
                ],
            },
        ),
        "ack" => (
            F::Ack { incarnation_id: eid(0x19), cursor: node_cursor(43) },
            S::Ack { incarnation_id: id(0x19), cursor: sdk_cursor(43) },
        ),
        "cursor" => (
            F::Cursor { incarnation_id: eid(0x1a), cursor: Some(node_cursor(44)) },
            S::Cursor { incarnation_id: id(0x1a), cursor: Some(sdk_cursor(44)) },
        ),
        "resync" => (
            F::Resync {
                incarnation_id: eid(0x1b),
                target_delivery_id: "target-r".into(),
                after_inbox_seq: 35,
                reason: n::SessionPushResyncReason::NotPushed,
            },
            S::Resync {
                incarnation_id: id(0x1b),
                target_delivery_id: "target-r".into(),
                after_inbox_seq: 35,
                reason: ResyncReason::NotPushed,
            },
        ),
        "nack" => (
            F::Nack {
                reason: n::SessionPushNackReason::InvalidResumeToken,
                incarnation_id: Some(eid(0x1c)),
            },
            S::Nack { reason: PushNackReason::InvalidResumeToken, incarnation_id: Some(id(0x1c)) },
        ),
        other => panic!("unknown vector {other}"),
    }
}

fn resume_page_case() -> n::SessionPushServerFrame {
    n::SessionPushServerFrame::ResumePage {
        target_delivery_id: "target-p".into(),
        incarnation_id: eid(0x14),
        after_inbox_seq: 3,
        covered_through_seq: 17,
        issued_inbox_seq: 19,
        settled_through_seq: 5,
        entries: vec![node_record(21, "p1", 3_333), node_record(22, "p2", 4_444)],
        known_losses: vec![
            n::KnownLoss { from_seq: 6, to_seq: 7, reason: n::PageReason::Expired },
            n::KnownLoss { from_seq: 9, to_seq: 9, reason: n::PageReason::Nacked },
        ],
        oversize_next: Some(23),
        more: true,
    }
}

fn resume_page_expected() -> S {
    S::ResumePage {
        target_delivery_id: "target-p".into(),
        incarnation_id: id(0x14),
        after_inbox_seq: 3,
        covered_through_seq: 17,
        issued_inbox_seq: 19,
        settled_through_seq: 5,
        entries: vec![sdk_record(21, "p1", 3_333), sdk_record(22, "p2", 4_444)],
        known_losses: vec![
            KnownLoss { from_seq: 6, to_seq: 7, reason: PageReason::Expired },
            KnownLoss { from_seq: 9, to_seq: 9, reason: PageReason::Nacked },
        ],
        oversize_next: Some(23),
        more: true,
    }
}

/// Producer order (i): node-core struct order.
fn typed_bytes(frame: &n::SessionPushServerFrame) -> Vec<u8> {
    serde_json::to_vec(frame).unwrap()
}

/// Producer order (ii): sorted-key `Value` order, as forwarded router JSON.
fn forwarded_bytes(frame: &n::SessionPushServerFrame) -> Vec<u8> {
    serde_json::to_vec(&serde_json::to_value(frame).unwrap()).unwrap()
}

/// Both producer orders must decode to exactly the expected source values.
fn assert_fields(frame: &n::SessionPushServerFrame, expected: &S, what: &str) {
    assert_eq!(&decode_server_frame(&typed_bytes(frame)).unwrap(), expected, "{what} typed");
    assert_eq!(&decode_server_frame(&forwarded_bytes(frame)).unwrap(), expected, "{what} fwd");
}

fn value(kind: &str) -> Value {
    serde_json::to_value(case(kind).0).unwrap()
}

fn walk<'a>(root: &'a mut Value, parents: &[&str]) -> &'a mut Value {
    let mut at = root;
    for key in parents {
        at = match key.parse::<usize>() {
            Ok(index) if at.is_array() => &mut at[index],
            _ => at.get_mut(*key).unwrap(),
        };
    }
    at
}

fn set(root: &mut Value, path: &[&str], new: Value) {
    let (last, parents) = path.split_last().unwrap();
    walk(root, parents)[*last] = new;
}

fn remove(root: &mut Value, path: &[&str]) {
    let (last, parents) = path.split_last().unwrap();
    let object = walk(root, parents).as_object_mut().unwrap();
    assert!(object.remove(*last).is_some(), "{path:?} absent");
}

/// Row failures are collected so one run reports every mismatch.
static MISMATCHES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// serde appends " at line L column C" to JSON errors; nothing else is stripped.
fn without_location(message: &str) -> &str {
    message.rsplit_once(" at line ").map_or(message, |(head, _)| head)
}

/// Asserts the decode of a valid vector first, then mutates exactly one field and compares the
/// complete error text.
fn refused(row: &str, mut vector: Value, mutate: impl FnOnce(&mut Value), expected: &str) {
    assert!(
        decode_server_frame(&serde_json::to_vec(&vector).unwrap()).is_ok(),
        "{row}: the unmutated vector must decode"
    );
    mutate(&mut vector);
    let outcome = decode_server_frame(&serde_json::to_vec(&vector).unwrap());
    let line = match outcome {
        Err(ramflux_protocol::ProtocolError::IJson(error))
            if without_location(&error.to_string()) == expected =>
        {
            return;
        }
        Err(error) => format!("{row}: expected {expected:?}, got {:?}", error.to_string()),
        Ok(frame) => format!("{row}: expected {expected:?}, but it decoded to {frame:?}"),
    };
    MISMATCHES.lock().unwrap().push(line);
}

fn e_path(kind: &str) -> Vec<&'static str> {
    if kind == "session_established" {
        vec!["session", "inbox_incarnation_id"]
    } else {
        vec!["incarnation_id"]
    }
}

fn ack_batch_value(seq: u64, outcome: n::SessionAckOutcome, reason: Option<&str>) -> Value {
    serde_json::to_value(n::SessionPushServerFrame::AckBatch {
        incarnation_id: eid(0x18),
        cursor: node_cursor(42),
        results: vec![node_result(seq, outcome, reason)],
    })
    .unwrap()
}

fn loss_value(from: u64, to: u64) -> Value {
    serde_json::to_value(n::SessionPushServerFrame::ResumePage {
        target_delivery_id: "target-p".into(),
        incarnation_id: eid(0x14),
        after_inbox_seq: 3,
        covered_through_seq: 17,
        issued_inbox_seq: 19,
        settled_through_seq: 5,
        entries: vec![],
        known_losses: vec![n::KnownLoss {
            from_seq: from,
            to_seq: to,
            reason: n::PageReason::Expired,
        }],
        oversize_next: None,
        more: false,
    })
    .unwrap()
}

#[test]
fn capable_server_frame_codecs() {
    // (p1) every variant: both producer orders decode to the node-core source values.
    for kind in FRAMES {
        let (frame, expected) = case(kind);
        assert_fields(&frame, &expected, kind);
    }
    // Raw-byte fixture for a typed frame.
    let accepted = typed_bytes(&case("submit_accepted").0);
    assert_eq!(
        std::str::from_utf8(&accepted).unwrap(),
        concat!(
            r#"{"frame_type":"submit_accepted","incarnation_id":"1323456789abcdef0123456789abcdef","#,
            r#""envelope_id":"env-sa","target_delivery_id":"target-sa","inbox_seq":202}"#
        )
    );

    // (p2) nack with a null incarnation and with an E; cursor frame with a null cursor.
    let nack = |incarnation_id: Option<String>| n::SessionPushServerFrame::Nack {
        reason: n::SessionPushNackReason::Busy,
        incarnation_id,
    };
    assert_fields(
        &nack(None),
        &S::Nack { reason: PushNackReason::Busy, incarnation_id: None },
        "nack null",
    );
    assert_fields(
        &nack(Some(eid(0x1d))),
        &S::Nack { reason: PushNackReason::Busy, incarnation_id: Some(id(0x1d)) },
        "nack E",
    );
    assert_fields(
        &n::SessionPushServerFrame::Cursor { incarnation_id: eid(0x1a), cursor: None },
        &S::Cursor { incarnation_id: id(0x1a), cursor: None },
        "cursor null",
    );

    // (p3) known loss with equal endpoints is covered by the resume page above (9..9) and
    // with from < to (6..7). (p9) oversize_next null.
    let mut no_oversize = resume_page_case();
    if let n::SessionPushServerFrame::ResumePage { oversize_next, more, .. } = &mut no_oversize {
        *oversize_next = None;
        *more = false;
    }
    let mut expected = resume_page_expected();
    if let S::ResumePage { oversize_next, more, .. } = &mut expected {
        *oversize_next = None;
        *more = false;
    }
    assert_fields(&no_oversize, &expected, "oversize null");

    // (p4) each PageReason alternative, (p5) each EntryGoneReason alternative.
    for (wire, expected) in [
        (n::PageReason::Expired, PageReason::Expired),
        (n::PageReason::AckWindowOverflow, PageReason::AckWindowOverflow),
        (n::PageReason::Nacked, PageReason::Nacked),
        (n::PageReason::Aborted, PageReason::Aborted),
    ] {
        let mut frame = resume_page_case();
        let mut want = resume_page_expected();
        if let (
            n::SessionPushServerFrame::ResumePage { known_losses, .. },
            S::ResumePage { known_losses: want_losses, .. },
        ) = (&mut frame, &mut want)
        {
            known_losses[0].reason = wire;
            want_losses[0].reason = expected;
        }
        assert_fields(&frame, &want, "page reason");
    }
    for (wire, expected) in [
        (n::EntryGoneReason::Expired, EntryGoneReason::Expired),
        (n::EntryGoneReason::AckWindowOverflow, EntryGoneReason::AckWindowOverflow),
        (n::EntryGoneReason::Nacked, EntryGoneReason::Nacked),
        (n::EntryGoneReason::Aborted, EntryGoneReason::Aborted),
        (n::EntryGoneReason::Unknown, EntryGoneReason::Unknown),
    ] {
        let (mut frame, mut want) = case("entry_gone");
        if let (
            n::SessionPushServerFrame::EntryGone { reason, .. },
            S::EntryGone { reason: want_reason, .. },
        ) = (&mut frame, &mut want)
        {
            *reason = wire;
            *want_reason = expected;
        }
        assert_fields(&frame, &want, "gone reason");
    }

    // (p6) each ack outcome, plus `rejected` with each of its two reasons.
    let ack_rows: [(n::SessionAckOutcome, Option<&str>, AckOutcome); 6] = [
        (n::SessionAckOutcome::Acked, None, AckOutcome::Acked),
        (n::SessionAckOutcome::AlreadySettled, None, AckOutcome::AlreadySettled),
        (n::SessionAckOutcome::NotFound, None, AckOutcome::NotFound),
        (n::SessionAckOutcome::InvalidSeq, None, AckOutcome::InvalidSeq),
        (n::SessionAckOutcome::Rejected, Some("ack_backpressure_retry"), AckOutcome::Rejected),
        (n::SessionAckOutcome::Rejected, Some("invalid_seq"), AckOutcome::Rejected),
    ];
    for (wire, reason, expected) in ack_rows {
        let frame = n::SessionPushServerFrame::AckBatch {
            incarnation_id: eid(0x18),
            cursor: node_cursor(42),
            results: vec![node_result(61, wire, reason)],
        };
        let want = S::AckBatch {
            incarnation_id: id(0x18),
            cursor: sdk_cursor(42),
            results: vec![sdk_result(61, expected, reason)],
        };
        assert_fields(&frame, &want, "ack outcome");
    }

    // (p7) each resync reason.
    for (wire, expected) in [
        (n::SessionPushResyncReason::QueueFull, ResyncReason::QueueFull),
        (n::SessionPushResyncReason::NotPushed, ResyncReason::NotPushed),
    ] {
        let (mut frame, mut want) = case("resync");
        if let (
            n::SessionPushServerFrame::Resync { reason, .. },
            S::Resync { reason: want_reason, .. },
        ) = (&mut frame, &mut want)
        {
            *reason = wire;
            *want_reason = expected;
        }
        assert_fields(&frame, &want, "resync reason");
    }

    // (p8) each capable nack reason.
    for (wire, expected) in [
        (W::IncarnationMismatch, PushNackReason::IncarnationMismatch),
        (W::InvalidSeq, PushNackReason::InvalidSeq),
        (W::InvalidLimit, PushNackReason::InvalidLimit),
        (W::CursorAhead, PushNackReason::CursorAhead),
        (W::PayloadTooLarge, PushNackReason::PayloadTooLarge),
        (W::AckBackpressureRetry, PushNackReason::AckBackpressureRetry),
        (W::GatewayRequestInvalid, PushNackReason::GatewayRequestInvalid),
        (W::InvalidResumeToken, PushNackReason::InvalidResumeToken),
        (W::Busy, PushNackReason::Busy),
    ] {
        assert_fields(
            &n::SessionPushServerFrame::Nack { reason: wire, incarnation_id: None },
            &S::Nack { reason: expected, incarnation_id: None },
            "nack reason",
        );
    }

    refusal_rows();
    let mismatches = MISMATCHES.lock().unwrap();
    assert!(mismatches.is_empty(), "refusal rows:\n{}", mismatches.join("\n"));
}

fn refusal_rows() {
    let unknown_variant = |name: &str, expected: &str| {
        format!("unknown variant `{name}`, expected one of {expected}")
    };
    // (r1) E of 31 characters at each of the 12 E sites, one row per site.
    for kind in FRAMES {
        refused(
            &format!("r1 {kind}"),
            value(kind),
            |v| set(v, &e_path(kind), json!(&E[..31])),
            BAD_E,
        );
    }
    // (r2) 33 characters, (r3) the non-hex character `g`, (r4) uppercase `A`: on `deliver`.
    let good = eid(0x12);
    for (row, bad) in [
        ("r2", format!("{good}0")),
        ("r3", format!("g{}", &good[1..])),
        ("r4", format!("A{}", &good[1..])),
    ] {
        refused(row, value("deliver"), |v| set(v, &["incarnation_id"], json!(bad)), BAD_E);
    }
    // (r5)-(r8) required and forbidden fields.
    refused(
        "r5",
        value("deliver"),
        |v| remove(v, &["incarnation_id"]),
        "missing field `incarnation_id`",
    );
    refused(
        "r6",
        value("deliver"),
        |v| remove(v, &["retain_until"]),
        "missing field `retain_until`",
    );
    refused(
        "r7",
        value("entry_too_large"),
        |v| remove(v, &["retain_until"]),
        "missing field `retain_until`",
    );
    refused(
        "r8",
        value("entry_gone"),
        |v| set(v, &["retain_until"], json!(1)),
        "unknown field `retain_until`, expected one of `incarnation_id`, `inbox_seq`, `observed_issued_inbox_seq`, `reason`",
    );
    // (r9) a loss with from_seq = to_seq + 1.
    refused(
        "r9",
        loss_value(5, 5),
        |v| set(v, &["known_losses", "0", "from_seq"], json!(6)),
        "known loss from_seq exceeds to_seq",
    );
    // (r10) page loss reason `unknown` is valid only for entry_gone; (r11) unknown gone reason.
    let page_reasons = "`expired`, `ack_window_overflow`, `nacked`, `aborted`";
    refused(
        "r10",
        loss_value(5, 5),
        |v| set(v, &["known_losses", "0", "reason"], json!("unknown")),
        &unknown_variant("unknown", page_reasons),
    );
    refused(
        "r11",
        value("entry_gone"),
        |v| set(v, &["reason"], json!("zz")),
        &unknown_variant("zz", "`expired`, `ack_window_overflow`, `nacked`, `aborted`, `unknown`"),
    );
    // (r12) unknown ack outcome.
    refused(
        "r12",
        value("ack_batch"),
        |v| set(v, &["results", "0", "outcome"], json!("zz")),
        &unknown_variant(
            "zz",
            "`acked`, `already_settled`, `not_found`, `invalid_seq`, `rejected`",
        ),
    );
    // (r13a-d) each null-required outcome, valid with a null reason, then only the reason
    // becomes non-null. (r14)/(r15) the same for `rejected` with an allowed reason.
    let null_required = [
        ("r13a", n::SessionAckOutcome::Acked),
        ("r13b", n::SessionAckOutcome::AlreadySettled),
        ("r13c", n::SessionAckOutcome::NotFound),
        ("r13d", n::SessionAckOutcome::InvalidSeq),
    ];
    for (row, outcome) in null_required {
        refused(
            row,
            ack_batch_value(61, outcome, None),
            |v| set(v, &["results", "0", "reason"], json!("x")),
            "ack reason must be null for this outcome",
        );
    }
    let rejected = || ack_batch_value(61, n::SessionAckOutcome::Rejected, Some("invalid_seq"));
    refused(
        "r14",
        rejected(),
        |v| set(v, &["results", "0", "reason"], json!("zz")),
        "rejected ack reason is not allowed",
    );
    refused(
        "r15",
        rejected(),
        |v| set(v, &["results", "0", "reason"], Value::Null),
        "rejected ack reason is not allowed",
    );
    // (r16) unknown resync reason; (r17) unknown capable nack reason.
    refused(
        "r16",
        value("resync"),
        |v| set(v, &["reason"], json!("zz")),
        "unknown variant `zz`, expected `queue_full` or `not_pushed`",
    );
    refused(
        "r17",
        value("nack"),
        |v| set(v, &["reason"], json!("zz")),
        &unknown_variant(
            "zz",
            "`incarnation_mismatch`, `invalid_seq`, `invalid_limit`, `cursor_ahead`, `payload_too_large`, `ack_backpressure_retry`, `gateway_request_invalid`, `invalid_resume_token`, `busy`",
        ),
    );
    // (r18) an extra unknown field on resume_page; (r19) unknown frame_type.
    refused(
        "r18",
        value("resume_page"),
        |v| set(v, &["extra"], json!(1)),
        "unknown field `extra`, expected one of `target_delivery_id`, `incarnation_id`, `after_inbox_seq`, `covered_through_seq`, `issued_inbox_seq`, `settled_through_seq`, `entries`, `known_losses`, `oversize_next`, `more`",
    );
    refused(
        "r19",
        value("deliver"),
        |v| set(v, &["frame_type"], json!("zz")),
        &unknown_variant(
            "zz",
            "`session_established`, `deliver`, `submit_accepted`, `resume_page`, `entry`, `entry_too_large`, `entry_gone`, `ack_batch`, `ack`, `cursor`, `resync`, `nack`",
        ),
    );
    // (r20)-(r22) required fields of session_established and submit_accepted.
    refused(
        "r20",
        value("session_established"),
        |v| remove(v, &["session", "inbox_incarnation_id"]),
        "missing field `inbox_incarnation_id`",
    );
    refused(
        "r21",
        value("session_established"),
        |v| remove(v, &["session", "capabilities"]),
        "missing field `capabilities`",
    );
    refused(
        "r22",
        value("submit_accepted"),
        |v| remove(v, &["inbox_seq"]),
        "missing field `inbox_seq`",
    );
}
