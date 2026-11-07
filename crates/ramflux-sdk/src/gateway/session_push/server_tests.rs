// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `capable_server_frame_codecs`: decoders for the negotiated server frames.
//!
//! Vectors are produced from node-core values in the two orders the gateway emits: struct
//! order (typed frames) and sorted-key `Value` order (frames forwarded from router JSON).
use super::{
    AckOutcome, CapableServerFrame, EntryGoneReason, PageReason, PushNackReason, ResyncReason,
    decode_server_frame,
};
use ramflux_node_core as n;
use serde_json::{Value, json};

use n::SessionPushNackReason as W;

const E: &str = "0123456789abcdef0123456789abcdef";
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

fn envelope() -> ramflux_protocol::Envelope {
    serde_json::from_value(json!({
        "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
        "signing_key_id":"dev","signature_alg":"ed25519","signature":"fixture",
        "envelope_id":"env-1","source_principal_id":"p","source_device_id":"d",
        "target_delivery_id":"target","delivery_class":"opaque_event","priority":"normal",
        "ttl":600,"created_at":1,"encrypted_payload":"opaque","payload_hash":"hash"
    }))
    .unwrap()
}

fn entry() -> n::InboxEntry {
    n::InboxEntry { inbox_seq: 7, target_delivery_id: "target".into(), envelope: envelope() }
}

fn record() -> n::PageEntryRecord {
    n::PageEntryRecord { entry: entry(), retain_until: 1_000 }
}

fn cursor() -> n::InboxCursorResponse {
    n::InboxCursorResponse {
        target_delivery_id: "target".into(),
        inbox_seq: 7,
        last_envelope_id: Some("env-1".into()),
        acked_envelope_ids: vec!["env-1".into()],
        nacked_envelope_ids: std::collections::BTreeMap::default(),
    }
}

fn result(outcome: n::SessionAckOutcome, reason: Option<&str>) -> n::SessionAckResult {
    n::SessionAckResult { inbox_seq: 7, outcome, reason: reason.map(Into::into) }
}

fn node_frame(kind: &str) -> n::SessionPushServerFrame {
    use n::SessionPushServerFrame as F;
    let id = || E.to_owned();
    match kind {
        "session_established" => F::SessionEstablished {
            session: n::SessionPushEstablishedFrame {
                session: n::GatewaySessionEstablishedFrame {
                    session_id: "s".into(),
                    gateway_id: "g".into(),
                    accepted_cursor: Some(cursor()),
                    resume_token: "t".into(),
                    resume_window_seconds: 30,
                },
                capabilities: vec![ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into()],
                inbox_incarnation_id: id(),
            },
        },
        "deliver" => F::Deliver { entry: entry(), incarnation_id: id(), retain_until: 1_000 },
        "submit_accepted" => F::SubmitAccepted {
            incarnation_id: id(),
            envelope_id: "env-1".into(),
            target_delivery_id: "target".into(),
            inbox_seq: 7,
        },
        "resume_page" => resume_page(vec![record()], vec![], None),
        "entry" => F::Entry { incarnation_id: id(), record: Box::new(record()) },
        "entry_too_large" => {
            F::EntryTooLarge { incarnation_id: id(), inbox_seq: 7, retain_until: 1_000 }
        }
        "entry_gone" => gone(n::EntryGoneReason::Expired),
        "ack_batch" => F::AckBatch {
            incarnation_id: id(),
            cursor: cursor(),
            results: vec![result(n::SessionAckOutcome::Acked, None)],
        },
        "ack" => F::Ack { incarnation_id: id(), cursor: cursor() },
        "cursor" => F::Cursor { incarnation_id: id(), cursor: Some(cursor()) },
        "resync" => F::Resync {
            incarnation_id: id(),
            target_delivery_id: "target".into(),
            after_inbox_seq: 3,
            reason: n::SessionPushResyncReason::QueueFull,
        },
        "nack" => nack(n::SessionPushNackReason::Busy, Some(id())),
        other => panic!("unknown vector {other}"),
    }
}

fn resume_page(
    entries: Vec<n::PageEntryRecord>,
    known_losses: Vec<n::KnownLoss>,
    oversize_next: Option<u64>,
) -> n::SessionPushServerFrame {
    n::SessionPushServerFrame::ResumePage {
        target_delivery_id: "target".into(),
        incarnation_id: E.into(),
        after_inbox_seq: 3,
        covered_through_seq: 9,
        issued_inbox_seq: 9,
        settled_through_seq: 2,
        entries,
        known_losses,
        oversize_next,
        more: false,
    }
}

fn gone(reason: n::EntryGoneReason) -> n::SessionPushServerFrame {
    n::SessionPushServerFrame::EntryGone {
        incarnation_id: E.into(),
        inbox_seq: 7,
        observed_issued_inbox_seq: 9,
        reason,
    }
}

fn nack(
    reason: n::SessionPushNackReason,
    incarnation_id: Option<String>,
) -> n::SessionPushServerFrame {
    n::SessionPushServerFrame::Nack { reason, incarnation_id }
}

/// Producer order (i): node-core struct order.
fn typed_bytes(frame: &n::SessionPushServerFrame) -> Vec<u8> {
    serde_json::to_vec(frame).unwrap()
}

/// Producer order (ii): sorted-key `Value` order, as forwarded router JSON.
fn forwarded_bytes(frame: &n::SessionPushServerFrame) -> Vec<u8> {
    serde_json::to_vec(&serde_json::to_value(frame).unwrap()).unwrap()
}

fn decode_both(frame: &n::SessionPushServerFrame) -> CapableServerFrame {
    let typed = decode_server_frame(&typed_bytes(frame)).unwrap();
    let forwarded = decode_server_frame(&forwarded_bytes(frame)).unwrap();
    assert_eq!(typed, forwarded);
    typed
}

fn value(kind: &str) -> Value {
    serde_json::to_value(node_frame(kind)).unwrap()
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

/// Mutates exactly one field of a valid vector and asserts the exact decode error.
fn refused(mut vector: Value, mutate: impl FnOnce(&mut Value), expected: &str) {
    mutate(&mut vector);
    let error = decode_server_frame(&serde_json::to_vec(&vector).unwrap())
        .expect_err("mutated vector must be refused");
    assert!(error.to_string().contains(expected), "expected {expected:?}, got {error}");
}

fn e_path(kind: &str) -> Vec<&'static str> {
    if kind == "session_established" {
        vec!["session", "inbox_incarnation_id"]
    } else {
        vec!["incarnation_id"]
    }
}

const BAD_E: &str = "invalid inbox incarnation id";

#[test]
fn capable_server_frame_codecs() {
    // (p1) every variant decodes identically from both producer orders; raw-byte fixture.
    for kind in FRAMES {
        let decoded = decode_both(&node_frame(kind));
        let tag = serde_json::to_value(node_frame(kind)).unwrap()["frame_type"].clone();
        assert_eq!(tag, kind);
        drop(decoded);
    }
    let accepted = typed_bytes(&node_frame("submit_accepted"));
    assert_eq!(
        std::str::from_utf8(&accepted).unwrap(),
        concat!(
            r#"{"frame_type":"submit_accepted","incarnation_id":"0123456789abcdef0123456789abcdef","#,
            r#""envelope_id":"env-1","target_delivery_id":"target","inbox_seq":7}"#
        )
    );
    assert!(matches!(
        decode_server_frame(&accepted).unwrap(),
        CapableServerFrame::SubmitAccepted { inbox_seq: 7, ref envelope_id, .. } if envelope_id == "env-1"
    ));
    let established = decode_both(&node_frame("session_established"));
    assert!(matches!(
        established,
        CapableServerFrame::SessionEstablished { ref session }
            if session.inbox_incarnation_id.as_str() == E
                && session.capabilities == [ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY]
    ));

    // (p2) nack with a null incarnation and with an E.
    assert!(matches!(
        decode_both(&nack(n::SessionPushNackReason::Busy, None)),
        CapableServerFrame::Nack { incarnation_id: None, .. }
    ));
    assert!(matches!(
        decode_both(&nack(n::SessionPushNackReason::Busy, Some(E.into()))),
        CapableServerFrame::Nack { incarnation_id: Some(_), .. }
    ));

    // (p3) known loss with equal endpoints, and with from < to.
    for (from, to) in [(5, 5), (5, 6)] {
        let loss = n::KnownLoss { from_seq: from, to_seq: to, reason: n::PageReason::Expired };
        let CapableServerFrame::ResumePage { known_losses, .. } =
            decode_both(&resume_page(vec![], vec![loss], None))
        else {
            panic!("not a resume page");
        };
        assert_eq!((known_losses[0].from_seq, known_losses[0].to_seq), (from, to));
    }

    // (p4) each PageReason alternative.
    for (wire, expected) in [
        (n::PageReason::Expired, PageReason::Expired),
        (n::PageReason::AckWindowOverflow, PageReason::AckWindowOverflow),
        (n::PageReason::Nacked, PageReason::Nacked),
        (n::PageReason::Aborted, PageReason::Aborted),
    ] {
        let loss = n::KnownLoss { from_seq: 1, to_seq: 2, reason: wire };
        let CapableServerFrame::ResumePage { known_losses, .. } =
            decode_both(&resume_page(vec![], vec![loss], None))
        else {
            panic!("not a resume page");
        };
        assert_eq!(known_losses[0].reason, expected);
    }

    // (p5) each EntryGoneReason alternative.
    for (wire, expected) in [
        (n::EntryGoneReason::Expired, EntryGoneReason::Expired),
        (n::EntryGoneReason::AckWindowOverflow, EntryGoneReason::AckWindowOverflow),
        (n::EntryGoneReason::Nacked, EntryGoneReason::Nacked),
        (n::EntryGoneReason::Aborted, EntryGoneReason::Aborted),
        (n::EntryGoneReason::Unknown, EntryGoneReason::Unknown),
    ] {
        let CapableServerFrame::EntryGone { reason, .. } = decode_both(&gone(wire)) else {
            panic!("not entry_gone");
        };
        assert_eq!(reason, expected);
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
            incarnation_id: E.into(),
            cursor: cursor(),
            results: vec![result(wire, reason)],
        };
        let CapableServerFrame::AckBatch { results, .. } = decode_both(&frame) else {
            panic!("not ack_batch");
        };
        assert_eq!((results[0].outcome, results[0].reason.as_deref()), (expected, reason));
    }

    // (p7) each resync reason.
    for (wire, expected) in [
        (n::SessionPushResyncReason::QueueFull, ResyncReason::QueueFull),
        (n::SessionPushResyncReason::NotPushed, ResyncReason::NotPushed),
    ] {
        let frame = n::SessionPushServerFrame::Resync {
            incarnation_id: E.into(),
            target_delivery_id: "target".into(),
            after_inbox_seq: 3,
            reason: wire,
        };
        let CapableServerFrame::Resync { reason, .. } = decode_both(&frame) else {
            panic!("not resync");
        };
        assert_eq!(reason, expected);
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
        let CapableServerFrame::Nack { reason, .. } = decode_both(&nack(wire, None)) else {
            panic!("not nack");
        };
        assert_eq!(reason, expected);
    }

    // (p9) oversize_next null and Some.
    for next in [None, Some(10)] {
        let CapableServerFrame::ResumePage { oversize_next, .. } =
            decode_both(&resume_page(vec![], vec![], next))
        else {
            panic!("not a resume page");
        };
        assert_eq!(oversize_next, next);
    }

    refusal_rows();
}

fn refusal_rows() {
    // (r1) E of 31 characters at each of the 12 E sites, one row per site.
    for kind in FRAMES {
        refused(value(kind), |v| set(v, &e_path(kind), json!(&E[..31])), BAD_E);
    }
    // (r2) 33 characters, (r3) the non-hex character `g`, (r4) uppercase `A`: on `deliver`.
    refused(value("deliver"), |v| set(v, &["incarnation_id"], json!(format!("{E}0"))), BAD_E);
    refused(
        value("deliver"),
        |v| set(v, &["incarnation_id"], json!(format!("g{}", &E[1..]))),
        BAD_E,
    );
    refused(
        value("deliver"),
        |v| set(v, &["incarnation_id"], json!(format!("A{}", &E[1..]))),
        BAD_E,
    );
    // (r5)-(r8) required and forbidden fields.
    refused(value("deliver"), |v| remove(v, &["incarnation_id"]), "missing field `incarnation_id`");
    refused(value("deliver"), |v| remove(v, &["retain_until"]), "missing field `retain_until`");
    refused(
        value("entry_too_large"),
        |v| remove(v, &["retain_until"]),
        "missing field `retain_until`",
    );
    refused(
        value("entry_gone"),
        |v| set(v, &["retain_until"], json!(1)),
        "unknown field `retain_until`",
    );
    // (r9) a loss with from_seq = to_seq + 1.
    refused(
        loss_value(),
        |v| set_loss(v, json!({"from_seq": 6, "to_seq": 5, "reason": "expired"})),
        "known loss from_seq exceeds to_seq",
    );
    // (r10) page loss reason `unknown` is valid only for entry_gone; (r11) unknown gone reason.
    refused(
        loss_value(),
        |v| set_loss(v, json!({"from_seq": 5, "to_seq": 5, "reason": "unknown"})),
        "unknown variant `unknown`",
    );
    refused(value("entry_gone"), |v| set(v, &["reason"], json!("zz")), "unknown variant `zz`");
    // (r12) unknown ack outcome.
    refused(
        value("ack_batch"),
        |v| set(v, &["results", "0", "outcome"], json!("zz")),
        "unknown variant `zz`",
    );
    // (r13a-d) each null-required outcome with a non-null reason, one isolated row each.
    for outcome in ["acked", "already_settled", "not_found", "invalid_seq"] {
        refused(
            value("ack_batch"),
            |v| {
                set(v, &["results", "0", "outcome"], json!(outcome));
                set(v, &["results", "0", "reason"], json!("x"));
            },
            "ack reason must be null for this outcome",
        );
    }
    // (r14) rejected with reason `zz`; (r15) rejected with a null reason.
    refused(
        value("ack_batch"),
        |v| {
            set(v, &["results", "0", "outcome"], json!("rejected"));
            set(v, &["results", "0", "reason"], json!("zz"));
        },
        "rejected ack reason is not allowed",
    );
    refused(
        value("ack_batch"),
        |v| {
            set(v, &["results", "0", "outcome"], json!("rejected"));
            set(v, &["results", "0", "reason"], Value::Null);
        },
        "rejected ack reason is not allowed",
    );
    // (r16) unknown resync reason; (r17) unknown capable nack reason.
    refused(value("resync"), |v| set(v, &["reason"], json!("zz")), "unknown variant `zz`");
    refused(value("nack"), |v| set(v, &["reason"], json!("zz")), "unknown variant `zz`");
    // (r18) an extra unknown field on resume_page; (r19) unknown frame_type.
    refused(value("resume_page"), |v| set(v, &["extra"], json!(1)), "unknown field `extra`");
    refused(value("deliver"), |v| set(v, &["frame_type"], json!("zz")), "unknown variant `zz`");
    // (r20)-(r22) required fields of session_established and submit_accepted.
    refused(
        value("session_established"),
        |v| remove(v, &["session", "inbox_incarnation_id"]),
        "missing field `inbox_incarnation_id`",
    );
    refused(
        value("session_established"),
        |v| remove(v, &["session", "capabilities"]),
        "missing field `capabilities`",
    );
    refused(value("submit_accepted"), |v| remove(v, &["inbox_seq"]), "missing field `inbox_seq`");
}

fn loss_value() -> Value {
    serde_json::to_value(resume_page(
        vec![],
        vec![n::KnownLoss { from_seq: 5, to_seq: 5, reason: n::PageReason::Expired }],
        None,
    ))
    .unwrap()
}

fn set_loss(root: &mut Value, loss: Value) {
    root["known_losses"][0] = loss;
}
