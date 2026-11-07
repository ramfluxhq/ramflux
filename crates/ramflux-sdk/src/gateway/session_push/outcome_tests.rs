// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `sender_outcome_classification`: typed submit refusals from decoded frames.
//!
//! The classifier is live. Every expected value below is an independent literal; no row is
//! built from the helper under test. Time is paused, so the frame timeout fires without
//! waiting.
use super::point_tests::{signed, signed_on};
use super::resume_tests::Sent;
use super::routing_tests::{envelope, push};
use super::{SessionMode, SubmitRefusal};
use crate::SdkError;
use crate::bus::connection_manager::DisconnectReason;
use ramflux_transport::{
    GatewaySessionFrameSink, GatewaySessionFrameSource, GatewaySessionTransport, TransportError,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;

#[derive(Clone, Copy)]
enum Fault {
    /// The write succeeds and the stream then drops.
    Drop,
    /// The write succeeds and nothing ever comes back.
    Hang,
    /// The write fails.
    WriteFail,
}

struct Faulty {
    fault: Fault,
    sent: Sent,
}

impl GatewaySessionFrameSink for Faulty {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> FrameFuture<'a, ()> {
        let fail = matches!(self.fault, Fault::WriteFail);
        if !fail {
            self.sent.lock().unwrap().push(frame.to_vec());
        }
        Box::pin(async move {
            if fail { Err(TransportError::Quic("write failed".into())) } else { Ok(()) }
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for Faulty {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        let drop_it = matches!(self.fault, Fault::Drop);
        Box::pin(async move {
            if drop_it {
                Err(TransportError::ShutdownDraining)
            } else {
                std::future::pending().await
            }
        })
    }
}

fn nack_bytes(reason: &str) -> Vec<u8> {
    format!(r#"{{"frame_type":"nack","reason":"{reason}"}}"#).into_bytes()
}

fn modes() -> [(&'static str, SessionMode); 2] {
    [("legacy", SessionMode::Legacy), ("push", push())]
}

async fn classified(
    mode: SessionMode,
    reason: &str,
) -> (Result<Result<crate::GatewayInboxEntry, SubmitRefusal>, SdkError>, DisconnectReasonOpt) {
    let (mut engine, _) = signed(mode, vec![nack_bytes(reason)]);
    let result = engine.submit_envelope_classified(envelope()).await;
    (result, engine.terminal_reason)
}

type DisconnectReasonOpt = Option<DisconnectReason>;

fn rejected(result: Result<Result<crate::GatewayInboxEntry, SubmitRefusal>, SdkError>) -> String {
    match result {
        Err(SdkError::GatewaySessionRejected(text)) => text,
        other => panic!("expected an outer GatewaySessionRejected, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn sender_outcome_classification() {
    // (p1)-(p3) Legacy mode, (p4)-(p6) Push mode: each exact reason is its typed refusal and
    // the session stays alive.
    let typed = [
        ("aborted_retry_safe", SubmitRefusal::RetrySafe),
        ("capacity_retry_after", SubmitRefusal::CapacityRetryAfter { retry_after_ms: 1000 }),
        ("idempotency_conflict", SubmitRefusal::Conflict),
    ];
    for (mode_name, mode) in modes() {
        for (reason, expected) in typed {
            let (result, terminal) = classified(mode.clone(), reason).await;
            match result {
                Ok(Err(got)) => assert_eq!(got, expected, "{mode_name} {reason}"),
                other => panic!("{mode_name} {reason}: expected a refusal, got {other:?}"),
            }
            assert!(terminal.is_none(), "{mode_name} {reason}: session stays alive");
        }
    }

    // (p7) the public submit_envelope error string is unchanged for all six.
    for (_, mode) in modes() {
        for (reason, _) in typed {
            let (mut engine, _) = signed(mode.clone(), vec![nack_bytes(reason)]);
            let text = rejected(engine.submit_envelope(envelope()).await.map(Ok));
            assert_eq!(text, reason);
        }
    }

    // (r1)-(r6) six other reasons and (r7)-(r9) three near misses are not refusals: the outer
    // error carries the exact string. Both modes.
    let not_typed = [
        "payload_too_large",
        "forward_in_progress",
        "rejected_x",
        "invalid_seq",
        "incarnation_mismatch",
        "unknown",
        "capacity_retry_after (retry_after_ms=1000)",
        "Capacity_retry_after",
        "idempotency_conflict ",
    ];
    assert_eq!(not_typed.len(), 9);
    for (mode_name, mode) in modes() {
        for reason in not_typed {
            let (result, _) = classified(mode.clone(), reason).await;
            assert_eq!(rejected(result), reason, "{mode_name} {reason:?}");
        }
    }

    // (r10) drop after the write, (r11) frame timeout after the write, (r13) write failure:
    // uncertain, in the outer error, never a refusal. (r14) the next attempt resubmits the
    // byte-identical envelope.
    let original = serde_json::to_value(envelope()).unwrap();
    for (mode_name, mode) in modes() {
        for (row, fault) in [("r10", Fault::Drop), ("r11", Fault::Hang), ("r13", Fault::WriteFail)]
        {
            let sent: Sent = Arc::new(Mutex::new(Vec::new()));
            let stream: Box<dyn GatewaySessionTransport + Send> =
                Box::new(Faulty { fault, sent: Arc::clone(&sent) });
            let mut engine = signed_on(mode.clone(), stream);
            engine.frame_timeout = Duration::from_secs(7);
            let result = engine.submit_envelope_classified(envelope()).await;
            let (want_text, want_reason) = match fault {
                Fault::Drop => (
                    "transport error: transport is draining and no longer accepts new work",
                    DisconnectReason::Transport,
                ),
                Fault::Hang => (
                    "gateway session rejected: submit response timed out after 7s",
                    DisconnectReason::CallTimeout,
                ),
                Fault::WriteFail => {
                    ("transport error: QUIC error: write failed", DisconnectReason::Transport)
                }
            };
            match &result {
                Err(error) => assert_eq!(error.to_string(), want_text, "{mode_name} {row}"),
                Ok(inner) => panic!("{mode_name} {row}: expected an outer error, got {inner:?}"),
            }
            assert_eq!(engine.terminal_reason, Some(want_reason), "{mode_name} {row}");
            if matches!(fault, Fault::Hang) {
                // The timeout shares the nack's error variant; only the typed channel and the
                // terminal reason tell them apart.
                assert!(matches!(&result, Err(SdkError::GatewaySessionRejected(m))
                    if m == "submit response timed out after 7s"));
            }
            // (r14) the next attempt, on a fresh session, writes the same envelope bytes.
            let (mut next, next_sent) =
                signed(mode.clone(), vec![nack_bytes("aborted_retry_safe")]);
            let again = next.submit_envelope_classified(envelope()).await;
            assert!(matches!(again, Ok(Err(SubmitRefusal::RetrySafe))));
            let written = next_sent.lock().unwrap().clone();
            let wire: Value = serde_json::from_slice(&written[0]).unwrap();
            assert_eq!(wire["submit"]["envelope"], original, "{mode_name} {row} resubmit");
            if !matches!(fault, Fault::WriteFail) {
                let first: Value = serde_json::from_slice(&sent.lock().unwrap()[0]).unwrap();
                assert_eq!(first["submit"]["envelope"], wire["submit"]["envelope"]);
            }
        }
    }
}
