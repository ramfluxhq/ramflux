// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `reply_stage_redrive` (P13's `receive_stage_redrive` first leg has not landed; the
//! controller merges these rows after P13). Do not edit `routed/receive.rs` / `sync_driver.rs`.
#![allow(clippy::unwrap_used, clippy::panic, clippy::needless_pass_by_value)]

use super::reply_outbox_crash_tests::{self, Fixture};
use super::{Admit, AdmitRequest, Fault, OUTBOX, ReplyKind, ReplyOutbox, run};
use crate::prelude::*;
use ramflux_storage::{ReceiveExpectation, StorageError};
use serde_json::json;
use std::time::Duration;

const BEFORE: &str = "reply outbox before-commit";
const SURFACE_RESPONSE: &str = "surface/resync-response/surface-auth";

struct HangGuard(Option<std::sync::mpsc::Sender<()>>);
impl Drop for HangGuard {
    fn drop(&mut self) {
        drop(self.0.take());
    }
}

/// Kill before/after each reply W1, redrive, one envelope, W0 staged.
#[test]
fn reply_stage_redrive() -> Result<(), SdkError> {
    let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if matches!(
            cancelled.recv_timeout(Duration::from_secs(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            panic!("30-second hang guard expired");
        }
    });
    let _hang = HangGuard(Some(cancel));
    let mut fixture = Fixture::new()?;
    redrive(&mut fixture, 1, "surface-auth", ReplyKind::Surface, Some(SURFACE_RESPONSE))?;
    redrive(&mut fixture, 2, "pair-auth", ReplyKind::Pair, None)?;
    Ok(())
}

fn redrive(
    fixture: &mut Fixture,
    sequence: u64,
    auth_key: &str,
    kind: ReplyKind,
    response: Option<&str>,
) -> Result<(), SdkError> {
    let envelope = reply_outbox_crash_tests::envelope(&format!("{auth_key}-env"));
    reply_outbox_crash_tests::stage(&fixture.client, sequence)?;
    if let Some(key) = response {
        fixture.client.account_db()?.persist_actor_state(key, &json!({"queued": true}))?;
    }
    let db = fixture.client.account_db()?;
    let gate = ReplyOutbox {
        expected: ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    };
    match run(Fault::BeforeCommit, || {
        gate.admit(
            db,
            AdmitRequest {
                sequence,
                auth_key,
                envelope: envelope.clone(),
                kind,
                response_key: response,
                message: None,
            },
        )
    }) {
        Err(SdkError::Storage(StorageError::Integrity(text))) if text == BEFORE => {}
        other => panic!("expected Integrity({BEFORE:?}), got {other:?}"),
    }
    reply_outbox_crash_tests::reopen(&mut fixture.client)?;
    let db = fixture.client.account_db()?;
    let (disposition, work_before) = db.receive_state_for_test(sequence)?;
    assert!(work_before >= 1);
    assert_eq!(disposition.as_deref(), Some("staged"));
    if let Some(key) = response {
        assert!(db.actor_state_exists(key)?);
    }
    assert!(!db.actor_state_exists(&format!("{OUTBOX}{auth_key}"))?);

    let gate = ReplyOutbox {
        expected: ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    };
    assert_eq!(
        gate.admit(
            db,
            AdmitRequest {
                sequence,
                auth_key,
                envelope: envelope.clone(),
                kind,
                response_key: response,
                message: None,
            },
        )?,
        Admit::Admitted
    );
    reply_outbox_crash_tests::reopen(&mut fixture.client)?;
    let db = fixture.client.account_db()?;
    let (disposition, work) = db.receive_state_for_test(sequence)?;
    assert_eq!(work, work_before, "W0 must survive reply admission");
    assert_eq!(disposition.as_deref(), Some("staged"));
    let stored: super::PreparedReply = db
        .load_actor_state(&format!("{OUTBOX}{auth_key}"))?
        .ok_or_else(|| SdkError::LocalBus("redrive missing envelope".into()))?;
    assert_eq!(stored.envelope, envelope);
    let gate = ReplyOutbox {
        expected: ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    };
    assert_eq!(
        gate.admit(
            db,
            AdmitRequest {
                sequence,
                auth_key,
                envelope,
                kind,
                response_key: response,
                message: None,
            },
        )?,
        Admit::Duplicate
    );
    Ok(())
}
