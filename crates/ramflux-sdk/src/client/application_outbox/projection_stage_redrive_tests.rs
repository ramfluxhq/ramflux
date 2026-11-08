// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Projection rows for P13's `receive_stage_redrive`.
#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use super::projection_write_failure::{self, Fixture};
use super::{Admit, AdmitRequest, ApplicationOutbox, Fault, OUTBOX, run};
use crate::prelude::*;
use ramflux_storage::{ReceiveExpectation, StorageError};
use std::time::Duration;

const BEFORE: &str = "application projection before-commit";
const AUTH: &str = "routed/committed/redrive-auth";
const MESSAGE: &str = "projection-owner";

struct HangGuard(Option<std::sync::mpsc::Sender<()>>);
impl Drop for HangGuard {
    fn drop(&mut self) {
        drop(self.0.take());
    }
}

/// Kill before/after the projection W1, redrive, one event, W0 staged.
/// Folded into `receive_stage_redrive` (P13 is on main).
pub(crate) fn projection_stage_redrive() -> Result<(), SdkError> {
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
    redrive(&mut fixture, 11, "redrive-a")?;
    redrive(&mut fixture, 12, "redrive-b")?;
    Ok(())
}

fn redrive(fixture: &mut Fixture, sequence: u64, env: &str) -> Result<(), SdkError> {
    let entry = projection_write_failure::inbox(env, sequence);
    let auth = format!("{AUTH}-{sequence}");
    projection_write_failure::stage(&fixture.client, sequence)?;
    projection_write_failure::persist_receipt(&fixture.client, &entry, &auth, MESSAGE)?;
    fixture.client.persist_routed_seen(&entry)?;
    let db = fixture.client.account_db()?;
    let gate = ApplicationOutbox {
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
            &AdmitRequest {
                sequence,
                auth_key: &auth,
                entry: &entry,
                message: Some(MESSAGE),
                client: &fixture.client,
            },
        )
    }) {
        Err(SdkError::Storage(StorageError::Integrity(text))) if text == BEFORE => {}
        other => panic!("expected Integrity({BEFORE:?}), got {other:?}"),
    }
    projection_write_failure::reopen(&mut fixture.client)?;
    let db = fixture.client.account_db()?;
    let (disposition, work_before) = db.receive_state_for_test(sequence)?;
    assert!(work_before >= 1);
    assert_eq!(disposition.as_deref(), Some("staged"));
    assert!(!db.actor_state_exists(&format!("{OUTBOX}{auth}"))?);
    assert!(
        fixture.client.routed_seen_marker(&entry)?.is_some(),
        "seen marker must not complete projection early"
    );

    let gate = ApplicationOutbox {
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
            &AdmitRequest {
                sequence,
                auth_key: &auth,
                entry: &entry,
                message: Some(MESSAGE),
                client: &fixture.client,
            },
        )?,
        Admit::Admitted
    );
    projection_write_failure::reopen(&mut fixture.client)?;
    let db = fixture.client.account_db()?;
    let (disposition, work) = db.receive_state_for_test(sequence)?;
    assert_eq!(work, work_before, "W0 must survive projection admission");
    assert_eq!(disposition.as_deref(), Some("staged"));
    assert!(db.actor_state_exists(&format!("{OUTBOX}{auth}"))?);
    let gate = ApplicationOutbox {
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
            &AdmitRequest {
                sequence,
                auth_key: &auth,
                entry: &entry,
                message: Some(MESSAGE),
                client: &fixture.client,
            },
        )?,
        Admit::Duplicate
    );
    Ok(())
}
