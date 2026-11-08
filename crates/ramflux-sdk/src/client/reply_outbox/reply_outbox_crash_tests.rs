// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `reply_outbox_crash`: crash around surface-answer and pair-reset outbox transfer.
#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use super::{
    Admit, AdmitRequest, Fault, MAX_OUTBOX, OUTBOX, PreparedReply, ReplyKind, ReplyOutbox,
    acknowledge, due, run, with_remove_before_admission,
};
use crate::prelude::*;
use ramflux_protocol::Envelope;
use ramflux_storage::{
    AccountDb, ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
};
use serde_json::json;
use std::time::Duration;

const INTEGRITY: &str = "source effect requires staged receive work";
const BEFORE: &str = "reply outbox before-commit";
const FULL: &str = "reply outbox is full";
const LOST: &str = "reply outbox removed response before admission";
const IMMUTABLE: &str = "reply outbox envelope is immutable";
const TARGET: &str = "t";
const INCARNATION: &str = "e";
const SURFACE_SEQ: u64 = 1;
const PAIR_SEQ: u64 = 2;
const SURFACE_KEY: &str = "surface-auth";
const PAIR_KEY: &str = "pair-auth";
const SURFACE_RESPONSE: &str = "surface/resync-response/surface-auth";
const MESSAGE: &str = "reply-owner";
const ERASE: &str = "erase-owner";

struct HangGuard(Option<std::sync::mpsc::Sender<()>>);
impl Drop for HangGuard {
    fn drop(&mut self) {
        drop(self.0.take());
    }
}

fn hang_guard() -> HangGuard {
    let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if matches!(
            cancelled.recv_timeout(Duration::from_secs(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            panic!("30-second hang guard expired");
        }
    });
    HangGuard(Some(cancel))
}

fn gate(db: &AccountDb) -> Result<ReplyOutbox<'static>, SdkError> {
    Ok(ReplyOutbox {
        expected: ReceiveExpectation {
            target: TARGET,
            incarnation: INCARNATION,
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    })
}

fn staged(entry: &[u8], sequence: u64) -> ReceiveStage<'_> {
    ReceiveStage {
        target: TARGET,
        incarnation: INCARNATION,
        sequence,
        entry_json: entry,
        admission_key: "authenticated-reply",
        retain_until: now_unix_timestamp().saturating_add(300),
        first_seen: 1,
    }
}

fn wire(sequence: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "inbox_seq": sequence,
        "target_delivery_id": TARGET,
        "envelope": {
            "schema": "test",
            "version": 1,
            "domain": "test",
            "signing_key_id": "key",
            "signature_alg": "ed25519",
            "signature": "sig",
            "envelope_id": format!("env-{sequence}"),
            "source_principal_id": "source",
            "source_device_id": "device",
            "target_delivery_id": TARGET,
            "delivery_class": "opaque_event",
            "priority": "normal",
            "ttl": 60,
            "created_at": 1,
            "encrypted_payload": "cipher",
            "payload_hash": format!("H{sequence}")
        }
    }))
    .unwrap()
}

pub(super) fn envelope(id: &str) -> Envelope {
    serde_json::from_value(json!({
        "schema": "ramflux.envelope.v1",
        "version": 1,
        "domain": "test",
        "signing_key_id": "key",
        "signature_alg": "ed25519",
        "signature": "sig",
        "envelope_id": id,
        "source_principal_id": "source",
        "source_device_id": "device",
        "target_delivery_id": TARGET,
        "delivery_class": "opaque_event",
        "priority": "normal",
        "ttl": 60,
        "created_at": 1,
        "encrypted_payload": format!("sealed-{id}"),
        "payload_hash": format!("P{id}")
    }))
    .unwrap()
}

pub(super) struct Fixture {
    root: std::path::PathBuf,
    pub client: RamfluxClient,
}

impl Fixture {
    pub(super) fn new() -> Result<Self, SdkError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rf-reply-outbox-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut client = RamfluxClient::new();
        client.create_identity_root("acct", [41; 32]);
        client.create_device_branch("acct", "acct-device", 1, [42; 32]);
        client.open_account_index(&root)?;
        client.create_account("acct", "reply-outbox-commitment")?;
        client.unlock_account("acct", b"reply-outbox-secret")?;
        let db = client.account_db()?;
        db.install_receive_ledger_schema()?;
        db.seed_receive_epoch_for_test(TARGET, INCARNATION)?;
        Ok(Self { root, client })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.client.active_account_db = None;
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub(super) fn reopen(client: &mut RamfluxClient) -> Result<(), SdkError> {
    let root = client.identity_root.clone();
    let branch = client.device_branch.clone();
    client.active_account_db = None;
    client.unlock_account("acct", b"reply-outbox-secret")?;
    if client.identity_root.is_none() {
        client.identity_root = root;
    }
    if client.device_branch.is_none() {
        client.device_branch = branch.clone();
        if let (Some(branch), Some(db)) = (branch, client.active_account_db.as_mut()) {
            db.set_device_signer(branch);
        }
    }
    Ok(())
}

pub(super) fn stage(client: &RamfluxClient, sequence: u64) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let entry = wire(sequence);
    assert_eq!(gate(db)?.stage(db, staged(&entry, sequence))?, ReceiveStageResult::Staged);
    Ok(())
}

fn queue_surface(client: &RamfluxClient) -> Result<(), SdkError> {
    client.account_db()?.persist_actor_state(SURFACE_RESPONSE, &json!({"queued": true}))?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Snap {
    response: bool,
    outbox: bool,
    marker: bool,
    envelope_id: Option<String>,
    work: i64,
    disposition: Option<String>,
}

fn snap(client: &RamfluxClient, auth_key: &str, sequence: u64) -> Result<Snap, SdkError> {
    let db = client.account_db()?;
    let stored = format!("{OUTBOX}{auth_key}");
    let prepared: Option<PreparedReply> = db.load_actor_state(&stored)?;
    let (disposition, work) = db.receive_state_for_test(sequence)?;
    Ok(Snap {
        response: db.actor_state_exists(SURFACE_RESPONSE)?,
        outbox: prepared.is_some(),
        marker: db.actor_state_exists(&format!("{}{auth_key}", super::MARKER))?,
        envelope_id: prepared.map(|row| row.envelope_id),
        work,
        disposition,
    })
}

fn assert_integrity(result: Result<Admit, SdkError>, text: &str) {
    match result {
        Err(SdkError::Storage(StorageError::Integrity(got))) if got == text => {}
        Err(error) => panic!("expected Integrity({text:?}), got {error}"),
        Ok(value) => panic!("expected Integrity({text:?}), got Ok({value:?})"),
    }
}

fn req<'a>(
    sequence: u64,
    auth_key: &'a str,
    envelope: Envelope,
    kind: ReplyKind,
    response_key: Option<&'a str>,
    message: Option<&'a str>,
) -> AdmitRequest<'a> {
    AdmitRequest { sequence, auth_key, envelope, kind, response_key, message }
}

/// Crash after preparing a surface answer and a pair-reset reply, before/after outbox
/// transfer and after network write before receipt.
#[test]
fn reply_outbox_crash() -> Result<(), SdkError> {
    let _hang = hang_guard();
    let mut fixture = Fixture::new()?;
    let surface = envelope("surface-env");
    let pair = envelope("pair-env");

    let missing = gate(fixture.client.account_db()?)?.admit(
        fixture.client.account_db()?,
        req(
            SURFACE_SEQ,
            SURFACE_KEY,
            surface.clone(),
            ReplyKind::Surface,
            Some(SURFACE_RESPONSE),
            Some(MESSAGE),
        ),
    );
    match missing {
        Err(SdkError::Storage(StorageError::Integrity(text))) if text == INTEGRITY => {}
        other => panic!("expected Integrity({INTEGRITY:?}), got {other:?}"),
    }

    stage(&fixture.client, SURFACE_SEQ)?;
    queue_surface(&fixture.client)?;
    let pre = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(pre.response);
    assert!(!pre.outbox);
    assert_eq!(pre.work, 1);

    assert_integrity(
        run(Fault::BeforeCommit, || {
            gate(fixture.client.account_db()?)?.admit(
                fixture.client.account_db()?,
                req(
                    SURFACE_SEQ,
                    SURFACE_KEY,
                    surface.clone(),
                    ReplyKind::Surface,
                    Some(SURFACE_RESPONSE),
                    Some(MESSAGE),
                ),
            )
        }),
        BEFORE,
    );
    reopen(&mut fixture.client)?;
    assert_eq!(snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?, pre);

    assert_eq!(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                SURFACE_SEQ,
                SURFACE_KEY,
                surface.clone(),
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
            ),
        )?,
        Admit::Admitted
    );
    reopen(&mut fixture.client)?;
    let after_surface = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(!after_surface.response, "surface response must transfer before removal");
    assert!(after_surface.outbox);
    assert!(after_surface.marker);
    assert_eq!(after_surface.envelope_id.as_deref(), Some("surface-env"));
    assert_eq!(after_surface.work, 1);
    assert_eq!(after_surface.disposition.as_deref(), Some("staged"));

    assert_eq!(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                SURFACE_SEQ,
                SURFACE_KEY,
                surface.clone(),
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
            ),
        )?,
        Admit::Duplicate
    );
    let mut changed = surface.clone();
    changed.encrypted_payload = "other-seal".into();
    assert_integrity(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                SURFACE_SEQ,
                SURFACE_KEY,
                changed,
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
            ),
        ),
        IMMUTABLE,
    );

    stage(&fixture.client, PAIR_SEQ)?;
    assert_eq!(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(PAIR_SEQ, PAIR_KEY, pair.clone(), ReplyKind::Pair, None, Some(MESSAGE)),
        )?,
        Admit::Admitted
    );
    reopen(&mut fixture.client)?;
    let after_pair = snap(&fixture.client, PAIR_KEY, PAIR_SEQ)?;
    assert!(after_pair.outbox);
    assert!(after_pair.marker);
    assert_eq!(after_pair.envelope_id.as_deref(), Some("pair-env"));
    assert_eq!(after_pair.work, 2, "surface and pair W0 rows both remain");
    assert_eq!(after_pair.disposition.as_deref(), Some("staged"));

    let first =
        due(fixture.client.account_db()?)?.ok_or(SdkError::LocalBus("due surface".into()))?;
    assert_eq!(first.1.envelope_id, "pair-env");
    assert_eq!(first.1.envelope, pair);
    acknowledge(fixture.client.account_db()?, &first.0)?;
    let still =
        due(fixture.client.account_db()?)?.ok_or(SdkError::LocalBus("due surface".into()))?;
    assert_eq!(still.1.envelope, surface);
    assert_eq!(still.1.kind, ReplyKind::Surface);
    reopen(&mut fixture.client)?;
    let pending = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(pending.outbox, "network write before receipt must retain the envelope");
    assert_eq!(pending.envelope_id.as_deref(), Some("surface-env"));
    acknowledge(fixture.client.account_db()?, SURFACE_KEY)?;
    reopen(&mut fixture.client)?;
    let done = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(!done.outbox);
    assert!(done.marker);
    assert_eq!(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                SURFACE_SEQ,
                SURFACE_KEY,
                surface.clone(),
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
            ),
        )?,
        Admit::Duplicate
    );
    assert!(due(fixture.client.account_db()?)?.is_none());

    queue_surface(&fixture.client)?;
    stage(&fixture.client, 3)?;
    assert_integrity(
        with_remove_before_admission(|| {
            gate(fixture.client.account_db()?)?.admit(
                fixture.client.account_db()?,
                req(
                    3,
                    "lost-auth",
                    envelope("lost-env"),
                    ReplyKind::Surface,
                    Some(SURFACE_RESPONSE),
                    None,
                ),
            )
        }),
        LOST,
    );
    reopen(&mut fixture.client)?;
    assert!(
        !fixture.client.account_db()?.actor_state_exists(SURFACE_RESPONSE)?,
        "BtF: remove response before admission loses the reply"
    );
    assert!(!fixture.client.account_db()?.actor_state_exists(&format!("{OUTBOX}lost-auth"))?);

    fill_and_hold(&mut fixture.client)?;
    erase_bound_row(&fixture.client)?;
    Ok(())
}

fn fill_and_hold(client: &mut RamfluxClient) -> Result<(), SdkError> {
    let db = client.account_db()?;
    for i in 0..MAX_OUTBOX {
        db.persist_actor_state(&format!("{OUTBOX}fill-{i}"), &json!({"pad": i}))?;
    }
    queue_surface(client)?;
    stage(client, 4)?;
    let pre = snap(client, "held-auth", 4)?;
    assert!(pre.response);
    assert_eq!(pre.disposition.as_deref(), Some("staged"));
    assert!(pre.work >= 1);
    assert_integrity(
        gate(client.account_db()?)?.admit(
            client.account_db()?,
            req(
                4,
                "held-auth",
                envelope("held-env"),
                ReplyKind::Pair,
                Some(SURFACE_RESPONSE),
                None,
            ),
        ),
        FULL,
    );
    reopen(client)?;
    let held = snap(client, "held-auth", 4)?;
    assert!(held.response, "full outbox must retain the response");
    assert!(!held.outbox);
    assert!(!held.marker);
    assert_eq!(held.work, pre.work, "full outbox must retain W0");
    assert_eq!(held.disposition.as_deref(), Some("staged"));
    Ok(())
}

fn erase_bound_row(client: &RamfluxClient) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.send_direct_message("thread", ERASE, "peer", b"secret")?;
    db.persist_message_actor_state(ERASE, &format!("{OUTBOX}erase"), &envelope("erase-env"))?;
    assert!(db.actor_state_exists(&format!("{OUTBOX}erase"))?);
    db.delete_direct_message("thread", ERASE, "local", "delete-reply")?;
    assert!(
        !db.actor_state_exists(&format!("{OUTBOX}erase"))?,
        "erase of the bound message must drop the reply outbox row"
    );
    Ok(())
}
