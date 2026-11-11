// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `projection_write_failure`: fail projection claim and outbox writes; held work remains,
//! no terminal ACK, retry creates one event.
#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use super::{
    Admit, AdmitRequest, ApplicationEvent, ApplicationOutbox, Fault, MAX_OUTBOX, OUTBOX, PUBLISHED,
    replay, run,
};
use crate::client::routed::{Committed, Kind, Routing};
use crate::prelude::*;
use ramflux_protocol::Envelope;
use ramflux_storage::{
    AccountDb, ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
};
use serde_json::json;
use std::time::Duration;

const CLAIM: &str = "application projection claim failed";
const OUTBOX_FAIL: &str = "application projection outbox failed";
const BEFORE: &str = "application projection before-commit";
const INTEGRITY: &str = "source effect requires staged receive work";
const TARGET: &str = "t";
const INCARNATION: &str = "e";
const SEQ: u64 = 1;
const MESSAGE: &str = "projection-owner";
const ERASE: &str = "erase-owner";

pub(super) struct HangGuard(Option<std::sync::mpsc::Sender<()>>);
impl Drop for HangGuard {
    fn drop(&mut self) {
        drop(self.0.take());
    }
}

pub(super) fn hang_guard() -> HangGuard {
    let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if matches!(
            cancelled.recv_timeout(Duration::from_secs(120)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            eprintln!("120-second hang guard expired");
            std::process::abort();
        }
    });
    HangGuard(Some(cancel))
}

fn gate(db: &AccountDb) -> Result<ApplicationOutbox<'static>, SdkError> {
    Ok(ApplicationOutbox {
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
        admission_key: "authenticated-projection",
        retain_until: now_unix_timestamp().saturating_add(300),
        first_seen: 1,
    }
}

pub(crate) fn envelope(id: &str) -> Envelope {
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

pub(crate) fn inbox(id: &str, sequence: u64) -> GatewayInboxEntry {
    GatewayInboxEntry {
        forwarded: false,
        inbox_seq: sequence,
        target_delivery_id: TARGET.to_owned(),
        envelope: envelope(id),
    }
}

pub(super) fn auth_key(entry: &GatewayInboxEntry) -> String {
    format!("routed/committed/{}", entry.envelope.envelope_id)
}

pub(super) struct Fixture {
    root: std::path::PathBuf,
    pub client: RamfluxClient,
}

impl Fixture {
    pub(super) fn new() -> Result<Self, SdkError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rf-application-outbox-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut client = RamfluxClient::new();
        client.create_identity_root("acct", [41; 32]);
        client.create_device_branch("acct", "acct-device", 1, [42; 32]);
        client.open_account_index(&root)?;
        client.create_account("acct", "application-outbox-commitment")?;
        client.unlock_account("acct", b"application-outbox-secret")?;
        let db = client.account_db()?;
        db.install_receive_ledger_schema()?;
        db.seed_receive_epoch_for_test(TARGET, INCARNATION)?;
        client.persist_root_verified_directory(
            &crate::client::identity_authority::test_support::public_manifest(&client)?,
        )?;
        db.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"direct","participants":[client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id]}),
        )?;
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
    client.unlock_account("acct", b"application-outbox-secret")?;
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
    let entry = serde_json::to_vec(&inbox("stage", sequence))?;
    assert_eq!(gate(db)?.stage(db, staged(&entry, sequence))?, ReceiveStageResult::Staged);
    Ok(())
}

pub(super) fn persist_receipt(
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
    message: &str,
) -> Result<String, SdkError> {
    let key = auth_key(entry);
    let receipt = Committed {
        routing: Routing {
            kind: Kind::Direct,
            conversation_id: "thread".to_owned(),
            group_id: None,
            message_id: message.to_owned(),
            group_message_id: None,
            attachments: false,
        },
        entry: entry.clone(),
        projected: false,
        erasure_targets: Vec::new(),
    };
    client.account_db()?.persist_actor_state(&key, &receipt)?;
    Ok(key)
}

#[derive(Debug, PartialEq, Eq)]
struct Snap {
    outbox: Option<ApplicationEvent>,
    projected: bool,
    work: i64,
    disposition: Option<String>,
    ack: bool,
}

fn snap(
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
    sequence: u64,
) -> Result<Snap, SdkError> {
    let db = client.account_db()?;
    let key = auth_key(entry);
    let stored = format!("{OUTBOX}{key}");
    let event: Option<ApplicationEvent> = db.load_actor_state(&stored)?;
    let projected =
        db.load_actor_state::<Committed>(&key)?.is_some_and(|receipt| receipt.projected);
    let (disposition, work) = db.receive_state_for_test(sequence)?;
    let receiver = client.owned_device_identity()?;
    Ok(Snap {
        outbox: event,
        projected,
        work,
        disposition,
        ack: db.has_gateway_ack(&receiver, TARGET, sequence)?,
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
    client: &'a RamfluxClient,
    sequence: u64,
    key: &'a str,
    entry: &'a GatewayInboxEntry,
) -> AdmitRequest<'a> {
    AdmitRequest { sequence, auth_key: key, entry, client }
}

fn fail_and_hold(
    fixture: &mut Fixture,
    entry: &GatewayInboxEntry,
    fault: Fault,
    text: &str,
) -> Result<(), SdkError> {
    let pre = snap(&fixture.client, entry, SEQ)?;
    assert!(pre.outbox.is_none());
    assert!(!pre.projected);
    assert_eq!(pre.work, 1);
    assert!(!pre.ack);
    let key = auth_key(entry);
    assert_integrity(
        run(fault, || {
            gate(fixture.client.account_db()?)?
                .admit(fixture.client.account_db()?, &req(&fixture.client, SEQ, &key, entry))
        }),
        text,
    );
    reopen(&mut fixture.client)?;
    let held = snap(&fixture.client, entry, SEQ)?;
    assert_eq!(held, pre, "failed projection must retain held work and write nothing");
    assert!(!held.ack, "failed projection must not ACK");
    assert_eq!(held.disposition.as_deref(), Some("staged"));
    Ok(())
}

/// Fail projection claim and outbox writes; held work remains, no terminal ACK, retry
/// creates one event. Seen marker still drains an unfinished projection.
#[test]
fn projection_write_failure() -> Result<(), SdkError> {
    let _hang = hang_guard();
    let mut fixture = Fixture::new()?;
    let entry = inbox("proj-env", SEQ);
    let key = auth_key(&entry);

    let missing = gate(fixture.client.account_db()?)?
        .admit(fixture.client.account_db()?, &req(&fixture.client, SEQ, &key, &entry));
    match missing {
        Err(SdkError::Storage(StorageError::Integrity(text))) if text == INTEGRITY => {}
        other => panic!("expected Integrity({INTEGRITY:?}), got {other:?}"),
    }

    stage(&fixture.client, SEQ)?;
    persist_receipt(&fixture.client, &entry, MESSAGE)?;
    fixture.client.persist_routed_seen(&entry)?;
    assert!(
        fixture.client.routed_seen_marker(&entry)?.is_some(),
        "seen marker is present before projection"
    );

    fail_and_hold(&mut fixture, &entry, Fault::Claim, CLAIM)?;
    fail_and_hold(&mut fixture, &entry, Fault::Outbox, OUTBOX_FAIL)?;
    fail_and_hold(&mut fixture, &entry, Fault::BeforeCommit, BEFORE)?;

    assert_eq!(
        gate(fixture.client.account_db()?)?
            .admit(fixture.client.account_db()?, &req(&fixture.client, SEQ, &key, &entry))?,
        Admit::Admitted,
        "seen marker must not skip projection as Completed"
    );
    reopen(&mut fixture.client)?;
    let once = snap(&fixture.client, &entry, SEQ)?;
    assert_eq!(
        once.outbox.as_ref(),
        Some(&ApplicationEvent {
            envelope_id: "proj-env".into(),
            payload_hash: "Pproj-env".into(),
            committed_key: key.clone(),
        }),
        "retry creates one durable application event with receipt identity"
    );
    assert!(once.projected);
    assert_eq!(once.work, 1, "W0 remains until W2");
    assert_eq!(once.disposition.as_deref(), Some("staged"));
    assert!(!once.ack, "projection W1 never ACKs");

    let mut ram = Vec::new();
    replay(fixture.client.account_db()?, &mut ram)?;
    assert_eq!(ram.len(), 1);
    assert_eq!(ram[0].envelope.envelope_id, "proj-env");
    assert!(
        !fixture.client.account_db()?.actor_state_exists(&format!("{OUTBOX}{key}"))?,
        "replay acknowledges the published row"
    );
    replay(fixture.client.account_db()?, &mut ram)?;
    assert_eq!(ram.len(), 1, "acknowledged row is never published again");

    assert_eq!(
        gate(fixture.client.account_db()?)?
            .admit(fixture.client.account_db()?, &req(&fixture.client, SEQ, &key, &entry))?,
        Admit::Duplicate
    );
    let again = snap(&fixture.client, &entry, SEQ)?;
    assert!(again.outbox.is_none(), "duplicate after ack must not rewrite the outbox");
    assert_eq!(again.projected, once.projected);

    drain_without_outbox(&mut fixture.client)?;
    erase_bound_row(&fixture.client)?;
    join_stage_and_admit(&mut fixture.client)?;
    drain_seventy(&mut fixture.client)?;
    // Fresh fixture: `work` counts every receive row, so the cap check needs an isolated account.
    let mut cap = Fixture::new()?;
    cap_full(&mut cap.client)?;
    Ok(())
}

fn drain_without_outbox(client: &mut RamfluxClient) -> Result<(), SdkError> {
    const DRAIN_SEQ: u64 = 2;
    let entry = inbox("drain-env", DRAIN_SEQ);
    stage(client, DRAIN_SEQ)?;
    let key = persist_receipt(client, &entry, MESSAGE)?;
    let db = client.account_db()?;
    client.write_inbox_projection_claim_at(db, &key, &entry)?;
    assert!(client.account_db()?.load_actor_state::<Committed>(&key)?.is_some_and(|r| r.projected));
    assert!(!client.account_db()?.actor_state_exists(&format!("{OUTBOX}{key}"))?);
    assert_eq!(
        gate(client.account_db()?)?
            .admit(client.account_db()?, &req(client, DRAIN_SEQ, &key, &entry))?,
        Admit::Duplicate,
        "projected-without-outbox must still drain the unfinished projection"
    );
    assert!(client.account_db()?.actor_state_exists(&format!("{OUTBOX}{key}"))?);
    Ok(())
}

fn erase_bound_row(client: &RamfluxClient) -> Result<(), SdkError> {
    const ESEQ: u64 = 6;
    let entry = inbox("erase-env", ESEQ);
    stage(client, ESEQ)?;
    let key = persist_receipt(client, &entry, ERASE)?;
    let db = client.account_db()?;
    db.send_direct_message("thread", ERASE, "peer", b"secret")?;
    let outbox = gate(db)?;
    db.receive_transaction(outbox.expected, outbox.generation, |tx| {
        outbox.admit_in(tx, &req(client, ESEQ, &key, &entry)).map_err(|error| match error {
            SdkError::Storage(storage) => storage,
            _ => StorageError::Integrity("erase admit"),
        })?;
        Ok(())
    })?;
    assert!(db.actor_state_exists(&format!("{OUTBOX}{key}"))?);
    db.delete_direct_message("thread", ERASE, "local", "delete-projection")?;
    assert!(
        !db.actor_state_exists(&format!("{OUTBOX}{key}"))?,
        "erase of the bound message must drop the application outbox row"
    );
    assert!(
        !db.actor_state_exists(&format!("{PUBLISHED}{key}"))?,
        "erase of the bound message must drop the published marker"
    );
    assert_integrity(
        gate(db)?.admit(db, &req(client, ESEQ, &key, &entry)),
        "application projection receipt missing",
    );
    assert!(
        !db.actor_state_exists(&format!("{OUTBOX}{key}"))?,
        "re-admitting a deleted message must leave the outbox row absent"
    );
    Ok(())
}

fn join_stage_and_admit(client: &mut RamfluxClient) -> Result<(), SdkError> {
    const JSEQ: u64 = 3;
    let entry = inbox("join-env", JSEQ);
    let key = auth_key(&entry);
    persist_receipt(client, &entry, MESSAGE)?;
    let wire = serde_json::to_vec(&entry)?;
    {
        let db = client.account_db()?;
        let outbox = gate(db)?;
        assert_integrity(
            run(Fault::BeforeCommit, || {
                db.receive_transaction(outbox.expected, outbox.generation, |tx| {
                    tx.stage(staged(&wire, JSEQ))?;
                    outbox.admit_in(tx, &req(client, JSEQ, &key, &entry)).map_err(|error| {
                        match error {
                            SdkError::Storage(storage) => storage,
                            _ => StorageError::Integrity("join admit"),
                        }
                    })?;
                    Ok(())
                })?;
                Ok(Admit::Admitted)
            }),
            BEFORE,
        );
    }
    reopen(client)?;
    let rolled = snap(client, &entry, JSEQ)?;
    assert!(rolled.outbox.is_none(), "joined W1+admit rolls back together");
    assert_eq!(rolled.disposition, None);
    persist_receipt(client, &entry, MESSAGE)?;
    {
        let db = client.account_db()?;
        let outbox = gate(db)?;
        db.receive_transaction(outbox.expected, outbox.generation, |tx| {
            tx.stage(staged(&wire, JSEQ))?;
            outbox.admit_in(tx, &req(client, JSEQ, &key, &entry)).map_err(|error| match error {
                SdkError::Storage(storage) => storage,
                _ => StorageError::Integrity("join admit"),
            })?;
            Ok(())
        })?;
    }
    let joined = snap(client, &entry, JSEQ)?;
    assert!(joined.outbox.is_some());
    assert!(joined.projected);
    assert_eq!(joined.disposition.as_deref(), Some("staged"));
    Ok(())
}

fn drain_seventy(client: &mut RamfluxClient) -> Result<(), SdkError> {
    const BASE: u64 = 20;
    stage(client, BASE)?;
    // Rows left by earlier rows of this test are published to a scratch page so the counts below are exact.
    replay(client.account_db()?, &mut Vec::new())?;
    assert_eq!(client.account_db()?.actor_state_usage(OUTBOX)?.0, 0);
    for index in 0..70u32 {
        let entry = inbox(&format!("burst-{index}"), BASE);
        persist_receipt(client, &entry, MESSAGE)?;
        let key = auth_key(&entry);
        assert_eq!(
            gate(client.account_db()?)?
                .admit(client.account_db()?, &req(client, BASE, &key, &entry))?,
            Admit::Admitted
        );
    }
    assert_eq!(client.account_db()?.actor_state_usage(OUTBOX)?.0, 70);
    let mut ram = Vec::new();
    replay(client.account_db()?, &mut ram)?;
    assert_eq!(ram.len(), 64, "first replay publishes only the free page capacity");
    assert_eq!(
        client.account_db()?.actor_state_usage(OUTBOX)?.0,
        6,
        "the 6 rows beyond the page stay durable"
    );
    let mut published: Vec<String> = ram.iter().map(|e| e.envelope.envelope_id.clone()).collect();
    ram.clear(); // the consumer drains the RAM page
    replay(client.account_db()?, &mut ram)?;
    assert_eq!(ram.len(), 6, "second replay publishes the remaining 6");
    assert_eq!(
        client.account_db()?.actor_state_usage(OUTBOX)?.0,
        0,
        "every pending outbox row is acknowledged once published"
    );
    published.extend(ram.iter().map(|e| e.envelope.envelope_id.clone()));
    let expected: std::collections::BTreeSet<String> =
        (0..70u32).map(|index| format!("burst-{index}")).collect();
    let got: std::collections::BTreeSet<String> = published.iter().cloned().collect();
    assert_eq!(published.len(), 70, "no event is duplicated");
    assert_eq!(got, expected, "no event is lost");
    let mut again = ram.clone();
    replay(client.account_db()?, &mut again)?;
    assert_eq!(again, ram, "republish after ack publishes nothing");
    let first = inbox("burst-0", BASE);
    let key = auth_key(&first);
    assert!(
        !client.account_db()?.actor_state_exists(&format!("{OUTBOX}{key}"))?,
        "acknowledged first row stays gone"
    );
    Ok(())
}

fn cap_full(client: &mut RamfluxClient) -> Result<(), SdkError> {
    const CAP_SEQ: u64 = 30;
    stage(client, CAP_SEQ)?;
    for index in 0..MAX_OUTBOX {
        let entry = inbox(&format!("cap-{index}"), CAP_SEQ);
        persist_receipt(client, &entry, MESSAGE)?;
        let key = auth_key(&entry);
        assert_eq!(
            gate(client.account_db()?)?
                .admit(client.account_db()?, &req(client, CAP_SEQ, &key, &entry))?,
            Admit::Admitted
        );
    }
    assert_eq!(client.account_db()?.actor_state_usage(OUTBOX)?.0, u64::from(MAX_OUTBOX));
    let extra = inbox("cap-extra", CAP_SEQ);
    persist_receipt(client, &extra, MESSAGE)?;
    let extra_key = auth_key(&extra);
    assert_eq!(
        gate(client.account_db()?)?
            .admit(client.account_db()?, &req(client, CAP_SEQ, &extra_key, &extra))?,
        Admit::OutboxFull
    );
    let held = snap(client, &extra, CAP_SEQ)?;
    assert!(held.outbox.is_none(), "the 257th row must not be admitted");
    assert!(!held.projected);
    assert_eq!(held.disposition.as_deref(), Some("held"), "OutboxFull holds W0");
    assert_eq!(held.work, 1, "OutboxFull keeps exactly one held receive");
    assert!(!held.ack, "OutboxFull must not ACK");
    Ok(())
}
