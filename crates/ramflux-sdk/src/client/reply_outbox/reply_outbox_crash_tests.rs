// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `reply_outbox_crash`: crash around surface-answer and pair-reset outbox transfer.
#![allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::unwrap_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use super::{
    Admit, AdmitRequest, Fault, OUTBOX, PreparedReply, ReplyKind, ReplyOutbox, acknowledge, due,
    run,
};
use crate::client::routed::SendMaterial;
use crate::client::surface::{CONTROL_PREFIX, ControlKind, SurfaceControl};
use crate::prelude::*;
use ramflux_protocol::Envelope;
use ramflux_storage::{
    AccountDb, ProjectionStore, ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
};
use serde_json::json;
use std::time::Duration;

const INTEGRITY: &str = "source effect requires staged receive work";
const BEFORE: &str = "reply outbox before-commit";
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

fn live_cursor(db: &AccountDb) -> Result<u64, SdkError> {
    db.projection_checkpoint(&format!("gateway_receive_cursor:{TARGET}"))?.map_or(Ok(0), |value| {
        value.parse().map_err(|_| SdkError::LocalBus("receive cursor".into()))
    })
}

fn gate(db: &AccountDb) -> Result<ReplyOutbox<'static>, SdkError> {
    Ok(ReplyOutbox {
        expected: ReceiveExpectation {
            target: TARGET,
            incarnation: INCARNATION,
            cursor: live_cursor(db)?,
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

pub(crate) fn envelope(id: &str) -> Envelope {
    envelope_at(id, TARGET)
}

fn envelope_at(id: &str, target: &str) -> Envelope {
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
        "target_delivery_id": target,
        "delivery_class": "opaque_event",
        "priority": "normal",
        "ttl": 60,
        "created_at": 1,
        "encrypted_payload": format!("sealed-{id}"),
        "payload_hash": format!("P{id}")
    }))
    .unwrap()
}

pub(super) fn bound_envelope(client: &RamfluxClient, id: &str) -> Result<Envelope, SdkError> {
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    Ok(envelope_at(id, &branch.device_id))
}

pub(super) fn session_config(client: &RamfluxClient) -> Result<GatewaySessionConfig, SdkError> {
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::LocalBus("address".into()))?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|_| SdkError::LocalBus("address".into()))?,
        server_name: "test".into(),
        ca_cert: std::path::PathBuf::from("ca.pem"),
        principal_id: branch.principal_id.clone(),
        device_id: branch.device_id.clone(),
        target_delivery_id: branch.device_id.clone(),
        prekey_http_url: None,
    })
    .with_account_identity(client)
}

fn device_target(client: &RamfluxClient) -> Result<String, SdkError> {
    Ok(client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id.clone())
}

pub(super) struct Fixture {
    pub client: RamfluxClient,
    pub peer: RamfluxClient,
    root: ramflux_test_support::TestPath,
    peer_root: ramflux_test_support::TestPath,
}

impl Fixture {
    pub(super) fn new() -> Result<Self, SdkError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("rf-reply-outbox-{}-{}", std::process::id(), n));
        let peer_root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("rf-reply-outbox-peer-{}-{}", std::process::id(), n));
        let client = open_identity(&root, "acct", "acct-device", [41; 32], [42; 32])?;
        let peer = open_identity(&peer_root, "peer", "peer-device", [43; 32], [44; 32])?;
        let db = client.account_db()?;
        db.install_receive_ledger_schema()?;
        db.seed_receive_epoch_for_test(TARGET, INCARNATION)?;
        client.persist_root_verified_directory(
            &crate::client::identity_authority::test_support::public_manifest(&client)?,
        )?;
        client.persist_identity_directory(
            &crate::client::identity_authority::test_support::manifest(&peer)?,
        )?;
        peer.persist_root_verified_directory(
            &crate::client::identity_authority::test_support::public_manifest(&peer)?,
        )?;
        peer.persist_identity_directory(
            &crate::client::identity_authority::test_support::manifest(&client)?,
        )?;
        let local_root = ramflux_crypto::identity_root_commitment(
            &client
                .identity_root
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .verifying_key(),
        );
        let peer_root_id = ramflux_crypto::identity_root_commitment(
            &peer
                .identity_root
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .verifying_key(),
        );
        client.establish_friend_link("link", &peer_root_id, &local_root)?;
        let local_principal = client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .principal_id
            .clone();
        let peer_principal =
            peer.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id.clone();
        db.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"direct","participants":[local_principal, peer_principal]}),
        )?;
        let config = session_config(&client)?;
        bootstrap_pair(&client, &peer, &config)?;
        Ok(Self { root, peer_root, client, peer })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.client.active_account_db = None;
        self.peer.active_account_db = None;
    }
}

fn open_identity(
    root: &std::path::Path,
    principal: &str,
    device: &str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root(principal, root_seed);
    client.create_device_branch(principal, device, 1, device_seed);
    client.open_account_index(&root)?;
    client.create_account(principal, &format!("{principal}-commitment"))?;
    client.unlock_account(principal, b"reply-outbox-secret")?;
    client.initialize_and_publish_prekey_bundle(principal, device, device, device_seed, None)?;
    Ok(client)
}

fn bootstrap_pair(
    sender: &RamfluxClient,
    peer: &RamfluxClient,
    config: &GatewaySessionConfig,
) -> Result<(), SdkError> {
    let peer_branch = peer.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let peer_root = ramflux_crypto::identity_root_commitment(
        &peer
            .identity_root
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key(),
    );
    let message = crate::GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "pair-bootstrap".into(),
        envelope_id: "pair-bootstrap".into(),
        source_principal_id: config.principal_id.clone(),
        sender_id: config.device_id.clone(),
        recipient_device_id: Some(peer_branch.device_id.clone()),
        recipient_principal_commitment: Some(peer_root),
        target_delivery_id: peer_branch.device_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 60,
    };
    let identity = peer.local_device_identity(&peer_branch.device_id)?;
    let bundle = peer.load_x3dh_private_state(&identity)?.bundle;
    let packet = sender.seal_routed_prepared(
        config,
        &message,
        b"bootstrap",
        crate::client::routed::Route::control(),
        SendMaterial { manifest: None, bundle: Some(bundle) },
    )?;
    let mut message = message;
    message.encrypted_body = serde_json::to_vec(&packet)?;
    let envelope = crate::dm::gateway_direct_message_envelope(config, &message, None)?;
    let local = peer_branch.device_id.clone();
    let _ = peer.open_routed(
        &crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: local.clone(),
            envelope,
        },
        &local,
    )?;
    Ok(())
}

pub(super) fn live_material() -> SendMaterial {
    SendMaterial { manifest: None, bundle: None }
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

fn queue_surface(client: &RamfluxClient, peer: &RamfluxClient) -> Result<(), SdkError> {
    queue_surface_at(client, peer, SURFACE_RESPONSE)
}

pub(super) fn queue_surface_at(
    client: &RamfluxClient,
    peer: &RamfluxClient,
    key: &str,
) -> Result<(), SdkError> {
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let peer_branch = peer.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let peer_root = ramflux_crypto::identity_root_commitment(
        &peer
            .identity_root
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key(),
    );
    let raw = json!({
        "carrier": {
            "schema": ramflux_protocol::domain::SURFACE_CARRIER,
            "content_type": "surface",
            "payload_kind": "event",
            "conversation_id": "thread",
            "surface_id": "s",
            "message_id": "resync-reply",
            "sender_principal_id": branch.principal_id,
            "sender_device_id": branch.device_id,
            "author_principal_id": branch.principal_id,
            "wire_base64": "Zg",
            "signature": "sig"
        },
        "principal": peer_branch.principal_id,
        "root": peer_root,
        "device": peer_branch.device_id,
        "target": peer_branch.device_id,
        "group": null,
        "epoch": null,
        "expires_at": now_unix_timestamp().saturating_add(300)
    });
    let reply: crate::client::surface::ResyncReply = serde_json::from_value(raw)?;
    let stored = serde_json::to_value(&reply)?;
    client.account_db()?.persist_actor_state(key, &stored)?;
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
    client: &'a RamfluxClient,
    sequence: u64,
    auth_key: &'a str,
    envelope: Envelope,
    kind: ReplyKind,
    response_key: Option<&'a str>,
    message: Option<&'a str>,
    config: Option<&'a GatewaySessionConfig>,
    material: Option<SendMaterial>,
) -> AdmitRequest<'a> {
    AdmitRequest {
        sequence,
        auth_key,
        envelope,
        kind,
        response_key,
        message,
        client,
        pair: None,
        config,
        material,
    }
}

/// Crash after preparing a surface answer, before/after outbox transfer, after courier ack
/// (marker stays), and after W0 terminal prune.
#[test]
fn reply_outbox_crash() -> Result<(), SdkError> {
    let _hang = hang_guard();
    let mut fixture = Fixture::new()?;
    let config = session_config(&fixture.client)?;
    let surface = envelope("surface-env");
    let second = bound_envelope(&fixture.client, "pair-env")?;
    let target = device_target(&fixture.peer)?;
    assert_ne!(surface.target_delivery_id, target);

    let missing = gate(fixture.client.account_db()?)?.admit(
        fixture.client.account_db()?,
        req(
            &fixture.client,
            SURFACE_SEQ,
            SURFACE_KEY,
            surface.clone(),
            ReplyKind::Surface,
            Some(SURFACE_RESPONSE),
            Some(MESSAGE),
            Some(&config),
            Some(live_material()),
        ),
    );
    match missing {
        Err(SdkError::Storage(StorageError::Integrity(text))) if text == INTEGRITY => {}
        other => panic!("expected Integrity({INTEGRITY:?}), got {other:?}"),
    }

    stage(&fixture.client, SURFACE_SEQ)?;
    queue_surface(&fixture.client, &fixture.peer)?;

    let pre = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(pre.response);
    assert!(!pre.outbox);
    assert_eq!(pre.work, 1);

    assert_integrity(
        run(Fault::BeforeCommit, || {
            gate(fixture.client.account_db()?)?.admit(
                fixture.client.account_db()?,
                req(
                    &fixture.client,
                    SURFACE_SEQ,
                    SURFACE_KEY,
                    surface.clone(),
                    ReplyKind::Surface,
                    Some(SURFACE_RESPONSE),
                    Some(MESSAGE),
                    Some(&config),
                    Some(live_material()),
                ),
            )
        }),
        BEFORE,
    );
    reopen(&mut fixture.client)?;
    assert_eq!(snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?, pre);

    let reply = queued_reply(&fixture.client)?;
    let pair_snap = pair_rows(fixture.client.account_db()?)?;
    let _clock = crate::time::FixedClock::set(now_unix_timestamp());
    let expected = crate::client::surface::with_fixed_surface_envelope_id("fixed-surface", || {
        fixture.client.seal_surface_resync_reply(&config, &reply, live_material())
    })?;
    restore_pair_rows(fixture.client.account_db()?, &pair_snap)?;
    assert_eq!(
        crate::client::surface::with_fixed_surface_envelope_id("fixed-surface", || {
            gate(fixture.client.account_db()?)?.admit(
                fixture.client.account_db()?,
                req(
                    &fixture.client,
                    SURFACE_SEQ,
                    SURFACE_KEY,
                    surface.clone(),
                    ReplyKind::Surface,
                    Some(SURFACE_RESPONSE),
                    Some(MESSAGE),
                    Some(&config),
                    Some(live_material()),
                ),
            )
        })?,
        Admit::Admitted
    );
    reopen(&mut fixture.client)?;
    let after_surface = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(!after_surface.response, "surface response must transfer before removal");
    assert!(after_surface.outbox);
    assert!(after_surface.marker);
    assert_ne!(after_surface.envelope_id.as_deref(), Some("surface-env"));
    assert_eq!(stored_target(&fixture.client, SURFACE_KEY)?, target);
    assert_eq!(after_surface.work, 1);
    assert_eq!(after_surface.disposition.as_deref(), Some("staged"));
    let stored = stored_reply(&fixture.client, SURFACE_KEY)?;
    assert_eq!(stored.envelope, expected);
    assert_control_packet(&fixture.peer, &stored, &reply)?;

    assert_eq!(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                &fixture.client,
                SURFACE_SEQ,
                SURFACE_KEY,
                envelope("placeholder"),
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
                None,
                None,
            ),
        )?,
        Admit::Duplicate
    );

    stage(&fixture.client, PAIR_SEQ)?;
    queue_surface(&fixture.client, &fixture.peer)?;
    assert_eq!(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                &fixture.client,
                PAIR_SEQ,
                PAIR_KEY,
                second.clone(),
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
                Some(&config),
                Some(live_material()),
            ),
        )?,
        Admit::Admitted
    );
    reopen(&mut fixture.client)?;
    let after_pair = snap(&fixture.client, PAIR_KEY, PAIR_SEQ)?;
    assert!(after_pair.outbox);
    assert!(after_pair.marker);
    assert_ne!(after_pair.envelope_id.as_deref(), Some("pair-env"));
    assert_eq!(after_pair.work, 2, "surface and pair W0 rows both remain");
    assert_eq!(after_pair.disposition.as_deref(), Some("staged"));

    let first =
        due(fixture.client.account_db()?)?.ok_or(SdkError::LocalBus("due surface".into()))?;
    assert_eq!(first.0, PAIR_KEY);
    assert_eq!(first.1.kind, ReplyKind::Surface);
    assert_eq!(first.1.envelope.target_delivery_id, target);
    acknowledge(fixture.client.account_db()?, &first.0)?;
    let still =
        due(fixture.client.account_db()?)?.ok_or(SdkError::LocalBus("due surface".into()))?;
    assert_eq!(still.0, SURFACE_KEY);
    assert_eq!(still.1.kind, ReplyKind::Surface);
    reopen(&mut fixture.client)?;
    let pending = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(pending.outbox, "network write before receipt must retain the envelope");
    acknowledge(fixture.client.account_db()?, SURFACE_KEY)?;
    reopen(&mut fixture.client)?;
    let acked = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(!acked.outbox);
    assert!(acked.marker, "courier ack keeps the transfer marker");
    assert_eq!(acked.disposition.as_deref(), Some("staged"));
    assert_eq!(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                &fixture.client,
                SURFACE_SEQ,
                SURFACE_KEY,
                envelope("placeholder"),
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
                None,
                None,
            ),
        )?,
        Admit::Duplicate
    );
    assert!(due(fixture.client.account_db()?)?.is_none());
    gate(fixture.client.account_db()?)?.settle_terminal(
        fixture.client.account_db()?,
        SURFACE_SEQ,
        SURFACE_KEY,
    )?;
    reopen(&mut fixture.client)?;
    let done = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(!done.outbox);
    assert!(!done.marker, "W0 terminal prunes the transfer marker");
    gate(fixture.client.account_db()?)?.settle_terminal(
        fixture.client.account_db()?,
        PAIR_SEQ,
        PAIR_KEY,
    )?;

    join_stage_and_admit(&mut fixture.client, &fixture.peer)?;
    acknowledge(fixture.client.account_db()?, "join-auth")?;
    gate(fixture.client.account_db()?)?.settle_terminal(
        fixture.client.account_db()?,
        3,
        "join-auth",
    )?;
    fill_and_hold(&mut fixture.client, &fixture.peer)?;
    erase_bound_row(&fixture.client, &fixture.peer)?;
    pair_requires_live_prepare(&fixture.client)?;
    hold_keeps_quarantined(&fixture.client)?;
    Ok(())
}

fn queued_reply(client: &RamfluxClient) -> Result<crate::client::surface::ResyncReply, SdkError> {
    client
        .account_db()?
        .load_actor_state(SURFACE_RESPONSE)?
        .ok_or_else(|| SdkError::LocalBus("queued surface reply".into()))
}

fn stored_reply(client: &RamfluxClient, auth_key: &str) -> Result<PreparedReply, SdkError> {
    client
        .account_db()?
        .load_actor_state(&format!("{OUTBOX}{auth_key}"))?
        .ok_or_else(|| SdkError::LocalBus("stored envelope".into()))
}

pub(crate) fn pair_rows(db: &AccountDb) -> Result<Vec<(String, serde_json::Value)>, SdkError> {
    let mut rows = Vec::new();
    for key in db.actor_state_keys("dm-pair/")? {
        let value = db
            .load_actor_state(&key)?
            .ok_or_else(|| SdkError::LocalBus("pair row missing".into()))?;
        rows.push((key, value));
    }
    Ok(rows)
}

pub(crate) fn restore_pair_rows(
    db: &AccountDb,
    rows: &[(String, serde_json::Value)],
) -> Result<(), SdkError> {
    for key in db.actor_state_keys("dm-pair/")? {
        db.remove_actor_state(&key)?;
    }
    for (key, value) in rows {
        db.persist_actor_state(key, value)?;
    }
    Ok(())
}

fn assert_control_packet(
    peer: &RamfluxClient,
    stored: &PreparedReply,
    reply: &crate::client::surface::ResyncReply,
) -> Result<(), SdkError> {
    let local = device_target(peer)?;
    let opened = peer.open_routed(
        &crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: local.clone(),
            envelope: stored.envelope.clone(),
        },
        &local,
    )?;
    assert!(
        opened.body.starts_with(CONTROL_PREFIX),
        "stored payload must be a surface control packet"
    );
    let control: SurfaceControl = serde_json::from_slice(&opened.body[CONTROL_PREFIX.len()..])?;
    assert!(matches!(control.kind, ControlKind::Peer));
    assert_eq!(control.carrier_base64, ramflux_protocol::encode_base64url(reply.carrier.bytes()?));
    assert_eq!(control.group_epoch, None);
    assert!(control.context.is_none());
    assert_eq!(control.manifests, Vec::new());
    Ok(())
}

fn stored_target(client: &RamfluxClient, auth_key: &str) -> Result<String, SdkError> {
    let prepared: PreparedReply = client
        .account_db()?
        .load_actor_state(&format!("{OUTBOX}{auth_key}"))?
        .ok_or_else(|| SdkError::LocalBus("stored envelope".into()))?;
    Ok(prepared.envelope.target_delivery_id)
}

fn pair_requires_live_prepare(client: &RamfluxClient) -> Result<(), SdkError> {
    const SEQ: u64 = 7;
    stage(client, SEQ)?;
    assert_integrity(
        gate(client.account_db()?)?.admit(
            client.account_db()?,
            AdmitRequest {
                sequence: SEQ,
                auth_key: "pair-live",
                envelope: envelope("pair-live-env"),
                kind: ReplyKind::Pair,
                response_key: None,
                message: None,
                client,
                pair: None,
                config: None,
                material: None,
            },
        ),
        "reply outbox pair requires live prepare",
    );
    Ok(())
}

fn join_stage_and_admit(client: &mut RamfluxClient, peer: &RamfluxClient) -> Result<(), SdkError> {
    const SEQ: u64 = 3;
    const KEY: &str = "join-auth";
    let entry = wire(SEQ);
    let envelope = bound_envelope(client, "join-env")?;
    let config = session_config(client)?;
    queue_surface(client, peer)?;
    {
        let db = client.account_db()?;
        let outbox = gate(db)?;
        assert_integrity(
            run(Fault::BeforeCommit, || {
                db.receive_transaction(outbox.expected, outbox.generation, |tx| {
                    tx.stage(staged(&entry, SEQ))?;
                    outbox
                        .admit_in(
                            tx,
                            req(
                                client,
                                SEQ,
                                KEY,
                                envelope.clone(),
                                ReplyKind::Surface,
                                Some(SURFACE_RESPONSE),
                                Some(MESSAGE),
                                Some(&config),
                                Some(live_material()),
                            ),
                        )
                        .map_err(|error| match error {
                            SdkError::Storage(storage) => storage,
                            _ => StorageError::Integrity("join admit"),
                        })?;
                    Ok(())
                })?;
                Ok(Admit::Admitted)
            }),
            BEFORE,
        );
    }
    reopen(client)?;
    let rolled = snap(client, KEY, SEQ)?;
    assert!(!rolled.outbox, "joined W1+admit rolls back together");
    assert_eq!(rolled.disposition, None);
    queue_surface(client, peer)?;
    {
        let db = client.account_db()?;
        let outbox = gate(db)?;
        db.receive_transaction(outbox.expected, outbox.generation, |tx| {
            tx.stage(staged(&entry, SEQ))?;
            outbox
                .admit_in(
                    tx,
                    req(
                        client,
                        SEQ,
                        KEY,
                        envelope,
                        ReplyKind::Surface,
                        Some(SURFACE_RESPONSE),
                        Some(MESSAGE),
                        Some(&config),
                        Some(live_material()),
                    ),
                )
                .map_err(|error| match error {
                    SdkError::Storage(storage) => storage,
                    _ => StorageError::Integrity("join admit"),
                })?;
            Ok(())
        })?;
    }
    reopen(client)?;
    let joined = snap(client, KEY, SEQ)?;
    assert!(joined.outbox);
    assert!(joined.marker);
    assert_eq!(joined.disposition.as_deref(), Some("staged"));
    Ok(())
}

fn fill_and_hold(client: &mut RamfluxClient, peer: &RamfluxClient) -> Result<(), SdkError> {
    let config = session_config(client)?;
    let cap = bound_envelope(client, "cap-env")?;
    let held_env = bound_envelope(client, "held-env")?;
    {
        let db = client.account_db()?;
        for i in 0..254 {
            db.persist_actor_state(&format!("{OUTBOX}fill-{i}"), &json!({"pad": i}))?;
        }
    }
    queue_surface(client, peer)?;
    stage(client, 4)?;
    assert_eq!(
        gate(client.account_db()?)?.admit(
            client.account_db()?,
            req(
                client,
                4,
                "cap-auth",
                cap,
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                None,
                Some(&config),
                Some(live_material()),
            ),
        )?,
        Admit::Admitted,
        "254 combined rows still admit (256 after both writes)"
    );
    queue_surface(client, peer)?;
    stage(client, 5)?;
    let pre = snap(client, "held-auth", 5)?;
    assert!(pre.response);
    assert_eq!(pre.disposition.as_deref(), Some("staged"));
    assert!(pre.work >= 1);
    assert_eq!(
        gate(client.account_db()?)?.admit(
            client.account_db()?,
            req(
                client,
                5,
                "held-auth",
                held_env.clone(),
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                None,
                Some(&config),
                Some(live_material()),
            ),
        )?,
        Admit::OutboxFull
    );
    reopen(client)?;
    let held = snap(client, "held-auth", 5)?;
    assert!(held.response, "full outbox must retain the response");
    assert!(!held.outbox);
    assert!(!held.marker);
    assert_eq!(held.work, pre.work, "full outbox must retain W0");
    assert_eq!(held.disposition.as_deref(), Some("held"));
    {
        let db = client.account_db()?;
        for i in 0..254 {
            db.remove_actor_state(&format!("{OUTBOX}fill-{i}"))?;
        }
    }
    acknowledge(client.account_db()?, "cap-auth")?;
    gate(client.account_db()?)?.settle_terminal(client.account_db()?, 4, "cap-auth")?;
    assert_eq!(
        gate(client.account_db()?)?.admit(
            client.account_db()?,
            req(
                client,
                5,
                "held-auth",
                held_env,
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                None,
                Some(&config),
                Some(live_material()),
            ),
        )?,
        Admit::Admitted,
        "held input re-admits once after the outbox drains"
    );
    Ok(())
}

fn erase_bound_row(client: &RamfluxClient, peer: &RamfluxClient) -> Result<(), SdkError> {
    const SEQ: u64 = 6;
    const KEY: &str = "erase-auth";
    let config = session_config(client)?;
    let envelope = bound_envelope(client, "erase-env")?;
    stage(client, SEQ)?;
    queue_surface(client, peer)?;
    let db = client.account_db()?;
    db.send_direct_message("thread", ERASE, "peer", b"secret")?;
    let outbox = gate(db)?;
    db.receive_transaction(outbox.expected, outbox.generation, |tx| {
        outbox
            .admit_in(
                tx,
                req(
                    client,
                    SEQ,
                    KEY,
                    envelope,
                    ReplyKind::Surface,
                    Some(SURFACE_RESPONSE),
                    Some(ERASE),
                    Some(&config),
                    Some(live_material()),
                ),
            )
            .map_err(|error| match error {
                SdkError::Storage(storage) => storage,
                _ => StorageError::Integrity("erase admit"),
            })?;
        Ok(())
    })?;
    assert!(db.actor_state_exists(&format!("{OUTBOX}{KEY}"))?);
    assert!(db.actor_state_exists(&format!("{}{KEY}", super::MARKER))?);
    db.delete_direct_message("thread", ERASE, "local", "delete-reply")?;
    assert!(
        !db.actor_state_exists(&format!("{OUTBOX}{KEY}"))?,
        "erase of the bound message must drop the reply outbox row"
    );
    assert!(
        !db.actor_state_exists(&format!("{}{KEY}", super::MARKER))?,
        "erase of the bound message must drop the transfer marker"
    );
    Ok(())
}

fn hold_keeps_quarantined(client: &RamfluxClient) -> Result<(), SdkError> {
    const SEQ: u64 = 8;
    stage(client, SEQ)?;
    let db = client.account_db()?;
    db.set_receipt_disposition_for_test(SEQ, "quarantined")?;
    let outbox = gate(db)?;
    db.receive_transaction(outbox.expected, outbox.generation, |tx| {
        tx.hold_receipt(SEQ)?;
        Ok(())
    })?;
    let (disposition, _) = db.receive_state_for_test(SEQ)?;
    assert_eq!(disposition.as_deref(), Some("quarantined"));
    Ok(())
}

#[test]
fn surface_admit_requires_config_and_material() -> Result<(), SdkError> {
    let _hang = hang_guard();
    let fixture = Fixture::new()?;
    let config = session_config(&fixture.client)?;
    let surface = envelope("surface-env");
    stage(&fixture.client, SURFACE_SEQ)?;
    queue_surface(&fixture.client, &fixture.peer)?;
    let pre = snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?;
    assert!(pre.response);
    assert!(!pre.outbox);
    assert_eq!(pre.work, 1);
    assert_eq!(pre.disposition.as_deref(), Some("staged"));

    assert_integrity(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                &fixture.client,
                SURFACE_SEQ,
                SURFACE_KEY,
                surface.clone(),
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
                None,
                Some(live_material()),
            ),
        ),
        "reply outbox surface requires session config",
    );
    assert_eq!(
        snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?,
        pre,
        "config None leaves response and W0 unchanged"
    );

    assert_integrity(
        gate(fixture.client.account_db()?)?.admit(
            fixture.client.account_db()?,
            req(
                &fixture.client,
                SURFACE_SEQ,
                SURFACE_KEY,
                surface,
                ReplyKind::Surface,
                Some(SURFACE_RESPONSE),
                Some(MESSAGE),
                Some(&config),
                None,
            ),
        ),
        "reply outbox surface requires send material",
    );
    assert_eq!(
        snap(&fixture.client, SURFACE_KEY, SURFACE_SEQ)?,
        pre,
        "material None leaves response and W0 unchanged"
    );
    Ok(())
}
