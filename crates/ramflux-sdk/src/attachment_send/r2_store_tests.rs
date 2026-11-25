// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Review r1 M2, M4, M5, M6 and M7 on real components: the real store, the real publish
//! phases, and the relay ledger behind the test listener. Faults are injected at the plane
//! or the sealing seam, never by seeding rows.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use prost::Message as _;
use ramflux_protocol::large_attachment::QualifiedOwner;

use super::budget;
use super::codes::{
    CODE_AUTHORITY_UNAVAILABLE, CODE_CANCELLED, CODE_DIGEST_MISMATCH, CODE_DISK_FULL, Refusal,
};
use super::listener::{Listener, NOW};
use super::meta::Phase;
use super::plane::{OwnerCall, Plane, ReadCall, RegisterCall, RetireCall};
use super::publish::{self, PublishInput};
use super::seal_job;
use super::section10::{accept, device, owner_pair, peer, publish_input};
use super::store::Store;

/// Forwards to the listener and loses the reply of the nth registration: the relay recorded
/// it, the caller never learns the capability.
struct LostRegisterReply<'a> {
    inner: &'a Listener,
    lose: u64,
    seen: AtomicU64,
}

impl Plane for LostRegisterReply<'_> {
    fn upload_status(
        &self,
        query: &super::plane::UploadQuery,
    ) -> Result<ramflux_protocol::attachment_wire::AttachmentUploadStatus, Refusal> {
        self.inner.upload_status(query)
    }
    fn owner(&self, call: &OwnerCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.inner.owner(call)
    }
    fn register(&self, call: &RegisterCall<'_>) -> Result<Vec<u8>, Refusal> {
        let reply = self.inner.register(call);
        if self.seen.fetch_add(1, Ordering::SeqCst) + 1 == self.lose {
            return Err(Refusal::new(CODE_AUTHORITY_UNAVAILABLE));
        }
        reply
    }
    fn read(&self, call: &ReadCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.inner.read(call)
    }
    fn retire(&self, call: &RetireCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.inner.retire(call)
    }
}

fn input<'a>(
    store: &'a Store,
    plane: &'a dyn Plane,
    owner: &'a QualifiedOwner,
    key: &'a SigningKey,
    targets: &'a [super::targets::MediaDevice],
) -> PublishInput<'a> {
    PublishInput {
        store,
        plane,
        owner,
        owner_key: key,
        targets,
        audience: "node-a",
        authority_generation: 4,
        source: "node-a",
        now: NOW,
        caption: "caption",
    }
}

#[test]
fn a_corrupt_snapshot_is_fenced_on_restart_and_never_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = accept(&store, "corrupt", b"hello attachment");
    let plain = store.plain_path(&row.prepare_id);
    let mut bytes = std::fs::read(&plain).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(&plain, bytes).unwrap();

    let restarted = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    restarted.recover_all(NOW).unwrap();
    let fenced = restarted.load(&row.prepare_id).unwrap();
    assert_eq!(fenced.phase, Phase::Fenced, "the corrupt snapshot fences the generation");
    assert!(!plain.exists(), "the corrupt plaintext is removed");
    let (device, _, _) = peer();
    let error = publish::upload_one(
        &input(&restarted, &listener, &owner, &key, std::slice::from_ref(&device)),
        &row.prepare_id,
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_CANCELLED, "a fenced prepare is not sealed");
    assert_eq!(listener.reserves(), 0, "nothing was reserved for the corrupt snapshot");
}

#[test]
fn a_short_snapshot_fails_verification_with_digest_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = accept(&store, "short", b"hello attachment");
    std::fs::write(store.plain_path(&row.prepare_id), b"hello").unwrap();
    let mut loaded = store.load(&row.prepare_id).unwrap();
    let error = store.verify_snapshot(&mut loaded).unwrap_err();
    assert_eq!(error.code, CODE_DIGEST_MISMATCH);
    assert_eq!(store.load(&row.prepare_id).unwrap().phase, Phase::Fenced);
}

#[test]
fn an_intact_snapshot_survives_recovery_and_seals() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = accept(&store, "intact", b"hello attachment");
    let restarted = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    restarted.recover_all(NOW).unwrap();
    assert_eq!(restarted.load(&row.prepare_id).unwrap().phase, Phase::Accepted);
    let (device, _, _) = peer();
    let done = publish::upload_one(
        &input(&restarted, &listener, &owner, &key, std::slice::from_ref(&device)),
        &row.prepare_id,
    )
    .unwrap();
    assert_eq!(done.phase, Phase::Committed);
}

#[test]
fn a_crash_during_sealing_then_restart_seals_a_new_object_and_abandons_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = accept(&store, "crash", b"hello attachment");
    let (device, _, _) = peer();
    let targets = std::slice::from_ref(&device);

    seal_job::crash_after_segment(Some(0));
    let crashed =
        publish::upload_one(&input(&store, &listener, &owner, &key, targets), &row.prepare_id);
    seal_job::crash_after_segment(None);
    assert!(crashed.is_err(), "the sealing step ended before the checkpoint");
    let sealing = store.load(&row.prepare_id).unwrap();
    assert_eq!(sealing.phase, Phase::Sealing, "the durable row says sealing");
    let old_object = sealing.object_id.unwrap();
    let old_upload = sealing.upload_id.unwrap();
    assert_eq!(listener.reserves(), 1);

    // A new process opens the same directory.
    let restarted = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    restarted.recover_all(NOW).unwrap();
    let recovered = restarted.load(&row.prepare_id).unwrap();
    assert_eq!(recovered.phase, Phase::Accepted, "the generation is fenced and re-planned");
    assert_eq!(recovered.generation, 2);
    assert!(recovered.object_id.is_none(), "the old object id is gone");
    assert!(restarted.open_secret(&recovered).is_err(), "the old key is destroyed");
    assert_eq!(recovered.abandoned, vec![old_upload]);

    let done =
        publish::upload_one(&input(&restarted, &listener, &owner, &key, targets), &row.prepare_id)
            .unwrap();
    assert_eq!(done.phase, Phase::Committed);
    assert_ne!(done.object_id, Some(old_object), "the old key and object id are never reused");
    assert_ne!(done.upload_id, Some(old_upload), "the old upload id is not reused");
    assert_eq!(listener.reserves(), 2, "exactly one more reservation for the new object");
    assert!(done.pending_abandon.is_empty(), "the relay confirmed the abandon of the old upload");
}

#[test]
fn a_lost_registration_reply_retries_the_same_grant_id() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let (device, _, _) = peer();
    let targets = std::slice::from_ref(&device);
    let row = accept(&store, "lost", b"hello attachment");
    let lossy = LostRegisterReply { inner: &listener, lose: 1, seen: AtomicU64::new(0) };
    let committed =
        publish::upload_one(&input(&store, &lossy, &owner, &key, targets), &row.prepare_id)
            .unwrap();
    assert_eq!(committed.phase, Phase::Committed);

    let first = publish::wrap_one(&input(&store, &lossy, &owner, &key, targets), &row.prepare_id);
    assert_eq!(first.unwrap_err().code, CODE_AUTHORITY_UNAVAILABLE, "the reply was lost");
    let planned = super::grant_wrap::load(&store, &row.prepare_id).unwrap();
    assert_eq!(planned.len(), 1, "the grant was written before registration");
    assert!(planned[0].capability.is_none(), "the capability was never received");

    // The same process, or a new one, retries.
    let restarted = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let wrapped =
        publish::wrap_one(&input(&restarted, &lossy, &owner, &key, targets), &row.prepare_id)
            .unwrap();
    let after = super::grant_wrap::load(&restarted, &row.prepare_id).unwrap();
    assert_eq!(after.len(), 1, "one grant per target, no leaked second grant");
    assert_eq!(after[0].grant_id, planned[0].grant_id, "the retry registers the same grant id");
    assert_eq!(listener.registers(), 2, "the relay saw the same grant twice");
    assert_eq!(wrapped.media.key_slots[0].grant_id, planned[0].grant_id.to_vec());
}

#[test]
fn retrying_a_finished_send_returns_the_stored_result_without_the_relay() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let (device, _, _) = peer();
    let targets = std::slice::from_ref(&device);
    let row = accept(&store, "retry", b"hello attachment");
    let first = publish::publish_all(
        &publish_input(&store, &listener, &owner, &key, targets, "node-a"),
        std::slice::from_ref(&row),
    )
    .unwrap();
    store.admit_granted(std::slice::from_ref(&row.prepare_id), "actual-message-id").unwrap();
    assert_eq!(store.load(&row.prepare_id).unwrap().phase, Phase::Admitted);
    let owner_calls = listener.owner_calls();
    let registers = listener.registers();

    let again = publish::publish_all(
        &publish_input(&store, &listener, &owner, &key, targets, "node-a"),
        std::slice::from_ref(&row),
    )
    .unwrap();
    assert_eq!(again[0].media.encode_to_vec(), first[0].media.encode_to_vec());
    assert_eq!(listener.owner_calls(), owner_calls, "no relay owner call on the retry");
    assert_eq!(listener.registers(), registers, "no second registration on the retry");
    assert_eq!(
        store.load(&row.prepare_id).unwrap().message_id.as_deref(),
        Some("actual-message-id"),
        "the row is bound to the actual message id"
    );
    let other =
        store.admit_granted(std::slice::from_ref(&row.prepare_id), "different-id").unwrap_err();
    assert_eq!(other.code, super::codes::CODE_DUPLICATE, "a row belongs to one message");
}

#[test]
fn a_roster_that_changed_during_upload_is_replanned_at_wrapping() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let first = device("peer-anchor", "first", 1, 4, 1);
    let second = device("peer-anchor", "second", 1, 4, 2);
    let row = accept(&store, "replan", b"hello attachment");
    publish::upload_one(
        &input(&store, &listener, &owner, &key, std::slice::from_ref(&first)),
        &row.prepare_id,
    )
    .unwrap();
    // The first device left and a second joined while the bytes were uploading.
    let wrapped = publish::wrap_one(
        &input(&store, &listener, &owner, &key, std::slice::from_ref(&second)),
        &row.prepare_id,
    )
    .unwrap();
    let slots = &wrapped.media.key_slots;
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].recipient.as_ref().unwrap().device_id, "second");
    let grants = super::grant_wrap::load(&store, &row.prepare_id).unwrap();
    assert_eq!(grants.len(), 1, "no grant was planned for the device that left");
    assert_eq!(listener.registers(), 1);
}

#[test]
fn a_grant_for_a_device_that_left_is_excluded_not_placed_in_the_inner() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let first = device("peer-anchor", "first", 1, 4, 1);
    let second = device("peer-anchor", "second", 1, 4, 2);
    let both = [first.clone(), second.clone()];
    let row = accept(&store, "exclude", b"hello attachment");
    let lossy = LostRegisterReply { inner: &listener, lose: 2, seen: AtomicU64::new(0) };
    publish::upload_one(&input(&store, &lossy, &owner, &key, &both), &row.prepare_id).unwrap();
    // The second registration is lost after the first grant registered.
    assert!(
        publish::wrap_one(&input(&store, &lossy, &owner, &key, &both), &row.prepare_id).is_err()
    );
    // The roster now holds only the second device.
    let wrapped = publish::wrap_one(
        &input(&store, &lossy, &owner, &key, std::slice::from_ref(&second)),
        &row.prepare_id,
    )
    .unwrap();
    assert_eq!(wrapped.media.key_slots.len(), 1);
    assert_eq!(
        wrapped.excluded.len(),
        1,
        "the registered grant of the departed device is reported"
    );
    assert_eq!(wrapped.excluded[0].device_id, "first");
    assert!(wrapped.excluded[0].capability.is_some(), "it is registered, so it must be retired");
}

#[test]
fn disk_full_leaves_the_log_unchanged_and_a_retry_succeeds_once_space_returns() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let begun = store
        .begin(
            super::meta::Intent {
                account: "acct",
                operation_id: "space",
                recipient: super::meta::Recipient::Dm { peer: "peer-anchor".into() },
                file_name: "a.bin",
                mime: "application/octet-stream",
            },
            true,
            NOW,
            None,
        )
        .unwrap();
    budget::force_free_bytes(dir.path(), 4);
    let refused = store.chunk(&begun.prepare_id, 1, 0, b"hello attachment", NOW).unwrap_err();
    assert_eq!(refused.code, CODE_DISK_FULL);
    assert_eq!(store.load(&begun.prepare_id).unwrap().accepted_through, 0, "nothing was copied");
    assert!(!store.plain_path(&begun.prepare_id).exists(), "no plaintext file was created");

    budget::force_free_bytes(dir.path(), 1 << 30);
    store.chunk(&begun.prepare_id, 1, 0, b"hello attachment", NOW).unwrap();
    // The ciphertext, workspace and margin do not fit in what is left.
    budget::force_free_bytes(dir.path(), 64);
    let digest = *blake3::hash(b"hello attachment").as_bytes();
    let refused = store
        .finish(
            &begun.prepare_id,
            1,
            16,
            super::metadata::Finished {
                digest,
                thumbnail: None,
                metadata: super::metadata::Metadata::default(),
            },
            NOW,
        )
        .unwrap_err();
    assert_eq!(refused.code, CODE_DISK_FULL);
    assert_eq!(
        store.load(&begun.prepare_id).unwrap().phase,
        Phase::Accepting,
        "the row stays open so the same finish can be retried"
    );
    budget::force_free_bytes(dir.path(), 1 << 30);
    let done = store
        .finish(
            &begun.prepare_id,
            1,
            16,
            super::metadata::Finished {
                digest,
                thumbnail: None,
                metadata: super::metadata::Metadata::default(),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(done.phase, Phase::Accepted);
    assert!(done.charged > 32, "snapshot, ciphertext, workspace and margin are all reserved");
}

#[test]
fn cancelling_twice_cannot_underflow_the_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = accept(&store, "twice", b"hello attachment");
    assert!(row.charged > 0);
    let first = store.cancel(&row.prepare_id, row.generation).unwrap();
    assert_eq!(first.charged, 0, "the reservation is returned once");
    let second = store.cancel(&row.prepare_id, row.generation).unwrap();
    assert_eq!(second.charged, 0, "a repeat returns nothing more");
}
