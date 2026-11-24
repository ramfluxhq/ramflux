// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Review r1 M3 and M7 on the import side, and the group-of-three, lost-export-reply and
//! missing-entry requirements, against the real ledger, backend and key slots.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use ed25519_dalek::SigningKey;
use prost::Message as _;
use ramflux_crypto::X25519KeyPair;
use ramflux_protocol::large_attachment::{MediaRef, QualifiedOwner};

use super::budget;
use super::codes::{CODE_LAYOUT_INVALID, CODE_NOT_GRANTEE, CODE_SEAL_FAILED, Refusal};
use super::import_job::{self, Importer, SourcePin};
use super::listener::{Listener, NOW};
use super::plane::{OwnerCall, Plane, ReadCall, RegisterCall, RetireCall};
use super::publish;
use super::section10::{accept, import_all, owner_pair, publish_input};
use super::store::Store;
use super::targets::{self, MediaDevice, MediaScope};

fn member(index: u64) -> (MediaDevice, [u8; 32], QualifiedOwner) {
    let mut seed = [11_u8; 32];
    seed[0] = u8::try_from(index).unwrap();
    let hpke = X25519KeyPair::from_seed(seed);
    let mut sign = [6_u8; 32];
    sign[0] = seed[0];
    let signing = SigningKey::from_bytes(&sign);
    let device = MediaDevice {
        account_anchor: format!("member-{index}"),
        device_id: format!("phone-{index}"),
        device_epoch: 1,
        signing_public: signing.verifying_key().to_bytes(),
        home_node_id: "node-a".into(),
        hpke_public: hpke.public,
        layer: 4,
        own: false,
    };
    let reader = QualifiedOwner {
        account_anchor: device.account_anchor.clone(),
        device_id: device.device_id.clone(),
        device_epoch: 1,
        signing_public_key: device.signing_public,
        home_node_id: "node-a".into(),
    };
    (device, seed, reader)
}

fn pin() -> ([u8; 32], u64) {
    (SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes(), 4)
}

/// Flips one byte of every ranged read, as a hostile or corrupted relay would.
struct Tamper<'a>(&'a Listener);

impl Plane for Tamper<'_> {
    fn owner(&self, call: &OwnerCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.0.owner(call)
    }
    fn register(&self, call: &RegisterCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.0.register(call)
    }
    fn read(&self, call: &ReadCall<'_>) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.0.read(call)?;
        if let Some(first) = bytes.first_mut() {
            *first ^= 0x55;
        }
        Ok(bytes)
    }
    fn retire(&self, call: &RetireCall<'_>) -> Result<Vec<u8>, Refusal> {
        self.0.retire(call)
    }
}

fn sent(
    dir: &std::path::Path,
    body: &[u8],
    targets: &[MediaDevice],
) -> (Listener, Store, ramflux_protocol::message::MediaRef, super::meta::Row) {
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir, owner.clone()).unwrap();
    let store = Store::open(dir, "acct", [3; 32]).unwrap();
    let row = accept(&store, "import", body);
    let wrapped = publish::publish_all(
        &publish_input(&store, &listener, &owner, &key, targets, "node-a"),
        std::slice::from_ref(&row),
    )
    .unwrap();
    let row = store.load(&row.prepare_id).unwrap();
    (listener, store, wrapped[0].media.clone(), row)
}

#[test]
fn a_group_of_three_each_member_imports_only_its_own_entry() {
    let dir = tempfile::tempdir().unwrap();
    let members: Vec<_> = (1..=3).map(member).collect();
    let devices: Vec<_> = members.iter().map(|(device, _, _)| device.clone()).collect();
    let chosen = targets::choose_targets(MediaScope::Group, &devices).unwrap();
    assert_eq!(chosen.len(), 3);
    let body = b"group file for three";
    let (listener, _store, media, _) = sent(dir.path(), body, &chosen);
    assert_eq!(media.key_slots.len(), 3, "one entry per member device");
    let (authority, generation) = pin();
    let source = SourcePin { source: "node-a", generation, public_key: &authority, now: NOW };
    for (device, seed, reader) in &members {
        listener.set_reader(reader.clone());
        let plain = import_all(
            &listener,
            &media,
            &Importer {
                account_anchor: &device.account_anchor,
                device_id: &device.device_id,
                device_epoch: 1,
                secret: seed,
            },
            &source,
        )
        .unwrap();
        assert_eq!(plain, body, "{} reads the file", device.device_id);
    }
    assert_eq!(listener.reads(), 3, "exactly one ranged read per member");

    // A former member has no entry: the message shows, the body is refused, no GET is sent.
    let outsider = import_all(
        &listener,
        &media,
        &Importer {
            account_anchor: "member-9",
            device_id: "phone-9",
            device_epoch: 1,
            secret: &[1; 32],
        },
        &source,
    )
    .unwrap_err();
    assert_eq!(outsider.code, CODE_NOT_GRANTEE);
    assert_eq!(listener.reads(), 3, "a missing entry sends no relay read");
}

#[test]
fn a_tampered_segment_is_refused_before_any_plaintext_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let (device, seed, reader) = member(1);
    let (listener, _store, media, _) =
        sent(dir.path(), b"integrity matters", std::slice::from_ref(&device));
    listener.set_reader(reader);
    let (authority, generation) = pin();
    let source = SourcePin { source: "node-a", generation, public_key: &authority, now: NOW };
    let importer = Importer {
        account_anchor: &device.account_anchor,
        device_id: &device.device_id,
        device_epoch: 1,
        secret: &seed,
    };
    let opened = import_job::open_entry(&media, &importer, &source).unwrap();
    let mut sink = Vec::new();
    let error = import_job::stream_remote(
        &Tamper(&listener),
        &opened,
        &mut sink,
        &|| false,
        &budget::Meter::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_SEAL_FAILED, "the segment digest does not match the manifest");
    assert!(sink.is_empty(), "no unverified byte reached the staging file");
}

#[test]
fn a_manifest_plaintext_digest_that_does_not_match_the_body_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (device, seed, reader) = member(1);
    let (listener, _store, media, _) =
        sent(dir.path(), b"plaintext digest", std::slice::from_ref(&device));
    listener.set_reader(reader);
    // Rebuild a canonical reference whose only change is the plaintext digest, so every
    // binding the codec checks still holds and only the end-to-end digest can catch it.
    let mut native = MediaRef::decode(&media.encode_to_vec()).unwrap();
    native.large_manifest.plaintext_digest = [0xAA; 32];
    native.manifest_digest = native.large_manifest.hash().unwrap();
    let forged = import_prost(&native);
    let (authority, generation) = pin();
    let source = SourcePin { source: "node-a", generation, public_key: &authority, now: NOW };
    let error = import_all(
        &listener,
        &forged,
        &Importer {
            account_anchor: &device.account_anchor,
            device_id: &device.device_id,
            device_epoch: 1,
            secret: &seed,
        },
        &source,
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_SEAL_FAILED, "the whole-plaintext digest is checked");
}

fn import_prost(native: &MediaRef) -> ramflux_protocol::message::MediaRef {
    ramflux_protocol::message::MediaRef::decode(native.canonical_bytes().unwrap().as_slice())
        .unwrap()
}

#[test]
fn a_reference_whose_grant_names_another_object_is_refused_without_a_read() {
    let dir = tempfile::tempdir().unwrap();
    let (device, seed, reader) = member(1);
    let (listener, _store, media, _) =
        sent(dir.path(), b"object binding", std::slice::from_ref(&device));
    listener.set_reader(reader);
    let mut forged = media.clone();
    forged.object_id = ramflux_protocol::encode_base64url([0x42; 32]);
    let (authority, generation) = pin();
    let source = SourcePin { source: "node-a", generation, public_key: &authority, now: NOW };
    let error = import_all(
        &listener,
        &forged,
        &Importer {
            account_anchor: &device.account_anchor,
            device_id: &device.device_id,
            device_epoch: 1,
            secret: &seed,
        },
        &source,
    )
    .unwrap_err();
    assert_eq!(
        error.code, CODE_LAYOUT_INVALID,
        "the capability's object id must equal the reference"
    );
    assert_eq!(listener.reads(), 0);
}

#[test]
fn a_duplicate_entry_for_one_device_is_refused_by_the_codec() {
    let dir = tempfile::tempdir().unwrap();
    let (device, _, _) = member(1);
    let (_listener, _store, media, _) =
        sent(dir.path(), b"duplicate slots", std::slice::from_ref(&device));
    let mut native = MediaRef::decode(&media.encode_to_vec()).unwrap();
    let again = native.key_slots[0].clone();
    native.key_slots.push(again.clone());
    native.large_manifest.key_slots.push(again);
    assert!(native.large_manifest.hash().is_err(), "two entries for one TargetKey do not encode");
}

#[test]
fn the_sender_reads_its_own_file_from_the_account_sealed_key_and_a_flipped_byte_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (device, _, _) = member(1);
    let body = b"my own file";
    let (_listener, store, _media, row) = sent(dir.path(), body, std::slice::from_ref(&device));
    let mut sink = Vec::new();
    import_job::stream_owned(&store, &row, &mut sink, &|| false, &budget::Meter::default())
        .unwrap();
    assert_eq!(sink, body);
    let segment = dir
        .path()
        .join("attachment-prepares")
        .join(&row.prepare_id)
        .join(super::seal_job::segment_name_of(0));
    let mut bytes = std::fs::read(&segment).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&segment, bytes).unwrap();
    let mut again = Vec::new();
    let error =
        import_job::stream_owned(&store, &row, &mut again, &|| false, &budget::Meter::default())
            .unwrap_err();
    assert_eq!(error.code, CODE_SEAL_FAILED);
    assert!(again.is_empty(), "nothing is written for a segment whose digest differs");
}

#[test]
fn a_nine_megabyte_import_holds_two_segments_not_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let (device, seed, reader) = member(1);
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let body: Vec<u8> = (0..9 * 1024 * 1024_u32).map(|n| u8::try_from(n % 251).unwrap()).collect();
    let begun = store
        .begin(
            super::meta::Intent {
                account: "acct",
                operation_id: "big",
                recipient: super::meta::Recipient::Dm { peer: "member-1".into() },
                file_name: "big.bin",
                mime: "application/octet-stream",
            },
            true,
            NOW,
            None,
        )
        .unwrap();
    let mut offset = 0_u64;
    for piece in body.chunks(524_288) {
        store.chunk(&begun.prepare_id, 1, offset, piece, NOW).unwrap();
        offset += u64::try_from(piece.len()).unwrap();
    }
    let digest = *blake3::hash(&body).as_bytes();
    let row = store
        .finish(
            &begun.prepare_id,
            1,
            offset,
            super::thumbnail::Finished { digest, thumbnail: None },
            NOW,
        )
        .unwrap();
    let wrapped = publish::publish_all(
        &publish_input(&store, &listener, &owner, &key, std::slice::from_ref(&device), "node-a"),
        std::slice::from_ref(&row),
    )
    .unwrap();
    listener.set_reader(reader);
    let (authority, generation) = pin();
    let source = SourcePin { source: "node-a", generation, public_key: &authority, now: NOW };
    let opened = import_job::open_entry(
        &wrapped[0].media,
        &Importer {
            account_anchor: &device.account_anchor,
            device_id: &device.device_id,
            device_epoch: 1,
            secret: &seed,
        },
        &source,
    )
    .unwrap();
    let meter = budget::Meter::default();
    let mut sink = Vec::new();
    import_job::stream_remote(&listener, &opened, &mut sink, &|| false, &meter).unwrap();
    assert_eq!(sink.len(), body.len());
    assert_eq!(blake3::hash(&sink).as_bytes(), &digest, "the body is intact");
    let segment = u64::from(ramflux_protocol::large_attachment::SEGMENT_BYTES);
    assert!(meter.peak() <= 2 * segment, "peak {} exceeds two segments", meter.peak());
    assert!(meter.peak() > 0, "the meter saw the working set");
    assert!(u64::try_from(body.len()).unwrap() > 2 * segment, "the file is larger than the window");
}
