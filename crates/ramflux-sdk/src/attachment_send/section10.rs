// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Design section 10. Real ledger admission, no seeded capability bytes.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use ed25519_dalek::SigningKey;
use prost::Message as _;
use ramflux_crypto::X25519KeyPair;
use ramflux_protocol::large_attachment::QualifiedOwner;

use serde_json::json;

use super::budget;
use super::codes::Refusal;
use super::codes::{
    CODE_DIGEST_MISMATCH, CODE_EXPIRED, CODE_LAYOUT_INVALID, CODE_MANIFEST_TOO_LARGE,
    CODE_NOT_GRANTEE, CODE_PEER_UPGRADE, CODE_RECIPIENT_EMPTY, CODE_RECIPIENT_LIMIT,
};
use super::import_job::{self, Importer, SourcePin};
use super::listener::{Listener, NOW};
use super::meta::{Intent, Phase, Recipient};
use super::plane::{Plane, ReadCall};
use super::preflight;
use super::publish::{self, PublishInput};
use super::store::Store;
use super::targets::{self, MediaDevice, MediaScope};

/// Opens the entry and streams the whole body into memory through the real streaming path.
pub(super) fn import_all(
    plane: &dyn Plane,
    media: &ramflux_protocol::message::MediaRef,
    importer: &Importer<'_>,
    pin: &SourcePin<'_>,
) -> Result<Vec<u8>, Refusal> {
    let opened = import_job::open_entry(media, importer, pin)?;
    let mut sink = Vec::new();
    import_job::stream_remote(plane, &opened, &mut sink, &|| false, &budget::Meter::default())?;
    Ok(sink)
}

pub(super) fn owner_pair() -> (SigningKey, QualifiedOwner) {
    let key = SigningKey::from_bytes(&ramflux_node_core::fixture::owner_signing_seed());
    let owner = QualifiedOwner {
        account_anchor: "owner-anchor".into(),
        device_id: "device-1".into(),
        device_epoch: 1,
        signing_public_key: key.verifying_key().to_bytes(),
        home_node_id: "node-a".into(),
    };
    (key, owner)
}

pub(super) fn device(anchor: &str, id: &str, epoch: u64, layer: u32, mark: u8) -> MediaDevice {
    let mut seed = [4_u8; 32];
    seed[0] = mark;
    let signing = SigningKey::from_bytes(&seed);
    MediaDevice {
        account_anchor: anchor.into(),
        device_id: id.into(),
        device_epoch: epoch,
        signing_public: signing.verifying_key().to_bytes(),
        home_node_id: "node-a".into(),
        hpke_public: [7; 32],
        layer,
        own: false,
    }
}

pub(super) fn peer() -> (MediaDevice, [u8; 32], QualifiedOwner) {
    let seed = [9_u8; 32];
    let hpke = X25519KeyPair::from_seed(seed);
    let signing = SigningKey::from_bytes(&[4; 32]);
    let device = MediaDevice {
        account_anchor: "peer-anchor".into(),
        device_id: "peer-device".into(),
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
        device_epoch: device.device_epoch,
        signing_public_key: device.signing_public,
        home_node_id: device.home_node_id.clone(),
    };
    (device, seed, reader)
}

pub(super) fn accept(store: &Store, operation: &str, bytes: &[u8]) -> super::meta::Row {
    let row = store
        .begin(
            Intent {
                account: "acct",
                operation_id: operation,
                recipient: Recipient::Dm { peer: "peer-anchor".into() },
                file_name: "a.bin",
                mime: "application/octet-stream",
            },
            true,
            NOW,
            None,
        )
        .unwrap();
    if !bytes.is_empty() {
        store.chunk(&row.prepare_id, row.generation, 0, bytes, NOW).unwrap();
    }
    let digest = *blake3::hash(bytes).as_bytes();
    let len = u64::try_from(bytes.len()).unwrap();
    store.finish(&row.prepare_id, row.generation, len, digest, NOW).unwrap()
}

#[test]
fn sixty_five_targets_do_not_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let (_, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let mut targets = Vec::new();
    for index in 0..65_u64 {
        let mark = u8::try_from(index).unwrap_or(0);
        targets.push(device("peer-anchor", &format!("device-{index}"), 1, 4, mark));
    }
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let key = SigningKey::from_bytes(&ramflux_node_core::fixture::owner_signing_seed());
    let error = publish::publish_all(
        &PublishInput {
            store: &store,
            plane: &listener,
            owner: &owner,
            owner_key: &key,
            targets: &targets,
            audience: "node-a",
            authority_generation: 4,
            source: "node-a",
            now: NOW,
            caption: "",
        },
        &[],
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_RECIPIENT_LIMIT);
    assert_eq!(listener.reserves(), 0);
}

#[test]
fn same_device_id_under_another_account_is_not_a_duplicate() {
    let left = device("account-a", "device", 1, 4, 1);
    let right = device("account-b", "device", 1, 4, 2);
    let chosen = targets::choose_targets(MediaScope::Dm, &[left, right]).unwrap();
    assert_eq!(chosen.len(), 2);
}

#[test]
fn repeated_target_key_is_layout_invalid_and_does_not_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let (_, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let one = device("peer-anchor", "device", 1, 4, 3);
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let key = SigningKey::from_bytes(&ramflux_node_core::fixture::owner_signing_seed());
    let error = publish::publish_all(
        &PublishInput {
            store: &store,
            plane: &listener,
            owner: &owner,
            owner_key: &key,
            targets: &[one.clone(), one],
            audience: "node-a",
            authority_generation: 4,
            source: "node-a",
            now: NOW,
            caption: "",
        },
        &[],
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_LAYOUT_INVALID);
    assert_eq!(listener.reserves(), 0);
}

#[test]
fn roster_rules_refuse_empty_group_downgrade_and_direct_upgrade() {
    assert_eq!(
        targets::choose_targets(MediaScope::Dm, &[]).unwrap_err().code,
        CODE_RECIPIENT_EMPTY
    );
    let low = device("peer-anchor", "old", 1, 3, 5);
    let high = device("peer-anchor", "new", 1, 4, 6);
    assert_eq!(
        targets::choose_targets(MediaScope::Group, &[low.clone(), high.clone()]).unwrap_err().code,
        CODE_PEER_UPGRADE
    );
    assert_eq!(targets::choose_targets(MediaScope::Dm, &[low, high]).unwrap().len(), 1);
    assert!(preflight::manifest_capability(&[1]).is_err());
    assert!(preflight::manifest_capability(&[]).is_ok());
}

#[test]
fn multi_gigabyte_prepare_is_disk_full_before_any_copy() {
    let dir = tempfile::tempdir().unwrap();
    budget::force_free_bytes(dir.path(), 128 * 1024 * 1024);
    let need = budget::prepare_bytes(4 << 30).unwrap();
    assert!(need > 8 << 30, "plaintext and ciphertext are both reserved: {need}");
    let before = budget::disk_reserved();
    assert_eq!(
        budget::reserve_disk(dir.path(), need).unwrap_err().code,
        super::codes::CODE_DISK_FULL
    );
    assert_eq!(budget::disk_reserved(), before, "a refused reservation holds nothing");
}

#[test]
fn dropped_chunk_retries_the_same_offset_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = store
        .begin(
            Intent {
                account: "acct",
                operation_id: "chunk",
                recipient: Recipient::Dm { peer: "peer".into() },
                file_name: "a.bin",
                mime: "application/octet-stream",
            },
            true,
            NOW,
            None,
        )
        .unwrap();
    let first = store.chunk(&row.prepare_id, 1, 0, b"hello", NOW).unwrap();
    let retry = store.chunk(&row.prepare_id, 1, 0, b"hello", NOW).unwrap();
    assert_eq!(first.accepted_through, 5);
    assert_eq!(retry.accepted_through, 5);
}

#[test]
fn digest_mismatch_fences_and_deletes_the_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = store
        .begin(
            Intent {
                account: "acct",
                operation_id: "digest",
                recipient: Recipient::Dm { peer: "peer".into() },
                file_name: "a.bin",
                mime: "application/octet-stream",
            },
            true,
            NOW,
            None,
        )
        .unwrap();
    store.chunk(&row.prepare_id, 1, 0, b"hello", NOW).unwrap();
    let error = store.finish(&row.prepare_id, 1, 5, [9; 32], NOW).unwrap_err();
    assert_eq!(error.code, CODE_DIGEST_MISMATCH);
    let fenced = store.load(&row.prepare_id).unwrap();
    assert_eq!(fenced.phase, Phase::Fenced);
    assert!(!store.plain_path(&row.prepare_id).exists());
}

#[test]
fn sealing_crash_discards_the_key_and_a_reserved_retry_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = accept(&store, "seal", b"hello");
    let reserved = store.draw(&row.prepare_id, NOW).unwrap();
    let object = reserved.object_id.unwrap();
    let upload = reserved.upload_id.unwrap();
    let again = store.draw(&row.prepare_id, NOW).unwrap();
    assert_eq!(again.object_id, Some(object));
    assert_eq!(again.upload_id, Some(upload));
    store.open_secret(&again).unwrap();
    store.mark(again, Phase::Sealing).unwrap();
    let resumed = store.resume(&row.prepare_id, NOW).unwrap();
    assert_eq!(resumed.phase, Phase::Accepted);
    assert_eq!(resumed.generation, 2);
    assert!(resumed.object_id.is_none());
    assert_eq!(resumed.abandoned, vec![upload]);
    assert!(store.open_secret(&resumed).is_err());
    let fresh = store.draw(&row.prepare_id, NOW).unwrap();
    assert_ne!(fresh.object_id, Some(object));
    assert_ne!(fresh.upload_id, Some(upload));
}

#[test]
fn cancel_after_commit_admits_nothing_and_a_bound_row_keeps_its_upload() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let (device, _, _) = peer();
    let committed = accept(&store, "cancel", b"hello");
    store.mark(committed.clone(), Phase::Committed).unwrap();
    store.cancel(&committed.prepare_id, committed.generation).unwrap();
    let input = PublishInput {
        store: &store,
        plane: &listener,
        owner: &owner,
        owner_key: &key,
        targets: std::slice::from_ref(&device),
        audience: "node-a",
        authority_generation: 4,
        source: "node-a",
        now: NOW,
        caption: "",
    };
    let error = publish::upload_one(&input, &committed.prepare_id).unwrap_err();
    assert_eq!(error.code, super::codes::CODE_CANCELLED);
    assert_eq!(listener.reserves(), 0);
    assert_eq!(store.load(&committed.prepare_id).unwrap().phase, Phase::Cleaning);

    let bound = accept(&store, "bound", b"hello");
    let reserved = store.draw(&bound.prepare_id, NOW).unwrap();
    let upload = reserved.upload_id.unwrap();
    let object = reserved.object_id.unwrap();
    store.mark(reserved, Phase::Bound).unwrap();
    let _ = publish::upload_one(&input, &bound.prepare_id);
    let kept = store.load(&bound.prepare_id).unwrap();
    assert_eq!(kept.upload_id, Some(upload));
    assert_eq!(kept.object_id, Some(object));
    store.mark(kept, Phase::Committed).unwrap();
    let resumed = store.resume(&bound.prepare_id, NOW).unwrap();
    assert_eq!(resumed.object_id, Some(object));
    assert_eq!(resumed.phase, Phase::Committed);
}

#[test]
fn reserve_after_the_hard_deadline_is_expired() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let row = accept(&store, "late", b"hello");
    let error = store.draw(&row.prepare_id, row.hard_deadline).unwrap_err();
    assert_eq!(error.code, CODE_EXPIRED);
    assert_eq!(store.load(&row.prepare_id).unwrap().phase, Phase::Fenced);
}

#[test]
fn one_entry_imports_only_its_grantee_and_a_copy_sends_no_get() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let (device, seed, reader) = peer();
    listener.set_reader(reader);
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let body = b"hello attachment";
    let row = accept(&store, "send", body);
    let wrapped = publish::publish_all(
        &PublishInput {
            store: &store,
            plane: &listener,
            owner: &owner,
            owner_key: &key,
            targets: std::slice::from_ref(&device),
            audience: "node-a",
            authority_generation: 4,
            source: "node-a",
            now: NOW,
            caption: "caption",
        },
        std::slice::from_ref(&row),
    )
    .unwrap();
    assert_eq!(listener.reserves(), 1);
    let authority = SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes();
    let pin = SourcePin { source: "node-a", generation: 4, public_key: &authority, now: NOW };
    let missing = import_all(
        &listener,
        &wrapped[0].media,
        &Importer {
            account_anchor: "peer-anchor",
            device_id: "someone-else",
            device_epoch: 1,
            secret: &seed,
        },
        &pin,
    )
    .unwrap_err();
    assert_eq!(missing.code, CODE_NOT_GRANTEE);
    assert_eq!(listener.reads(), 0);
    let opened = import_all(
        &listener,
        &wrapped[0].media,
        &Importer {
            account_anchor: "peer-anchor",
            device_id: "peer-device",
            device_epoch: 1,
            secret: &seed,
        },
        &pin,
    )
    .unwrap();
    assert_eq!(opened, body);
    assert_eq!(listener.reads(), 1);
    let slot = &wrapped[0].media.key_slots[0];
    let object: [u8; 32] = ramflux_protocol::decode_base64url(&wrapped[0].media.object_id)
        .unwrap()
        .try_into()
        .unwrap();
    let manifest = wrapped[0].media.large_manifest.as_ref().unwrap();
    let hash: [u8; 32] = manifest.manifest_id.as_slice().try_into().unwrap();
    listener.set_reader(owner);
    let copied = listener
        .read(&ReadCall {
            capability: &slot.read_capability,
            object_id: &object,
            manifest_hash: &hash,
            index: 0,
            offset: 0,
            length: u64::try_from(body.len()).unwrap().saturating_add(16),
        })
        .unwrap_err();
    assert_eq!(copied.code, CODE_NOT_GRANTEE);
    assert_eq!(listener.reads(), 1);
    let mut media = wrapped[0].media.clone();
    media.large_manifest.as_mut().unwrap().read_capability = vec![1];
    let layout = import_all(
        &listener,
        &media,
        &Importer {
            account_anchor: "peer-anchor",
            device_id: "peer-device",
            device_epoch: 1,
            secret: &seed,
        },
        &pin,
    )
    .unwrap_err();
    assert_eq!(layout.code, CODE_LAYOUT_INVALID);
    assert_eq!(listener.reads(), 1);
}

#[test]
fn relay_erased_follows_only_the_cleanup_ack() {
    assert_eq!(super::handles::revoke_state(None), "retirement_pending");
    let pending = json!({ "relay_erased": false });
    assert_eq!(super::handles::revoke_state(Some(&pending)), "retirement_pending");
    let acked = json!({ "relay_erased": true });
    assert_eq!(super::handles::revoke_state(Some(&acked)), "relay_erased");
}

pub(super) fn wide(index: u64) -> MediaDevice {
    let mut seed = [8_u8; 32];
    seed[0] = u8::try_from(index).unwrap_or(1);
    let hpke = X25519KeyPair::from_seed(seed);
    let mut sign = [5_u8; 32];
    sign[0] = seed[0];
    let signing = SigningKey::from_bytes(&sign);
    MediaDevice {
        account_anchor: format!("peer-{index}"),
        device_id: format!("device-{index}"),
        device_epoch: 1,
        signing_public: signing.verifying_key().to_bytes(),
        home_node_id: "node-a".into(),
        hpke_public: hpke.public,
        layer: 4,
        own: false,
    }
}

pub(super) fn publish_input<'a>(
    store: &'a Store,
    listener: &'a Listener,
    owner: &'a QualifiedOwner,
    key: &'a SigningKey,
    targets: &'a [MediaDevice],
    source: &'a str,
) -> PublishInput<'a> {
    PublishInput {
        store,
        plane: listener,
        owner,
        owner_key: key,
        targets,
        audience: "node-a",
        authority_generation: 4,
        source,
        now: NOW,
        caption: "caption",
    }
}

#[test]
fn sixty_four_fitting_entries_seal_and_sixteen_files_do_not_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let targets: Vec<_> = (0..64).map(wide).collect();
    let row = accept(&store, "fit", b"hello attachment");
    let wrapped = publish::publish_all(
        &publish_input(&store, &listener, &owner, &key, &targets, "node-a"),
        std::slice::from_ref(&row),
    )
    .unwrap();
    assert_eq!(listener.reserves(), 1);
    assert_eq!(wrapped[0].media.key_slots.len(), 64);
    let mut rows = Vec::new();
    for index in 0..16_u64 {
        rows.push(accept(&store, &format!("file-{index}"), b"hello attachment"));
    }
    let error = publish::publish_all(
        &publish_input(&store, &listener, &owner, &key, &targets, "node-a"),
        &rows,
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_MANIFEST_TOO_LARGE);
    assert_eq!(listener.reserves(), 1);
}

#[test]
fn doubled_max_capabilities_are_manifest_too_large() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let home = "h".repeat(256);
    let targets: Vec<_> = (0..64_u64)
        .map(|index| {
            let mut anchor = format!("a{index}");
            anchor.push_str(&"x".repeat(256 - anchor.len()));
            MediaDevice {
                account_anchor: anchor,
                device_id: format!("d{index:02}"),
                device_epoch: 1,
                signing_public: [u8::try_from(index).unwrap_or(1); 32],
                home_node_id: home.clone(),
                hpke_public: [9; 32],
                layer: 4,
                own: false,
            }
        })
        .collect();
    let owner_len =
        preflight::qualified_len(&owner.account_anchor, &owner.device_id, &owner.home_node_id)
            .unwrap();
    let mut source = String::new();
    loop {
        let len = preflight::capability_len(&targets[0], owner_len, &source).unwrap();
        if len == 8192 {
            break;
        }
        assert!(len < 8192, "estimate {len} passed 8192");
        source.push('s');
    }
    let row = accept(&store, "fat", b"hi");
    let error = publish::publish_all(
        &publish_input(&store, &listener, &owner, &key, &targets, &source),
        std::slice::from_ref(&row),
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_MANIFEST_TOO_LARGE);
    assert_eq!(listener.reserves(), 0);
}

#[test]
fn three_devices_import_only_their_entry_and_a_retry_does_not_reserve_again() {
    let dir = tempfile::tempdir().unwrap();
    let (key, owner) = owner_pair();
    let listener = Listener::open(dir.path(), owner.clone()).unwrap();
    let store = Store::open(dir.path(), "acct", [3; 32]).unwrap();
    let mut targets = Vec::new();
    let mut secrets = Vec::new();
    for index in 1..4_u64 {
        let mut seed = [9_u8; 32];
        seed[0] = u8::try_from(index).unwrap();
        let hpke = X25519KeyPair::from_seed(seed);
        let mut sign = [4_u8; 32];
        sign[0] = seed[0];
        let signing = SigningKey::from_bytes(&sign);
        let device = MediaDevice {
            account_anchor: format!("anchor-{index}"),
            device_id: format!("device-{index}"),
            device_epoch: 1,
            signing_public: signing.verifying_key().to_bytes(),
            home_node_id: "node-a".into(),
            hpke_public: hpke.public,
            layer: 4,
            own: index == 1,
        };
        secrets.push((device.account_anchor.clone(), device.device_id.clone(), seed));
        targets.push(device);
    }
    let chosen = targets::choose_targets(MediaScope::Dm, &targets).unwrap();
    assert_eq!(chosen.len(), 3);
    let body = b"hello attachment";
    let row = accept(&store, "group3", body);
    let input = publish_input(&store, &listener, &owner, &key, &chosen, "node-a");
    let wrapped = publish::publish_all(&input, std::slice::from_ref(&row)).unwrap();
    let again = publish::publish_all(&input, std::slice::from_ref(&row)).unwrap();
    assert_eq!(wrapped[0].media.encode_to_vec(), again[0].media.encode_to_vec());
    assert_eq!(listener.reserves(), 1);
    let authority = SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes();
    let pin = SourcePin { source: "node-a", generation: 4, public_key: &authority, now: NOW };
    for (anchor, id, seed) in &secrets {
        listener.set_reader(QualifiedOwner {
            account_anchor: anchor.clone(),
            device_id: id.clone(),
            device_epoch: 1,
            signing_public_key: targets
                .iter()
                .find(|device| device.device_id == *id)
                .unwrap()
                .signing_public,
            home_node_id: "node-a".into(),
        });
        let opened = import_all(
            &listener,
            &wrapped[0].media,
            &Importer { account_anchor: anchor, device_id: id, device_epoch: 1, secret: seed },
            &pin,
        )
        .unwrap();
        assert_eq!(opened, body);
    }
    assert_eq!(listener.reads(), 3);
    let missing = import_all(
        &listener,
        &wrapped[0].media,
        &Importer {
            account_anchor: "anchor-9",
            device_id: "device-9",
            device_epoch: 1,
            secret: &[9; 32],
        },
        &pin,
    )
    .unwrap_err();
    assert_eq!(missing.code, CODE_NOT_GRANTEE);
    assert_eq!(listener.reads(), 3);
    let stored = store.read_named(&row.prepare_id, "inner.bin").unwrap();
    std::fs::remove_file(
        dir.path().join("attachment-prepares").join(&row.prepare_id).join("secret.bin"),
    )
    .unwrap();
    assert_eq!(store.read_named(&row.prepare_id, "inner.bin").unwrap(), stored);
    listener.set_reader(QualifiedOwner {
        account_anchor: secrets[0].0.clone(),
        device_id: secrets[0].1.clone(),
        device_epoch: 1,
        signing_public_key: targets[0].signing_public,
        home_node_id: "node-a".into(),
    });
    let still = import_all(
        &listener,
        &wrapped[0].media,
        &Importer {
            account_anchor: &secrets[0].0,
            device_id: &secrets[0].1,
            device_epoch: 1,
            secret: &secrets[0].2,
        },
        &pin,
    )
    .unwrap();
    assert_eq!(still, body);
}
