// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retirement with a real account database, real store and the real ledger listener.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use ed25519_dalek::SigningKey;
use ramflux_crypto::X25519KeyPair;
use ramflux_protocol::large_attachment::QualifiedOwner;
use ramflux_protocol::message::MediaRef;
use ramflux_storage::{AccountDb, AccountDbKey, AccountIndex};
use tempfile::TempDir;

use super::codes::{CODE_ATTACHMENT_DELETED, CODE_NOT_GRANTEE, CODE_RETIREMENT_PENDING};
use super::handles::{self, RETIREMENT, TOMBSTONE};
use super::import_job::{self, Importer, SourcePin};
use super::listener::Listener;
use super::meta::{Intent, Phase, Recipient, Row};
use super::publish::{self, PublishInput};
use super::retire::{self, RetireCtx, Sent, Source};
use super::store::Store;
use super::targets::MediaDevice;
use crate::custody::memory_vault::MemoryPrimaryVault;
use crate::custody::tests::{Root, create};

fn code_of(error: &crate::SdkError) -> String {
    match error {
        crate::SdkError::LocalBusRefused { code, .. } => code.clone(),
        other => format!("{other}"),
    }
}

const BODY: &[u8] = b"retire me";

struct Peer {
    device: MediaDevice,
    seed: [u8; 32],
    reader: QualifiedOwner,
}

fn peer(index: u8) -> Peer {
    let mut seed = [9_u8; 32];
    seed[0] = index;
    let hpke = X25519KeyPair::from_seed(seed);
    let mut sign = [4_u8; 32];
    sign[0] = index;
    let signing = SigningKey::from_bytes(&sign);
    let device = MediaDevice {
        account_anchor: format!("peer-anchor-{index}"),
        device_id: format!("peer-device-{index}"),
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
    Peer { device, seed, reader }
}

struct Fixture {
    _root: Root,
    dir: TempDir,
    vault: MemoryPrimaryVault,
    account: crate::custody::BornAccount,
    index: AccountIndex,
    db: AccountDb,
    store: Store,
    listener: Listener,
    owner: QualifiedOwner,
    key: SigningKey,
    authority: [u8; 32],
    now: u64,
}

impl Fixture {
    fn new() -> Self {
        let root = Root::new().unwrap();
        let vault = MemoryPrimaryVault::default();
        let now = crate::custody::network_now().unwrap();
        let account = create(&root.0, "human", &vault, now).unwrap();
        let index = AccountIndex::open(&root.0).unwrap();
        let db_key = AccountDbKey::generate().unwrap();
        let db = AccountDb::open(&index, "human", &db_key).unwrap();
        let (actor, credentials) = account
            .credentials(&vault, "primary", now)
            .map_err(|error| format!("credentials: {error:?}"))
            .unwrap();
        let key = credentials.signing.signing_key.clone();
        let owner = QualifiedOwner {
            account_anchor: actor.account_anchor,
            device_id: actor.device_id,
            device_epoch: actor.device_epoch,
            signing_public_key: key.verifying_key().to_bytes(),
            home_node_id: "node-a".into(),
        };
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), "human", [3; 32]).unwrap();
        let listener = Listener::open_at(dir.path(), owner.clone(), now).unwrap();
        let authority = SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes();
        Self {
            _root: root,
            dir,
            vault,
            account,
            index,
            db,
            store,
            listener,
            owner,
            key,
            authority,
            now,
        }
    }

    fn ctx(&self) -> RetireCtx<'_> {
        RetireCtx {
            db: &self.db,
            index: &self.index,
            account: &self.account,
            vault: &self.vault,
            store: &self.store,
        }
    }

    fn source(&self) -> Source<'_> {
        Source { authority: "node-a", generation: 4, public_key: &self.authority }
    }

    fn accept(&self, operation: &str) -> Row {
        let row = self
            .store
            .begin(
                Intent {
                    account: "human",
                    operation_id: operation,
                    recipient: Recipient::Dm { peer: "peer".into() },
                    file_name: "a.bin",
                    mime: "application/octet-stream",
                },
                true,
                self.now,
                None,
            )
            .unwrap();
        self.store.chunk(&row.prepare_id, row.generation, 0, BODY, self.now).unwrap();
        let digest = *blake3::hash(BODY).as_bytes();
        let len = u64::try_from(BODY.len()).unwrap();
        self.store.finish(&row.prepare_id, row.generation, len, digest, self.now).unwrap()
    }

    fn send(&self, operation: &str, peers: &[&Peer]) -> (Row, MediaRef) {
        let row = self.accept(operation);
        let targets: Vec<MediaDevice> = peers.iter().map(|peer| peer.device.clone()).collect();
        let wrapped = publish::publish_all(
            &PublishInput {
                store: &self.store,
                plane: &self.listener,
                owner: &self.owner,
                owner_key: &self.key,
                targets: &targets,
                audience: "node-a",
                authority_generation: 4,
                source: "node-a",
                now: self.now,
                caption: "",
            },
            std::slice::from_ref(&row),
        )
        .unwrap();
        (row, wrapped.into_iter().next().unwrap().media)
    }

    fn import(&self, who: &Peer, media: &MediaRef) -> Result<Vec<u8>, super::codes::Refusal> {
        self.listener.set_reader(who.reader.clone());
        let pin = SourcePin {
            source: "node-a",
            generation: 4,
            public_key: &self.authority,
            now: self.now,
        };
        import_job::import_entry(
            &self.listener,
            media,
            &Importer {
                account_anchor: &who.device.account_anchor,
                device_id: &who.device.device_id,
                device_epoch: 1,
                secret: &who.seed,
            },
            &pin,
        )
    }

    fn plane(&self) -> &dyn super::plane::Plane {
        &self.listener
    }

    fn erased(&self, message: &str) -> bool {
        let row = self.db.client_record(RETIREMENT, message).unwrap();
        handles::revoke_state(row.as_ref()) == "relay_erased"
    }
}

fn secret_present(fixture: &Fixture, row: &Row) -> bool {
    fixture.dir.path().join("attachment-prepares").join(&row.prepare_id).join("secret.bin").exists()
}

#[test]
fn revoke_refuses_later_reads_wipes_keys_and_is_erased_only_with_the_source_answer() {
    let fixture = Fixture::new();
    let (a, b) = (peer(1), peer(2));
    let (row, media) = fixture.send("send", &[&a, &b]);
    let sent = [Sent { prepare_id: &row.prepare_id, media: &media }];
    retire::bind_message(&fixture.ctx(), "m1", &sent, &fixture.source(), fixture.now).unwrap();
    retire::barrier_db(&fixture.db, "m1").unwrap();
    assert_eq!(fixture.import(&a, &media).unwrap(), BODY, "readable before revoke");
    assert!(secret_present(&fixture, &row), "the sender still holds the key before revoke");

    let state =
        retire::revoke(&fixture.ctx(), Some(fixture.plane()), "m1", &fixture.source(), fixture.now)
            .unwrap();
    assert_eq!(state, "relay_erased", "both grants retired and the source erased the object");
    assert_eq!(fixture.listener.retires(), 2, "one retirement per grant");
    assert!(fixture.erased("m1"));
    assert!(fixture.db.client_record(TOMBSTONE, "m1").unwrap().is_some());
    assert_eq!(
        code_of(&retire::barrier_db(&fixture.db, "m1").unwrap_err()),
        CODE_ATTACHMENT_DELETED
    );
    assert_eq!(fixture.import(&a, &media).unwrap_err().code, CODE_NOT_GRANTEE);
    assert_eq!(fixture.import(&b, &media).unwrap_err().code, CODE_NOT_GRANTEE);
    assert!(!secret_present(&fixture, &row), "the sealed file key is wiped");
    assert!(
        fixture.store.read_named(&row.prepare_id, "media.bin").is_err(),
        "ACK cleanup wipes capabilities"
    );
}

#[test]
fn an_unreachable_source_is_retirement_pending_until_a_sweep_delivers() {
    let fixture = Fixture::new();
    let a = peer(1);
    let (row, media) = fixture.send("send", &[&a]);
    let sent = [Sent { prepare_id: &row.prepare_id, media: &media }];
    retire::bind_message(&fixture.ctx(), "m2", &sent, &fixture.source(), fixture.now).unwrap();
    fixture.listener.set_unreachable(true);
    let state =
        retire::revoke(&fixture.ctx(), Some(fixture.plane()), "m2", &fixture.source(), fixture.now)
            .unwrap();
    assert_eq!(state, "retirement_pending", "a timeout is never success");
    assert_eq!(fixture.listener.retires(), 0);
    assert!(!fixture.erased("m2"));
    assert!(
        !secret_present(&fixture, &row),
        "the tombstone is durable, so the key is already wiped"
    );
    assert!(
        fixture.store.read_named(&row.prepare_id, "media.bin").is_ok(),
        "queued work keeps its capability"
    );
    // A second revoke while still unreachable stays pending and queues nothing twice.
    let again =
        retire::revoke(&fixture.ctx(), Some(fixture.plane()), "m2", &fixture.source(), fixture.now)
            .unwrap();
    assert_eq!(again, "retirement_pending");

    fixture.listener.set_unreachable(false);
    let swept =
        retire::sweep(&fixture.ctx(), Some(fixture.plane()), &fixture.source(), fixture.now)
            .unwrap();
    assert_eq!(swept.retired, 1);
    assert!(fixture.erased("m2"), "the retried delivery reaches relay_erased");
    let repeated =
        retire::revoke(&fixture.ctx(), Some(fixture.plane()), "m2", &fixture.source(), fixture.now)
            .unwrap();
    assert_eq!(repeated, "relay_erased");
}

#[test]
fn retiring_one_grant_leaves_the_other_recipient_readable() {
    let fixture = Fixture::new();
    let (a, b) = (peer(1), peer(2));
    let (row, media) = fixture.send("send", &[&a, &b]);
    let sent = [Sent { prepare_id: &row.prepare_id, media: &media }];
    let first = media
        .key_slots
        .iter()
        .find(|slot| slot.recipient.as_ref().is_some_and(|who| who.device_id == a.device.device_id))
        .unwrap();
    let only: [u8; 32] = first.grant_id.as_slice().try_into().unwrap();
    let outcome = retire::retire_grants(
        &fixture.ctx(),
        Some(fixture.plane()),
        &retire::Subset { message_id: "unadmitted:m3", files: &sent, only: &[only] },
        &fixture.source(),
        fixture.now,
    )
    .unwrap();
    assert_eq!(outcome.retired, 1);
    assert_eq!(fixture.listener.retires(), 1, "only the named grant was retired");
    assert_eq!(fixture.import(&a, &media).unwrap_err().code, CODE_NOT_GRANTEE);
    assert_eq!(fixture.import(&b, &media).unwrap(), BODY, "the other grant keeps reading");
    assert!(
        fixture.db.client_record(TOMBSTONE, "unadmitted:m3").unwrap().is_none(),
        "retiring a subset does not tombstone the message"
    );
    assert!(!fixture.erased("unadmitted:m3"), "the object is still referenced");
}

#[test]
fn revoke_fences_an_open_import_handle_and_removes_its_staging_file() {
    let fixture = Fixture::new();
    let a = peer(1);
    let (row, media) = fixture.send("send", &[&a]);
    let sent = [Sent { prepare_id: &row.prepare_id, media: &media }];
    retire::bind_message(&fixture.ctx(), "m4", &sent, &fixture.source(), fixture.now).unwrap();
    let staging = fixture.dir.path().join("staging-m4.bin");
    std::fs::write(&staging, b"plaintext in flight").unwrap();
    handles::test_register_job("import-m4", "human", "m4", staging.clone());
    handles::test_register_job("import-other", "human", "other-message", staging.clone());
    retire::revoke(&fixture.ctx(), Some(fixture.plane()), "m4", &fixture.source(), fixture.now)
        .unwrap();
    assert!(handles::test_job_cancelled("import-m4"), "the open handle is fenced");
    assert!(!handles::test_job_cancelled("import-other"), "another message is untouched");
    assert!(!staging.exists(), "the staging file is removed");
}

#[test]
fn cancel_wipes_the_key_and_snapshot_and_a_missing_record_blocks_the_wipe() {
    let fixture = Fixture::new();
    let row = fixture.accept("cancel");
    let drawn = fixture.store.draw(&row.prepare_id, fixture.now).unwrap();
    fixture.store.mark(drawn.clone(), Phase::Committed).unwrap();
    assert!(secret_present(&fixture, &row));
    // No durable fence record: the wipe must fail and keep the key.
    let dir = fixture.dir.path().join("attachment-prepares").join(&row.prepare_id);
    let meta = std::fs::read(dir.join("meta.json")).unwrap();
    std::fs::remove_file(dir.join("meta.json")).unwrap();
    assert!(fixture.store.retire_and_wipe(&row.prepare_id).is_err());
    assert!(secret_present(&fixture, &row), "no record, no wipe");
    std::fs::write(dir.join("meta.json"), meta).unwrap();

    let cancelled = fixture.store.cancel(&row.prepare_id, row.generation).unwrap();
    assert_eq!(cancelled.phase, Phase::Cleaning);
    assert_eq!(fixture.store.load(&row.prepare_id).unwrap().phase, Phase::Cleaning);
    assert!(!secret_present(&fixture, &row), "the key is wiped after the Cleaning record");
    assert!(!dir.join("plain.bin").exists(), "the plaintext snapshot is wiped");
}

#[test]
fn deleting_the_last_local_reference_retires_no_other_grant() {
    let fixture = Fixture::new();
    let (a, b) = (peer(1), peer(2));
    let (row, media) = fixture.send("send", &[&a, &b]);
    retire::release_local(&fixture.store, &row.prepare_id).unwrap();
    assert!(!secret_present(&fixture, &row), "the local key is gone");
    assert_eq!(fixture.listener.retires(), 0, "no retirement was sent");
    assert_eq!(fixture.import(&a, &media).unwrap(), BODY, "other grants keep reading");
    assert_eq!(fixture.import(&b, &media).unwrap(), BODY);
}

#[test]
fn a_fenced_generation_and_a_pending_revoke_have_stable_barrier_codes() {
    let fixture = Fixture::new();
    let row = fixture.accept("barrier");
    assert!(retire::barrier_prepare(&row, row.generation).is_ok());
    assert_eq!(
        retire::barrier_prepare(&row, row.generation + 1).unwrap_err().code,
        super::codes::CODE_STALE_GENERATION
    );
    let cancelled = fixture.store.cancel(&row.prepare_id, row.generation).unwrap();
    assert_eq!(
        retire::barrier_prepare(&cancelled, cancelled.generation).unwrap_err().code,
        super::codes::CODE_CANCELLED
    );
    fixture
        .db
        .persist_client_record(RETIREMENT, "m5", &serde_json::json!({ "relay_erased": false }))
        .unwrap();
    assert_eq!(
        code_of(&retire::barrier_db(&fixture.db, "m5").unwrap_err()),
        CODE_RETIREMENT_PENDING
    );
}

#[test]
fn cancel_after_commit_retires_registered_grants_of_the_unadmitted_prepare() {
    let fixture = Fixture::new();
    let a = peer(1);
    let (row, media) = fixture.send("send", &[&a]);
    assert_eq!(fixture.import(&a, &media).unwrap(), BODY);
    let current = fixture.store.load(&row.prepare_id).unwrap();
    let cancelled = fixture.store.cancel(&row.prepare_id, current.generation).unwrap();
    assert_eq!(cancelled.phase, Phase::Cleaning, "a granted prepare cancels to Cleaning");
    assert!(!secret_present(&fixture, &row), "cancel wipes the sealed key");
    let outcome = retire::cancel_registered(
        &fixture.ctx(),
        Some(fixture.plane()),
        &row.prepare_id,
        &fixture.source(),
        fixture.now,
    )
    .unwrap();
    assert_eq!(outcome.retired, 1, "the registered grant is retired");
    assert_eq!(fixture.import(&a, &media).unwrap_err().code, CODE_NOT_GRANTEE);
}
