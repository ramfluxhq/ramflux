// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use crate::RelayRedbStore;
use crate::relay::attachment::backend::BackendSegment;
use crate::relay::attachment::{AttachmentAuthority, AttachmentOwner, AttachmentPolicy};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_crypto::large_attachment::{SegmentSealer, segment_digest};
use ramflux_protocol::large_attachment::{
    AttachmentOperation, ContentManifest, OwnerAttachmentOperation, OwnerBind, OwnerPut,
    OwnerReserve, QualifiedOwner, RequesterPop, SegmentLayout, body_digest, requester_digest,
};
use redb::{ReadableDatabase, ReadableTableMetadata};

struct World {
    _dir: tempfile::TempDir,
    registry: crate::relay::attachment::ScopedGrantRegistry,
    backend: crate::relay::attachment::backend::LocalAttachmentBackend,
    signer: SigningKey,
    requester: QualifiedOwner,
    now: u64,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let store = RelayRedbStore::open(dir.path().join("relay.redb")).unwrap();
    let authority_key = SigningKey::from_bytes(&[77; 32]);
    let registry = store
        .attachment_ledger(AttachmentPolicy::default())
        .unwrap()
        .scoped_grants(AttachmentAuthority {
            source: "node-a".into(),
            generation: 4,
            signing_public_key: authority_key.verifying_key().to_bytes(),
        })
        .unwrap();
    let backend = store.local_attachment_backend([1; 32], dir.path().join("objects")).unwrap();
    let signer = SigningKey::from_bytes(&[3; 32]);
    let requester = QualifiedOwner {
        account_anchor: "owner-anchor".into(),
        device_id: "device-1".into(),
        device_epoch: 1,
        signing_public_key: signer.verifying_key().to_bytes(),
        home_node_id: "home".into(),
    };
    World { _dir: dir, registry, backend, signer, requester, now: 2_000_000_000 }
}

fn prove(world: &World, op: &OwnerAttachmentOperation, nonce: u8) -> (Vec<u8>, [u8; 64]) {
    let pop = RequesterPop {
        operation_hash: op.hash().unwrap(),
        requester_digest: requester_digest(&world.requester).unwrap(),
        nonce: [nonce; 32],
        issued_at: world.now,
        expires_at: world.now + 30,
        forward_digest: [0; 32],
    };
    let signature = world.signer.sign(&pop.signing_bytes().unwrap()).to_bytes();
    (pop.canonical_bytes().unwrap(), signature)
}

fn admit(
    world: &World,
    op: &OwnerAttachmentOperation,
    body: &[u8],
    nonce: u8,
) -> Result<Vec<u8>, OwnerAdmissionError> {
    let bytes = op.canonical_bytes().unwrap();
    let (proof, signature) = prove(world, op, nonce);
    world.registry.admit_owner_operation_after_authentication(
        &OwnerAdmission {
            operation: &bytes,
            body,
            proof: &proof,
            proof_signature: &signature,
            requester: &world.requester,
            now: world.now,
        },
        &world.backend,
    )
}

fn reserve_op(
    upload: [u8; 32],
    object: [u8; 32],
    deadline: u64,
) -> (OwnerAttachmentOperation, Vec<u8>) {
    OwnerAttachmentOperation::reserve(&OwnerReserve {
        audience: "node-a",
        object_id: object,
        authority_generation: 4,
        upload_id: upload,
        plaintext_length: 0,
        network_chunk_bytes: 524_288,
        lease_hard_until: deadline,
    })
    .unwrap()
}

fn record(world: &World, upload: &[u8; 32]) -> AttachmentReservation {
    let owner = AttachmentOwner::from_authenticated_session("owner-anchor").unwrap();
    world.registry.ledger.reservation(&owner, upload).unwrap()
}

fn json_kind(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn replay_returns_the_stored_deadline_and_charges_once() {
    let world = world();
    let upload = [4; 32];
    let object = [9; 32];
    let (op, body) = reserve_op(upload, object, world.now + 100);
    let first = json_kind(&admit(&world, &op, &body, 1).unwrap());
    assert_eq!(first["kind"], "owner_result");
    assert_eq!(first["state"], "pending");
    assert!(first["manifest_hash"].is_null());
    assert_eq!(first["request_id"], hex(&[1; 32]));
    let stored = record(&world, &upload);
    assert_eq!(stored.lease_hard_until, world.now + 100);
    assert_eq!(stored.size, 16);
    let (later, later_body) = reserve_op(upload, object, world.now + 50_000);
    admit(&world, &later, &later_body, 2).unwrap();
    let again = record(&world, &upload);
    assert_eq!(again.lease_hard_until, stored.lease_hard_until);
    assert_eq!(again.lease_until, stored.lease_until);
    let owner = AttachmentOwner::from_authenticated_session("owner-anchor").unwrap();
    let usage = world.registry.ledger.usage(&owner).unwrap();
    assert_eq!(usage.records, 1);
    assert_eq!(usage.reserved, 16);
}

#[test]
fn elapsed_deadline_reserves_nothing_and_same_nonce_is_replay() {
    let world = world();
    let upload = [5; 32];
    let object = [8; 32];
    let (op, body) = reserve_op(upload, object, world.now);
    let error = admit(&world, &op, &body, 1).unwrap_err();
    assert!(matches!(error, OwnerAdmissionError::Ledger(AttachmentLedgerError::Expired)));
    let owner = AttachmentOwner::from_authenticated_session("owner-anchor").unwrap();
    assert!(matches!(
        world.registry.ledger.reservation(&owner, &upload),
        Err(AttachmentLedgerError::Conflict)
    ));
    let (live, live_body) = reserve_op(upload, object, world.now + 1000);
    admit(&world, &live, &live_body, 3).unwrap();
    let error = admit(&world, &live, &live_body, 3).unwrap_err();
    assert!(matches!(error, OwnerAdmissionError::Replay(AttachmentReplayError::Replay)));
    assert_eq!(record(&world, &upload).object_id, object);
}

#[test]
fn different_object_conflicts_and_does_not_rebind() {
    let world = world();
    let upload = [6; 32];
    let object = [9; 32];
    let (op, body) = reserve_op(upload, object, world.now + 1000);
    admit(&world, &op, &body, 1).unwrap();
    let (other, other_body) = reserve_op(upload, [2; 32], world.now + 1000);
    let error = admit(&world, &other, &other_body, 2).unwrap_err();
    assert!(matches!(error, OwnerAdmissionError::Ledger(AttachmentLedgerError::Conflict)));
    assert_eq!(record(&world, &upload).object_id, object);
}

#[test]
fn owner_put_is_not_a_reader_operation_and_writes_no_grant() {
    let world = world();
    let sealed = seal(&world.requester, &world.signer);
    let upload = [7; 32];
    let (reserved, body) = reserve_op(upload, sealed.object, world.now + 1000);
    admit(&world, &reserved, &body, 1).unwrap();
    let bind = OwnerAttachmentOperation::bind(&OwnerBind {
        audience: "node-a",
        object_id: sealed.object,
        manifest_hash: sealed.hash,
        authority_generation: 4,
        operation_id: upload,
        payload_generation: 1,
        body: &sealed.signed,
    })
    .unwrap();
    let bound = json_kind(&admit(&world, &bind, &sealed.signed, 2).unwrap());
    assert_eq!(bound["manifest_hash"], hex(&sealed.hash));
    let put = OwnerAttachmentOperation::put(&OwnerPut {
        audience: "node-a",
        object_id: sealed.object,
        manifest_hash: sealed.hash,
        authority_generation: 4,
        operation_id: upload,
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        body: &sealed.cipher,
    })
    .unwrap();
    let put_bytes = put.canonical_bytes().unwrap();
    assert_eq!(AttachmentOperation::decode(&put_bytes).unwrap_err().0, "operation kind");
    let reader = reader_head();
    assert_eq!(
        OwnerAttachmentOperation::decode(&reader.canonical_bytes().unwrap()).unwrap_err().0,
        "operation kind"
    );
    admit(&world, &put, &sealed.cipher, 3).unwrap();
    let commit =
        OwnerAttachmentOperation::commit("node-a", sealed.object, sealed.hash, 4, upload, 1)
            .unwrap();
    let committed = json_kind(&admit(&world, &commit, &[], 4).unwrap());
    assert_eq!(committed["state"], "committed");
    let spec = BackendSegment::from_manifest(&sealed.verified, 1, 0).unwrap();
    let mut out = Vec::new();
    world
        .backend
        .read_range(&spec, 0, u64::try_from(sealed.cipher.len()).unwrap(), &mut out)
        .unwrap();
    assert_eq!(out, sealed.cipher);
    assert!(world.registry.lookup(&[0; 32]).unwrap().is_none());
    let tx = world.registry.ledger.db.begin_read().unwrap();
    let grants = tx.open_table(super::super::super::GRANTS).unwrap();
    assert_eq!(grants.len().unwrap(), 0);
    let same = OwnerAttachmentOperation::bind(&OwnerBind {
        audience: "node-a",
        object_id: sealed.object,
        manifest_hash: sealed.hash,
        authority_generation: 4,
        operation_id: upload,
        payload_generation: 1,
        body: &sealed.signed,
    })
    .unwrap();
    assert_eq!(json_kind(&admit(&world, &same, &sealed.signed, 5).unwrap())["state"], "committed");
}

#[test]
fn late_put_after_retire_does_not_publish() {
    let world = world();
    let sealed = seal(&world.requester, &world.signer);
    let upload = [8; 32];
    let (reserved, body) = reserve_op(upload, sealed.object, world.now + 1000);
    admit(&world, &reserved, &body, 1).unwrap();
    let bind = OwnerAttachmentOperation::bind(&OwnerBind {
        audience: "node-a",
        object_id: sealed.object,
        manifest_hash: sealed.hash,
        authority_generation: 4,
        operation_id: upload,
        payload_generation: 1,
        body: &sealed.signed,
    })
    .unwrap();
    admit(&world, &bind, &sealed.signed, 2).unwrap();
    let retire = OwnerAttachmentOperation::retire("node-a", sealed.object, 4, upload).unwrap();
    let retired = json_kind(&admit(&world, &retire, &[], 3).unwrap());
    assert_eq!(retired["state"], "debt_pending");
    let put = OwnerAttachmentOperation::put(&OwnerPut {
        audience: "node-a",
        object_id: sealed.object,
        manifest_hash: sealed.hash,
        authority_generation: 4,
        operation_id: upload,
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        body: &sealed.cipher,
    })
    .unwrap();
    let error = admit(&world, &put, &sealed.cipher, 4).unwrap_err();
    assert!(matches!(error, OwnerAdmissionError::Ledger(AttachmentLedgerError::State)));
    let listed = world.backend.enumerate(None, 8).unwrap();
    assert_eq!(listed.len(), 0);
    assert_eq!(record(&world, &upload).state, AttachmentReservationState::DebtPending);
}

struct Sealed {
    object: [u8; 32],
    hash: [u8; 32],
    cipher: Vec<u8>,
    signed: Vec<u8>,
    verified: ramflux_protocol::large_attachment::VerifiedContentManifest,
}

fn seal(requester: &QualifiedOwner, signer: &SigningKey) -> Sealed {
    let layout = SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 };
    let object = [9; 32];
    let mut sealer = SegmentSealer::from_persisted([7; 32], object, layout).unwrap();
    let cipher = sealer.seal(0, &[]).unwrap();
    let manifest = ContentManifest {
        object_id: object,
        owner: requester.clone(),
        layout,
        segment_digests: vec![segment_digest(&cipher).unwrap()],
    };
    let signature = signer.sign(&manifest.signing_bytes().unwrap()).to_bytes();
    let container = manifest.signed_bytes(&signature).unwrap();
    let verified = ContentManifest::decode_signed(&container).unwrap();
    let hash = verified.manifest().hash().unwrap();
    Sealed { object, hash, cipher, signed: container, verified }
}

fn reader_head() -> AttachmentOperation {
    let object_id = [9; 32];
    let manifest_hash = [4; 32];
    let path = format!("/attachments/{}/{}", hex(&object_id), hex(&manifest_hash));
    AttachmentOperation {
        op: 2,
        method: "HEAD".into(),
        path: format!("{path}/segments/0"),
        audience: "node-a".into(),
        object_id,
        manifest_hash,
        grant_id: [5; 32],
        grant_epoch: 1,
        authority_generation: 4,
        operation_id: [6; 32],
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        length: 0,
        body_digest: body_digest(&[]),
    }
}
