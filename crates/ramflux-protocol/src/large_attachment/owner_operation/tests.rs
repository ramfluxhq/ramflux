// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{OwnerAttachmentOperation, OwnerBind, OwnerPut, OwnerReserve};
use crate::large_attachment::{AttachmentOperation, FormatError, body_digest};

fn audience() -> &'static str {
    "relay.example"
}

#[test]
fn owner_reserve_round_trips_and_reader_decode_fails_as_kind() -> Result<(), FormatError> {
    let (op, body) = OwnerAttachmentOperation::reserve(&OwnerReserve {
        audience: audience(),
        object_id: [9; 32],
        authority_generation: 4,
        upload_id: [3; 32],
        plaintext_length: 31,
        network_chunk_bytes: 524_288,
        lease_hard_until: 9_000,
    })?;
    assert_eq!(body.len(), 84);
    assert_eq!(op.body_digest, body_digest(&body));
    let bytes = op.canonical_bytes()?;
    assert_eq!(OwnerAttachmentOperation::decode(&bytes)?, op);
    assert_eq!(AttachmentOperation::decode(&bytes), Err(FormatError("operation kind")));
    Ok(())
}

#[test]
fn owner_bind_put_commit_and_retire_round_trip() -> Result<(), FormatError> {
    let object = [4; 32];
    let hash = [5; 32];
    let bind = OwnerAttachmentOperation::bind(&OwnerBind {
        audience: audience(),
        object_id: object,
        manifest_hash: hash,
        authority_generation: 2,
        operation_id: [6; 32],
        payload_generation: 1,
        body: b"MC",
    })?;
    assert_eq!(OwnerAttachmentOperation::decode(&bind.canonical_bytes()?)?, bind);
    let put = OwnerAttachmentOperation::put(&OwnerPut {
        audience: audience(),
        object_id: object,
        manifest_hash: hash,
        authority_generation: 2,
        operation_id: [7; 32],
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        body: &[1, 2, 3, 4],
    })?;
    assert_eq!(OwnerAttachmentOperation::decode(&put.canonical_bytes()?)?, put);
    let commit = OwnerAttachmentOperation::commit(audience(), object, hash, 2, [8; 32], 1)?;
    assert_eq!(OwnerAttachmentOperation::decode(&commit.canonical_bytes()?)?, commit);
    let retire = OwnerAttachmentOperation::retire(audience(), object, 2, [1; 32])?;
    assert_eq!(retire.manifest_hash, [0; 32]);
    assert_eq!(OwnerAttachmentOperation::decode(&retire.canonical_bytes()?)?, retire);
    Ok(())
}

#[test]
fn owner_decoder_rejects_a_reader_operation_and_a_nonzero_grant() -> Result<(), FormatError> {
    let mut reader = AttachmentOperation {
        op: 1,
        method: "GET".into(),
        path: String::new(),
        audience: audience().into(),
        object_id: [1; 32],
        manifest_hash: [2; 32],
        grant_id: [3; 32],
        grant_epoch: 1,
        authority_generation: 1,
        operation_id: [4; 32],
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        length: 1,
        body_digest: body_digest(&[]),
    };
    reader.path = format!("/attachments/{}/{}", hex(&reader.object_id), hex(&reader.manifest_hash));
    reader.path.push_str("/segments/0");
    let bytes = reader.canonical_bytes()?;
    assert_eq!(OwnerAttachmentOperation::decode(&bytes), Err(FormatError("operation kind")));
    let (owner, _) = OwnerAttachmentOperation::reserve(&OwnerReserve {
        audience: audience(),
        object_id: [9; 32],
        authority_generation: 4,
        upload_id: [3; 32],
        plaintext_length: 0,
        network_chunk_bytes: 524_288,
        lease_hard_until: 1,
    })?;
    flipped_grant(&owner)
}

fn flipped_grant(op: &OwnerAttachmentOperation) -> Result<(), FormatError> {
    let mut bytes = op.canonical_bytes()?;
    let grant_at = bytes.len() - 144;
    bytes[grant_at] = 1;
    assert_eq!(OwnerAttachmentOperation::decode(&bytes), Err(FormatError("operation generation")));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [char::from(HEX[usize::from(byte >> 4)]), char::from(HEX[usize::from(byte & 15)])]
        })
        .collect()
}
