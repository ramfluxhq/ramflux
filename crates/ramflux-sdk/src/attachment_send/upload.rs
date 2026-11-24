// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable slice ACKs for immutable sealed uploads. Uncertain replies replay the same bytes.

use std::io::Read as _;

use ramflux_crypto::large_attachment::segment_digest;
use ramflux_protocol::attachment_wire::AttachmentUploadStatus;
use ramflux_protocol::large_attachment::{OwnerAttachmentOperation, OwnerPut, SegmentLayout};

use super::codes::{CODE_EXPIRED, CODE_SEAL_FAILED, CODE_UPLOAD_REJECTED, Refusal};
use super::meta::{CHUNK, Row};
use super::owner_wire;
use super::plane::UploadQuery;
use super::publish::PublishInput;
use super::seal_job::segment_name_of;

/// Reconciles every segment before PUT and checkpoints each successful reply before the next
/// slice. A relay-only ACK is uncertain locally and is replayed byte for byte. Returns true
/// when all segments were already committed, including recovery of a lost Commit reply.
pub(super) fn put_segments(input: &PublishInput<'_>, row: &mut Row) -> Result<bool, Refusal> {
    let layout = SegmentLayout {
        plaintext_length: row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        network_chunk_bytes: u32::try_from(CHUNK).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?,
    };
    let (count, _) = layout.dimensions().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let count = usize::try_from(count).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    if row.segment_digests.len() != count || row.upload_acks.len() != count {
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    let mut committed = None;
    for segment in 0..count {
        let index = u32::try_from(segment).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let length = layout
            .segment_plaintext_length(u64::from(index))
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?
            + 16;
        let _held = super::budget::memory(length + CHUNK)?;
        let file =
            std::fs::File::open(input.store.dir(&row.prepare_id).join(segment_name_of(index)))
                .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let mut cipher = Vec::new();
        file.take(length + 1)
            .read_to_end(&mut cipher)
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let digest = row.segment_digests.get(segment).ok_or(Refusal::new(CODE_SEAL_FAILED))?;
        if u64::try_from(cipher.len()).ok() != Some(length)
            || segment_digest(&cipher).map_err(|_| Refusal::new(CODE_SEAL_FAILED))? != *digest
        {
            return Err(Refusal::new(CODE_SEAL_FAILED));
        }
        let status = input.plane.upload_status(&query(row, index)?)?;
        validate(&status, row, index, length, input.now)?;
        let is_committed = status.state == "committed";
        if committed.is_some_and(|previous| previous != is_committed) {
            return Err(Refusal::new(CODE_UPLOAD_REJECTED));
        }
        committed = Some(is_committed);
        let ack = row.upload_acks.get_mut(segment).ok_or(Refusal::new(CODE_SEAL_FAILED))?;
        // Never silently trust a local checkpoint if the relay no longer confirms it.
        *ack = if is_committed { status.received_bitmap } else { *ack & status.received_bitmap };
        input.store.save_row(row)?;
        if !is_committed {
            put_slices(input, row, segment, &cipher)?;
        }
    }
    Ok(committed == Some(true))
}

fn query(row: &Row, index: u32) -> Result<UploadQuery, Refusal> {
    Ok(UploadQuery {
        upload_id: row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        object_id: row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        manifest_hash: row.manifest_hash.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        payload_generation: row.payload_generation,
        index,
    })
}

fn validate(
    status: &AttachmentUploadStatus,
    row: &Row,
    index: u32,
    length: u64,
    now: u64,
) -> Result<(), Refusal> {
    let slices = length.div_ceil(CHUNK);
    let mask =
        u8::try_from((1_u16 << slices) - 1).map_err(|_| Refusal::new(CODE_UPLOAD_REJECTED))?;
    let received: u64 = (0..slices)
        .filter(|bit| status.received_bitmap & (1 << bit) != 0)
        .map(|bit| (length - bit * CHUNK).min(CHUNK))
        .sum();
    if status.index != index
        || status.payload_generation != row.payload_generation
        || status.segment_length != length
        || u64::from(status.network_chunk_bytes) != CHUNK
        || status.received_bitmap & !mask != 0
        || status.received_bytes != received
        || status.lease_until > status.lease_hard_until
        || status.lease_hard_until > row.hard_deadline
        || !matches!(status.state.as_str(), "pending" | "committed")
        || (status.state == "committed" && status.received_bitmap != mask)
    {
        return Err(Refusal::new(CODE_UPLOAD_REJECTED));
    }
    if now >= row.hard_deadline
        || (status.state == "pending" && now >= status.lease_until)
        || status.expires_at.is_some_and(|expiry| now >= expiry)
    {
        return Err(Refusal::new(CODE_EXPIRED));
    }
    Ok(())
}

fn put_slices(
    input: &PublishInput<'_>,
    row: &mut Row,
    segment: usize,
    cipher: &[u8],
) -> Result<(), Refusal> {
    let step = usize::try_from(CHUNK).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    for (slice, body) in cipher.chunks(step).enumerate() {
        let bit = 1_u8
            .checked_shl(u32::try_from(slice).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?)
            .ok_or(Refusal::new(CODE_SEAL_FAILED))?;
        if row.upload_acks.get(segment).is_some_and(|ack| ack & bit != 0) {
            continue;
        }
        let op = OwnerAttachmentOperation::put(&OwnerPut {
            audience: input.audience,
            object_id: row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
            manifest_hash: row.manifest_hash.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
            authority_generation: input.authority_generation,
            operation_id: row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
            payload_generation: row.payload_generation,
            segment_index: u64::try_from(segment).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?,
            offset: u64::try_from(slice).map_err(|_| Refusal::new(CODE_SEAL_FAILED))? * CHUNK,
            body,
        })
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let reply =
            owner_wire::submit(input.plane, &op, body, input.owner, input.owner_key, input.now)?;
        if owner_wire::reply_object(&reply)?
            != row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?
        {
            return Err(Refusal::new(CODE_UPLOAD_REJECTED));
        }
        *row.upload_acks.get_mut(segment).ok_or(Refusal::new(CODE_SEAL_FAILED))? |= bit;
        input.store.save_row(row)?;
    }
    Ok(())
}
