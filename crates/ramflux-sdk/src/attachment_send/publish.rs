// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reserve, seal, upload, then one Inner. A sealing crash retires that generation.

use ed25519_dalek::SigningKey;
use ramflux_protocol::large_attachment::{
    OwnerAttachmentOperation, OwnerBind, OwnerPut, OwnerReserve, QualifiedOwner,
};

use super::codes::{
    CODE_CANCELLED, CODE_EXPIRED, CODE_RECIPIENT_EMPTY, CODE_RECIPIENT_LIMIT, CODE_SEAL_FAILED,
    Refusal,
};
use super::grant_wrap::{self, WrapInput, Wrapped};
use super::meta::MAX_ENTRIES;
use super::meta::{Phase, Row};
use super::owner_wire;
use super::plane::Plane;
use super::preflight::{self, FileBound, IdentityLen};
use super::seal_job::{self, segment_name_of};
use super::store::Store;
use super::targets::MediaDevice;

const NETWORK_CHUNK: u32 = 524_288;

pub(crate) struct PublishInput<'a> {
    pub store: &'a Store,
    pub plane: &'a dyn Plane,
    pub owner: &'a QualifiedOwner,
    pub owner_key: &'a SigningKey,
    pub targets: &'a [MediaDevice],
    pub audience: &'a str,
    pub authority_generation: u64,
    pub source: &'a str,
    pub now: u64,
    pub caption: &'a str,
}

/// Reserve, seal, bind, upload and commit every file. Nothing is granted or wrapped here, so
/// the recipient set may still change; wrapping runs after `wrap_all`'s fresh roster check.
/// # Errors
/// Returns a stable refusal and does not reserve when the roster does not fit.
pub(crate) fn upload_all(input: &PublishInput<'_>, rows: &[Row]) -> Result<Vec<Row>, Refusal> {
    check_roster(input, rows)?;
    let mut done = Vec::with_capacity(rows.len());
    for row in rows {
        done.push(upload_one(input, &row.prepare_id)?);
    }
    Ok(done)
}

/// Registers one grant per target, wraps the file key, and returns the finished references.
/// The roster in `input` is the one that applies now; a grant planned for a device that left
/// it is reported in `Wrapped::excluded` and is in no entry.
/// # Errors
/// Returns a stable refusal when a grant, the Inner, or the group frame does not fit.
pub(crate) fn wrap_all(input: &PublishInput<'_>, rows: &[Row]) -> Result<Vec<Wrapped>, Refusal> {
    check_roster(input, rows)?;
    let mut wrapped = Vec::with_capacity(rows.len());
    for row in rows {
        wrapped.push(wrap_one(input, &row.prepare_id)?);
    }
    Ok(wrapped)
}

/// Both phases in order, for callers that hold one fixed roster.
/// # Errors
/// Returns a stable refusal and does not reserve when the roster does not fit.
#[cfg(test)]
pub(crate) fn publish_all(input: &PublishInput<'_>, rows: &[Row]) -> Result<Vec<Wrapped>, Refusal> {
    let rows = upload_all(input, rows)?;
    wrap_all(input, &rows)
}

fn check_roster(input: &PublishInput<'_>, rows: &[Row]) -> Result<(), Refusal> {
    if input.targets.is_empty() {
        return Err(Refusal::new(CODE_RECIPIENT_EMPTY));
    }
    if input.targets.len() > MAX_ENTRIES {
        return Err(Refusal::new(CODE_RECIPIENT_LIMIT));
    }
    super::targets::require_distinct(input.targets)?;
    let files: Vec<FileBound<'_>> = rows
        .iter()
        .map(|row| FileBound {
            mime: &row.mime,
            name: &row.file_name,
            plaintext_length: row.plaintext_length.unwrap_or(0),
            thumbnail: row.thumbnail.as_ref(),
            metadata: &row.metadata,
        })
        .collect();
    preflight::measure(
        &files,
        input.targets,
        input.caption,
        IdentityLen {
            account: &input.owner.account_anchor,
            device: &input.owner.device_id,
            home: &input.owner.home_node_id,
        },
        input.source,
    )
}

/// # Errors
/// Returns a stable refusal. A mismatched reservation is fenced and not sealed.
pub(crate) fn upload_one(input: &PublishInput<'_>, prepare_id: &str) -> Result<Row, Refusal> {
    let mut row = input.store.load(prepare_id)?;
    if row.phase == Phase::Cleaning || row.phase == Phase::Fenced {
        return Err(Refusal::new(CODE_CANCELLED));
    }
    // A retry of a send that already reached the grants finds the result it left behind.
    if matches!(row.phase, Phase::Committed | Phase::Granted | Phase::Admitted) {
        return Ok(row);
    }
    if row.phase == Phase::Sealing {
        row = recover_sealing(input, &row)?;
    }
    if row.phase == Phase::Accepted {
        row = retire_abandoned(input, row)?;
        bound_one(input, &row)?;
        input.store.verify_snapshot(&mut row)?;
        row = input.store.draw(prepare_id, input.now)?;
    }
    if row.phase == Phase::Reserved {
        row = reserve_and_seal(input, row)?;
    }
    if row.phase == Phase::Bound {
        row = bind_remote(input, row)?;
    }
    if row.phase == Phase::Uploading {
        row = upload_remote(input, row)?;
    }
    if row.phase == Phase::Committed {
        return Ok(row);
    }
    Err(Refusal::new(CODE_SEAL_FAILED))
}

/// # Errors
/// Returns a stable refusal. A finished wrap is returned unchanged, also after admission.
pub(crate) fn wrap_one(input: &PublishInput<'_>, prepare_id: &str) -> Result<Wrapped, Refusal> {
    let row = input.store.load(prepare_id)?;
    match row.phase {
        Phase::Cleaning | Phase::Fenced => Err(Refusal::new(CODE_CANCELLED)),
        Phase::Committed | Phase::Granted | Phase::Admitted => finish_grant(input, row),
        _ => Err(Refusal::new(CODE_SEAL_FAILED)),
    }
}

fn bound_one(input: &PublishInput<'_>, row: &Row) -> Result<(), Refusal> {
    preflight::measure(
        &[FileBound {
            mime: &row.mime,
            name: &row.file_name,
            plaintext_length: row.plaintext_length.unwrap_or(0),
            thumbnail: row.thumbnail.as_ref(),
            metadata: &row.metadata,
        }],
        input.targets,
        input.caption,
        IdentityLen {
            account: &input.owner.account_anchor,
            device: &input.owner.device_id,
            home: &input.owner.home_node_id,
        },
        input.source,
    )
}

fn recover_sealing(input: &PublishInput<'_>, row: &Row) -> Result<Row, Refusal> {
    input.store.resume(&row.prepare_id, input.now)
}

/// Sends the relay Retire for every abandoned reservation not yet confirmed. A refusal keeps
/// the entry pending; the predecessor's charge stays held until the relay acknowledges it.
fn retire_abandoned(input: &PublishInput<'_>, mut row: Row) -> Result<Row, Refusal> {
    if row.pending_abandon.is_empty() {
        return Ok(row);
    }
    let pending = std::mem::take(&mut row.pending_abandon);
    for (upload, object) in pending {
        if retire(input, upload, object).is_err() {
            row.pending_abandon.push((upload, object));
        }
    }
    input.store.save_row(&row)?;
    Ok(row)
}

fn reserve_and_seal(input: &PublishInput<'_>, row: Row) -> Result<Row, Refusal> {
    if input.now >= row.hard_deadline {
        return Err(Refusal::new(CODE_EXPIRED));
    }
    let upload = row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let object = row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let length = row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let (op, body) = OwnerAttachmentOperation::reserve(&OwnerReserve {
        audience: input.audience,
        object_id: object,
        authority_generation: input.authority_generation,
        upload_id: upload,
        plaintext_length: length,
        network_chunk_bytes: NETWORK_CHUNK,
        lease_hard_until: row.hard_deadline,
    })
    .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let reply =
        owner_wire::submit(input.plane, &op, &body, input.owner, input.owner_key, input.now)?;
    if owner_wire::reply_object(&reply)? != object {
        input.store.fence_secret(row)?;
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    let mut row = row;
    input.store.verify_snapshot(&mut row)?;
    let row = input.store.mark(row, Phase::Sealing)?;
    let sealed = seal_job::seal_persisted(input.store, &row, input.owner, input.owner_key)?;
    if sealed.object_id != object {
        input.store.fence_secret(row)?;
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    let mut row = row;
    row.segment_digests = sealed.digests;
    row.manifest_hash = Some(sealed.hash);
    row.phase = Phase::Bound;
    input.store.write_named(&row.prepare_id, "manifest.bin", &sealed.bytes)?;
    input.store.save_row(&row)?;
    Ok(row)
}

fn bind_remote(input: &PublishInput<'_>, row: Row) -> Result<Row, Refusal> {
    let manifest = input.store.read_named(&row.prepare_id, "manifest.bin")?;
    let op = OwnerAttachmentOperation::bind(&OwnerBind {
        audience: input.audience,
        object_id: row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        manifest_hash: row.manifest_hash.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        authority_generation: input.authority_generation,
        operation_id: row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        payload_generation: row.payload_generation,
        body: &manifest,
    })
    .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    owner_wire::submit(input.plane, &op, &manifest, input.owner, input.owner_key, input.now)?;
    input.store.mark(row, Phase::Uploading)
}

fn upload_remote(input: &PublishInput<'_>, row: Row) -> Result<Row, Refusal> {
    put_segments(input, &row)?;
    let op = OwnerAttachmentOperation::commit(
        input.audience,
        row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        row.manifest_hash.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        input.authority_generation,
        row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        row.payload_generation,
    )
    .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    owner_wire::submit(input.plane, &op, &[], input.owner, input.owner_key, input.now)?;
    input.store.mark(row, Phase::Committed)
}

fn put_segments(input: &PublishInput<'_>, row: &Row) -> Result<(), Refusal> {
    for (index, _) in row.segment_digests.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let name = segment_name_of(index);
        let _held = super::budget::memory(
            u64::from(ramflux_protocol::large_attachment::SEGMENT_BYTES) + u64::from(NETWORK_CHUNK),
        )?;
        let cipher = input.store.read_named(&row.prepare_id, &name)?;
        put_slices(input, row, u64::from(index), &cipher)?;
    }
    Ok(())
}

fn put_slices(
    input: &PublishInput<'_>,
    row: &Row,
    index: u64,
    cipher: &[u8],
) -> Result<(), Refusal> {
    let mut offset = 0_usize;
    while offset < cipher.len() {
        let step = usize::try_from(NETWORK_CHUNK).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let end = offset.saturating_add(step).min(cipher.len());
        let body = &cipher[offset..end];
        let at = u64::try_from(offset).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let op = OwnerAttachmentOperation::put(&OwnerPut {
            audience: input.audience,
            object_id: row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
            manifest_hash: row.manifest_hash.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
            authority_generation: input.authority_generation,
            operation_id: row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
            payload_generation: row.payload_generation,
            segment_index: index,
            offset: at,
            body,
        })
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        owner_wire::submit(input.plane, &op, body, input.owner, input.owner_key, input.now)?;
        offset = end;
    }
    Ok(())
}

fn finish_grant(input: &PublishInput<'_>, row: Row) -> Result<Wrapped, Refusal> {
    let manifest = input.store.read_named(&row.prepare_id, "manifest.bin")?;
    let wrapped = grant_wrap::wrap(&WrapInput {
        store: input.store,
        plane: input.plane,
        row: &row,
        owner: input.owner,
        owner_key: input.owner_key,
        targets: input.targets,
        manifest: &manifest,
        relay_hash: row.manifest_hash.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        source: input.source,
        now: input.now,
        caption: input.caption,
    })?;
    if row.phase == Phase::Committed {
        input.store.mark(row, Phase::Granted)?;
    }
    Ok(wrapped)
}

fn retire(input: &PublishInput<'_>, upload: [u8; 32], object: [u8; 32]) -> Result<(), Refusal> {
    let op = OwnerAttachmentOperation::retire(
        input.audience,
        object,
        input.authority_generation,
        upload,
    )
    .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    owner_wire::submit(input.plane, &op, &[], input.owner, input.owner_key, input.now)?;
    Ok(())
}
