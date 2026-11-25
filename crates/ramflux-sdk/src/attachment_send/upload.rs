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

/// The encrypted account-DB journal of slice ACKs, one entry per upload generation. The
/// worker reaches it through [`JournalSink`], which the account task serves.
pub(crate) trait AckJournal: Send + Sync {
    /// # Errors
    /// Returns a stable refusal when the journal cannot be read.
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, Refusal>;
    /// # Errors
    /// Returns a stable refusal when the checkpoint is not durable.
    fn save(&self, key: &str, acks: &[u8]) -> Result<(), Refusal>;
    /// Appends one transfer snapshot to the account-DB journal under `source` (its dedup key).
    /// # Errors
    /// Returns a stable refusal when the snapshot is not durable.
    fn emit(&self, source: &str, body: &serde_json::Value) -> Result<(), Refusal>;
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct AckRecord {
    pub(crate) acks: Vec<u8>,
}

/// Account-DB key of the ACK bitmap. The upload id is part of the key, so an abandoned
/// generation can never leak ACKs into a fresh one.
pub(crate) fn journal_key(prepare_id: &str, upload_id: [u8; 32]) -> String {
    format!("attachment-upload-acks/{prepare_id}/{}", owner_wire::encode_hex(&upload_id))
}

/// Journal rows are read and written by the account task; the blocking worker blocks on a reply.
#[derive(Clone)]
pub(crate) struct JournalSink {
    tx: tokio::sync::mpsc::Sender<JournalCall>,
}

pub(crate) enum JournalCall {
    Load {
        key: String,
        reply: tokio::sync::oneshot::Sender<Result<Option<Vec<u8>>, Refusal>>,
    },
    Save {
        key: String,
        acks: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<(), Refusal>>,
    },
    Emit {
        source: String,
        body: serde_json::Value,
        reply: tokio::sync::oneshot::Sender<Result<(), Refusal>>,
    },
}

/// Bounded: the worker has at most one call in flight, so this only absorbs scheduling jitter.
pub(crate) const JOURNAL_QUEUE: usize = 8;

impl JournalSink {
    pub(crate) fn channel() -> (Self, tokio::sync::mpsc::Receiver<JournalCall>) {
        let (tx, rx) = tokio::sync::mpsc::channel(JOURNAL_QUEUE);
        (Self { tx }, rx)
    }
}

impl AckJournal for JournalSink {
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, Refusal> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        self.tx
            .blocking_send(JournalCall::Load { key: key.to_owned(), reply })
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        answer.blocking_recv().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?
    }

    fn save(&self, key: &str, acks: &[u8]) -> Result<(), Refusal> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        self.tx
            .blocking_send(JournalCall::Save { key: key.to_owned(), acks: acks.to_vec(), reply })
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        answer.blocking_recv().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?
    }

    fn emit(&self, source: &str, body: &serde_json::Value) -> Result<(), Refusal> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        self.tx
            .blocking_send(JournalCall::Emit {
                source: source.to_owned(),
                body: body.clone(),
                reply,
            })
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        answer.blocking_recv().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?
    }
}

/// Validates one journal entry. The journal hands back the bitmap bytes already unwrapped from
/// `AckRecord`, so they are checked for length, never parsed again. An absent entry is an
/// all-unacknowledged bitmap.
pub(crate) fn decode_acks(bytes: Option<Vec<u8>>, count: usize) -> Result<Vec<u8>, Refusal> {
    match bytes {
        None => Ok(vec![0; count]),
        Some(acks) if acks.len() == count => Ok(acks),
        Some(_) => Err(Refusal::new(CODE_SEAL_FAILED)),
    }
}

fn checkpoint(input: &PublishInput<'_>, row: &Row) -> Result<(), Refusal> {
    let upload = row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    input.journal.save(&journal_key(&row.prepare_id, upload), &row.upload_acks)
}

/// Reconciles every segment before PUT and checkpoints each successful reply before the next
/// slice. A relay-only ACK is uncertain locally and is replayed byte for byte. Returns true
/// when all segments were already committed, including recovery of a lost Commit reply.
pub(super) fn put_segments(input: &PublishInput<'_>, row: &mut Row) -> Result<bool, Refusal> {
    let outcome = put_segments_inner(input, row);
    match &outcome {
        Ok(true) => publish_transfer(input, row, "uploaded", None, false, true)?,
        // The failure snapshot is best effort: the refusal itself is what the caller acts on.
        Err(refusal) => {
            let _ = publish_transfer(input, row, "failed", Some(refusal.code), true, true);
        }
        Ok(false) => {}
    }
    outcome
}

fn put_segments_inner(input: &PublishInput<'_>, row: &mut Row) -> Result<bool, Refusal> {
    let layout = SegmentLayout {
        plaintext_length: row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        network_chunk_bytes: u32::try_from(CHUNK).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?,
    };
    let (count, _) = layout.dimensions().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let count = usize::try_from(count).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    if row.segment_digests.len() != count {
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    // Ciphertext bytes of the whole upload: each segment carries a 16-byte AEAD tag.
    let total = u64::try_from(count)
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?
        .checked_mul(16)
        .and_then(|tags| tags.checked_add(layout.plaintext_length))
        .ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    // The journal, never meta.json, is the only source of ACKs; a fresh upload id finds none.
    let upload = row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    row.upload_acks =
        decode_acks(input.journal.load(&journal_key(&row.prepare_id, upload))?, count)?;
    let _running = super::transfer::enter(input.store.account_id(), &row.prepare_id, total)?;
    super::transfer::set_unique(input.store.account_id(), &row.prepare_id, ack_unique(row)?);
    publish_transfer(input, row, "uploading", None, false, true)?;
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
        checkpoint(input, row)?;
        super::transfer::set_unique(input.store.account_id(), &row.prepare_id, ack_unique(row)?);
        publish_transfer(input, row, "uploading", None, false, false)?;
        if !is_committed {
            put_slices(input, row, segment, &cipher)?;
        }
    }
    Ok(committed == Some(true))
}

/// Unique ciphertext bytes confirmed by the ACK bitmap of `row`. It is derived from the
/// journal, so it is the same before and after a restart and never double-counts a retry.
pub(crate) fn ack_unique(row: &Row) -> Result<u64, Refusal> {
    let layout = SegmentLayout {
        plaintext_length: row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        network_chunk_bytes: u32::try_from(CHUNK).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?,
    };
    let mut unique = 0_u64;
    for (segment, ack) in row.upload_acks.iter().enumerate() {
        let index = u64::try_from(segment).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let length =
            layout.segment_plaintext_length(index).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?
                + 16;
        unique = unique.saturating_add(acked_bytes(length, *ack));
    }
    Ok(unique)
}

/// Ciphertext bytes of the slices whose ACK bit is set, for a segment of `length` bytes.
fn acked_bytes(length: u64, ack: u8) -> u64 {
    (0..8_u64)
        .filter(|slice| (ack >> slice) & 1 == 1)
        .map(|slice| length.saturating_sub(slice * CHUNK).min(CHUNK))
        .sum()
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
        // A paused upload stops before the next slice; nothing is sent while it waits.
        if super::transfer::is_paused(input.store.account_id(), &row.prepare_id) {
            publish_transfer(input, row, "paused", None, true, true)?;
        }
        super::transfer::gate(input.store.account_id(), &row.prepare_id)?;
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
        let reply = owner_wire::submit(input.plane, &op, body, input.owner, input.owner_key)?;
        if owner_wire::reply_object(&reply)?
            != row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?
        {
            return Err(Refusal::new(CODE_UPLOAD_REJECTED));
        }
        *row.upload_acks.get_mut(segment).ok_or(Refusal::new(CODE_SEAL_FAILED))? |= bit;
        checkpoint(input, row)?;
        super::transfer::set_unique(input.store.account_id(), &row.prepare_id, ack_unique(row)?);
        publish_transfer(input, row, "uploading", None, false, false)?;
    }
    Ok(())
}

/// Ciphertext bytes of the whole upload: plaintext plus one 16-byte AEAD tag per segment.
pub(crate) fn ciphertext_total(row: &Row) -> Result<u64, Refusal> {
    let plaintext = row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let segments =
        u64::try_from(row.segment_digests.len()).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    segments
        .checked_mul(16)
        .and_then(|tags| tags.checked_add(plaintext))
        .ok_or(Refusal::new(CODE_SEAL_FAILED))
}

/// Appends one `attachment.transfer.changed` snapshot. Counts are ciphertext bytes; the body
/// carries no paths, names, captions, keys, grants or raw errors.
fn publish_transfer(
    input: &PublishInput<'_>,
    row: &Row,
    phase: &str,
    reason: Option<&str>,
    retryable: bool,
    force: bool,
) -> Result<(), Refusal> {
    let account = input.store.account_id();
    let Some(revision) = super::transfer::claim_emit(account, &row.prepare_id, force) else {
        return Ok(());
    };
    let unique = ack_unique(row)?;
    let total = ciphertext_total(row)?;
    let body = serde_json::json!({
        "transfer_id": row.prepare_id,
        "prepare_id": row.prepare_id,
        "operation_id": row.operation_id,
        "client_message_id": serde_json::Value::Null,
        "message_id": row.message_id,
        "import_id": serde_json::Value::Null,
        "direction": "upload",
        "phase": phase,
        "generation": row.payload_generation,
        "total_bytes": total,
        "accepted_bytes": total,
        "uploaded_bytes": unique,
        "unique_bytes": unique,
        "verified_bytes": serde_json::Value::Null,
        "expires_at": row.expires_at,
        "reason_code": reason,
        "retryable": retryable,
    });
    let source =
        format!("attachment-transfer/{}/{}/{revision}", row.prepare_id, row.payload_generation);
    input.journal.emit(&source, &body)
}

/// In-memory journal for the store fixtures; production always uses [`JournalSink`].
#[cfg(test)]
pub(crate) struct MemoryJournal(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

#[cfg(test)]
pub(crate) static TEST_JOURNAL: MemoryJournal =
    MemoryJournal(std::sync::Mutex::new(std::collections::BTreeMap::new()));

#[cfg(test)]
impl AckJournal for MemoryJournal {
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, Refusal> {
        let map = self.0.lock().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        Ok(map.get(key).cloned())
    }

    fn save(&self, key: &str, acks: &[u8]) -> Result<(), Refusal> {
        let mut map = self.0.lock().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        map.insert(key.to_owned(), acks.to_vec());
        Ok(())
    }

    fn emit(&self, _source: &str, _body: &serde_json::Value) -> Result<(), Refusal> {
        Ok(())
    }
}
