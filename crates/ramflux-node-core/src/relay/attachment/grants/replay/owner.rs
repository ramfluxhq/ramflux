// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner reserve, bind, upload, commit, and pending retire.
//! Reader admission is not this path and no recipient grant is created here.
//! redb allows one write transaction, so a chunk is stored only after that
//! transaction commits. The upload lease stays held across the write, and the
//! reservation is read again before the chunk is treated as published.

use super::storage::{Limits, consume};
use super::{AttachmentReplayError, AttachmentReplayProof};
use crate::relay::attachment::backend::{AttachmentBackend, BackendSegment};
use crate::relay::attachment::{
    AttachmentLedgerError, AttachmentOwner, AttachmentReservation, AttachmentReservationRequest,
    AttachmentReservationState, BeginError, RECORDS, ReadableTable, decode, key, store,
};
use ramflux_protocol::canonical_json_bytes;
use ramflux_protocol::large_attachment::{
    ContentManifest, OwnerAttachmentOperation, QualifiedOwner, RequesterPop, body_digest,
    requester_digest,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

mod status;
pub use status::AttachmentCheckpoint;

#[cfg(test)]
mod tests;

/// One authenticated owner request. The session is already the owner.
pub struct OwnerAdmission<'a> {
    pub operation: &'a [u8],
    pub body: &'a [u8],
    pub proof: &'a [u8],
    pub proof_signature: &'a [u8; 64],
    pub requester: &'a QualifiedOwner,
    pub now: u64,
}

/// Refusal of an owner upload request.
#[derive(Debug, thiserror::Error)]
pub enum OwnerAdmissionError {
    /// The transcript, proof, or reply is not an owner operation.
    #[error("owner operation refused")]
    Refused,
    /// The ciphertext backend rejected the chunk or its commit.
    #[error("owner publication refused")]
    Publication,
    /// The proof was already consumed or its lifetime is not current.
    #[error(transparent)]
    Replay(#[from] AttachmentReplayError),
    /// The reservation ledger refused the transition.
    #[error(transparent)]
    Ledger(#[from] AttachmentLedgerError),
}

struct Checked {
    op: OwnerAttachmentOperation,
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    owner: AttachmentOwner,
}

struct UploadLease {
    leases: Arc<super::super::retirement::LeaseOwner>,
    key: [u8; 32],
    flag: Arc<AtomicBool>,
}

impl super::super::ScopedGrantRegistry {
    /// Admits one owner operation and returns the canonical JSON result.
    /// # Errors
    /// Refuses a reader transcript, a bad proof, replay, conflict, expiry, or a fenced upload.
    #[must_use = "the caller must return this result or its refusal"]
    pub fn admit_owner_operation_after_authentication(
        &self,
        request: &OwnerAdmission<'_>,
        backend: &dyn AttachmentBackend,
    ) -> Result<Vec<u8>, OwnerAdmissionError> {
        let checked = check(self, request)?;
        let record = match checked.op.op {
            9 => self.owner_reserve(request, &checked)?,
            10 => self.owner_bind(request, &checked)?,
            4 => self.owner_put(request, &checked, backend)?,
            5 => self.owner_commit(request, &checked, backend)?,
            7 => self.owner_retire(request, &checked)?,
            _ => return Err(OwnerAdmissionError::Refused),
        };
        owner_reply(&checked.nonce, &record)
    }
}

fn check(
    registry: &super::super::ScopedGrantRegistry,
    request: &OwnerAdmission<'_>,
) -> Result<Checked, OwnerAdmissionError> {
    let op = OwnerAttachmentOperation::decode(request.operation)
        .map_err(|_| OwnerAdmissionError::Refused)?;
    if op.body_digest != body_digest(request.body)
        || op.audience != registry.authority.source
        || op.authority_generation != registry.authority.generation
    {
        return Err(OwnerAdmissionError::Refused);
    }
    let pop = RequesterPop::decode(request.proof).map_err(|_| OwnerAdmissionError::Refused)?;
    let operation_hash = op.hash().map_err(|_| OwnerAdmissionError::Refused)?;
    let bound = requester_digest(request.requester).map_err(|_| OwnerAdmissionError::Refused)?;
    if pop.forward_digest != [0; 32]
        || pop.operation_hash != operation_hash
        || pop.requester_digest != bound
    {
        return Err(OwnerAdmissionError::Refused);
    }
    pop.verify(&request.requester.signing_public_key, request.proof_signature)
        .map_err(|_| OwnerAdmissionError::Refused)?;
    let owner = AttachmentOwner::from_authenticated_session(&request.requester.account_anchor)?;
    Ok(Checked {
        op,
        nonce: pop.nonce,
        issued_at: pop.issued_at,
        expires_at: pop.expires_at,
        owner,
    })
}

impl super::super::ScopedGrantRegistry {
    fn transact<T>(
        &self,
        body: impl FnOnce(&redb::WriteTransaction) -> Result<T, OwnerAdmissionError>,
    ) -> Result<T, OwnerAdmissionError> {
        let tx = self.ledger.begin_write_until(self.deadline.as_ref()).map_err(begin_error)?;
        let value = body(&tx)?;
        tx.commit().map_err(store)?;
        Ok(value)
    }

    fn owner_reserve(
        &self,
        request: &OwnerAdmission<'_>,
        checked: &Checked,
    ) -> Result<AttachmentReservation, OwnerAdmissionError> {
        let parsed = parse_reserve(request.body)?;
        if parsed.upload_id != checked.op.operation_id || parsed.object_id != checked.op.object_id {
            return Err(OwnerAdmissionError::Refused);
        }
        let reservation = AttachmentReservationRequest {
            upload_id: parsed.upload_id,
            object_id: parsed.object_id,
            layout: ramflux_protocol::large_attachment::SegmentLayout {
                plaintext_length: parsed.plaintext_length,
                network_chunk_bytes: parsed.network_chunk_bytes,
            },
        };
        self.transact(|tx| {
            consume_owner(self, tx, request, checked)?;
            Ok(self.ledger.reserve_on(
                tx,
                &checked.owner,
                &reservation,
                request.now,
                Some(parsed.lease_hard_until),
            )?)
        })
    }

    fn owner_bind(
        &self,
        request: &OwnerAdmission<'_>,
        checked: &Checked,
    ) -> Result<AttachmentReservation, OwnerAdmissionError> {
        let manifest = ContentManifest::decode_signed(request.body)
            .map_err(|_| OwnerAdmissionError::Refused)?;
        let hash = manifest.manifest().hash().map_err(|_| OwnerAdmissionError::Refused)?;
        if hash != checked.op.manifest_hash
            || manifest.manifest().owner != *request.requester
            || manifest.manifest().object_id != checked.op.object_id
        {
            return Err(OwnerAdmissionError::Refused);
        }
        self.transact(|tx| {
            consume_owner(self, tx, request, checked)?;
            let record = load_tx(tx, &checked.owner, &checked.op.operation_id)?;
            if checked.op.payload_generation != record.pending_generation {
                return Err(AttachmentLedgerError::Conflict.into());
            }
            Ok(crate::relay::attachment::AttachmentLedger::bind_on(
                tx,
                &checked.owner,
                &checked.op.operation_id,
                &crate::relay::attachment::quota::BindOn {
                    manifest: &manifest,
                    signed: request.body,
                    now: request.now,
                },
            )?)
        })
    }

    fn owner_put(
        &self,
        request: &OwnerAdmission<'_>,
        checked: &Checked,
        backend: &dyn AttachmentBackend,
    ) -> Result<AttachmentReservation, OwnerAdmissionError> {
        let body_len =
            u64::try_from(request.body.len()).map_err(|_| OwnerAdmissionError::Refused)?;
        if body_len != checked.op.length {
            return Err(OwnerAdmissionError::Refused);
        }
        let _lease = self.acquire_upload(checked.op.operation_id, false)?;
        let record = self.transact(|tx| {
            consume_owner(self, tx, request, checked)?;
            let record = load_tx(tx, &checked.owner, &checked.op.operation_id)?;
            accept_chunk(&record, &checked.op, request.now)?;
            Ok(record)
        })?;
        self.write_chunk(request, checked, backend, &record)
    }

    fn write_chunk(
        &self,
        request: &OwnerAdmission<'_>,
        checked: &Checked,
        backend: &dyn AttachmentBackend,
        record: &AttachmentReservation,
    ) -> Result<AttachmentReservation, OwnerAdmissionError> {
        let spec = segment_spec(record, checked.op.segment_index)?;
        let mut body = std::io::Cursor::new(request.body);
        // A rejected retry must not retire the object or destroy previously accepted slices.
        // Incomplete writes have no checkpoint; reconciliation verifies the durable bits.
        backend.write_chunk(&spec, checked.op.offset, &mut body).map_err(publication)?;
        let current = self.ledger.reservation(&checked.owner, &checked.op.operation_id)?;
        let retired = matches!(
            current.state,
            AttachmentReservationState::DebtPending
                | AttachmentReservationState::DebtCommitted
                | AttachmentReservationState::Released
        );
        if retired
            || current.manifest_hash != Some(checked.op.manifest_hash)
            || current.object_id != checked.op.object_id
        {
            backend.delete(&spec).map_err(publication)?;
            return Err(AttachmentLedgerError::State.into());
        }
        Ok(current)
    }

    fn owner_commit(
        &self,
        request: &OwnerAdmission<'_>,
        checked: &Checked,
        backend: &dyn AttachmentBackend,
    ) -> Result<AttachmentReservation, OwnerAdmissionError> {
        if !request.body.is_empty() {
            return Err(OwnerAdmissionError::Refused);
        }
        let _lease = self.acquire_upload(checked.op.operation_id, false)?;
        // One transaction consumes the proof and validates the reservation. Nothing is
        // published before this commits, so a replayed or stale proof publishes nothing.
        let (record, committed) = self.transact(|tx| {
            consume_owner(self, tx, request, checked)?;
            let record = load_tx(tx, &checked.owner, &checked.op.operation_id)?;
            if checked.op.payload_generation != record.pending_generation
                || record.manifest_hash != Some(checked.op.manifest_hash)
                || record.object_id != checked.op.object_id
            {
                return Err(AttachmentLedgerError::Conflict.into());
            }
            if record.state == AttachmentReservationState::Committed {
                // An already-Committed retry returns the stored record and charges nothing.
                if record.expires_at.is_none_or(|expiry| request.now >= expiry) {
                    return Err(AttachmentLedgerError::Expired.into());
                }
                record.require_bound_generation()?;
                return Ok((record, true));
            }
            crate::relay::attachment::quota::pending(&record, request.now)?;
            Ok((record, false))
        })?;
        if committed {
            return Ok(record);
        }
        publish_segments(backend, &record)?;
        // The lease stays held. Re-read the reservation before the Committed transition.
        self.transact(|tx| {
            let again = load_tx(tx, &checked.owner, &checked.op.operation_id)?;
            if again.state != AttachmentReservationState::Pending
                || again.manifest_hash != record.manifest_hash
                || again.pending_generation != record.pending_generation
            {
                return Err(AttachmentLedgerError::State.into());
            }
            Ok(crate::relay::attachment::AttachmentLedger::commit_on(
                tx,
                &checked.owner,
                &checked.op.operation_id,
                again.pending_generation,
                request.now,
            )?)
        })
    }

    fn owner_retire(
        &self,
        request: &OwnerAdmission<'_>,
        checked: &Checked,
    ) -> Result<AttachmentReservation, OwnerAdmissionError> {
        if !request.body.is_empty() {
            return Err(OwnerAdmissionError::Refused);
        }
        let _lease = self.acquire_upload(checked.op.operation_id, true)?;
        self.transact(|tx| {
            consume_owner(self, tx, request, checked)?;
            Ok(crate::relay::attachment::AttachmentLedger::abandon_on(
                tx,
                &checked.owner,
                &checked.op.operation_id,
            )?)
        })
    }

    fn acquire_upload(
        &self,
        upload_id: [u8; 32],
        exclusive: bool,
    ) -> Result<UploadLease, OwnerAdmissionError> {
        let key = upload_lease_key(&upload_id);
        let mut map = self.leases.lock()?;
        map.retain(|_, holders| {
            holders.retain(|holder| holder.strong_count() > 0);
            !holders.is_empty()
        });
        let live: Vec<Arc<AtomicBool>> = map
            .get(&key)
            .map(|holders| holders.iter().filter_map(std::sync::Weak::upgrade).collect())
            .unwrap_or_default();
        if exclusive {
            if !live.is_empty() {
                return Err(AttachmentLedgerError::State.into());
            }
        } else if live.iter().any(|flag| flag.load(Ordering::Acquire)) {
            return Err(AttachmentLedgerError::State.into());
        }
        if map.values().map(Vec::len).sum::<usize>() >= 32 {
            return Err(AttachmentLedgerError::Capacity.into());
        }
        let flag = Arc::new(AtomicBool::new(exclusive));
        map.entry(key).or_default().push(Arc::downgrade(&flag));
        Ok(UploadLease { leases: Arc::clone(&self.leases), key, flag })
    }
}

impl Drop for UploadLease {
    fn drop(&mut self) {
        let flag = std::mem::replace(&mut self.flag, Arc::new(AtomicBool::new(false)));
        drop(flag);
        let Ok(mut map) = self.leases.lock() else {
            return;
        };
        let Some(holders) = map.get_mut(&self.key) else {
            return;
        };
        holders.retain(|holder| holder.strong_count() > 0);
        if holders.is_empty() {
            map.remove(&self.key);
        }
    }
}

fn consume_owner(
    registry: &super::super::ScopedGrantRegistry,
    tx: &redb::WriteTransaction,
    request: &OwnerAdmission<'_>,
    checked: &Checked,
) -> Result<(), OwnerAdmissionError> {
    let proof = AttachmentReplayProof {
        nonce: checked.nonce,
        issued_at: checked.issued_at,
        expires_at: checked.expires_at,
    };
    consume(
        tx,
        &registry.authority.source,
        request.requester,
        &proof,
        request.now,
        Limits::default(),
    )?;
    Ok(())
}

fn accept_chunk(
    record: &AttachmentReservation,
    op: &OwnerAttachmentOperation,
    now: u64,
) -> Result<(), AttachmentLedgerError> {
    crate::relay::attachment::quota::pending(record, now)?;
    if record.object_id != op.object_id || record.manifest_hash != Some(op.manifest_hash) {
        return Err(AttachmentLedgerError::Conflict);
    }
    if op.payload_generation != record.pending_generation {
        return Err(AttachmentLedgerError::Conflict);
    }
    Ok(())
}

fn load_tx(
    tx: &redb::WriteTransaction,
    owner: &AttachmentOwner,
    id: &[u8; 32],
) -> Result<AttachmentReservation, AttachmentLedgerError> {
    let records = tx.open_table(RECORDS).map_err(store)?;
    let value = records
        .get(key(owner, id).as_slice())
        .map_err(store)?
        .ok_or(AttachmentLedgerError::Conflict)?;
    decode(value.value())
}

struct ReserveBody {
    upload_id: [u8; 32],
    object_id: [u8; 32],
    plaintext_length: u64,
    network_chunk_bytes: u32,
    lease_hard_until: u64,
}

fn parse_reserve(body: &[u8]) -> Result<ReserveBody, OwnerAdmissionError> {
    if body.len() != 84 {
        return Err(OwnerAdmissionError::Refused);
    }
    let upload_id = copy32(body, 0)?;
    let object_id = copy32(body, 32)?;
    let plaintext_length = u64_at(body, 64)?;
    let network_chunk_bytes = u32_at(body, 72)?;
    let lease_hard_until = u64_at(body, 76)?;
    Ok(ReserveBody {
        upload_id,
        object_id,
        plaintext_length,
        network_chunk_bytes,
        lease_hard_until,
    })
}

fn copy32(body: &[u8], at: usize) -> Result<[u8; 32], OwnerAdmissionError> {
    let end = at.checked_add(32).ok_or(OwnerAdmissionError::Refused)?;
    body.get(at..end)
        .ok_or(OwnerAdmissionError::Refused)?
        .try_into()
        .map_err(|_| OwnerAdmissionError::Refused)
}

fn u64_at(body: &[u8], at: usize) -> Result<u64, OwnerAdmissionError> {
    let end = at.checked_add(8).ok_or(OwnerAdmissionError::Refused)?;
    let bytes: [u8; 8] = body
        .get(at..end)
        .ok_or(OwnerAdmissionError::Refused)?
        .try_into()
        .map_err(|_| OwnerAdmissionError::Refused)?;
    Ok(u64::from_be_bytes(bytes))
}

fn u32_at(body: &[u8], at: usize) -> Result<u32, OwnerAdmissionError> {
    let end = at.checked_add(4).ok_or(OwnerAdmissionError::Refused)?;
    let bytes: [u8; 4] = body
        .get(at..end)
        .ok_or(OwnerAdmissionError::Refused)?
        .try_into()
        .map_err(|_| OwnerAdmissionError::Refused)?;
    Ok(u32::from_be_bytes(bytes))
}

fn segment_spec(
    record: &AttachmentReservation,
    index: u64,
) -> Result<BackendSegment, OwnerAdmissionError> {
    let manifest = ContentManifest::decode_signed(&record.manifest_bytes)
        .map_err(|_| OwnerAdmissionError::Refused)?;
    let index = u32::try_from(index).map_err(|_| OwnerAdmissionError::Refused)?;
    BackendSegment::from_manifest(&manifest, record.pending_generation, index).map_err(publication)
}

fn publish_segments(
    backend: &dyn AttachmentBackend,
    record: &AttachmentReservation,
) -> Result<(), OwnerAdmissionError> {
    let manifest = ContentManifest::decode_signed(&record.manifest_bytes)
        .map_err(|_| OwnerAdmissionError::Refused)?;
    let count =
        manifest.manifest().layout.dimensions().map_err(|_| OwnerAdmissionError::Refused)?.0;
    for index in 0..count {
        let spec = BackendSegment::from_manifest(&manifest, record.pending_generation, index)
            .map_err(publication)?;
        backend.commit(&spec).map_err(publication)?;
    }
    Ok(())
}

fn owner_reply(
    nonce: &[u8; 32],
    record: &AttachmentReservation,
) -> Result<Vec<u8>, OwnerAdmissionError> {
    let body = OwnerResult {
        kind: "owner_result",
        request_id: hex(nonce),
        upload_id: hex(&record.upload_id),
        object_id: hex(&record.object_id),
        state: record.state,
        manifest_hash: record.manifest_hash.as_ref().map(|hash| hex(hash)),
    };
    let bytes = canonical_json_bytes(&body).map_err(|_| OwnerAdmissionError::Refused)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| OwnerAdmissionError::Refused)?;
    if bytes.len() > 4096 || json_depth(&value) > 32 {
        return Err(OwnerAdmissionError::Refused);
    }
    Ok(bytes)
}

#[derive(serde::Serialize)]
struct OwnerResult {
    kind: &'static str,
    request_id: String,
    upload_id: String,
    object_id: String,
    state: AttachmentReservationState,
    manifest_hash: Option<String>,
}

fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn upload_lease_key(upload_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ramflux.attachment.owner-lease.v1");
    hasher.update(upload_id);
    *hasher.finalize().as_bytes()
}

fn begin_error(error: BeginError) -> OwnerAdmissionError {
    match error {
        BeginError::Busy => AttachmentLedgerError::Capacity.into(),
        BeginError::Store(message) => AttachmentLedgerError::Store(message).into(),
    }
}

fn publication(error: impl std::fmt::Display) -> OwnerAdmissionError {
    tracing::debug!(error = %error, "owner publication refused");
    OwnerAdmissionError::Publication
}
