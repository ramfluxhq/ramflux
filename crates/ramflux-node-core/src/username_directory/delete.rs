// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One closed request derives an abort and signed delete, committed in one protected transaction.
use super::{
    CheckpointError, DirectoryAuthority, Result, VerifiedReporter, WriterIdentity,
    checkpoint_group::{AppendGroup, BatchSeed},
    image::ImagePlan,
    transitions::{self, ensure},
};
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};

impl DirectoryAuthority {
    pub(super) fn preempt_delete_if_needed(
        &mut self,
        writer: &WriterIdentity,
        reporter: &VerifiedReporter,
        phase: super::MutationPhase,
        operation: &w::UsernameOperation,
        profile: Option<&w::SignedIdentityProfileV2>,
    ) -> Result<bool> {
        if let Some(request) = self.witness.retained_delete_request(operation)? {
            self.delete_preempting_pending(writer, reporter, &w::encode(&request)?)?;
            return Ok(true);
        }
        if phase == super::MutationPhase::Reserve
            && let Some(root) = self.current_root(&reporter.root)?
            && root.pending_operation_id.is_some()
        {
            super::center::verify_profile(reporter, operation, profile, Some(&root.profile))?;
            let head = self.head();
            let request = w::DeletePreemptingPending {
                tx_id: operation.body.operation_id.clone(),
                operation: operation.clone(),
                expected_head: w::ExpectedHead { lsn: head.lsn, digest: head.digest },
                requested_time: operation.body.issued_at,
            };
            self.delete_preempting_pending(writer, reporter, &w::encode(&request)?)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Whole-request retry lookup precedes stale-head and operation freshness checks.
    /// The returned result is private until primary application and fenced publication.
    /// # Errors
    /// Refuses changed retries, stale heads, invalid signatures, overflow or exhausted capacity.
    pub fn delete_preempting_pending(
        &mut self,
        writer: &WriterIdentity,
        reporter: &VerifiedReporter,
        bytes: &[u8],
    ) -> Result<w::BatchRow> {
        let request: w::DeletePreemptingPending = w::decode(bytes)?;
        let time = self.witness.sample_time()?;
        self.fence.check_ready(writer, &self.head(), time)?;
        ensure(
            request.operation.body.principal_commitment == reporter.root
                && time.wall < reporter.expires_at,
            Code::OwnershipMismatch,
        )?;
        if let Some(row) = self.witness.delete_batch_retry(bytes)? {
            ensure(row.root == reporter.root, Code::OwnershipMismatch)?;
            return Ok(row);
        }
        // Retry lookup persists a newer safe clock. Append must use a fresh sample,
        // with the same writer and reporting authority rechecked after that write.
        let time = self.witness.sample_time()?;
        self.fence.check_ready(writer, &self.head(), time)?;
        ensure(time.wall < reporter.expires_at, Code::AuthenticationRequired)?;
        let expected = self.head();
        ensure(
            request.expected_head.lsn == expected.lsn
                && request.expected_head.digest == expected.digest,
            Code::StaleEpoch,
        )?;
        ensure(
            request.requested_time <= time.wall
                && time.wall.saturating_sub(request.requested_time) <= 300,
            Code::Replay,
        )?;
        ramflux_crypto::username_directory::verify_operation(&reporter.master, &request.operation)?;
        let mut abort = ImagePlan::new(&self.witness.db);
        let root =
            abort.root(&reporter.root)?.ok_or(CheckpointError::Directory(Code::StaleEpoch))?;
        let pending =
            root.pending_operation_id.ok_or(CheckpointError::Directory(Code::OperationPending))?;
        let mut preimage = b"delete_preempting_pending/abort".to_vec();
        for id in [&request.tx_id, &pending] {
            preimage.extend(
                ramflux_protocol::decode_base64url(id)
                    .map_err(|_| CheckpointError::Directory(Code::Replay))?,
            );
        }
        let abort_id = ramflux_protocol::encode_base64url(blake3::hash(&preimage).as_bytes());
        ensure(abort_id != request.tx_id, Code::Replay)?;
        transitions::abort(&mut abort, &reporter.root, &pending, time.wall)?;
        let mut delete = abort.fork();
        let details = delete.detail_count(&reporter.root)?;
        transitions::reserve(&mut delete, reporter, &request.operation, time.wall, details, None)?;
        transitions::commit(&mut delete, reporter, &request.operation, time.wall)?;
        let deltas = vec![
            w::CheckpointDelta {
                kind: w::DeltaKind::Abort,
                tx_id: abort_id,
                writer_incarnation: writer.incarnation.clone(),
                clock_floor: time.wall,
                operation: None,
                rows: abort.finish(),
            },
            w::CheckpointDelta {
                kind: w::DeltaKind::Commit,
                tx_id: request.tx_id.clone(),
                writer_incarnation: writer.incarnation.clone(),
                clock_floor: time.wall,
                operation: Some(request.operation),
                rows: delete.finish(),
            },
        ];
        self.witness.append_group(AppendGroup {
            expected: &expected,
            deltas,
            root: &reporter.root,
            control: true,
            time,
            batch: Some(BatchSeed {
                request_hash: ramflux_protocol::encode_base64url(blake3::hash(bytes).as_bytes()),
            }),
        })?;
        self.fence.advancing_head();
        self.witness
            .delete_batch_retry(bytes)?
            .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))
    }
}
