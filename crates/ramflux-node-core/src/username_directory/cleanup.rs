// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed, bounded expiry work. No owner metadata is retained in relinquished-name holds.
use super::{
    CheckpointError, DirectoryAuthority, IMAGE, Result, WriterIdentity,
    image::ImagePlan,
    storage,
    transitions::{self, ensure},
};
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};
use redb::ReadableDatabase;

impl DirectoryAuthority {
    /// Process one complete due unit. The background coordinator fsyncs its primary projection
    /// before requesting another; maintenance never publishes an intermediate head.
    /// # Errors
    /// Refuses fenced/unapplied primaries and corrupt links. Returns false if nothing is due.
    pub fn cleanup_next(&mut self, writer: &WriterIdentity) -> Result<bool> {
        let time = self.witness.sample_time()?;
        self.fence.check_ready(writer, &self.head(), time)?;
        let due = {
            let tx = self.witness.db.begin_read().map_err(storage)?;
            let image = tx.open_table(IMAGE).map_err(storage)?;
            let mut range = image.range(b"due\0".as_slice()..).map_err(storage)?;
            if let Some(entry) = range.next() {
                let (key, value) = entry.map_err(storage)?;
                if key.value().starts_with(b"due\0") {
                    match w::decode::<w::Replacement>(value.value())? {
                        w::Replacement::Due { key, old: None, new: Some(row) } => Some((key, row)),
                        _ => return Err(CheckpointError::Directory(Code::DirectoryUnavailable)),
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };
        let Some((key, due)) = due else {
            return Ok(false);
        };
        let at = match &key {
            w::DueKey::Hold { at, .. }
            | w::DueKey::Operation { at, .. }
            | w::DueKey::RootWindow { at, .. }
            | w::DueKey::HomeHoldCredit { at, .. } => *at,
        };
        if time.wall < at {
            return Ok(false);
        }
        let mut plan = ImagePlan::new(&self.witness.db);
        let mut kind = w::DeltaKind::Gc;
        let root_id = match &key {
            w::DueKey::Hold { at, name, skeleton } => {
                let hold_key = w::HoldKey { name: name.clone(), skeleton: skeleton.clone() };
                let hold = plan
                    .hold(&hold_key)?
                    .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                ensure(hold.hold_until == *at && due.count == 1, Code::DirectoryUnavailable)?;
                plan.put_hold(&hold_key, None)?;
                let counter = w::CounterKey::Global { metric: w::Metric::HeldNames };
                debit(&mut plan, &counter, 1)?;
                plan.put_due(&key, None)?;
                super::transport::digest(&hold_key)?
            }
            w::DueKey::Operation { at, root, operation_id, phase } => {
                let op_key =
                    w::OperationKey { root: root.clone(), operation_id: operation_id.clone() };
                let row = plan
                    .operation(&op_key)?
                    .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                match phase {
                    w::DuePhase::Reservation => {
                        ensure(
                            row.reservation_expires_at == *at
                                && row.state == w::ReceiptState::Reserved,
                            Code::DirectoryUnavailable,
                        )?;
                        transitions::abort(&mut plan, root, operation_id, time.wall)?;
                        kind = w::DeltaKind::Expire;
                    }
                    w::DuePhase::Detail => {
                        ensure(
                            row.retain_until == Some(*at) && row.state != w::ReceiptState::Reserved,
                            Code::DirectoryUnavailable,
                        )?;
                        let owner = plan
                            .owner(operation_id)?
                            .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                        ensure(
                            owner.root == *root && owner.operation_hash == row.operation_hash,
                            Code::DirectoryUnavailable,
                        )?;
                        let root_row = plan
                            .root(root)?
                            .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                        plan.put_operation(&op_key, None)?;
                        plan.put_owner(operation_id, None)?;
                        plan.put_due(&key, None)?;
                        transitions::bump(
                            &mut plan,
                            &root_row.node,
                            w::Metric::OperationDetails,
                            -1,
                        )?;
                    }
                }
                root.clone()
            }
            w::DueKey::RootWindow { root, .. } => {
                let mut row = plan
                    .root(root)?
                    .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                transitions::prune_window(&mut plan, root, &mut row, time.wall)?;
                plan.put_root(root, Some(row))?;
                root.clone()
            }
            w::DueKey::HomeHoldCredit { home, .. } => {
                debit(
                    &mut plan,
                    &w::CounterKey::Home { home: home.clone(), metric: w::Metric::HeldNames },
                    due.count,
                )?;
                plan.put_due(&key, None)?;
                super::transport::digest(&key)?
            }
        };
        let delta = w::CheckpointDelta {
            kind,
            tx_id: super::fence::random_id()?,
            writer_incarnation: writer.incarnation.clone(),
            clock_floor: time.wall,
            operation: None,
            rows: plan.finish(),
        };
        ensure(!delta.rows.is_empty(), Code::DirectoryUnavailable)?;
        self.witness.append_at(&self.head(), delta, &root_id, true, time)?;
        self.fence.advancing_head();
        Ok(true)
    }
}

fn debit(plan: &mut ImagePlan<'_>, key: &w::CounterKey, amount: u64) -> Result<()> {
    let old = plan.counter(key)?.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
    let value = old
        .value
        .checked_sub(amount)
        .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
    plan.put_counter(key, Some(w::CounterRow { value }))
}
