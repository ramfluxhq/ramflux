// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! State transitions derived inside the witness from signatures and its own authority image.
use super::{
    CheckpointError, Result, VerifiedReporter,
    image::{ImagePlan, skeleton},
};
use ramflux_crypto::username_directory as crypto;
use ramflux_protocol::username_directory::{self as w, Action, DirectoryCode as Code};

pub(super) const HOLD_SECONDS: u64 = 2_592_000;
const CHANGE_MIN_SECONDS: u64 = 86_400;
pub(super) const DETAIL_SECONDS: u64 = 86_400;

pub(super) fn ensure(value: bool, code: Code) -> Result<()> {
    if value { Ok(()) } else { Err(CheckpointError::Directory(code)) }
}

pub(super) fn after(time: u64, delta: u64) -> Result<u64> {
    time.checked_add(delta)
        .filter(|v| *v <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
        .ok_or(CheckpointError::Directory(Code::ClockUnsafe))
}

fn empty_root(home: &str) -> w::RootRow {
    w::RootRow {
        epoch: 0,
        name: None,
        node: home.into(),
        discoverable: true,
        deleted: false,
        profile: w::ProfileRef { version: 0, epoch: 0, hash: None },
        binding_hash: None,
        current_binding: None,
        receipt_decision: None,
        last_operation_id: None,
        last_operation_hash: None,
        pending_operation_id: None,
        changes: Vec::new(),
        hold_deadlines: Vec::new(),
    }
}

pub(super) fn operation_key(op: &w::UsernameOperation) -> w::OperationKey {
    w::OperationKey {
        root: op.body.principal_commitment.clone(),
        operation_id: op.body.operation_id.clone(),
    }
}

fn expectation(
    root: &w::RootRow,
    op: &w::UsernameOperation,
    reporter: &VerifiedReporter,
    now: u64,
) -> Result<()> {
    let body = &op.body;
    ensure(!root.deleted, Code::AccountDeleted)?;
    ensure(body.principal_commitment == reporter.root, Code::OwnershipMismatch)?;
    crypto::verify_operation(&reporter.master, op)?;
    ensure(body.issued_at <= now && now < body.expires_at, Code::Replay)?;
    ensure(root.epoch == body.expected_epoch, Code::StaleEpoch)?;
    ensure(root.profile == body.expected_profile, Code::StaleProfile)?;
    ensure(root.name == body.old_name, Code::StaleEpoch)?;
    ensure(root.node == reporter.home || body.action == Action::MoveHome, Code::OwnershipMismatch)?;
    if body.action == Action::MoveHome {
        ensure(
            root.node != reporter.home
                && reporter.history.records().iter().any(|e| e.record.home().0 == root.node),
            Code::MigrationRequired,
        )?;
    }
    if let Some(binding) = &body.binding {
        ensure(binding.body.node == reporter.home, Code::OwnershipMismatch)?;
    }
    ensure(body.profile.version == 2, Code::InvalidProfile)?;
    match body.action {
        Action::ProfileUpdate => {
            ensure(body.profile.epoch > root.profile.epoch, Code::StaleProfile)?;
        }
        _ if root.profile.version == 2 => ensure(body.profile == root.profile, Code::StaleProfile)?,
        _ => ensure(body.profile.epoch > 0, Code::InvalidProfile)?,
    }
    Ok(())
}

pub(super) fn bump(
    plan: &mut ImagePlan<'_>,
    home: &str,
    metric: w::Metric,
    amount: i64,
) -> Result<()> {
    for key in [w::CounterKey::Global { metric }, w::CounterKey::Home { home: home.into(), metric }]
    {
        let old = plan.counter(&key)?.map_or(0, |row| row.value);
        let value = old
            .checked_add_signed(amount)
            .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
        let row = w::CounterRow { value };
        w::encode(&w::Replacement::Counter { key: key.clone(), old: None, new: Some(row.clone()) })
            .map_err(|_| CheckpointError::Directory(Code::Capacity))?;
        plan.put_counter(&key, Some(row))?;
    }
    Ok(())
}

fn current_window(root: &w::RootRow) -> Result<Option<u64>> {
    let change = root.changes.first().map(|time| after(*time, HOLD_SECONDS)).transpose()?;
    Ok(change.into_iter().chain(root.hold_deadlines.first().copied()).min())
}

pub(super) fn prune_window(
    plan: &mut ImagePlan<'_>,
    key: &str,
    root: &mut w::RootRow,
    now: u64,
) -> Result<()> {
    let before = current_window(root)?;
    root.changes.retain(|time| now.saturating_sub(*time) < HOLD_SECONDS);
    root.hold_deadlines.retain(|deadline| now < *deadline);
    window_due(plan, key, before, current_window(root)?)
}

fn window_due(
    plan: &mut ImagePlan<'_>,
    root: &str,
    old: Option<u64>,
    new: Option<u64>,
) -> Result<()> {
    if old != new {
        if let Some(at) = old {
            plan.put_due(&w::DueKey::RootWindow { at, root: root.into() }, None)?;
        }
        if let Some(at) = new {
            plan.put_due(
                &w::DueKey::RootWindow { at, root: root.into() },
                Some(w::DueRow { count: 1 }),
            )?;
        }
    }
    Ok(())
}

fn change_allowed(root: &w::RootRow, action: Action, now: u64) -> Result<()> {
    if matches!(action, Action::Rename | Action::Release) {
        ensure(
            root.changes.len() < 3
                && root.hold_deadlines.len() < 3
                && root
                    .changes
                    .last()
                    .is_none_or(|last| now.saturating_sub(*last) >= CHANGE_MIN_SECONDS),
            Code::RateLimited,
        )?;
    }
    Ok(())
}

fn reserve_keys(
    plan: &mut ImagePlan<'_>,
    root: &w::RootRow,
    op: &w::UsernameOperation,
    held_skeleton: Option<&w::HoldKey>,
) -> Result<()> {
    let Some(binding) = &op.body.binding else {
        return Ok(());
    };
    let name = &binding.body.name;
    if root.name.as_ref() == Some(name) {
        return Ok(());
    }
    let key = skeleton(name)?;
    ensure(
        root.name.as_ref().map(|n| skeleton(n)).transpose()?.as_ref() != Some(&key),
        Code::InvalidUsername,
    )?;
    ensure(held_skeleton.is_none(), Code::UsernameHeld)?;
    ensure(plan.name(name)?.is_none() && plan.skeleton(&key)?.is_none(), Code::UsernameTaken)?;
    plan.put_name(
        name,
        Some(w::NameRow {
            root: op.body.principal_commitment.clone(),
            state: w::IndexState::Reserved,
            operation_id: Some(op.body.operation_id.clone()),
        }),
    )?;
    plan.put_skeleton(
        &key,
        Some(w::SkeletonRow {
            name: name.clone(),
            root: op.body.principal_commitment.clone(),
            state: w::IndexState::Reserved,
            operation_id: Some(op.body.operation_id.clone()),
        }),
    )
}

pub(super) fn reserve(
    plan: &mut ImagePlan<'_>,
    reporter: &VerifiedReporter,
    op: &w::UsernameOperation,
    now: u64,
    detail_count: u64,
    held_skeleton: Option<&w::HoldKey>,
) -> Result<()> {
    let key = &reporter.root;
    let mut root = if let Some(root) = plan.root(key)? {
        root
    } else {
        ensure(
            matches!(op.body.action, Action::Claim | Action::ProfileUpdate),
            Code::InvalidUsername,
        )?;
        bump(plan, &reporter.home, w::Metric::RootSlots, 1)?;
        empty_root(&reporter.home)
    };
    expectation(&root, op, reporter, now)?;
    ensure(root.pending_operation_id.is_none(), Code::OperationPending)?;
    ensure(detail_count < if op.body.action == Action::Delete { 8 } else { 7 }, Code::Capacity)?;
    ensure(plan.owner(&op.body.operation_id)?.is_none(), Code::Replay)?;
    prune_window(plan, key, &mut root, now)?;
    change_allowed(&root, op.body.action, now)?;
    reserve_keys(plan, &root, op, held_skeleton)?;
    root.pending_operation_id = Some(op.body.operation_id.clone());
    let hash = crypto::operation_hash(op)?;
    plan.put_root(key, Some(root))?;
    plan.put_operation(
        &operation_key(op),
        Some(w::OperationRow {
            operation: op.clone(),
            operation_hash: hash.clone(),
            state: w::ReceiptState::Reserved,
            reserved_at: now,
            reservation_expires_at: after(now, 120)?,
            finished_at: None,
            retain_until: None,
        }),
    )?;
    plan.put_owner(
        &op.body.operation_id,
        Some(w::OperationOwnerRow { root: key.clone(), operation_hash: hash }),
    )?;
    plan.put_due(
        &w::DueKey::Operation {
            at: after(now, 120)?,
            root: key.clone(),
            operation_id: op.body.operation_id.clone(),
            phase: w::DuePhase::Reservation,
        },
        Some(w::DueRow { count: 1 }),
    )?;
    bump(plan, &reporter.home, w::Metric::PendingOperations, 1)?;
    bump(plan, &reporter.home, w::Metric::OperationDetails, 1)
}

fn terminal(
    plan: &mut ImagePlan<'_>,
    row: &mut w::OperationRow,
    now: u64,
    state: w::ReceiptState,
    home: &str,
) -> Result<()> {
    let op = &row.operation.body;
    plan.put_due(
        &w::DueKey::Operation {
            at: row.reservation_expires_at,
            root: op.principal_commitment.clone(),
            operation_id: op.operation_id.clone(),
            phase: w::DuePhase::Reservation,
        },
        None,
    )?;
    let retain = after(now, DETAIL_SECONDS)?;
    plan.put_due(
        &w::DueKey::Operation {
            at: retain,
            root: op.principal_commitment.clone(),
            operation_id: op.operation_id.clone(),
            phase: w::DuePhase::Detail,
        },
        Some(w::DueRow { count: 1 }),
    )?;
    row.state = state;
    row.finished_at = Some(now);
    row.retain_until = Some(retain);
    bump(plan, home, w::Metric::PendingOperations, -1)
}

fn relinquish(plan: &mut ImagePlan<'_>, root: &mut w::RootRow, key: &str, now: u64) -> Result<()> {
    let Some(name) = &root.name else {
        return Ok(());
    };
    let skel = skeleton(name)?;
    let hold_until = after(now, HOLD_SECONDS)?;
    let hold_key = w::HoldKey { name: name.clone(), skeleton: skel.clone() };
    ensure(plan.hold(&hold_key)?.is_none(), Code::DirectoryUnavailable)?;
    let active = plan.name(name)?.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
    let comparison =
        plan.skeleton(&skel)?.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
    ensure(
        active.root == key
            && comparison.root == key
            && active.state == w::IndexState::Active
            && comparison.state == w::IndexState::Active
            && comparison.name == *name,
        Code::DirectoryUnavailable,
    )?;
    plan.put_name(name, None)?;
    plan.put_skeleton(&skel, None)?;
    plan.put_hold(&hold_key, Some(w::HoldRow { release_at: now, hold_until }))?;
    plan.put_due(
        &w::DueKey::Hold { at: hold_until, name: name.clone(), skeleton: skel },
        Some(w::DueRow { count: 1 }),
    )?;
    let credit = w::DueKey::HomeHoldCredit { at: hold_until, home: root.node.clone() };
    let count = plan
        .due(&credit)?
        .map_or(0, |v| v.count)
        .checked_add(1)
        .ok_or(CheckpointError::Directory(Code::Capacity))?;
    plan.put_due(&credit, Some(w::DueRow { count }))?;
    bump(plan, &root.node, w::Metric::HeldNames, 1)?;
    bump(plan, &root.node, w::Metric::ActiveNames, -1)?;
    root.hold_deadlines.push(hold_until);
    Ok(())
}

pub(super) fn commit(
    plan: &mut ImagePlan<'_>,
    reporter: &VerifiedReporter,
    op: &w::UsernameOperation,
    now: u64,
) -> Result<()> {
    let key = &reporter.root;
    let mut root = plan.root(key)?.ok_or(CheckpointError::Directory(Code::StaleEpoch))?;
    expectation(&root, op, reporter, now)?;
    ensure(
        root.pending_operation_id.as_ref() == Some(&op.body.operation_id),
        Code::OperationPending,
    )?;
    let mut row = plan
        .operation(&operation_key(op))?
        .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
    ensure(
        row.operation == *op && row.operation_hash == crypto::operation_hash(op)?,
        Code::Replay,
    )?;
    ensure(
        row.state == w::ReceiptState::Reserved && now < row.reservation_expires_at,
        Code::Replay,
    )?;
    prune_window(plan, key, &mut root, now)?;
    let window = current_window(&root)?;
    change_allowed(&root, op.body.action, now)?;
    let next_name = op.body.binding.as_ref().map(|b| b.body.name.clone());
    if root.name != next_name {
        relinquish(plan, &mut root, key, now)?;
        if let Some(name) = &next_name {
            let skel = skeleton(name)?;
            let reserved =
                plan.name(name)?.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
            let comparison = plan
                .skeleton(&skel)?
                .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
            ensure(
                reserved.root == *key
                    && comparison.root == *key
                    && comparison.name == *name
                    && reserved.operation_id.as_ref() == Some(&op.body.operation_id)
                    && comparison.operation_id == reserved.operation_id,
                Code::OwnershipMismatch,
            )?;
            plan.put_name(
                name,
                Some(w::NameRow {
                    root: key.clone(),
                    state: w::IndexState::Active,
                    operation_id: None,
                }),
            )?;
            plan.put_skeleton(
                &skel,
                Some(w::SkeletonRow {
                    name: name.clone(),
                    root: key.clone(),
                    state: w::IndexState::Active,
                    operation_id: None,
                }),
            )?;
            bump(plan, &root.node, w::Metric::ActiveNames, 1)?;
        }
    }
    if matches!(op.body.action, Action::Rename | Action::Release) {
        root.changes.push(now);
    }
    if op.body.action == Action::MoveHome {
        transfer_home(plan, &root, &reporter.home, key)?;
        root.node.clone_from(&reporter.home);
    }
    root.epoch = op.body.next_epoch;
    root.profile = op.body.profile.clone();
    root.name = next_name;
    root.current_binding.clone_from(&op.body.binding);
    root.binding_hash = root.current_binding.as_ref().map(crypto::binding_hash).transpose()?;
    root.receipt_decision = Some(w::ReceiptDecision { committed_at: now });
    root.last_operation_id = Some(op.body.operation_id.clone());
    root.last_operation_hash = Some(row.operation_hash.clone());
    root.pending_operation_id = None;
    root.discoverable = op.body.discoverable;
    root.deleted = op.body.action == Action::Delete;
    window_due(plan, key, window, current_window(&root)?)?;
    terminal(plan, &mut row, now, w::ReceiptState::Committed, &root.node)?;
    plan.put_operation(&operation_key(op), Some(row))?;
    plan.put_root(key, Some(root))
}

fn transfer_home(
    plan: &mut ImagePlan<'_>,
    root: &w::RootRow,
    home: &str,
    root_key: &str,
) -> Result<()> {
    let details = plan.detail_count(root_key)?;
    // Historical hold credits remain with their original reporting home.
    for (metric, amount) in [
        (w::Metric::RootSlots, 1_i64),
        (w::Metric::ActiveNames, i64::from(root.name.is_some())),
        (w::Metric::PendingOperations, 1),
        (
            w::Metric::OperationDetails,
            i64::try_from(details).map_err(|_| CheckpointError::Directory(Code::Capacity))?,
        ),
    ] {
        if amount == 0 {
            continue;
        }
        for (node, delta) in [(root.node.as_str(), -amount), (home, amount)] {
            let key = w::CounterKey::Home { home: node.to_owned(), metric };
            let old = plan.counter(&key)?.map_or(0, |v| v.value);
            let value = old
                .checked_add_signed(delta)
                .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
            let row = w::CounterRow { value };
            w::encode(&w::Replacement::Counter {
                key: key.clone(),
                old: None,
                new: Some(row.clone()),
            })
            .map_err(|_| CheckpointError::Directory(Code::Capacity))?;
            plan.put_counter(&key, Some(row))?;
        }
    }
    Ok(())
}

pub(super) fn abort(
    plan: &mut ImagePlan<'_>,
    root_key: &String,
    operation_id: &String,
    now: u64,
) -> Result<()> {
    let mut root =
        plan.root(root_key)?.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
    let key = w::OperationKey { root: root_key.clone(), operation_id: operation_id.clone() };
    let mut row =
        plan.operation(&key)?.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
    ensure(
        row.state == w::ReceiptState::Reserved
            && root.pending_operation_id.as_ref() == Some(operation_id),
        Code::OperationPending,
    )?;
    if let Some(binding) = &row.operation.body.binding
        && root.name.as_ref() != Some(&binding.body.name)
    {
        let name = &binding.body.name;
        let skel = skeleton(name)?;
        let candidate =
            plan.name(name)?.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
        let comparison =
            plan.skeleton(&skel)?.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
        ensure(
            candidate.root == *root_key
                && comparison.root == *root_key
                && candidate.operation_id.as_ref() == Some(operation_id)
                && comparison.operation_id == candidate.operation_id,
            Code::DirectoryUnavailable,
        )?;
        plan.put_name(name, None)?;
        plan.put_skeleton(&skel, None)?;
    }
    root.pending_operation_id = None;
    terminal(plan, &mut row, now, w::ReceiptState::Aborted, &root.node)?;
    plan.put_operation(&key, Some(row))?;
    plan.put_root(root_key, Some(root))
}
