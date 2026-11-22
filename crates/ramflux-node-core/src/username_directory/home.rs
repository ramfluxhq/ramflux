// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary home durability: signed intent/suppression, prepared bytes, then exact committed state.
use super::{
    CenterPin, CheckpointError, Result, canonical, fixed, require, storage,
    transitions::{after, ensure},
};
use ed25519_dalek::VerifyingKey;
use ramflux_crypto::username_directory as crypto;
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
mod publication;
mod recovery;
pub use publication::*;

const ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("username_home_roots");
const OUTBOX: TableDefinition<&str, &[u8]> = TableDefinition::new("username_home_outbox");
const DUE: TableDefinition<(u64, &str), u8> = TableDefinition::new("username_home_due");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("username_home_meta");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeIntent {
    pub operation: w::UsernameOperation,
    pub profile: w::SignedIdentityProfileV2,
    pub reservation: Option<w::DirectoryReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeProfileView {
    pub operation: w::UsernameOperation,
    pub binding: Option<w::UsernameBinding>,
    pub profile: w::SignedIdentityProfileV2,
    pub receipt: w::DirectoryReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HomeRoot {
    directory_epoch: u64,
    binding_hash: Option<String>,
    profile_floor: w::ProfileRef,
    deleted: bool,
    suppressed: bool,
    committed: Option<HomeProfileView>,
    intent: Option<HomeIntent>,
}

impl Default for HomeRoot {
    fn default() -> Self {
        Self {
            directory_epoch: 0,
            binding_hash: None,
            profile_floor: w::ProfileRef { version: 0, epoch: 0, hash: None },
            deleted: false,
            suppressed: false,
            committed: None,
            intent: None,
        }
    }
}

/// Consumed by one home decision. Transport must supply this only from a fresh, authenticated
/// exchange with the provisioned centre; a receipt alone is not currentness evidence.
pub struct LiveHomeRevalidation {
    result: w::HomeRevalidateResult,
}

impl LiveHomeRevalidation {
    fn into_result(self) -> w::HomeRevalidateResult {
        self.result
    }

    /// Called by the pinned TLS exchange adapter, never on an offline/archive/user payload.
    /// # Errors
    /// Refuses wrong root/nonce, stale wrappers and substituted or expired inner receipts.
    pub fn from_authenticated_reply(
        pin: &CenterPin,
        request: &w::HomeRevalidateRequest,
        result: w::HomeRevalidateResult,
        now: u64,
    ) -> Result<Self> {
        w::encode(&result)?;
        ensure(
            result.current_receipt.as_ref().map_or(0, |r| r.body.epoch)
                >= request.known_directory_epoch,
            Code::ProfileRollback,
        )?;
        ensure(
            result.root == request.root
                && result.nonce == request.nonce
                && result.issued_at <= now
                && now < result.expires_at
                && result.expires_at <= after(result.issued_at, 10)?,
            Code::DirectoryUnavailable,
        )?;
        let key = ramflux_crypto::verifying_key_from_base64url(&pin.public_key)
            .map_err(|_| CheckpointError::Directory(Code::SignatureInvalid))?;
        for receipt in [&result.current_receipt, &result.pending_receipt].into_iter().flatten() {
            crypto::verify_receipt(&key, &pin.id, receipt)?;
            ensure(
                receipt.body.principal_commitment == request.root
                    && receipt.body.committed_at <= now
                    && now < receipt.body.expires_at,
                Code::DirectoryUnavailable,
            )?;
            if receipt.body.state != w::ReceiptState::Reserved {
                ensure(receipt.body.expires_at <= after(now, 60)?, Code::DirectoryUnavailable)?;
            }
        }
        Ok(Self { result })
    }
}

pub struct HomeDirectory {
    db: redb::Database,
    home: String,
    center: CenterPin,
    serving: std::sync::Mutex<()>,
}

impl HomeDirectory {
    /// Local metadata only; caller must already have verified current native home authority.
    /// # Errors
    /// Refuses malformed roots, capacity exhaustion and unavailable durable storage.
    pub fn enrol(&self, root: &str) -> Result<()> {
        fixed(root)?;
        let _serving = self.publication_guard()?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        let mut roots = tx.open_table(ROOTS).map_err(storage)?;
        if roots.get(root).map_err(storage)?.is_some() {
            return Ok(());
        }
        ensure(roots.len().map_err(storage)? < 100_000, Code::Capacity)?;
        put_root(&mut roots, root, &HomeRoot::default())?;
        drop(roots);
        tx.commit().map_err(storage)?;
        Ok(())
    }

    /// # Errors
    /// Refuses corrupt/unavailable local floors; this is never positive currentness evidence.
    pub fn directory_epoch(&self, root: &str) -> Result<u64> {
        fixed(root)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(ROOTS).map_err(storage)?;
        Ok(read_root(&table, root)?.map_or(0, |state| state.directory_epoch))
    }

    /// Bounded local page for locator renewal. Tombstones still advance the scan cursor.
    /// # Errors
    /// Refuses malformed cursors/limits and corrupt/unavailable durable metadata.
    pub fn reporting_roots(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<String>, Option<String>)> {
        require((1..=128).contains(&limit), "home_page")?;
        if let Some(after) = after {
            fixed(after)?;
        }
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(ROOTS).map_err(storage)?;
        let mut rows = Vec::new();
        let mut last = None;
        let mut scanned = 0;
        for item in table.range(after.unwrap_or("")..).map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            if after == Some(key.value()) {
                continue;
            }
            let state: HomeRoot = serde_json::from_slice(value.value())?;
            last = Some(key.value().to_owned());
            scanned += 1;
            if !state.deleted {
                rows.push(key.value().to_owned());
            }
            if scanned == limit {
                break;
            }
        }
        Ok((rows, if scanned == limit { last } else { None }))
    }
    #[must_use]
    pub fn center_pin(&self) -> &CenterPin {
        &self.center
    }
    /// Explicit operator initialization; normal startup uses open and never recreates anchors.
    /// # Errors
    /// Refuses existing paths, invalid provisioning and unavailable durable storage.
    pub fn initialize(path: &Path, home: &str, center: CenterPin) -> Result<Self> {
        center.validate()?;
        super::config::validate_node(home)?;
        super::reserve_file(path)?;
        crate::durability_io::sync_dir(
            path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")),
        )?;
        let db = redb::Database::create(path).map_err(storage)?;
        let mut tx = db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        tx.open_table(ROOTS).map_err(storage)?;
        tx.open_table(OUTBOX).map_err(storage)?;
        tx.open_table(DUE).map_err(storage)?;
        tx.open_table(META)
            .map_err(storage)?
            .insert("identity", canonical(&(home, &center.id, center.generation))?.as_slice())
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(Self { db, home: home.into(), center, serving: std::sync::Mutex::new(()) })
    }

    /// # Errors
    /// Refuses absent/foreign/corrupt stores. Positive serving still requires live revalidation.
    pub fn open(path: &Path, home: &str, center: CenterPin) -> Result<Self> {
        center.validate()?;
        super::config::validate_node(home)?;
        require(path.is_file(), "home_missing")?;
        let db = redb::Database::open(path).map_err(storage)?;
        {
            let tx = db.begin_read().map_err(storage)?;
            tx.open_table(ROOTS).map_err(storage)?;
            tx.open_table(OUTBOX).map_err(storage)?;
            tx.open_table(DUE).map_err(storage)?;
            let table = tx.open_table(META).map_err(storage)?;
            let row = table
                .get("identity")
                .map_err(storage)?
                .ok_or(CheckpointError::Refused("home_missing"))?;
            require(
                row.value() == canonical(&(home, &center.id, center.generation))?,
                "home_identity",
            )?;
        }
        Ok(Self { db, home: home.into(), center, serving: std::sync::Mutex::new(()) })
    }

    /// H1 atomically stores the exact intent, candidate bytes, restrictive suppression and outbox.
    /// Caller must already have authenticated current native account/branch authority.
    /// # Errors
    /// Refuses stale floors, concurrent edits, invalid signatures and avatar candidates.
    pub fn begin(
        &self,
        master: &VerifyingKey,
        operation: w::UsernameOperation,
        profile: Option<w::SignedIdentityProfileV2>,
        now: u64,
    ) -> Result<()> {
        let _serving = self.publication_guard()?;
        crypto::verify_operation(master, &operation)?;
        ensure(operation.body.issued_at <= now && now < operation.body.expires_at, Code::Replay)?;
        let root = operation.body.principal_commitment.clone();
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        let mut table = tx.open_table(ROOTS).map_err(storage)?;
        let mut state = read_root(&table, &root)?.unwrap_or_default();
        if let Some(intent) = &state.intent {
            if intent.operation == operation {
                if let Some(profile) = profile {
                    ensure(profile == intent.profile, Code::Replay)?;
                }
                return Ok(());
            }
            ensure(operation.body.action == w::Action::Delete, Code::OperationPending)?;
            // Preserve the uncertain predecessor's exact bytes for fresh-tuple base repair.
            let mut meta = tx.open_table(META).map_err(storage)?;
            let key = format!("preempted:{root}");
            ensure(meta.get(key.as_str()).map_err(storage)?.is_none(), Code::OperationPending)?;
            meta.insert(key.as_str(), canonical(intent)?.as_slice()).map_err(storage)?;
        }
        ensure(!state.deleted, Code::AccountDeleted)?;
        ensure(state.directory_epoch == operation.body.expected_epoch, Code::StaleEpoch)?;
        ensure(state.profile_floor == operation.body.expected_profile, Code::StaleProfile)?;
        if let Some(binding) = &operation.body.binding {
            ensure(binding.body.node == self.home, Code::OwnershipMismatch)?;
        }
        let profile = profile
            .or_else(|| state.committed.as_ref().map(|c| c.profile.clone()))
            .ok_or(CheckpointError::Directory(Code::InvalidProfile))?;
        verify_candidate(master, &operation, &profile)?;
        state.suppressed |= restrictive(&operation);
        state.intent = Some(HomeIntent { operation, profile, reservation: None });
        if table.get(root.as_str()).map_err(storage)?.is_none() {
            ensure(table.len().map_err(storage)? < 100_000, Code::Capacity)?;
        }
        put_root(&mut table, &root, &state)?;
        if let Some(old) = tx
            .open_table(OUTBOX)
            .map_err(storage)?
            .insert(root.as_str(), canonical(&now)?.as_slice())
            .map_err(storage)?
        {
            let at: u64 = serde_json::from_slice(old.value())?;
            ensure(
                tx.open_table(DUE)
                    .map_err(storage)?
                    .remove((at, root.as_str()))
                    .map_err(storage)?
                    .is_some(),
                Code::DirectoryUnavailable,
            )?;
        }
        tx.open_table(DUE).map_err(storage)?.insert((now, root.as_str()), 1).map_err(storage)?;
        drop(table);
        tx.commit().map_err(storage)?;
        Ok(())
    }

    /// H2 publishes no new profile bytes: it persists exact preparation and matching reservation.
    /// # Errors
    /// Refuses stale/foreign reservations, mismatched operation/profile tuples and late ACKs.
    pub fn prepare(&self, root: &str, receipt: w::DirectoryReceipt, now: u64) -> Result<()> {
        verify_receipt(&self.center, &receipt, now)?;
        ensure(receipt.body.state == w::ReceiptState::Reserved, Code::OperationPending)?;
        self.update(root, |state| {
            let intent = state.intent.as_mut().ok_or(CheckpointError::Directory(Code::Replay))?;
            matches_intent(intent, &receipt)?;
            ensure(
                state.directory_epoch == intent.operation.body.expected_epoch
                    && state.profile_floor == intent.operation.body.expected_profile,
                Code::StaleEpoch,
            )?;
            intent.reservation = Some(receipt);
            Ok(())
        })
    }

    /// H3 atomically commits exact prepared bytes/receipt/floors, clears outbox and sets visibility.
    /// A committed receipt by itself never authorizes this transition.
    /// # Errors
    /// Refuses stale wrappers, superseded operations, missing bytes and profile/directory rollback.
    pub fn finalize(
        &self,
        root: &str,
        live: LiveHomeRevalidation,
        now: u64,
    ) -> Result<HomeProfileView> {
        let live = live.into_result();
        ensure(live.issued_at <= now && now < live.expires_at, Code::DirectoryUnavailable)?;
        ensure(live.root == root, Code::OwnershipMismatch)?;
        let current = live
            .current_receipt
            .as_ref()
            .ok_or(CheckpointError::Directory(Code::OperationPending))?;
        ensure(current.body.state == w::ReceiptState::Committed, Code::OperationPending)?;
        let mut result = None;
        self.update(root, |state| {
            observe(state, &live)?;
            if let Some(intent) = &state.intent {
                matches_intent(intent, current)?;
                // Normal coordination persists H2 before requesting commit. After home rollback,
                // this fresh exact committed tuple also authorizes recovery of retained bytes;
                // it does not replay an expired operation as a new mutation.
                ensure(live.current_binding == intent.operation.body.binding, Code::StaleEpoch)?;
                let committed = HomeProfileView {
                    operation: intent.operation.clone(),
                    binding: live.current_binding.clone(),
                    profile: intent.profile.clone(),
                    receipt: current.clone(),
                };
                state.deleted |= intent.operation.body.action == w::Action::Delete;
                state.suppressed = !live.lookup_allowed;
                state.committed = Some(committed.clone());
                state.intent = None;
                result = Some(committed);
            } else {
                let committed = state
                    .committed
                    .as_ref()
                    .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                ensure(
                    committed.receipt.body.operation_id == current.body.operation_id
                        && committed.receipt.body.operation_hash == current.body.operation_hash
                        && committed.binding == live.current_binding,
                    Code::StaleEpoch,
                )?;
                state.suppressed = !live.lookup_allowed;
                let mut current_view = committed.clone();
                current_view.receipt = current.clone();
                result = Some(current_view);
            }
            Ok(())
        })?;
        result.ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))
    }

    /// Product profile read: consume one current-home wrapper, persist restrictive floors first,
    /// and expose only the bytes matching its current signed centre commitment.
    /// # Errors
    /// Refuses unavailable/missing current bytes, hidden state and every rollback/substitution.
    pub fn visible_profile(
        &self,
        root: &str,
        live: LiveHomeRevalidation,
        master: &VerifyingKey,
        now: u64,
    ) -> Result<HomeProfileView> {
        self.read_profile(root, live, master, now, true)?
            .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))
    }

    /// Authenticated owner view, including hidden or deleted state. No other caller may use it.
    /// Empty is authoritative only after observing a fresh empty centre wrapper.
    /// # Errors
    /// Refuses missing bytes, substitutions, stale wrappers and durable floor conflicts.
    pub fn owner_profile(
        &self,
        root: &str,
        live: LiveHomeRevalidation,
        master: &VerifyingKey,
        now: u64,
    ) -> Result<Option<HomeProfileView>> {
        self.read_profile(root, live, master, now, false)
    }

    fn read_profile(
        &self,
        root: &str,
        live: LiveHomeRevalidation,
        master: &VerifyingKey,
        now: u64,
        require_lookup: bool,
    ) -> Result<Option<HomeProfileView>> {
        let live = live.into_result();
        ensure(live.issued_at <= now && now < live.expires_at, Code::DirectoryUnavailable)?;
        ensure(live.root == root, Code::OwnershipMismatch)?;
        let mut view = None;
        let mut refused = None;
        self.update(root, |state| {
            observe(state, &live)?;
            let allowed =
                !require_lookup || live.lookup_allowed && !state.deleted && !state.suppressed;
            if !allowed {
                refused = Some(Code::NotFound);
                return Ok(());
            }
            let Some(committed) = &state.committed else {
                if !require_lookup && live.current_receipt.is_none() {
                    return Ok(());
                }
                refused = Some(Code::DirectoryUnavailable);
                return Ok(());
            };
            let Some(current) = &live.current_receipt else {
                refused = Some(Code::DirectoryUnavailable);
                return Ok(());
            };
            if committed.binding != live.current_binding
                || committed.receipt.body.epoch != current.body.epoch
                || committed.receipt.body.profile != current.body.profile
            {
                state.suppressed = true;
                refused = Some(Code::DirectoryUnavailable);
                return Ok(());
            }
            if crypto::verify_profile(master, &committed.profile).is_err() {
                state.suppressed = true;
                refused = Some(Code::SignatureInvalid);
                return Ok(());
            }
            if crypto::verify_operation(master, &committed.operation).is_err()
                || committed.operation.body.principal_commitment != root
                || committed.operation.body.binding != committed.binding
                || committed.operation.body.profile != current.body.profile
                || committed.operation.body.operation_id != current.body.operation_id
                || crypto::operation_hash(&committed.operation)? != current.body.operation_hash
            {
                state.suppressed = true;
                refused = Some(Code::ProfileEquivocation);
                return Ok(());
            }
            if current.body.profile.hash.as_ref()
                != Some(&crypto::profile_hash_v2(&committed.profile)?)
            {
                state.suppressed = true;
                refused = Some(Code::ProfileEquivocation);
                return Ok(());
            }
            if let Some(binding) = &committed.binding {
                crypto::verify_binding(master, binding)?;
            }
            let mut current_view = committed.clone();
            current_view.receipt = current.clone();
            view = Some(current_view);
            Ok(())
        })?;
        if let Some(code) = refused {
            return Err(CheckpointError::Directory(code));
        }
        Ok(view)
    }

    /// # Errors
    /// Refuses unsupported roots and malformed/corrupt durable intents.
    pub fn intent(&self, root: &str) -> Result<Option<HomeIntent>> {
        fixed(root)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(ROOTS).map_err(storage)?;
        Ok(read_root(&table, root)?.and_then(|row| row.intent))
    }

    /// Bounded indexed work source; the background worker, not an API caller, drives retries.
    /// # Errors
    /// Refuses oversized pages and unavailable storage.
    pub fn pending_roots(&self, after: Option<&str>, limit: usize) -> Result<Vec<String>> {
        ensure((1..=128).contains(&limit), Code::Capacity)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(OUTBOX).map_err(storage)?;
        let mut roots = Vec::new();
        for entry in table
            .range(after.unwrap_or("")..)
            .map_err(storage)?
            .take(limit + usize::from(after.is_some()))
        {
            let (key, _) = entry.map_err(storage)?;
            if Some(key.value()) != after {
                roots.push(key.value().into());
            }
            if roots.len() == limit {
                break;
            }
        }
        Ok(roots)
    }

    /// Bounded due-time index; unrelated roots are never traversed to find retry work.
    /// # Errors
    /// Refuses excessive page sizes and corrupt/unavailable storage.
    pub fn due_roots(&self, now: u64, limit: usize) -> Result<Vec<String>> {
        ensure((1..=128).contains(&limit), Code::Capacity)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(DUE).map_err(storage)?;
        let mut roots = Vec::new();
        for entry in table.range(..=(now, "~")).map_err(storage)?.take(limit) {
            let (key, _) = entry.map_err(storage)?;
            roots.push(key.value().1.to_owned());
        }
        Ok(roots)
    }

    /// # Errors
    /// Refuses missing work, clock overflow and delays beyond the 60-second reconciliation cap.
    pub fn retry_later(&self, root: &str, now: u64, delay_seconds: u64) -> Result<()> {
        self.retry_later_for(root, None, now, delay_seconds)
    }

    /// An old worker cannot postpone an operation that preempted it during network I/O.
    /// # Errors
    /// Refuses unavailable storage, malformed IDs, overflow and out-of-bound delays.
    pub fn retry_later_for(
        &self,
        root: &str,
        operation_id: Option<&str>,
        now: u64,
        delay_seconds: u64,
    ) -> Result<()> {
        ensure((1..=60).contains(&delay_seconds), Code::RateLimited)?;
        fixed(root)?;
        let next = after(now, delay_seconds)?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        if let Some(id) = operation_id {
            let roots = tx.open_table(ROOTS).map_err(storage)?;
            if !read_root(&roots, root)?
                .and_then(|state| state.intent)
                .is_some_and(|intent| intent.operation.body.operation_id == id)
            {
                return Ok(());
            }
        }
        let mut outbox = tx.open_table(OUTBOX).map_err(storage)?;
        let old: u64 = serde_json::from_slice(
            outbox
                .get(root)
                .map_err(storage)?
                .ok_or(CheckpointError::Directory(Code::NotFound))?
                .value(),
        )?;
        let mut due = tx.open_table(DUE).map_err(storage)?;
        ensure(due.remove((old, root)).map_err(storage)?.is_some(), Code::DirectoryUnavailable)?;
        due.insert((next, root), 1).map_err(storage)?;
        outbox.insert(root, canonical(&next)?.as_slice()).map_err(storage)?;
        drop(due);
        drop(outbox);
        tx.commit().map_err(storage)?;
        Ok(())
    }

    /// Discard only a definitively aborted/expired candidate, after fresh current-state proof.
    /// Timeout alone never invokes this transition or clears restrictive suppression.
    /// # Errors
    /// Refuses pending/committed operations, stale proofs and mismatched restored bytes/floors.
    pub fn discard_aborted(
        &self,
        root: &str,
        abort: Option<&w::DirectoryReceipt>,
        live: LiveHomeRevalidation,
        now: u64,
    ) -> Result<()> {
        let live = live.into_result();
        ensure(
            live.root == root
                && live.issued_at <= now
                && now < live.expires_at
                && live.pending_receipt.is_none(),
            Code::OperationPending,
        )?;
        if let Some(abort) = abort {
            verify_receipt(&self.center, abort, now)?;
        }
        self.update(root, |state| {
            let intent = state.intent.as_ref().ok_or(CheckpointError::Directory(Code::NotFound))?;
            if let Some(abort) = abort {
                ensure(abort.body.state == w::ReceiptState::Aborted, Code::OperationPending)?;
                matches_intent(intent, abort)?;
            } else {
                ensure(now >= intent.operation.body.expires_at, Code::OperationPending)?;
            }
            ensure(
                live.current_receipt.as_ref().map_or(0, |r| r.body.epoch)
                    == intent.operation.body.expected_epoch,
                Code::StaleEpoch,
            )?;
            observe(state, &live)?;
            if let Some(committed) = &state.committed {
                ensure(
                    live.current_binding == committed.binding
                        && live
                            .current_receipt
                            .as_ref()
                            .is_some_and(|r| r.body.profile == committed.receipt.body.profile),
                    Code::DirectoryUnavailable,
                )?;
            } else {
                ensure(live.current_receipt.is_none(), Code::DirectoryUnavailable)?;
            }
            state.intent = None;
            state.suppressed = !live.lookup_allowed;
            Ok(())
        })
    }

    fn update<T>(&self, root: &str, change: impl FnOnce(&mut HomeRoot) -> Result<T>) -> Result<T> {
        let _serving = self.publication_guard()?;
        fixed(root)?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        let mut table = tx.open_table(ROOTS).map_err(storage)?;
        let mut state =
            read_root(&table, root)?.ok_or(CheckpointError::Directory(Code::NotFound))?;
        let result = change(&mut state)?;
        put_root(&mut table, root, &state)?;
        if state.intent.is_none() {
            tx.open_table(META)
                .map_err(storage)?
                .remove(format!("preempted:{root}").as_str())
                .map_err(storage)?;
        } else if let Some(committed) = &state.committed {
            let mut meta = tx.open_table(META).map_err(storage)?;
            let key = format!("preempted:{root}");
            let restored = meta
                .get(key.as_str())
                .map_err(storage)?
                .map(|bytes| {
                    require(bytes.value().len() <= 16384, "home_intent_size")?;
                    let old: HomeIntent = serde_json::from_slice(bytes.value())?;
                    Ok::<_, CheckpointError>(old.operation == committed.operation)
                })
                .transpose()?
                .unwrap_or(false);
            if restored {
                meta.remove(key.as_str()).map_err(storage)?;
            }
        }
        if state.intent.is_none()
            && let Some(old) =
                tx.open_table(OUTBOX).map_err(storage)?.remove(root).map_err(storage)?
        {
            let at: u64 = serde_json::from_slice(old.value())?;
            ensure(
                tx.open_table(DUE).map_err(storage)?.remove((at, root)).map_err(storage)?.is_some(),
                Code::DirectoryUnavailable,
            )?;
        }
        drop(table);
        tx.commit().map_err(storage)?;
        Ok(result)
    }
}

fn read_root(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    root: &str,
) -> Result<Option<HomeRoot>> {
    table
        .get(root)
        .map_err(storage)?
        .map(|v| {
            require(v.value().len() <= 32768, "home_record_size")?;
            let row: HomeRoot = serde_json::from_slice(v.value())?;
            require(canonical(&row)? == v.value(), "home_record_canonical")?;
            Ok(row)
        })
        .transpose()
}

fn put_root(table: &mut redb::Table<&str, &[u8]>, root: &str, state: &HomeRoot) -> Result<()> {
    let bytes = canonical(state)?;
    ensure(bytes.len() <= 32768, Code::Capacity)?;
    table.insert(root, bytes.as_slice()).map_err(storage)?;
    Ok(())
}

fn restrictive(op: &w::UsernameOperation) -> bool {
    matches!(
        op.body.action,
        w::Action::Rename | w::Action::Release | w::Action::Delete | w::Action::MoveHome
    ) || op.body.action == w::Action::SetVisibility && !op.body.discoverable
}

fn verify_candidate(
    master: &VerifyingKey,
    op: &w::UsernameOperation,
    profile: &w::SignedIdentityProfileV2,
) -> Result<()> {
    crypto::verify_profile(master, profile)?;
    ensure(profile.body.avatar.is_none(), Code::InvalidAvatar)?;
    ensure(
        profile.body.principal_commitment == op.body.principal_commitment
            && op.body.profile.version == 2
            && op.body.profile.epoch == profile.body.epoch
            && op.body.profile.hash.as_ref() == Some(&crypto::profile_hash_v2(profile)?),
        Code::InvalidProfile,
    )
}

fn verify_receipt(pin: &CenterPin, receipt: &w::DirectoryReceipt, now: u64) -> Result<()> {
    let key = ramflux_crypto::verifying_key_from_base64url(&pin.public_key)
        .map_err(|_| CheckpointError::Directory(Code::SignatureInvalid))?;
    crypto::verify_receipt(&key, &pin.id, receipt)?;
    ensure(receipt.body.committed_at <= now && now < receipt.body.expires_at, Code::Replay)
}

fn matches_intent(intent: &HomeIntent, receipt: &w::DirectoryReceipt) -> Result<()> {
    let op = &intent.operation.body;
    ensure(
        receipt.body.operation_id == op.operation_id
            && receipt.body.principal_commitment == op.principal_commitment
            && receipt.body.operation_hash == crypto::operation_hash(&intent.operation)?
            && receipt.body.epoch == op.next_epoch
            && receipt.body.profile == op.profile
            && receipt.body.discoverable == op.discoverable
            && receipt.body.binding_hash
                == op.binding.as_ref().map(crypto::binding_hash).transpose()?,
        Code::StaleEpoch,
    )
}

fn observe(state: &mut HomeRoot, live: &w::HomeRevalidateResult) -> Result<()> {
    let Some(receipt) = &live.current_receipt else {
        ensure(
            state.directory_epoch == 0 && state.profile_floor.version == 0,
            Code::ProfileDowngrade,
        )?;
        return Ok(());
    };
    let tuple = &receipt.body;
    ensure(tuple.epoch >= state.directory_epoch, Code::ProfileRollback)?;
    if tuple.epoch == state.directory_epoch {
        ensure(tuple.binding_hash == state.binding_hash, Code::ProfileEquivocation)?;
    }
    ensure(
        tuple.profile.version == 2 && tuple.profile.epoch >= state.profile_floor.epoch,
        Code::ProfileRollback,
    )?;
    if tuple.profile.epoch == state.profile_floor.epoch {
        ensure(tuple.profile == state.profile_floor, Code::ProfileEquivocation)?;
    }
    state.directory_epoch = tuple.epoch;
    state.binding_hash.clone_from(&tuple.binding_hash);
    state.profile_floor = tuple.profile.clone();
    if !live.lookup_allowed {
        state.suppressed = true;
    }
    Ok(())
}
