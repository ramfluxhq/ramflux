// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Import handles. `begin` runs the local checks, reserves disk, and returns while a bounded
//! worker streams the body to a staging file. Nothing is readable until the worker has
//! checked every segment digest and the plaintext digest.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::SdkError;
use crate::bus::account_runtime::attachment_sends::ParkedImport;
use crate::bus::daemon::LocalBusDispatchResult;
use crate::bus::dispatch::local_bus_ok;
use crate::bus::io::request_account_id;
use crate::bus::protocol::LocalBusFrame;

use super::budget;
use super::bus;
use super::codes::{
    CODE_ATTACHMENT_DELETED, CODE_CANCELLED, CODE_DISK_FULL, CODE_DUPLICATE, CODE_EXPIRED,
    CODE_LAYOUT_INVALID, CODE_NOT_GRANTEE, CODE_NOT_OWNER, CODE_NOT_READY, CODE_SEAL_FAILED,
    CODE_STALE_GENERATION, CODE_STREAM_OFFSET, Refusal,
};
use super::import_cache;
use super::import_job::{self, Importer, Opened, SourcePin};
use super::import_journal::{self, Binding, ImportPhase, ImportRecord};
use super::meta::CHUNK;
use super::plane::Plane;
use super::scheduler;
use super::store::Store;
use super::transfer::TRANSFER_TOPIC;
use super::upload::JournalSink;

/// Progress snapshots of one download are at most this far apart (four per second).
const EMIT_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) const TOMBSTONE: &str = "attachment-tombstone";
pub(crate) const RETIREMENT: &str = "attachment-retirement";
const SENT: &str = "attachment-send";
/// Open handles one account may hold, and the whole process.
const HANDLES_ACCOUNT: usize = 16;
const HANDLES_PROCESS: usize = 64;

struct Job {
    account: String,
    message_id: String,
    generation: u64,
    length: u64,
    expires_at: u64,
    dir: PathBuf,
    path: PathBuf,
    reserved: AtomicU64,
    ready: AtomicBool,
    failed: Mutex<Option<&'static str>>,
    cancelled: AtomicBool,
    /// Set at shutdown: the worker stops, the cache and the Pending record are kept.
    stop: Arc<AtomicBool>,
    finished: AtomicBool,
    meter: budget::Meter,
    privacy: Mutex<Option<ramflux_storage::PrivacyResourceRegistration>>,
}

impl Job {
    fn release(&self) {
        budget::release_disk(self.reserved.swap(0, Ordering::AcqRel));
    }

    /// Stops the handle: marks it fenced, drops the staging directory and the reservation.
    fn invalidate(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = fs::remove_dir_all(&self.dir);
        self.release();
    }

    fn dead(&self, now: u64) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self.finished.load(Ordering::Acquire)
            || now >= self.expires_at
            || self.failed.lock().map_or(true, |code| code.is_some())
    }
}

fn jobs() -> &'static Mutex<BTreeMap<String, Arc<Job>>> {
    static JOBS: OnceLock<Mutex<BTreeMap<String, Arc<Job>>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Fences every open handle of `message_id`: no new byte is copied out, the staging file is
/// removed, and the reservation is returned. Called when the message is retired or deleted.
pub(crate) fn fence_message(message_id: &str) {
    let table = jobs().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for job in table.values().filter(|job| job.message_id == message_id) {
        job.invalidate();
    }
}

/// # Errors
/// Returns `not_grantee` before any body read, or another stable refusal.
pub(crate) fn begin(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: BeginBody = serde_json::from_value(request.body.clone())?;
    let id = request_account_id(request)?.to_owned();
    super::retire::barrier(&account.client, &body.message_id)?;
    let now = bus::unix_now()?;
    reap(now);
    let fingerprint = import_journal::fingerprint(&body.message_id, body.index);
    let (resumed, import_id) = match resolve(&account.client, &id, &body, &fingerprint, now)? {
        Resolved::Live(job, import_id) => return Ok(local_bus_ok(job_view(&import_id, &job))),
        Resolved::Admit { resumed, import_id } => (resumed, import_id),
    };
    let source = Source::find(&account.client, &id, &body)?;
    let length = source.length();
    let (generation, expires_at, revision) = match &resumed {
        Some(record) if record.plaintext_length != length => {
            return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
        }
        Some(record) => (record.generation, record.expires_at, record.revision),
        None => (1, now.saturating_add(super::meta::LEASE), 0),
    };
    let plane = if matches!(&source, Source::Remote { .. }) {
        Some(bus::plane_for(account)?)
    } else {
        None
    };
    let scheduler_large = length >= scheduler::LARGE_BYTES;
    let root = bus::account_dir(&account.client)?;
    let dir = root.join("attachment-imports").join(&import_id);
    let reserve = budget::import_bytes(length)?;
    count_ok(&id)?;
    budget::reserve_disk(&root, reserve)?;
    let job = Arc::new(Job {
        account: id.clone(),
        message_id: body.message_id.clone(),
        generation,
        length,
        expires_at,
        path: dir.join("body.bin"),
        dir,
        reserved: AtomicU64::new(reserve),
        ready: AtomicBool::new(false),
        failed: Mutex::new(None),
        cancelled: AtomicBool::new(false),
        finished: AtomicBool::new(false),
        meter: budget::Meter::default(),
        privacy: Mutex::new(None),
        stop: Arc::new(AtomicBool::new(false)),
    });
    let count = import_cache::segment_count(length)?;
    let verified = match &resumed {
        Some(prior) if prior.verified.len() == count as usize => prior.verified.clone(),
        _ => vec![false; count as usize],
    };
    let record = ImportRecord {
        import_id: import_id.clone(),
        generation,
        message_id: body.message_id.clone(),
        index: body.index,
        plaintext_length: length,
        expires_at,
        phase: ImportPhase::Pending,
        revision: revision.saturating_add(1),
        verified,
        failure: None,
    };
    let fresh = resumed.is_none().then_some((body.operation_id.as_str(), fingerprint.as_str()));
    if let Err(error) = admit_record(&account.client, &record, fresh) {
        job.invalidate();
        return Err(error);
    }
    if let Err(error) = register_recovery_privacy(&account.client, &import_id, &job, &source) {
        job.invalidate();
        return Err(error);
    }
    jobs()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(import_id.clone(), Arc::clone(&job));
    let (journal, calls) = JournalSink::channel();
    let (done, done_rx) = tokio::sync::oneshot::channel::<()>();
    let stop = Arc::clone(&job.stop);
    let task = Task {
        job: Arc::clone(&job),
        source,
        plane,
        ledger: Ledger {
            journal,
            record: RefCell::new(record.clone()),
            last_emit: Cell::new(None),
        },
        done,
    };
    if let Err(refusal) = scheduler::submit(&id, scheduler_large, move || task.run()) {
        remove(&import_id, &job);
        return Err(refusal.into());
    }
    // The worker runs off the actor; the actor serves its journal calls until it stops.
    account.attachment_send.import =
        Some(ParkedImport { import_id: import_id.clone(), calls, done: done_rx, stop });
    Ok(local_bus_ok(view(&import_id, generation, "pending", 0, length, expires_at)))
}

/// What `begin` resolves to: the live handle of a resumed import, or the admission to make.
enum Resolved {
    Live(Arc<Job>, String),
    Admit { resumed: Option<ImportRecord>, import_id: String },
}

/// Matches an operation to its durable import: a fresh id, a live handle, or the record to resume.
fn resolve(
    client: &crate::RamfluxClient,
    account_id: &str,
    body: &BeginBody,
    fingerprint: &str,
    now: u64,
) -> Result<Resolved, SdkError> {
    let Some(binding) = import_journal::load_binding(client.account_db()?, &body.operation_id)?
    else {
        return Ok(Resolved::Admit { resumed: None, import_id: fresh_id()? });
    };
    if binding.fingerprint != fingerprint {
        return Err(Refusal::new(CODE_DUPLICATE).into());
    }
    if let Some(job) = live_job(&binding.import_id, now) {
        if job.account != account_id {
            return Err(Refusal::new(CODE_NOT_OWNER).into());
        }
        return Ok(Resolved::Live(job, binding.import_id));
    }
    let record = import_journal::load_record(client.account_db()?, &binding.import_id)?
        .ok_or(Refusal::new(CODE_NOT_READY))?;
    import_journal::admissible(&record, now)?;
    Ok(Resolved::Admit { resumed: Some(record), import_id: binding.import_id })
}

/// Writes the durable record, and the operation binding on first admission, before a worker
/// is scheduled.
fn admit_record(
    client: &crate::RamfluxClient,
    record: &ImportRecord,
    fresh: Option<(&str, &str)>,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    import_journal::save_record(db, record)?;
    if let Some((operation_id, fingerprint)) = fresh {
        import_journal::save_binding(
            db,
            operation_id,
            &Binding { import_id: record.import_id.clone(), fingerprint: fingerprint.to_owned() },
        )?;
    }
    Ok(())
}

fn register_recovery_privacy(
    client: &crate::RamfluxClient,
    import_id: &str,
    job: &Arc<Job>,
    source: &Source,
) -> Result<(), SdkError> {
    let Source::Recovered { reader, .. } = source else { return Ok(()) };
    let weak = Arc::downgrade(job);
    let registration = client.account_db()?.register_privacy_resource(
        import_id,
        reader.privacy_erasure_generation()?,
        Arc::new(move || {
            if let Some(job) = weak.upgrade() {
                job.invalidate();
            }
            Ok(())
        }),
    )?;
    *job.privacy.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(registration);
    Ok(())
}

/// What the worker streams from.
enum Source {
    /// A reference this device holds an entry in.
    Remote { opened: Box<Opened>, length: u64 },
    /// A file this account sealed: its own prepare row and account-sealed key.
    Owned { store: Store, row: Box<super::meta::Row>, length: u64 },
    Recovered {
        reader: Box<ramflux_storage::AccountDb>,
        media: Box<ramflux_storage::BackupMedia>,
        length: u64,
    },
}

impl Source {
    fn length(&self) -> u64 {
        match self {
            Self::Remote { length, .. }
            | Self::Owned { length, .. }
            | Self::Recovered { length, .. } => *length,
        }
    }
}

impl Source {
    fn find(
        client: &crate::RamfluxClient,
        account_id: &str,
        body: &BeginBody,
    ) -> Result<Self, SdkError> {
        let media = message_media(client, &body.message_id, body.index)?;
        let reference = import_job::canonical(&media)?;
        let length = reference.large_manifest.plaintext_length;
        if let Some(saved) = super::recovery::stored(
            client.account_db()?,
            &body.message_id,
            body.index,
            &prost::Message::encode_to_vec(&media),
        )? {
            return Ok(Self::Recovered {
                reader: Box::new(client.account_db()?.open_backup_reader()?),
                media: Box::new(saved),
                length,
            });
        }
        if let Some(prepare_id) = prepare_at(client, &body.message_id, body.index)? {
            let store = bus::open_store(client, account_id)?;
            let row = store.load(&prepare_id)?;
            if row.plaintext_length != Some(length) {
                return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
            }
            return Ok(Self::Owned { store, row: Box::new(row), length });
        }
        let anchor = client.own_account_anchor()?;
        let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let secret = client.attachment_device_secret()?;
        let pin = bus::authority(client)?;
        let opened = import_job::open_entry(
            &media,
            &Importer {
                account_anchor: &anchor,
                device_id: &local.device_id,
                device_epoch: local.device_epoch,
                secret: &secret,
            },
            &SourcePin {
                source: &pin.source,
                generation: pin.generation,
                public_key: &pin.public_key,
                now: bus::unix_now()?,
            },
        )?;
        Ok(Self::Remote { opened: Box::new(opened), length })
    }
}

/// What the worker writes through the actor: the record, its progress snapshots and its terminal
/// snapshot. The actor refuses a write once the stored record is no longer pending.
struct Ledger {
    journal: JournalSink,
    record: RefCell<ImportRecord>,
    last_emit: Cell<Option<Instant>>,
}

impl Ledger {
    /// Writes the record, with a snapshot when one is due. Progress (`force` false) is published
    /// at most once per interval; a phase change always is.
    fn write(&self, phase: ImportPhase, reason: Option<&str>, force: bool) -> Result<(), Refusal> {
        let now = Instant::now();
        let due = force
            || self.last_emit.get().is_none_or(|last| now.duration_since(last) >= EMIT_INTERVAL);
        let mut current = self.record.borrow_mut();
        current.revision = current.revision.saturating_add(1);
        let bytes = import_journal::encode(&current).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let event = due.then(|| {
            (
                import_journal::event_source(&current),
                import_journal::event_body(&current, phase, reason, false),
            )
        });
        let key = import_journal::record_key(&current.import_id);
        drop(current);
        self.journal.import(&key, bytes, event)?;
        if due {
            self.last_emit.set(Some(now));
        }
        Ok(())
    }

    /// Moves the record to a phase and publishes that change at once.
    fn settle(&self, phase: ImportPhase, failure: Option<&str>) -> Result<(), Refusal> {
        {
            let mut current = self.record.borrow_mut();
            current.phase = phase;
            current.failure = failure.map(str::to_owned);
        }
        self.write(phase, failure, true)
    }
}

struct Task {
    job: Arc<Job>,
    source: Source,
    plane: Option<Arc<dyn Plane>>,
    ledger: Ledger,
    done: tokio::sync::oneshot::Sender<()>,
}

impl Task {
    fn run(self) {
        let Self { job, source, plane, ledger, done } = self;
        let result = stream(&job, &source, plane.as_deref(), &ledger);
        drop(done);
        match result.and_then(|()| ledger.settle(ImportPhase::Ready, None)) {
            Ok(()) => job.ready.store(true, Ordering::Release),
            Err(refusal) => {
                // Shutdown keeps the Pending record and the verified cache for a same-operation resume.
                if job.stop.load(Ordering::Acquire) && !job.cancelled.load(Ordering::Acquire) {
                    return;
                }
                // A cancel already wrote its terminal record; only a real failure is recorded.
                if !job.cancelled.load(Ordering::Acquire) && refusal.code != CODE_CANCELLED {
                    let _ = ledger.settle(ImportPhase::Failed, Some(refusal.code));
                }
                fail(&job, refusal.code);
                let _ = fs::remove_dir_all(&job.dir);
                job.release();
            }
        }
    }
}

fn stream(
    job: &Job,
    source: &Source,
    plane: Option<&dyn Plane>,
    ledger: &Ledger,
) -> Result<(), Refusal> {
    fs::create_dir_all(&job.dir).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let part = job.dir.join("body.part");
    let file = File::create(&part).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let mut sink = BufWriter::with_capacity(256 * 1024, file);
    let fenced = || job.cancelled.load(Ordering::Acquire) || job.stop.load(Ordering::Acquire);
    match source {
        Source::Remote { opened, .. } => {
            let verified = ledger.record.borrow().verified.clone();
            let checkpoint = |bits: &[bool]| checkpoint_record(ledger, bits);
            let mut cache = import_job::SegmentCache {
                dir: job.dir.as_path(),
                verified,
                checkpoint: &checkpoint,
            };
            import_job::stream_remote(
                plane.ok_or(Refusal::new(CODE_NOT_GRANTEE))?,
                opened,
                &mut sink,
                &fenced,
                &job.meter,
                Some(&mut cache),
            )?;
        }
        Source::Owned { store, row, .. } => {
            import_job::stream_owned(store, row, &mut sink, &fenced, &job.meter)?;
        }
        Source::Recovered { reader, media, .. } => {
            super::recovery::stream(reader, media, &mut sink, &fenced, &job.meter)?;
        }
    }
    sink.flush().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let file = sink.into_inner().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    file.sync_all().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    drop(file);
    if fenced() {
        return Err(Refusal::new(CODE_CANCELLED));
    }
    fs::rename(&part, &job.path).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    Ok(())
}

/// Writes the bitmap with its record through the account actor. The worker writes a segment
/// durably before it reaches here, so a set bit never names missing bytes.
fn checkpoint_record(ledger: &Ledger, bits: &[bool]) -> Result<(), Refusal> {
    ledger.record.borrow_mut().verified = bits.to_vec();
    ledger.write(ImportPhase::Pending, None, false)
}

/// # Errors
/// Returns `not_ready`, `expired`, `cancelled`, or `stream_offset`.
pub(crate) fn read(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: ReadBody = serde_json::from_value(request.body.clone())?;
    if body.max_bytes == 0 || body.max_bytes > CHUNK {
        return Err(Refusal::new(CODE_STREAM_OFFSET).into());
    }
    let job = lookup(&body.import_id, request_account_id(request)?)?;
    if body.generation != job.generation {
        return Err(Refusal::new(CODE_STALE_GENERATION).into());
    }
    gate(&account.client, &job)?;
    ready_or_refuse(&job)?;
    if body.offset > job.length {
        return Err(Refusal::new(CODE_STREAM_OFFSET).into());
    }
    let available = job.length.saturating_sub(body.offset);
    let take = available.min(body.max_bytes);
    let bytes = read_at(&job.path, body.offset, take)?;
    Ok(local_bus_ok(json!({
        "offset": body.offset,
        "bytes": ramflux_protocol::encode_base64url(&bytes),
        "eof": body.offset.saturating_add(take) >= job.length,
    })))
}

fn ready_or_refuse(job: &Job) -> Result<(), SdkError> {
    if job.ready.load(Ordering::Acquire) {
        return Ok(());
    }
    if let Some(code) = failed_code(job) {
        return Err(Refusal::new(code).into());
    }
    Err(Refusal::new(CODE_NOT_READY).into())
}

/// # Errors
/// Returns `not_owner` when the handle belongs to another account.
pub(crate) fn status(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: IdBody = serde_json::from_value(request.body.clone())?;
    let job = lookup(&body.import_id, request_account_id(request)?)?;
    gate(&account.client, &job)?;
    if let Some(code) = failed_code(&job) {
        return Err(Refusal::new(code).into());
    }
    let ready = job.ready.load(Ordering::Acquire);
    let through = if ready { job.length } else { 0 };
    Ok(local_bus_ok(view(
        &body.import_id,
        job.generation,
        if ready { "ready" } else { "pending" },
        through,
        job.length,
        job.expires_at,
    )))
}

/// # Errors
/// Returns `not_owner` when the handle belongs to another account.
pub(crate) fn finish(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: IdBody = serde_json::from_value(request.body.clone())?;
    let job = lookup(&body.import_id, request_account_id(request)?)?;
    job.finished.store(true, Ordering::Release);
    remove(&body.import_id, &job);
    import_journal::set_phase(
        account.client.account_db()?,
        &body.import_id,
        ImportPhase::Finished,
    )?;
    Ok(local_bus_ok(json!({"import_id": body.import_id, "state": "finished"})))
}

/// # Errors
/// Returns `not_owner` when the handle belongs to another account.
pub(crate) fn cancel(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: IdBody = serde_json::from_value(request.body.clone())?;
    match lookup(&body.import_id, request_account_id(request)?) {
        Ok(job) => {
            job.cancelled.store(true, Ordering::Release);
            remove(&body.import_id, &job);
        }
        Err(refusal) if refusal.code == CODE_NOT_GRANTEE => {
            // No live handle after a restart: the durable record decides, and the cache goes.
            let db = account.client.account_db()?;
            if import_journal::load_record(db, &body.import_id)?.is_none() {
                return Err(refusal.into());
            }
            let root = bus::account_dir(&account.client)?;
            let _ = fs::remove_dir_all(root.join("attachment-imports").join(&body.import_id));
        }
        Err(refusal) => return Err(refusal.into()),
    }
    let db = account.client.account_db()?;
    let before = import_journal::load_record(db, &body.import_id)?;
    import_journal::set_phase(db, &body.import_id, ImportPhase::Cancelled)?;
    // The terminal snapshot is published once: only the first cancel of a live record emits it.
    if let Some(mut terminal) = before.filter(|record| record.phase != ImportPhase::Cancelled) {
        terminal.phase = ImportPhase::Cancelled;
        terminal.revision = terminal.revision.saturating_add(1);
        let body = import_journal::event_body(
            &terminal,
            ImportPhase::Cancelled,
            Some(CODE_CANCELLED),
            false,
        );
        db.append_journal(
            &import_journal::event_source(&terminal),
            TRANSFER_TOPIC,
            &body,
            crate::time::now_unix_timestamp(),
            None,
        )
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    }
    Ok(local_bus_ok(json!({"import_id": body.import_id, "state": "cancelled"})))
}

/// `attachment.import.export`: writes the whole verified plaintext to a new file at `path`.
/// Only a live ready handle exports; a restarted account replays the import first.
/// # Errors
/// Returns `not_owner`, `stale_generation`, `not_ready`, `cancelled`, `expired`, or `path_refused`.
pub(crate) fn export(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: ExportBody = serde_json::from_value(request.body.clone())?;
    let job = lookup(&body.import_id, request_account_id(request)?)?;
    if body.generation != job.generation {
        return Err(Refusal::new(CODE_STALE_GENERATION).into());
    }
    gate(&account.client, &job)?;
    ready_or_refuse(&job)?;
    super::import_export::publish(&job.path, job.length, Path::new(&body.path))?;
    Ok(local_bus_ok(json!({
        "import_id": body.import_id,
        "generation": job.generation,
        "plaintext_length": job.length,
    })))
}

/// `relay_erased` is reported only after a confirmed cleanup ACK.
#[must_use]
pub(crate) fn revoke_state(existing: Option<&Value>) -> &'static str {
    if existing.and_then(|row| row.get("relay_erased")).and_then(Value::as_bool) == Some(true) {
        "relay_erased"
    } else {
        "retirement_pending"
    }
}

fn remove(import_id: &str, job: &Job) {
    job.invalidate();
    jobs().lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(import_id);
}

/// Drops every handle that is finished, cancelled, failed or past its lease.
fn reap(now: u64) {
    let mut table = jobs().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let dead: Vec<String> =
        table.iter().filter(|(_, job)| job.dead(now)).map(|(id, _)| id.clone()).collect();
    for id in dead {
        if let Some(job) = table.remove(&id) {
            job.invalidate();
        }
    }
}

/// The live handle for an import, if it has not died.
fn live_job(import_id: &str, now: u64) -> Option<Arc<Job>> {
    let table = jobs().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    table.get(import_id).filter(|job| !job.dead(now)).cloned()
}

fn job_view(import_id: &str, job: &Job) -> Value {
    let ready = job.ready.load(Ordering::Acquire);
    view(
        import_id,
        job.generation,
        if ready { "ready" } else { "pending" },
        if ready { job.length } else { 0 },
        job.length,
        job.expires_at,
    )
}

fn count_ok(account: &str) -> Result<(), Refusal> {
    let table = jobs().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mine = table.values().filter(|job| job.account == account).count();
    if table.len() >= HANDLES_PROCESS || mine >= HANDLES_ACCOUNT {
        return Err(Refusal::new(CODE_DISK_FULL));
    }
    Ok(())
}

fn fail(job: &Job, code: &'static str) {
    if let Ok(mut failed) = job.failed.lock() {
        *failed = Some(code);
    }
}

/// The message's media entry, read from the stored Inner of the message, which is the sender's
/// exact Message on both sides.
fn message_media(
    client: &crate::RamfluxClient,
    message_id: &str,
    index: u64,
) -> Result<ramflux_protocol::message::MediaRef, SdkError> {
    let index = usize::try_from(index).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    message_media_entries(client.account_db()?, message_id)?.into_iter().nth(index).ok_or_else(
        || {
            Refusal::because_of(CODE_LAYOUT_INVALID, "the message has no media entry at that index")
                .into()
        },
    )
}

pub(super) fn message_media_entries(
    db: &ramflux_storage::AccountDb,
    message_id: &str,
) -> Result<Vec<ramflux_protocol::message::MediaRef>, SdkError> {
    let exact = db
        .message_content(message_id)?
        .ok_or_else(|| SdkError::from(Refusal::new(CODE_ATTACHMENT_DELETED)))?;
    let (_, content) = crate::RamfluxClient::decode_generated_inner(&exact)?;
    let Some(ramflux_protocol::message::content::Value::Message(message)) = content.value else {
        return Err(Refusal::because_of(
            CODE_LAYOUT_INVALID,
            "the stored content is not a message",
        )
        .into());
    };
    // A received group message keeps its wire wrapper in the Inner and the opened Message
    // beside it; the opened bytes are the sender's Message and carry the media.
    let message = if message.sealed_group.is_some() {
        let opened = db
            .load_actor_state::<Vec<u8>>(&format!("routed/group-content/{message_id}"))?
            .ok_or_else(|| {
                Refusal::because_of(CODE_LAYOUT_INVALID, "the opened group message is not stored")
            })?;
        <ramflux_protocol::message::Message as prost::Message>::decode(opened.as_slice()).map_err(
            |_| Refusal::because_of(CODE_LAYOUT_INVALID, "the opened group message is malformed"),
        )?
    } else {
        message
    };
    Ok(message.media)
}

/// The prepare behind entry `index` of a message this account sent.
fn prepare_at(
    client: &crate::RamfluxClient,
    message_id: &str,
    index: u64,
) -> Result<Option<String>, SdkError> {
    prepare_at_on(client.account_db()?, message_id, index)
}

pub(super) fn prepare_at_on(
    db: &ramflux_storage::AccountDb,
    message_id: &str,
    index: u64,
) -> Result<Option<String>, SdkError> {
    let Some(record) = db.client_record(SENT, message_id)? else {
        return Ok(None);
    };
    let index = usize::try_from(index).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    Ok(record
        .get("prepares")
        .and_then(Value::as_array)
        .and_then(|rows| rows.get(index))
        .and_then(Value::as_str)
        .map(str::to_owned))
}

/// Records which prepares a sent message carries, so the sender can import its own file.
/// # Errors
/// Returns a storage error when the record cannot be saved.
pub(crate) fn remember_sent(
    client: &crate::RamfluxClient,
    message_id: &str,
    prepares: &[String],
) -> Result<(), SdkError> {
    client.account_db()?.persist_client_record(
        SENT,
        message_id,
        &json!({ "prepares": prepares }),
    )?;
    Ok(())
}

fn lookup(import_id: &str, account: &str) -> Result<Arc<Job>, Refusal> {
    let table = jobs().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let job = table.get(import_id).cloned().ok_or(Refusal::new(CODE_NOT_GRANTEE))?;
    if job.account != account {
        return Err(Refusal::new(CODE_NOT_OWNER));
    }
    Ok(job)
}

fn gate(client: &crate::RamfluxClient, job: &Job) -> Result<(), SdkError> {
    super::retire::barrier(client, &job.message_id)?;
    if job.cancelled.load(Ordering::Acquire) || job.finished.load(Ordering::Acquire) {
        return Err(Refusal::new(CODE_CANCELLED).into());
    }
    if bus::unix_now()? >= job.expires_at {
        return Err(Refusal::new(CODE_EXPIRED).into());
    }
    Ok(())
}

fn failed_code(job: &Job) -> Option<&'static str> {
    job.failed.lock().ok().and_then(|guard| *guard)
}

fn view(
    import_id: &str,
    generation: u64,
    state: &str,
    through: u64,
    length: u64,
    expires: u64,
) -> Value {
    json!({
        "import_id": import_id,
        "generation": generation,
        "state": state,
        "accepted_through": through,
        "plaintext_length": length,
        "expires_at": expires,
    })
}

fn read_at(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, Refusal> {
    let mut file = File::open(path).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    file.seek(SeekFrom::Start(offset)).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    let len = usize::try_from(len).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    Ok(bytes)
}

fn fresh_id() -> Result<String, Refusal> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    Ok(ramflux_protocol::encode_base64url(bytes))
}

#[derive(Deserialize)]
struct BeginBody {
    message_id: String,
    index: u64,
    operation_id: String,
}

#[derive(Deserialize)]
struct ReadBody {
    import_id: String,
    generation: u64,
    offset: u64,
    max_bytes: u64,
}

#[derive(Deserialize)]
struct IdBody {
    import_id: String,
}

#[derive(Deserialize)]
struct ExportBody {
    import_id: String,
    generation: u64,
    path: String,
}

/// Test seam: registers an open import handle so a fence can be observed.
#[cfg(test)]
pub(crate) fn test_register_job(import_id: &str, account: &str, message_id: &str, path: PathBuf) {
    let job = Arc::new(Job {
        account: account.to_owned(),
        message_id: message_id.to_owned(),
        generation: 1,
        length: 0,
        expires_at: u64::MAX,
        dir: path.parent().map(Path::to_path_buf).unwrap_or_default(),
        path,
        reserved: AtomicU64::new(0),
        ready: AtomicBool::new(true),
        failed: Mutex::new(None),
        cancelled: AtomicBool::new(false),
        finished: AtomicBool::new(false),
        meter: budget::Meter::default(),
        privacy: Mutex::new(None),
        stop: Arc::new(AtomicBool::new(false)),
    });
    jobs()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(import_id.to_owned(), job);
}

/// Test seam: whether the registered handle was cancelled.
#[cfg(test)]
pub(crate) fn test_job_cancelled(import_id: &str) -> bool {
    jobs()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(import_id)
        .is_some_and(|job| job.cancelled.load(Ordering::Acquire))
}
