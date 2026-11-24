// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Import handles. `begin` runs the local checks, reserves disk, and returns while a bounded
//! worker streams the body to a staging file. Nothing is readable until the worker has
//! checked every segment digest and the plaintext digest.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::SdkError;
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
use super::import_job::{self, Importer, Opened, SourcePin};
use super::meta::CHUNK;
use super::plane::Plane;
use super::scheduler;
use super::store::Store;

pub(crate) const TOMBSTONE: &str = "attachment-tombstone";
const BINDING: &str = "attachment-import";
pub(crate) const RETIREMENT: &str = "attachment-retirement";
const SENT: &str = "attachment-send";
/// Open handles one account may hold, and the whole process.
const HANDLES_ACCOUNT: usize = 16;
const HANDLES_PROCESS: usize = 64;

struct Job {
    account: String,
    message_id: String,
    index: u64,
    generation: u64,
    length: u64,
    expires_at: u64,
    dir: PathBuf,
    path: PathBuf,
    reserved: AtomicU64,
    ready: AtomicBool,
    failed: Mutex<Option<&'static str>>,
    cancelled: AtomicBool,
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
    if let Some(existing) = bound(&account.client, &body.operation_id)?
        && let Ok(view) = resume_existing(&id, &existing, &body)
    {
        return Ok(view);
    }
    let source = Source::find(&account.client, &id, &body)?;
    let plane = if matches!(&source, Source::Remote { .. }) {
        Some(bus::plane_for(account)?)
    } else {
        None
    };
    let length = source.length();
    let scheduler_large = length >= scheduler::LARGE_BYTES;
    let import_id = fresh_id()?;
    let root = bus::account_dir(&account.client)?;
    let dir = root.join("attachment-imports").join(&import_id);
    let reserve = budget::import_bytes(length)?;
    count_ok(&id)?;
    budget::reserve_disk(&root, reserve)?;
    let job = Arc::new(Job {
        account: id.clone(),
        message_id: body.message_id.clone(),
        index: body.index,
        generation: 1,
        length,
        expires_at: now.saturating_add(super::meta::LEASE),
        path: dir.join("body.bin"),
        dir,
        reserved: AtomicU64::new(reserve),
        ready: AtomicBool::new(false),
        failed: Mutex::new(None),
        cancelled: AtomicBool::new(false),
        finished: AtomicBool::new(false),
        meter: budget::Meter::default(),
        privacy: Mutex::new(None),
    });
    if let Err(error) = register_recovery_privacy(&account.client, &import_id, &job, &source) {
        job.invalidate();
        return Err(error);
    }
    jobs()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(import_id.clone(), Arc::clone(&job));
    let task = Task { job: Arc::clone(&job), source, plane };
    if let Err(refusal) = scheduler::submit(&id, scheduler_large, move || task.run()) {
        remove(&import_id, &job);
        return Err(refusal.into());
    }
    if let Err(error) = save_binding(&account.client, &body.operation_id, &import_id, &body) {
        job.invalidate();
        return Err(error);
    }
    Ok(local_bus_ok(view(&import_id, 1, "pending", 0, length, job.expires_at)))
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

struct Task {
    job: Arc<Job>,
    source: Source,
    plane: Option<Arc<dyn Plane>>,
}

impl Task {
    fn run(self) {
        let Self { job, source, plane } = self;
        let result = stream(&job, &source, plane.as_deref());
        match result {
            Ok(()) => job.ready.store(true, Ordering::Release),
            Err(refusal) => {
                fail(&job, refusal.code);
                // A failed import never leaves bytes behind and returns what it reserved.
                let _ = fs::remove_dir_all(&job.dir);
                job.release();
            }
        }
    }
}

fn stream(job: &Job, source: &Source, plane: Option<&dyn Plane>) -> Result<(), Refusal> {
    fs::create_dir_all(&job.dir).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let part = job.dir.join("body.part");
    let file = File::create(&part).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let mut sink = BufWriter::with_capacity(256 * 1024, file);
    let fenced = || job.cancelled.load(Ordering::Acquire);
    match source {
        Source::Remote { opened, .. } => {
            import_job::stream_remote(
                plane.ok_or(Refusal::new(CODE_NOT_GRANTEE))?,
                opened,
                &mut sink,
                &fenced,
                &job.meter,
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
    _account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: IdBody = serde_json::from_value(request.body.clone())?;
    let job = lookup(&body.import_id, request_account_id(request)?)?;
    job.finished.store(true, Ordering::Release);
    remove(&body.import_id, &job);
    Ok(local_bus_ok(json!({"import_id": body.import_id, "state": "finished"})))
}

/// # Errors
/// Returns `not_owner` when the handle belongs to another account.
pub(crate) fn cancel(
    _account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: IdBody = serde_json::from_value(request.body.clone())?;
    let job = lookup(&body.import_id, request_account_id(request)?)?;
    job.cancelled.store(true, Ordering::Release);
    remove(&body.import_id, &job);
    Ok(local_bus_ok(json!({"import_id": body.import_id, "state": "cancelled"})))
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

fn count_ok(account: &str) -> Result<(), Refusal> {
    let table = jobs().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mine = table.values().filter(|job| job.account == account).count();
    if table.len() >= HANDLES_PROCESS || mine >= HANDLES_ACCOUNT {
        return Err(Refusal::new(CODE_DISK_FULL));
    }
    Ok(())
}

fn resume_existing(
    account_id: &str,
    import_id: &str,
    body: &BeginBody,
) -> Result<LocalBusDispatchResult, SdkError> {
    let job = lookup(import_id, account_id)?;
    if job.message_id != body.message_id || job.index != body.index {
        return Err(Refusal::new(CODE_DUPLICATE).into());
    }
    let ready = job.ready.load(Ordering::Acquire);
    Ok(local_bus_ok(view(
        import_id,
        job.generation,
        if ready { "ready" } else { "pending" },
        if ready { job.length } else { 0 },
        job.length,
        job.expires_at,
    )))
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

fn bound(client: &crate::RamfluxClient, operation_id: &str) -> Result<Option<String>, SdkError> {
    let row = client.account_db()?.client_record(BINDING, operation_id)?;
    Ok(row.and_then(|value| value.get("import_id").and_then(Value::as_str).map(str::to_owned)))
}

fn save_binding(
    client: &crate::RamfluxClient,
    operation_id: &str,
    import_id: &str,
    body: &BeginBody,
) -> Result<(), SdkError> {
    let row = json!({"import_id": import_id, "message_id": body.message_id, "index": body.index});
    client.account_db()?.persist_client_record(BINDING, operation_id, &row)?;
    Ok(())
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

/// Test seam: registers an open import handle so a fence can be observed.
#[cfg(test)]
pub(crate) fn test_register_job(import_id: &str, account: &str, message_id: &str, path: PathBuf) {
    let job = Arc::new(Job {
        account: account.to_owned(),
        message_id: message_id.to_owned(),
        index: 0,
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
