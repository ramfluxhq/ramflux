// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Import handles. `begin` returns before the body worker finishes.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use prost::Message as _;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::SdkError;
use crate::bus::daemon::LocalBusDispatchResult;
use crate::bus::dispatch::local_bus_ok;
use crate::bus::io::request_account_id;
use crate::bus::protocol::LocalBusFrame;

use super::bus;
use super::codes::{
    CODE_ATTACHMENT_DELETED, CODE_AUTHORITY_UNAVAILABLE, CODE_CANCELLED, CODE_DUPLICATE,
    CODE_EXPIRED, CODE_LAYOUT_INVALID, CODE_NOT_GRANTEE, CODE_NOT_OWNER, CODE_NOT_READY,
    CODE_RETIREMENT_PENDING, CODE_SEAL_FAILED, CODE_STALE_GENERATION, CODE_STREAM_OFFSET, Refusal,
};
use super::import_job::{self, Importer, SourcePin};
use super::meta::CHUNK;
use super::plane::Plane;

const DIRECTORY: &str = "attachment-inner";
const TOMBSTONE: &str = "attachment-tombstone";
pub(crate) const RETIREMENT: &str = "attachment-retirement";
const BINDING: &str = "attachment-import";

struct Job {
    account: String,
    message_id: String,
    index: u64,
    generation: u64,
    length: u64,
    expires_at: u64,
    path: PathBuf,
    ready: AtomicBool,
    failed: Mutex<Option<&'static str>>,
    cancelled: AtomicBool,
    finished: AtomicBool,
}

fn jobs() -> &'static Mutex<BTreeMap<String, Arc<Job>>> {
    static JOBS: OnceLock<Mutex<BTreeMap<String, Arc<Job>>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// # Errors
/// Returns a storage error when the inner record cannot be saved.
pub(crate) fn remember_inner(
    client: &crate::RamfluxClient,
    message_id: &str,
    inner: &[u8],
    prepares: &[String],
) -> Result<(), SdkError> {
    let row = json!({
        "inner_base64": ramflux_protocol::encode_base64url(inner),
        "prepares": prepares,
    });
    client.account_db()?.persist_client_record(DIRECTORY, message_id, &row)?;
    Ok(())
}

/// # Errors
/// Returns `not_grantee` before any body read, or another stable refusal.
pub(crate) fn begin(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: BeginBody = serde_json::from_value(request.body.clone())?;
    let id = request_account_id(request)?.to_owned();
    if tombstone(&account.client, &body.message_id)? {
        return Err(Refusal::new(CODE_ATTACHMENT_DELETED).into());
    }
    let now = bus::unix_now()?;
    if let Some(existing) = bound(&account.client, &body.operation_id)? {
        return resume_existing(&id, &existing, &body);
    }
    let record = inner_record(&account.client, &body.message_id)?;
    let message = decode_message(&record)?;
    let media =
        message.media.get(usize_index(body.index)?).ok_or(Refusal::new(CODE_LAYOUT_INVALID))?;
    let length = media
        .large_manifest
        .as_ref()
        .map(|item| item.plaintext_length)
        .ok_or(Refusal::new(CODE_LAYOUT_INVALID))?;
    let prepare_id = prepare_at(&record, body.index);
    let anchor = account.client.own_account_anchor()?;
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    if prepare_id.is_none() {
        let importer = Importer {
            account_anchor: &anchor,
            device_id: &local.device_id,
            device_epoch: local.device_epoch,
            secret: &[0; 32],
        };
        import_job::select(media, &importer)?;
    }
    let pin = if prepare_id.is_none() { Some(owned_pin(&account.client)?) } else { None };
    let device_id = local.device_id.clone();
    let device_epoch = local.device_epoch;
    let import_id = fresh_id()?;
    let root = account.client.reader_account_root.clone().ok_or(SdkError::AccountDbNotUnlocked)?;
    let path = root.join("attachment-imports").join(&import_id).join("body.bin");
    let job = Arc::new(Job {
        account: id.clone(),
        message_id: body.message_id.clone(),
        index: body.index,
        generation: 1,
        length,
        expires_at: now.saturating_add(super::meta::LEASE),
        path: path.clone(),
        ready: AtomicBool::new(false),
        failed: Mutex::new(None),
        cancelled: AtomicBool::new(false),
        finished: AtomicBool::new(false),
    });
    jobs()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(import_id.clone(), Arc::clone(&job));
    save_binding(&account.client, &body.operation_id, &import_id, &body)?;
    spawn_worker(WorkerIn {
        job,
        media: media.clone(),
        prepare_id,
        plane: account.client.attachment_plane.clone(),
        root: Some(root),
        secret: account
            .client
            .vault_secret_source()
            .ok()
            .and_then(|source| source.vault_secret(&id).ok()),
        anchor,
        device_id,
        device_epoch,
        pin,
    });
    Ok(local_bus_ok(view(
        &import_id,
        1,
        "pending",
        0,
        length,
        now.saturating_add(super::meta::LEASE),
    )))
}

struct OwnedPin {
    source: String,
    generation: u64,
    public_key: [u8; 32],
}

struct WorkerIn {
    job: Arc<Job>,
    media: ramflux_protocol::message::MediaRef,
    prepare_id: Option<String>,
    plane: Option<Arc<dyn Plane>>,
    root: Option<PathBuf>,
    secret: Option<[u8; 32]>,
    anchor: String,
    device_id: String,
    device_epoch: u64,
    pin: Option<OwnedPin>,
}

fn spawn_worker(input: WorkerIn) {
    thread::spawn(move || worker(&input));
}

fn worker(input: &WorkerIn) {
    let result = match super::budget::staging_bytes(input.job.length) {
        Ok(cost) => match super::budget::charge(cost) {
            Ok(()) => {
                let fetched = fetch_body(input);
                super::budget::release(cost);
                fetched
            }
            Err(refusal) => Err(refusal),
        },
        Err(refusal) => Err(refusal),
    };
    match result {
        Ok(bytes) => {
            if write_body(&input.job.path, &bytes).is_ok() {
                input.job.ready.store(true, Ordering::Release);
            } else {
                fail(&input.job, CODE_SEAL_FAILED);
            }
        }
        Err(refusal) => fail(&input.job, refusal.code),
    }
}

fn fetch_body(input: &WorkerIn) -> Result<Vec<u8>, Refusal> {
    if input.job.cancelled.load(Ordering::Acquire) {
        return Err(Refusal::new(CODE_CANCELLED));
    }
    if let Some(prepare_id) = input.prepare_id.as_deref() {
        let root = input.root.as_deref().ok_or(Refusal::new(CODE_NOT_GRANTEE))?;
        let secret = input.secret.ok_or(Refusal::new(CODE_NOT_GRANTEE))?;
        let store = super::store::Store::open(root, &input.job.account, secret)?;
        return import_job::import_owned(&store, &store.load(prepare_id)?);
    }
    let plane = input.plane.as_deref().ok_or(Refusal::new(CODE_AUTHORITY_UNAVAILABLE))?;
    let file_secret = device_secret(input.root.as_deref())?;
    let pin = input.pin.as_ref().ok_or(Refusal::new(CODE_AUTHORITY_UNAVAILABLE))?;
    let importer = Importer {
        account_anchor: &input.anchor,
        device_id: &input.device_id,
        device_epoch: input.device_epoch,
        secret: &file_secret,
    };
    let source = SourcePin {
        source: &pin.source,
        generation: pin.generation,
        public_key: &pin.public_key,
        now: bus::unix_now().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?,
    };
    import_job::import_entry(plane, &input.media, &importer, &source)
}

fn fail(job: &Job, code: &'static str) {
    if let Ok(mut failed) = job.failed.lock() {
        *failed = Some(code);
    }
}

fn owned_pin(client: &crate::RamfluxClient) -> Result<OwnedPin, SdkError> {
    let pin = bus::authority(client)?;
    Ok(OwnedPin { source: pin.source, generation: pin.generation, public_key: pin.public_key })
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
    if !job.ready.load(Ordering::Acquire) {
        if let Some(code) = failed_code(&job) {
            return Err(Refusal::new(code).into());
        }
        return Err(Refusal::new(CODE_NOT_READY).into());
    }
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

/// # Errors
/// Returns `not_owner` when the handle belongs to another account.
pub(crate) fn status(
    account: &mut crate::bus::state::LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: IdBody = serde_json::from_value(request.body.clone())?;
    let job = lookup(&body.import_id, request_account_id(request)?)?;
    gate(&account.client, &job)?;
    let state = if job.ready.load(Ordering::Acquire) { "ready" } else { "pending" };
    let through = if job.ready.load(Ordering::Acquire) { job.length } else { 0 };
    Ok(local_bus_ok(view(
        &body.import_id,
        job.generation,
        state,
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
    let _ = fs::remove_file(&job.path);
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
    let _ = fs::remove_file(&job.path);
    Ok(local_bus_ok(json!({"import_id": body.import_id, "state": "cancelled"})))
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
    let state = if job.ready.load(Ordering::Acquire) { "ready" } else { "pending" };
    Ok(local_bus_ok(view(import_id, job.generation, state, 0, job.length, job.expires_at)))
}

fn device_secret(root: Option<&Path>) -> Result<[u8; 32], Refusal> {
    let root = root.ok_or(Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    let bytes = fs::read(root.join("attachment-device.key"))
        .map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    let secret: [u8; 32] =
        bytes.try_into().map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    Ok(secret)
}

fn prepare_at(record: &Value, index: u64) -> Option<String> {
    let rows = record.get("prepares")?.as_array()?;
    let index = usize::try_from(index).ok()?;
    rows.get(index)?.as_str().map(str::to_owned)
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
    if tombstone(client, &job.message_id)? {
        return Err(Refusal::new(CODE_ATTACHMENT_DELETED).into());
    }
    if retirement_pending(client, &job.message_id)? {
        return Err(Refusal::new(CODE_RETIREMENT_PENDING).into());
    }
    if job.cancelled.load(Ordering::Acquire) {
        return Err(Refusal::new(CODE_CANCELLED).into());
    }
    if job.finished.load(Ordering::Acquire) {
        return Err(Refusal::new(CODE_CANCELLED).into());
    }
    let now = bus::unix_now()?;
    if now >= job.expires_at {
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

fn tombstone(client: &crate::RamfluxClient, message_id: &str) -> Result<bool, SdkError> {
    Ok(client.account_db()?.client_record(TOMBSTONE, message_id)?.is_some())
}

fn retirement_pending(client: &crate::RamfluxClient, message_id: &str) -> Result<bool, SdkError> {
    let Some(row) = client.account_db()?.client_record(RETIREMENT, message_id)? else {
        return Ok(false);
    };
    Ok(revoke_state(Some(&row)) != "relay_erased")
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

fn inner_record(client: &crate::RamfluxClient, message_id: &str) -> Result<Value, SdkError> {
    client
        .account_db()?
        .client_record(DIRECTORY, message_id)?
        .ok_or_else(|| SdkError::from(Refusal::new(CODE_ATTACHMENT_DELETED)))
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

fn decode_message(record: &Value) -> Result<ramflux_protocol::message::Message, Refusal> {
    let text = record
        .get("inner_base64")
        .and_then(Value::as_str)
        .ok_or(Refusal::new(CODE_LAYOUT_INVALID))?;
    let bytes =
        ramflux_protocol::decode_base64url(text).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    ramflux_protocol::message::Message::decode(bytes.as_slice())
        .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))
}

fn usize_index(index: u64) -> Result<usize, Refusal> {
    usize::try_from(index).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))
}

fn write_body(path: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    }
    let mut file = File::create(path).map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    file.write_all(bytes).map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    file.sync_all().map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    Ok(())
}

fn read_at(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, Refusal> {
    let mut file = File::open(path).map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    file.seek(SeekFrom::Start(offset)).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    let len = usize::try_from(len).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes).map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
    Ok(bytes)
}

fn fresh_id() -> Result<String, Refusal> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Refusal::new(super::codes::CODE_SEAL_FAILED))?;
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
