// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Version 2: bounded asynchronous requests through the process supervisor.
//! See docs/design/c-abi-v2.md for ownership, cancellation and wire contracts.

use super::super::{CAbiError, RamfluxBuffer, RamfluxErrorCode};
use super::runtime::{Client, CloseResult, Command};
use super::state::{self, MAX_FRAME_BYTES, MAX_OPERATIONS, Operation, OperationKind};
use crate::{LocalBusConfig, LocalBusFrame};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};

/// Additional v2 transport statuses. Existing `RamfluxErrorCode` values 0..23 are unchanged.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamfluxV2Status {
    /// No terminal completion or event is available. Poll again without resubmitting.
    Pending = 24,
    /// Cancellation won before carrier admission; no business effects occurred.
    Cancelled = 25,
    /// The client has closed. Admitted mutations may have effects; reconcile their keys.
    Closed = 26,
    /// Event credit was exhausted. Re-read projections and reopen the subscription.
    ResyncRequired = 27,
}

#[derive(Default)]
struct Registry {
    next: u64,
    opening: usize,
    clients: BTreeMap<u64, Arc<Client>>,
}
static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    data_root: std::path::PathBuf,
    #[serde(default)]
    builtin_nodes: Vec<crate::NodeProfile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    account_id: Option<String>,
    sdk_api: String,
    method: String,
    body: serde_json::Value,
    /// Required absolute Unix milliseconds. The bridge never fabricates a mutation key.
    deadline_ms: u64,
    operation_id: Option<String>,
}

impl Drop for Request {
    fn drop(&mut self) {
        crate::bus::inprocess::erase_value(&mut self.body);
    }
}

fn invalid(message: &str) -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, message)
}
fn internal() -> CAbiError {
    CAbiError::new(RamfluxErrorCode::Internal, "bridge lock poisoned")
}
fn busy() -> CAbiError {
    CAbiError::new(RamfluxErrorCode::RateLimited, "bridge capacity exhausted")
}
fn next_id(registry: &mut Registry) -> Result<u64, CAbiError> {
    registry.next = registry.next.checked_add(1).ok_or_else(busy)?;
    Ok(registry.next)
}
fn client(handle: u64) -> Result<Arc<Client>, CAbiError> {
    REGISTRY
        .lock()
        .map_err(|_| internal())?
        .clients
        .get(&handle)
        .cloned()
        .ok_or_else(|| invalid("unknown client handle"))
}
fn operation(client: &Client, id: u64) -> Result<Arc<Operation>, CAbiError> {
    client
        .shared
        .operations
        .lock()
        .map_err(|_| internal())?
        .get(&id)
        .cloned()
        .ok_or_else(|| invalid("unknown operation handle"))
}
fn call(action: impl FnOnce() -> Result<(), CAbiError>) -> i32 {
    match action() {
        Ok(()) => 0,
        Err(error) => error.code as i32,
    }
}
fn write_handle(out: *mut u64, value: u64) -> Result<(), CAbiError> {
    if out.is_null() {
        return Err(invalid("null handle output"));
    }
    // SAFETY: callers supply a valid aligned writable u64 output for the duration of the call.
    unsafe {
        out.write(value);
    }
    Ok(())
}
fn bounded(value: &serde_json::Value, depth: usize, budget: &mut usize) -> bool {
    if depth > 32 || *budget == 0 {
        return false;
    }
    *budget -= 1;
    match value {
        serde_json::Value::Array(items) => items.iter().all(|v| bounded(v, depth + 1, budget)),
        serde_json::Value::Object(items) => items.values().all(|v| bounded(v, depth + 1, budget)),
        _ => true,
    }
}
fn input<T: serde::de::DeserializeOwned>(ptr: *const u8, len: usize) -> Result<T, CAbiError> {
    if ptr.is_null() || len == 0 || len > MAX_FRAME_BYTES {
        return Err(invalid("invalid input length"));
    }
    // SAFETY: callers supply len readable bytes until this call returns; bounds were checked.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let value: serde_json::Value =
        ramflux_protocol::parse_i_json(bytes).map_err(|_| invalid("invalid I-JSON request"))?;
    if !bounded(&value, 0, &mut 4096) {
        return Err(invalid("request complexity limit"));
    }
    serde_json::from_value(value).map_err(|_| invalid("invalid request schema"))
}

/// Return ABI v2 metadata, descriptor fingerprint, limits and the operation inventory.
/// Pass major=2 and a minimum minor supported by the host. Does not open a data root.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_negotiate(
    major: u32,
    min_minor: u32,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    call(|| {
        super::super::clear_out_ptr(out)?;
        if major != 2 || min_minor > 0 {
            return Err(CAbiError::new(RamfluxErrorCode::UnsupportedVersion, "unsupported ABI"));
        }
        super::super::write_json_buffer(
            out,
            &json!({
                "abi_major":2,"abi_minor":0,"bus_protocol":"ramflux.local_bus.v1",
                "message_descriptor_blake3":blake3::hash(crate::message::FILE_DESCRIPTOR_SET).to_hex().to_string(),
                "max_frame_bytes":MAX_FRAME_BYTES,"max_operations":MAX_OPERATIONS,
                "max_events":state::MAX_EVENTS,"max_event_bytes":state::MAX_EVENT_BYTES,
                "methods":crate::bus::inprocess::method_names(),
            "method_policy":super::method_policy::manifest(),
            }),
        )
    })
}

/// Open one supervisor on a dedicated thread. Config is `{data_root,builtin_nodes?}`.
/// This may block during startup; invoke off the UI thread. Output is zero on failure.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_client_open(
    config: *const u8,
    len: usize,
    out_client: *mut u64,
) -> i32 {
    call(|| {
        write_handle(out_client, 0)?;
        let config: Config = input(config, len)?;
        if config.data_root.as_os_str().is_empty() || !config.data_root.is_absolute() {
            return Err(invalid("data_root must be absolute"));
        }
        let candidate_root = std::fs::canonicalize(&config.data_root).ok();
        // A registered root remains reserved until shutdown is acknowledged, even if
        // its OS lease is released just before the worker publishes completion.
        // No bridge registry lock spans filesystem I/O.
        let id = {
            let mut registry = REGISTRY.lock().map_err(|_| internal())?;
            if candidate_root.as_ref().is_some_and(|root| {
                registry.clients.values().any(|client| &client.data_root == root)
            }) {
                return Err(CAbiError::new(
                    RamfluxErrorCode::AccountBusy,
                    "data root has a registered client",
                ));
            }
            if registry.clients.len().saturating_add(registry.opening) >= 16 {
                return Err(busy());
            }
            let id = next_id(&mut registry)?;
            registry.opening += 1;
            id
        };
        let mut bus = LocalBusConfig::new(std::path::PathBuf::new(), config.data_root);
        bus.builtin_nodes = config.builtin_nodes;
        let started = Client::start(bus);
        let mut registry = REGISTRY.lock().map_err(|_| internal())?;
        registry.opening = registry.opening.saturating_sub(1);
        let client = started.map_err(|error| super::super::map_sdk_error(&error))?;
        registry.clients.insert(id, client);
        write_handle(out_client, id)
    })
}

/// Stop the supervisor and release its writer lease. Call off the UI thread.
/// The first wait expires with Timeout=10; retries return Pending=24 until completion.
/// Pending/failed shutdown retains the handle and completion state; only Done=0 removes it.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_client_close(handle: u64) -> i32 {
    let mut status = 0;
    let code = call(|| {
        let client = REGISTRY.lock().map_err(|_| internal())?.clients.get(&handle).cloned();
        if let Some(client) = client {
            match client.close().map_err(|error| super::super::map_sdk_error(&error))? {
                CloseResult::Done => {
                    REGISTRY.lock().map_err(|_| internal())?.clients.remove(&handle);
                }
                CloseResult::TimedOut => status = RamfluxErrorCode::Timeout as i32,
                CloseResult::Pending => status = RamfluxV2Status::Pending as i32,
            }
        }
        Ok(())
    });
    if code == 0 { status } else { code }
}

/// Release a retained failed shutdown after the host has inspected its error.
/// Returns Pending=24 until the owner thread has reported a terminal outcome.
/// Ordinary successful close already releases its handle; repeated release is harmless.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_client_release(handle: u64) -> i32 {
    let mut status = 0;
    let code = call(|| {
        let client = REGISTRY.lock().map_err(|_| internal())?.clients.get(&handle).cloned();
        if let Some(client) = client {
            if client.shutdown_confirmed().map_err(|error| super::super::map_sdk_error(&error))? {
                REGISTRY.lock().map_err(|_| internal())?.clients.remove(&handle);
            } else {
                status = RamfluxV2Status::Pending as i32;
            }
        }
        Ok(())
    });
    if code == 0 { status } else { code }
}

#[cfg(test)]
pub(super) fn register_test_client(client: Arc<Client>) -> u64 {
    let mut registry = REGISTRY.lock().expect("test: registry");
    let id = next_id(&mut registry).expect("test: client id");
    registry.clients.insert(id, client);
    id
}

/// Submit one request, copying input before return. Returns an explicit operation/cancel handle.
/// `deadline_ms` is required; `operation_id` is supplied by the caller for lifecycle reconciliation.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_execute(
    handle: u64,
    request: *const u8,
    len: usize,
    out_operation: *mut u64,
) -> i32 {
    call(|| {
        write_handle(out_operation, 0)?;
        let mut request: Request = input(request, len)?;
        if request.method.contains("itest")
            || request.method.is_empty()
            || request.method.len() > 128
            || request.sdk_api.len() > 128
            || request.account_id.as_ref().is_some_and(|id| id.len() > 128)
        {
            return Err(invalid("invalid method"));
        }
        let client = client(handle)?;
        if client.closing.load(std::sync::atomic::Ordering::Acquire)
            || client.shared.closed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(CAbiError::new(RamfluxErrorCode::TransportUnavailable, "client closed"));
        }
        let subscription = matches!(request.method.as_str(), "subscription.open" | "bus.subscribe");
        let id = next_id(&mut *REGISTRY.lock().map_err(|_| internal())?)?;
        let deadline_ms = Some(request.deadline_ms);
        let mut frame = LocalBusFrame::request(
            id.to_string(),
            request.account_id.take(),
            std::mem::take(&mut request.sdk_api),
            std::mem::take(&mut request.method),
            std::mem::take(&mut request.body),
        );
        frame.deadline_ms = Some(request.deadline_ms);
        frame.operation_id = request.operation_id.take();
        let bytes = crate::bus::inprocess::encode_request(frame);
        let bytes =
            zeroize::Zeroizing::new(bytes.map_err(|error| super::super::map_sdk_error(&error))?);
        let operation = Arc::new(Operation::default());
        operation.state.lock().map_err(|_| internal())?.kind =
            if subscription { OperationKind::Subscription } else { OperationKind::Request };
        let mut operations = client.shared.operations.lock().map_err(|_| internal())?;
        if operations.len() >= MAX_OPERATIONS {
            return Err(busy());
        }
        let mut subscribed = client.shared.subscription.lock().map_err(|_| internal())?;
        if subscription && subscribed.is_some() {
            return Err(busy());
        }
        operations.insert(id, Arc::clone(&operation));
        if client.commands.try_send(Command { id, bytes, operation, deadline_ms }).is_err() {
            operations.remove(&id);
            return Err(busy());
        }
        if subscription {
            *subscribed = Some(id);
        }
        write_handle(out_operation, id)
    })
}

/// Poll a completion without blocking. Returns Pending=24 with a null buffer until terminal.
/// A successful poll returns JSON {code,response?}; code is a stable numeric SDK error.
/// Repeated polls return the same terminal value until `operation_release`.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_operation_poll(
    handle: u64,
    id: u64,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    let mut pending = false;
    let code = call(|| {
        super::super::clear_out_ptr(out)?;
        let client = client(handle)?;
        let operation = operation(&client, id)?;
        let state = operation.state.lock().map_err(|_| internal())?;
        if let Some(bytes) = &state.result {
            super::super::write_buffer(out, bytes.to_vec())?;
        } else {
            pending = true;
        }
        Ok(())
    });
    if code == 0 && pending { RamfluxV2Status::Pending as i32 } else { code }
}

/// Cancel the waiter. Before admission: completion code=25 and effects=none.
/// After admission: execution/receipts remain supervisor-owned; poll/reconcile the original key.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_operation_cancel(handle: u64, id: u64) -> i32 {
    call(|| {
        let client = client(handle)?;
        let operations = client.shared.operations.lock().map_err(|_| internal())?;
        let operation = operations.get(&id).ok_or_else(|| invalid("unknown operation handle"))?;
        let mut subscribed = client.shared.subscription.lock().map_err(|_| internal())?;
        let mut state = operation.state.lock().map_err(|_| internal())?;
        if state.detached {
            return Err(invalid("released operation handle"));
        }
        if state.kind == OperationKind::Subscription && *subscribed == Some(id) {
            if state.admitted {
                let frame =
                    LocalBusFrame::request("0", None, "bus", "subscription.close", json!({}));
                let bytes = crate::bus::inprocess::encode_request(frame)
                    .map_err(|error| super::super::map_sdk_error(&error))?;
                client
                    .commands
                    .try_send(Command {
                        id: 0,
                        deadline_ms: None,
                        bytes: zeroize::Zeroizing::new(bytes),
                        operation: Arc::new(Operation::default()),
                    })
                    .map_err(|_| busy())?;
            }
            *subscribed = None;
        }
        state.cancelled = true;
        Ok(())
    })
}

/// Release an operation handle. An admitted operation retains bounded internal credit until terminal.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_operation_release(handle: u64, id: u64) -> i32 {
    let cancelled = ramflux_v2_operation_cancel(handle, id);
    if cancelled != 0 {
        return cancelled;
    }
    call(|| {
        let client = client(handle)?;
        let mut operations = client.shared.operations.lock().map_err(|_| internal())?;
        let Some(operation) = operations.get(&id) else {
            return Err(invalid("unknown operation"));
        };
        let finished = {
            let mut state = operation.state.lock().map_err(|_| internal())?;
            state.detached = true;
            state.cancelled = true;
            state.result.is_some()
        };
        if finished {
            operations.remove(&id);
        }
        Ok(())
    })
}

/// Poll one subscription event without blocking. Subscribe using execute(subscription.open/bus.subscribe).
/// ResyncRequired=27 explicitly signals event overflow; terminal completions use separate credit.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_event_poll(handle: u64, out: *mut *mut RamfluxBuffer) -> i32 {
    let mut status = 0;
    let code = call(|| {
        super::super::clear_out_ptr(out)?;
        let client = client(handle)?;
        let mut events = client.shared.events.lock().map_err(|_| internal())?;
        if events.resync {
            super::super::write_json_buffer(
                out,
                &json!({
                    "bus_protocol":"ramflux.local_bus.v1","frame_id":"c_abi_resync",
                    "kind":"event","request_id":"","sdk_api":"bus","method":"stream.lagged",
                    "account_id":events.account_id,"body":{"resync_required":true},
                    "subscription_generation":events.generation.to_string(),
                }),
            )?;
            status = RamfluxV2Status::ResyncRequired as i32;
        } else if let Some(bytes) = events.queue.pop_front() {
            events.bytes = events.bytes.saturating_sub(bytes.len());
            super::super::write_buffer(out, bytes.to_vec())?;
        } else if client.shared.closed.load(std::sync::atomic::Ordering::Acquire) {
            status = RamfluxV2Status::Closed as i32;
        } else {
            status = RamfluxV2Status::Pending as i32;
        }
        Ok(())
    });
    if code == 0 { status } else { code }
}

pub(super) fn failure(status: RamfluxV2Status, message: &str, effects: &str) -> serde_json::Value {
    json!({"code":status as i32,"message":message,"effects":effects})
}

pub(super) fn error_code(name: &str) -> i32 {
    use RamfluxErrorCode as E;
    match name {
        "InvalidArgument" | "InvalidRequest" | "ValidationFailed" | "CustodySetupInvalid" => {
            E::InvalidArgument as i32
        }
        "InvalidCanonicalJson" => E::InvalidCanonicalJson as i32,
        "UnsupportedVersion" | "AccountSchemaTooNew" => E::UnsupportedVersion as i32,
        "AuthFailed" | "AccountLocked" | "Unauthenticated" | "TransportSecurity" => {
            E::AuthFailed as i32
        }
        "CapabilityRejected" => E::CapabilityRejected as i32,
        "ReplayRejected" | "ReplayMismatch" => E::ReplayRejected as i32,
        "McpGrantRejected" => E::McpGrantRejected as i32,
        "ObjectTransferFailed" => E::ObjectTransferFailed as i32,
        "DeviceRevoked" => E::DeviceRevoked as i32,
        "CryptoFailed" => E::CryptoFailed as i32,
        "StorageFailed" | "storage_unavailable" => E::StorageFailed as i32,
        "TransportUnavailable" | "NetworkingPending" | "Unavailable" | "NoNodeSelected" => {
            E::TransportUnavailable as i32
        }
        "Timeout" | "DeadlineExceeded" => E::Timeout as i32,
        "PermissionDenied" | "authorization_rejected" => E::PermissionDenied as i32,
        "RateLimited" => E::RateLimited as i32,
        "AccountBusy" | "DataRootInUse" | "account_busy" => E::AccountBusy as i32,
        "ObjectErased" => E::ObjectErased as i32,
        "ObjectIdentityConflict" => E::ObjectIdentityConflict as i32,
        "ObjectOwnershipUnverified" => E::ObjectOwnershipUnverified as i32,
        "CustodyForkFenced" => E::CustodyForkFenced as i32,
        "SchemaResetRequired" => E::SchemaResetRequired as i32,
        "resync_required" => RamfluxV2Status::ResyncRequired as i32,
        _ => E::Internal as i32,
    }
}

/// Erase and release a v2 output buffer exactly once. Null is accepted.
/// All v2 output buffers, including secret ceremony responses, must use this function.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_buffer_free(buffer: *mut RamfluxBuffer) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: callers transfer a live uniquely owned bridge buffer exactly once.
    let buffer = unsafe { Box::from_raw(buffer) };
    if !buffer.ptr.is_null() {
        let raw = std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
        // SAFETY: write_buffer allocated this exact boxed slice, including its length.
        let mut bytes = unsafe { Box::from_raw(raw) };
        zeroize::Zeroize::zeroize(bytes.as_mut());
    }
}

/// Clear the latched event gap only for the last successful subscription generation.
/// Pass 0 only before the first subscription. Stale generations return InvalidArgument=1.
/// Reopen bus.subscribe using the snapshot's journal cursor after this call.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_event_reset(handle: u64, subscription_generation: u64) -> i32 {
    call(|| {
        let client = client(handle)?;
        let mut events = client.shared.events.lock().map_err(|_| internal())?;
        if events.generation != subscription_generation {
            return Err(invalid("stale subscription generation"));
        }
        events.queue.clear();
        events.bytes = 0;
        events.resync = false;
        Ok(())
    })
}

/// Project shared conversation rows, bounded pages and unread/attention totals without opening a client.
/// Inputs are authoritative host snapshot facts; output buffers use `ramflux_v2_buffer_free`.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_conversation_project(
    input_json: *const u8,
    len: usize,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    call(|| {
        super::super::clear_out_ptr(out)?;
        let request: super::projection::Directory = input(input_json, len)?;
        let mut value = super::projection::directory(&request)?;
        let result = super::super::write_json_buffer(out, &value);
        crate::bus::inprocess::erase_value(&mut value);
        result
    })
}

/// Present an authoritative receipt with the shared model; incoming receipts return JSON null.
/// This never upgrades acceptance to delivery/read or authorizes an uncertain retry.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_receipt_present(
    input_json: *const u8,
    len: usize,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    call(|| {
        super::super::clear_out_ptr(out)?;
        let request: super::projection::ReceiptRequest = input(input_json, len)?;
        let mut value = super::projection::present(&request)?;
        let result = super::super::write_json_buffer(out, &value);
        crate::bus::inprocess::erase_value(&mut value);
        result
    })
}
