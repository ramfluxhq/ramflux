// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Version 2: bounded asynchronous requests through the process supervisor.
//! See docs/design/c-abi-v2.md for ownership, cancellation and wire contracts.

use super::super::{CAbiError, RamfluxBuffer, RamfluxErrorCode};
use super::runtime::{Client, CloseResult, Command};
use super::state::{self, MAX_FRAME_BYTES, MAX_OPERATIONS, Operation, OperationKind};
use crate::{LocalBusConfig, LocalBusFrame};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
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
    /// The client released its files. 28 and 29 belong to pairing on `RamfluxErrorCode`.
    /// A refused call had no business effects. An admitted call reports effects `unknown`.
    Suspended = 30,
    /// Host custody is locked, including before the first device unlock. No client was opened.
    VaultLocked = 31,
}

#[derive(Default)]
struct Registry {
    next: u64,
    opening: BTreeSet<std::path::PathBuf>,
    clients: BTreeMap<u64, Arc<Client>>,
}
static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));

#[derive(zeroize::ZeroizeOnDrop)]
pub(super) struct Config {
    #[zeroize(skip)]
    pub(super) diag: crate::diag::DiagnosticConfig,
    #[zeroize(skip)]
    pub(super) username_directory: Option<ramflux_protocol::username_directory::NativeDirectoryPin>,
    #[zeroize(skip)]
    pub(super) session_lease: Option<(crate::SessionLeasePriority, u64)>,
    pub(super) resume_wait_ms: Option<u64>,
    pub(super) allow_raw_messages: bool,
    pub(super) allow_secret_exports: bool,
    pub(super) data_root: String,
    pub(super) builtin_nodes: Vec<super::input_config::OwnedProfile>,
}

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
        zeroize::Zeroize::zeroize(&mut self.account_id);
        zeroize::Zeroize::zeroize(&mut self.sdk_api);
        zeroize::Zeroize::zeroize(&mut self.method);
        zeroize::Zeroize::zeroize(&mut self.operation_id);
    }
}

fn invalid(message: &str) -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, message)
}

/// A `message.submit` whose only content is Typing. Plaintext stays behind
/// `allow_raw_messages`. Any sibling field, or a message next to typing, does not qualify.
fn typing_only_submit(body: &serde_json::Value) -> bool {
    let Some(map) = body.as_object() else {
        return false;
    };
    if map.keys().any(|key| {
        !matches!(key.as_str(), "send" | "requestId" | "request_id" | "accountId" | "account_id")
    }) {
        return false;
    }
    let Some(send) = map.get("send").and_then(serde_json::Value::as_object) else {
        return false;
    };
    if send.keys().any(|key| {
        !matches!(
            key.as_str(),
            "conversationId" | "conversation_id" | "operationId" | "operation_id" | "content"
        )
    }) {
        return false;
    }
    let Some(content) = send.get("content").and_then(serde_json::Value::as_object) else {
        return false;
    };
    content.len() == 1 && content.contains_key("typing")
}

fn refuse_raw_submit(client: &Client, request: &Request) -> Result<(), CAbiError> {
    if request.method == "message.submit"
        && !client.shared.allow_raw_messages.load(std::sync::atomic::Ordering::Acquire)
        && !typing_only_submit(&request.body)
    {
        return Err(CAbiError::new(
            RamfluxErrorCode::PermissionDenied,
            "raw_message capability is disabled",
        ));
    }
    Ok(())
}
fn refuse_closed(client: &Client) -> Result<(), CAbiError> {
    if client.closing.load(std::sync::atomic::Ordering::Acquire)
        || client.shared.closed.load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(CAbiError::new(RamfluxErrorCode::TransportUnavailable, "client closed"));
    }
    Ok(())
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
pub(super) fn client(handle: u64) -> Result<Arc<Client>, CAbiError> {
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
#[allow(
    clippy::disallowed_methods,
    reason = "Native FFI unwind containment; abort profiles are refused"
)]
pub(super) fn call(action: impl FnOnce() -> Result<(), CAbiError>) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[cfg(test)]
        super::review_tests::maybe_panic();
        action()
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            let code = error.status.unwrap_or(error.code as i32);
            crate::diag::logging::refusal(
                &json!({"code":code,"name":super::native_error::status_name(i64::from(code)),"reason_code":"native_admission_refused","effects":"none"}),
            );
            code
        }
        Err(payload) => {
            // Arbitrary panic payload destructors may panic again. Never unwind from this boundary.
            std::mem::forget(payload);
            RamfluxErrorCode::PanicAborted as i32
        }
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
fn input<T: super::input::Decode>(ptr: *const u8, len: usize) -> Result<T, CAbiError> {
    if ptr.is_null() || len == 0 || len > MAX_FRAME_BYTES {
        return Err(invalid("input"));
    }
    // SAFETY: the host lends len readable bytes until this synchronous call returns.
    super::input::decode(unsafe { std::slice::from_raw_parts(ptr, len) })
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
        if major != 2 || min_minor > 1 {
            return Err(CAbiError::new(RamfluxErrorCode::UnsupportedVersion, "unsupported ABI"));
        }
        super::buffer::write_json_buffer(
            out,
            &json!({
                "abi_major":2,"abi_minor":1,"bus_protocol":"ramflux.local_bus.v1",
                "message_schema_generation":ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION,
                "message_descriptor_blake3":blake3::hash(crate::message::FILE_DESCRIPTOR_SET).to_hex().to_string(),
                "max_frame_bytes":MAX_FRAME_BYTES,"max_operations":MAX_OPERATIONS,
                "max_events":state::MAX_EVENTS,"max_event_bytes":state::MAX_EVENT_BYTES,
                "methods":crate::bus::inprocess::method_names().into_iter().filter(|name| super::method_policy::allowed(name)).collect::<Vec<_>>(),
            "method_policy":super::method_policy::manifest(),
                "card_runtime":super::card::metadata(),
                "voice_media":super::media::voice_media_capability(),
            }),
        )
    })
}

/// Open one supervisor on a dedicated thread. Config is `{data_root,builtin_nodes?,allow_raw_messages?,allow_secret_exports?,session_lease?}`.
/// The host must supply an existing private directory; see the shared-root contract.
/// This may block during startup; invoke off the UI thread. Output is zero on failure.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_client_open(
    config: *const u8,
    len: usize,
    out_client: *mut u64,
) -> i32 {
    open(config, len, out_client, None)
}

/// Open with trusted host OS credential storage (provider ABI version 1).
/// The table is borrowed only during this call; retained context lives through shutdown.
/// Custody preflight runs before startup; locked custody returns `VaultLocked` (31).
/// Mobile providers must allow background use after the first device unlock.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_client_open_with_custody(
    config: *const u8,
    len: usize,
    provider: *const super::custody::RamfluxV2CustodyProvider,
    out_client: *mut u64,
) -> i32 {
    call(|| {
        write_handle(out_client, 0)?;
        if provider.is_null() {
            return Err(invalid("provider"));
        }
        // SAFETY: the host supplies one valid aligned provider table during this call.
        let table = unsafe { provider.read() };
        let vault = super::custody::HostVault::new(table)
            .map_err(|error| super::super::map_sdk_error(&error))?;
        open_inner(config, len, out_client, Some(vault))
    })
}

fn open(
    config: *const u8,
    len: usize,
    out_client: *mut u64,
    vault: Option<Arc<dyn crate::custody::PrimaryVault + Send + Sync>>,
) -> i32 {
    call(|| open_inner(config, len, out_client, vault))
}

struct Opening(std::path::PathBuf);
impl Drop for Opening {
    fn drop(&mut self) {
        if let Ok(mut registry) = REGISTRY.lock() {
            registry.opening.remove(&self.0);
        }
    }
}

fn open_inner(
    config: *const u8,
    len: usize,
    out_client: *mut u64,
    vault: Option<Arc<dyn crate::custody::PrimaryVault + Send + Sync>>,
) -> Result<(), CAbiError> {
    write_handle(out_client, 0)?;
    let mut config: Config = input(config, len)?;
    if let Some(vault) = &vault {
        vault.preflight().map_err(|error| super::data_root::custody_error(&error))?;
    }
    let candidate_root = super::data_root::validate(&config.data_root)?;
    config.data_root = candidate_root.to_str().ok_or_else(|| invalid("data_root encoding"))?.into();
    // A registered root remains reserved until shutdown is acknowledged, even if
    // its OS lease is released just before the worker publishes completion.
    // No bridge registry lock spans filesystem I/O.
    let id = {
        let mut registry = REGISTRY.lock().map_err(|_| internal())?;
        if registry.opening.contains(&candidate_root)
            || registry.clients.values().any(|client| client.data_root == candidate_root)
        {
            return Err(CAbiError::new(
                RamfluxErrorCode::AccountBusy,
                "data root has a registered client",
            ));
        }
        if registry.clients.len().saturating_add(registry.opening.len()) >= 16 {
            return Err(busy());
        }
        let id = next_id(&mut registry)?;
        registry.opening.insert(candidate_root.clone());
        id
    };
    let _opening = Opening(candidate_root.clone());
    let diagnostics = crate::diag::start(&candidate_root, config.diag.clone())
        .map_err(|e| super::super::map_sdk_error(&e))?;
    let mut bus = LocalBusConfig::in_process(
        std::path::PathBuf::new(),
        std::mem::take(&mut config.data_root),
    );
    if let Some((priority, wait_ms)) = config.session_lease {
        bus = bus.with_session_lease(priority, std::time::Duration::from_millis(wait_ms));
    }
    if let Some(wait_ms) = config.resume_wait_ms {
        bus = bus.with_resume_wait(std::time::Duration::from_millis(wait_ms));
    }
    bus.builtin_nodes = std::mem::take(&mut config.builtin_nodes)
        .into_iter()
        .map(|mut profile| profile.take_node())
        .collect();
    bus.username_directory = config.username_directory.take();
    bus.custody_vault = vault;
    let started = Client::start_with_diagnostics(bus, diagnostics);
    let mut registry = REGISTRY.lock().map_err(|_| internal())?;
    let client = started.map_err(|error| super::super::map_sdk_error(&error))?;
    client
        .shared
        .allow_raw_messages
        .store(config.allow_raw_messages, std::sync::atomic::Ordering::Release);
    client
        .shared
        .allow_secret_exports
        .store(config.allow_secret_exports, std::sync::atomic::Ordering::Release);
    registry.clients.insert(id, client);
    write_handle(out_client, id)
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
            client.shared.credentials.shutdown();
            match client.close().map_err(|error| super::super::map_sdk_error(&error))? {
                CloseResult::Done => {
                    if let Some(diag) = &client.diagnostics {
                        diag.flush();
                    }
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

fn reject_request_shape(request: &Request) -> Result<(), CAbiError> {
    if request.method.contains("itest")
        || request.method.is_empty()
        || request.method.len() > 128
        || request.sdk_api.len() > 128
        || request.account_id.as_ref().is_some_and(|id| id.len() > 128)
        || request.operation_id.as_ref().is_some_and(|id| id.is_empty() || id.len() > 256)
    {
        return Err(invalid("invalid method"));
    }
    Ok(())
}

fn send_command(client: &Client, command: Command) -> Result<(), CAbiError> {
    client.commands.try_send(command).map_err(|error| {
        if matches!(error, tokio::sync::mpsc::error::TrySendError::Closed(_))
            || client.closing.load(std::sync::atomic::Ordering::Acquire)
            || client.shared.closed.load(std::sync::atomic::Ordering::Acquire)
        {
            CAbiError::new(RamfluxErrorCode::TransportUnavailable, "closed")
        } else {
            busy()
        }
    })
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
    let status = call(|| {
        write_handle(out_operation, 0)?;
        let mut request: Request = input(request, len)?;
        reject_request_shape(&request)?;
        if !super::method_policy::allowed(&request.method) {
            return Err(CAbiError::new(RamfluxErrorCode::PermissionDenied, "method"));
        }
        let client = client(handle)?;
        if super::method_policy::requires_key_export(&request.method)
            && !client.shared.allow_secret_exports.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(CAbiError::new(RamfluxErrorCode::PermissionDenied, "secret_export"));
        }
        refuse_raw_submit(&client, &request)?;
        if request.method == "contact.verify" {
            let digest = blake3::hash(crate::message::FILE_DESCRIPTOR_SET).to_hex().to_string();
            if !super::method_policy::loaded_cas_descriptor_matches(&digest) {
                return Err(CAbiError::new(
                    RamfluxErrorCode::CapabilityRejected,
                    "contact.verify.cas",
                ));
            }
        }
        refuse_closed(&client)?;
        let subscription = matches!(request.method.as_str(), "subscription.open" | "bus.subscribe");
        let id = next_id(&mut *REGISTRY.lock().map_err(|_| internal())?)?;
        let frame_method_close = request.method == "subscription.close";
        let deadline_ms = Some(request.deadline_ms);
        let attended_method = request.method.clone();
        let attended_account = request.account_id.clone();
        let access = super::app_lock::capture_access(
            &client.shared,
            &request.method,
            request.account_id.as_deref(),
        )
        .map_err(|_| internal())?;
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
        operation.state.lock().map_err(|_| internal())?.access = access;
        if attended_method == "call.media.open" {
            operation.state.lock().map_err(|_| internal())?.media_client = Some(handle);
        }
        operation.state.lock().map_err(|_| internal())?.kind = if subscription {
            OperationKind::Subscription
        } else if frame_method_close {
            OperationKind::SubscriptionClose
        } else {
            OperationKind::Request
        };
        let mut operations = client.shared.operations.lock().map_err(|_| internal())?;
        if client.shared.suspended.load(std::sync::atomic::Ordering::Acquire) {
            return Err(CAbiError::with_status(RamfluxV2Status::Suspended as i32, "suspended"));
        }
        if operations.len() >= MAX_OPERATIONS {
            return Err(busy());
        }
        let mut subscribed = client.shared.subscription.lock().map_err(|_| internal())?;
        if subscription && subscribed.is_some() {
            return Err(busy());
        }
        operations.insert(id, Arc::clone(&operation));
        if let Err(error) = send_command(
            &client,
            Command {
                id,
                bytes,
                operation,
                deadline_ms,
                method: attended_method,
                account_id: attended_account,
            },
        ) {
            operations.remove(&id);
            return Err(error);
        }
        if subscription {
            *subscribed = Some(id);
        }
        write_handle(out_operation, id)
    });
    if status == RamfluxErrorCode::TransportUnavailable as i32 {
        RamfluxV2Status::Closed as i32
    } else {
        status
    }
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
        let mut deliver = || {
            let state = operation.state.lock().map_err(|_| internal())?;
            if let Some(bytes) = &state.result {
                super::buffer::write_buffer(out, bytes.to_vec())?;
            } else {
                pending = true;
            }
            Ok(())
        };
        if let Some(fences) = client.shared.app_fences.get() {
            fences.serialize(deliver).map_err(|_| internal())?
        } else {
            deliver()
        }
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
                    .try_send(Command::carrier(
                        0,
                        zeroize::Zeroizing::new(bytes),
                        Arc::new(Operation::default()),
                        None,
                    ))
                    .map_err(|_| busy())?;
            }
            *subscribed = None;
            client.shared.deactivate_generation();
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
        client.shared.credentials.forget_username(id);
        Ok(())
    })
}

/// Authorize a username draft with the account master recovery phrase.
/// `phrase_bytes` is borrowed for this call and is not placed in JSON or logs.
/// Cancellation writes no signed output and does not submit. A lost submit reply
/// is reconciled with `username.status`; this function does not sign a replacement.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_username_authorize(
    handle: u64,
    public_request_json: *const u8,
    public_request_len: usize,
    phrase_bytes: *const u8,
    phrase_len: usize,
    out_signed_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    let mut cancelled = false;
    let code = call(|| {
        super::super::clear_out_ptr(out_signed_json)?;
        super::super::clear_out_ptr(out_error_json)?;
        let client = client(handle)?;
        cancelled = super::username::authorize(
            &client,
            &super::username::AuthorizeInput {
                public_json: public_request_json,
                public_len: public_request_len,
                phrase: phrase_bytes,
                phrase_len,
                out_signed: out_signed_json,
                out_error: out_error_json,
            },
        )?;
        Ok(())
    });
    if code == 0 && cancelled { RamfluxV2Status::Cancelled as i32 } else { code }
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
        let mut deliver = || {
            if let Some(bytes) = client.shared.controls.lock().map_err(|_| internal())?.pop_front()
            {
                super::buffer::write_buffer(out, bytes.to_vec())?;
                return Ok(());
            }
            let mut events = client.shared.events.lock().map_err(|_| internal())?;
            while events.queue.front().is_some_and(|event| {
                !events.active || event.generation == 0 || event.generation != events.generation
            }) {
                if let Some(event) = events.queue.pop_front() {
                    events.bytes = events.bytes.saturating_sub(event.bytes.len());
                }
            }
            if events.resync && events.active && events.generation != 0 {
                super::buffer::write_json_buffer(
                    out,
                    &json!({
                        "bus_protocol":"ramflux.local_bus.v1","frame_id":"c_abi_resync",
                        "kind":"event","request_id":"","sdk_api":"bus","method":"stream.lagged",
                        "account_id":events.account_id,"body":{"resync_required":true},
                        "subscription_generation":events.generation.to_string(),
                    }),
                )?;
                status = RamfluxV2Status::ResyncRequired as i32;
            } else if let Some(event) = events.queue.pop_front() {
                events.bytes = events.bytes.saturating_sub(event.bytes.len());
                super::buffer::write_buffer(out, event.bytes.to_vec())?;
            } else if client.shared.closed.load(std::sync::atomic::Ordering::Acquire) {
                status = RamfluxV2Status::Closed as i32;
            } else {
                status = RamfluxV2Status::Pending as i32;
            }
            Ok(())
        };
        if let Some(fences) = client.shared.app_fences.get() {
            fences.serialize(deliver).map_err(|_| internal())?
        } else {
            deliver()
        }
    });
    if code == 0 { status } else { code }
}

pub(super) fn failure(status: RamfluxV2Status, effects: &str) -> serde_json::Value {
    json!({"code":status as i32,"effects":effects})
}

pub(super) fn error_code(name: &str) -> i32 {
    use RamfluxErrorCode as E;
    match name {
        "InvalidArgument"
        | "InvalidRequest"
        | "ValidationFailed"
        | "CustodySetupInvalid"
        | "CustodyPublicationFailed"
        | "invalid_argument"
        | "invalid_json"
        | "payload_too_large"
        | "target_not_found"
        | "target_deleted"
        | "edit_conflict"
        | "field_invalid"
        | "confirmation_required"
        | "model_capabilities_unknown"
        | "prx_command"
        | "home_missing"
        | "memory_missing"
        | "provider_missing"
        | "runtime_invalid"
        | "runtime_mode"
        | "input_invalid"
        | "input_missing"
        | "prx_spawn"
        | "approval_decided"
        | "approval_unknown"
        | "approval_expired"
        | "approval_run_mismatch"
        | "authority_unavailable"
        | "layout_invalid"
        | "recipient_empty"
        | "not_grantee"
        | "not_owner"
        | "not_ready"
        | "stream_closed"
        | "stream_offset"
        | "digest_mismatch"
        | "seal_failed"
        | "upload_rejected"
        | "stale_generation"
        | "duplicate_operation"
        | "path_refused"
        | "file_too_large"
        | "manifest_too_large"
        | "recipient_limit"
        | "expired"
        | "cancelled"
        | "retirement_pending"
        | "large_attachments" => E::InvalidArgument as i32,
        "InvalidCanonicalJson" => E::InvalidCanonicalJson as i32,
        "UnsupportedVersion"
        | "AccountSchemaTooNew"
        | "peer_upgrade_required"
        | "manifest_unavailable"
        | "unsupported_platform" => E::UnsupportedVersion as i32,
        name if super::native_error::auth_failure(name) => E::AuthFailed as i32,
        "CapabilityRejected" | "push_route_refused" => E::CapabilityRejected as i32,
        "ReplayRejected" | "ReplayMismatch" => E::ReplayRejected as i32,
        "McpGrantRejected" => E::McpGrantRejected as i32,
        "ObjectTransferFailed" => E::ObjectTransferFailed as i32,
        "DeviceRevoked" => E::DeviceRevoked as i32,
        "CryptoFailed" | "crypto_failure" => E::CryptoFailed as i32,
        "StorageFailed" | "storage_unavailable" | "storage_capacity" | "disk_full" => {
            E::StorageFailed as i32
        }
        "TransportUnavailable"
        | "NetworkingPending"
        | "Unavailable"
        | "NoNodeSelected"
        | "not_connected"
        | "ephemeral_unavailable"
        | "runtime_missing"
        | "prx_missing"
        | "runtime_stale" => E::TransportUnavailable as i32,
        "Timeout" | "DeadlineExceeded" => E::Timeout as i32,
        "PermissionDenied"
        | "authorization_rejected"
        | "not_authorized"
        | "desktop_required"
        | "ancestor_rejected" => E::PermissionDenied as i32,
        "RateLimited" | "rate_limited" | "Busy" | "quota_exceeded" => E::RateLimited as i32,
        "AccountBusy" | "DataRootInUse" | "account_busy" | "SessionLeaseBusy" => {
            E::AccountBusy as i32
        }
        "ObjectErased" | "attachment_deleted" => E::ObjectErased as i32,
        "ObjectIdentityConflict" => E::ObjectIdentityConflict as i32,
        "ObjectOwnershipUnverified" => E::ObjectOwnershipUnverified as i32,
        "CustodyForkFenced" => E::CustodyForkFenced as i32,
        "SchemaResetRequired" | "schema_reset_required" => E::SchemaResetRequired as i32,
        "resync_required" => RamfluxV2Status::ResyncRequired as i32,
        "ClientSuspended" => RamfluxV2Status::Suspended as i32,
        _ => E::Internal as i32,
    }
}

/// Erase and release a v2 output buffer exactly once. Null is accepted.
/// All v2 output buffers, including secret ceremony responses, must use this function.
/// Never use the v1 `ramflux_buffer_free`: it does not erase secret bytes.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_buffer_free(buffer: *mut RamfluxBuffer) {
    let _ = call(|| {
        if buffer.is_null() {
            return Ok(());
        }
        // SAFETY: callers transfer a live uniquely owned bridge buffer exactly once.
        let buffer = unsafe { Box::from_raw(buffer) };
        if !buffer.ptr.is_null() {
            let raw = std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
            // SAFETY: write_buffer allocated this exact boxed slice, including its length.
            let mut bytes = unsafe { Box::from_raw(raw) };
            zeroize::Zeroize::zeroize(bytes.as_mut());
        }
        Ok(())
    });
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
        let result = super::buffer::write_json_buffer(out, &value);
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
        let result = super::buffer::write_json_buffer(out, &value);
        crate::bus::inprocess::erase_value(&mut value);
        result
    })
}

/// Return the SDK-bundled public card trust package, signed descriptor and host presentation assets.
/// Hosts independently pin its manifest digest and policy in their signed application release.
/// The owned JSON output uses `ramflux_v2_buffer_free`; no account or renderer is opened.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_card_trust_package(out: *mut *mut RamfluxBuffer) -> i32 {
    call(|| {
        super::super::clear_out_ptr(out)?;
        let value =
            super::card::trust_package().map_err(|error| super::super::map_sdk_error(&error))?;
        super::buffer::write_json_buffer(out, &value)
    })
}

/// Install or clear the in-process account-code callback.
/// Host output capacities are 1024 bytes; SDK storage is zeroized on every path.
/// Setup requires the code twice and the copies must match. Unlock and phrase take one copy.
/// A null callback unregisters and drains. The host must not reenter this client from the
/// callback. Close and replacement wait until the callback returns.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_set_credential_provider(
    handle: u64,
    callback: super::super::pairing::CredentialProviderCallback,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    call(|| {
        let client = client(handle)?;
        if client.closing.load(std::sync::atomic::Ordering::Acquire)
            || client.shared.closed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(CAbiError::new(RamfluxErrorCode::TransportUnavailable, "client closed"));
        }
        let next = callback.map(|callback| {
            Arc::new(super::super::pairing::CallbackProvider::new(
                client.data_root.clone(),
                callback,
                user_data,
            ))
        });
        client.shared.credentials.replace(next).map_err(|error| super::super::map_sdk_error(&error))
    })
}

#[cfg(test)]
pub(super) fn test_shared(handle: u64) -> Arc<super::state::Shared> {
    Arc::clone(&client(handle).expect("test: live client").shared)
}

impl super::input::Decode for Request {
    fn decode(value: &mut serde_json::Value) -> Result<Self, CAbiError> {
        use super::input as i;
        i::object(
            value,
            &["account_id", "sdk_api", "method", "body", "deadline_ms", "operation_id"],
        )?;
        let account = i::optional(value, "account_id")?;
        let api = i::string(value, "sdk_api")?;
        let method = i::string(value, "method")?;
        let operation = i::optional(value, "operation_id")?;
        let deadline =
            value.get("deadline_ms").and_then(serde_json::Value::as_u64).ok_or_else(i::invalid)?;
        if value.get("body").is_none() {
            return Err(i::invalid());
        }
        // All schema checks precede allocation/transfer; no partially built request can fail.
        let result = Self {
            account_id: account.map(str::to_owned),
            sdk_api: api.into(),
            method: method.into(),
            body: serde_json::Value::Null,
            deadline_ms: deadline,
            operation_id: operation.map(str::to_owned),
        };
        let mut result = result;
        result.body =
            value.as_object_mut().and_then(|map| map.remove("body")).ok_or_else(i::invalid)?;
        Ok(result)
    }
}

/// Install or clear the provider-key callback for `agent.host.credential`.
/// The callback receives the provider id and writes the key into `out`. Return 0 when provided
/// and 1 when refused. A null callback clears the slot. The key is never placed in JSON.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_set_host_credential_provider(
    handle: u64,
    callback: Option<
        extern "C" fn(*const u8, usize, *mut u8, usize, *mut usize, *mut std::ffi::c_void) -> i32,
    >,
    user: *mut std::ffi::c_void,
) -> i32 {
    call(|| {
        let client = client(handle)?;
        let mut slot = client.shared.host_key.lock().map_err(|_| internal())?;
        *slot = callback.map(|call| super::state::HostKeyFn { call, user: user as usize });
        Ok(())
    })
}

/// Return the build-pinned diagnostic support public key catalog, without opening an account.
/// An unprovisioned build returns available=false. Free output with `ramflux_v2_buffer_free`.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_diag_support_key(out: *mut *mut RamfluxBuffer) -> i32 {
    call(|| {
        super::super::clear_out_ptr(out)?;
        let bytes = include_bytes!("../../../diag/support-public-keys.v1.json");
        let catalog = ramflux_protocol::diag_support::Catalog::decode(bytes);
        match catalog {
            Ok(catalog) if catalog.active_epoch.is_some() => {
                super::buffer::write_json_buffer(out, &catalog)
            }
            _ => super::buffer::write_json_buffer(
                out,
                &serde_json::json!({
                    "available": false, "reason": "support_key_unavailable"
                }),
            ),
        }
    })
}
