// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The exported `ramflux_v2_*` symbols. Each one is a panic guard around a safe function.

use super::driver::{
    CancelFlag, Driver, ExecuteJob, Job, Stage, WAITER_GRACE, wait_reply,
};
use super::error::{Effect, V2Error, V2Result, write_error};
use super::host::CoreHost;
use super::subscription::{EventQueue, OPEN_DEADLINE, SubscribeJob, Terminal, unix_deadline};
use super::types::{
    DEFAULT_QUEUE_EVENTS, MAX_FRAME_BYTES, MAX_QUEUE_EVENTS, RAMFLUX_V2_ABI_MAJOR,
    RAMFLUX_V2_ABI_MINOR, RamfluxV2Cancel, RamfluxV2Config, RamfluxV2Core, RamfluxV2Request,
    RamfluxV2SubscribeOptions, RamfluxV2Subscription, RamfluxV2Version, bounded_bytes,
    declared_size, optional_text, read_versioned, required_text,
};
use super::super::{
    PROTOCOL_VERSION, RamfluxBuffer, RamfluxErrorCode, clear_optional_out_error, clear_out_ptr,
    write_buffer, write_json_buffer, write_out_ptr,
};
use crate::{LifecycleState, LocalBusFrame, LocalBusFrameKind};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::time::{Duration, Instant};

/// OPEN-VALUE: deadline of a request that names none.
const DEFAULT_REQUEST_DEADLINE: Duration = Duration::from_secs(30);

pub(super) struct CoreInner {
    host: Arc<dyn CoreHost>,
    driver: Driver,
    closing: AtomicBool,
    request_deadline: Duration,
    suspend_deadline: Duration,
    next_request: AtomicU64,
}

impl CoreInner {
    pub(super) fn with_host(
        host: Arc<dyn CoreHost>,
        request_deadline: Duration,
        suspend_deadline: Duration,
    ) -> V2Result<Arc<Self>> {
        let driver = Driver::start(Arc::clone(&host))?;
        Ok(Arc::new(Self {
            host,
            driver,
            closing: AtomicBool::new(false),
            request_deadline,
            suspend_deadline,
            next_request: AtomicU64::new(1),
        }))
    }

    fn admit(&self) -> V2Result<()> {
        if self.closing.load(Ordering::Acquire) {
            return Err(V2Error::closed(Effect::None));
        }
        Ok(())
    }

    /// Close admission, end the shim thread and stop the supervisor. Idempotent.
    pub(super) fn close(&self) -> V2Result<()> {
        if self.closing.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.driver.shutdown();
        self.host.stop().map_err(|error| V2Error::from_sdk(&error, Effect::None))
    }

    pub(super) fn execute(
        &self,
        mut frame: LocalBusFrame,
        cancel: Option<&CancelFlag>,
    ) -> V2Result<serde_json::Value> {
        self.admit()?;
        if cancel.is_some_and(CancelFlag::is_cancelled) {
            return Err(V2Error::cancelled(Effect::None));
        }
        let now_ms = unix_deadline(Duration::ZERO).unwrap_or(0);
        let deadline_ms = match frame.deadline_ms {
            Some(deadline) => deadline,
            None => unix_deadline(self.request_deadline).ok_or_else(|| {
                V2Error::new(RamfluxErrorCode::Internal, "system clock is before the Unix epoch")
            })?,
        };
        if deadline_ms <= now_ms {
            return Err(V2Error::deadline(Effect::None));
        }
        frame.deadline_ms = Some(deadline_ms);
        let wait_until =
            Instant::now() + Duration::from_millis(deadline_ms - now_ms) + WAITER_GRACE;
        let stage = Arc::new(Stage::default());
        let (reply, answer) = sync_channel(1);
        self.driver.submit(Job::Execute(ExecuteJob {
            frame: Some(frame),
            stage: Arc::clone(&stage),
            reply,
        }))?;
        let frame = wait_reply(&answer, &stage, cancel, wait_until)?;
        if frame.kind == LocalBusFrameKind::Error {
            return Err(V2Error::from_refusal(frame.error));
        }
        Ok(frame.body)
    }

    fn subscribe(
        &self,
        account_id: Option<String>,
        body: serde_json::Value,
        capacity: usize,
    ) -> V2Result<Arc<EventQueue>> {
        self.admit()?;
        let queue = EventQueue::new(capacity);
        let (opened, wait) = sync_channel(1);
        self.driver.submit(Job::Subscribe(SubscribeJob {
            account_id,
            body,
            queue: Arc::clone(&queue),
            opened,
        }))?;
        match wait.recv_timeout(OPEN_DEADLINE + WAITER_GRACE) {
            Ok(Ok(())) => Ok(queue),
            Ok(Err(error)) => Err(V2Error::from_sdk(&error, Effect::Refused)),
            Err(_) => {
                queue.terminate(Terminal::Cancelled);
                Err(V2Error::deadline(Effect::None))
            }
        }
    }
}

fn guard(out_error_json: *mut *mut RamfluxBuffer, function: impl FnOnce() -> V2Result<()>) -> i32 {
    clear_optional_out_error(out_error_json);
    match catch_unwind(AssertUnwindSafe(function)) {
        Ok(Ok(())) => RamfluxErrorCode::Ok as i32,
        Ok(Err(error)) => {
            write_error(out_error_json, &error);
            error.code as i32
        }
        Err(_panic) => {
            let error =
                V2Error::new(RamfluxErrorCode::PanicAborted, "panic crossed the C ABI boundary")
                    .with_effect(Effect::Unknown);
            write_error(out_error_json, &error);
            RamfluxErrorCode::PanicAborted as i32
        }
    }
}

/// Borrow a core handle for one call. The clone keeps the core alive for the call even
/// when another thread closes it; `ramflux_v2_core_free` must not race with any call.
fn core(handle: *mut RamfluxV2Core) -> V2Result<Arc<CoreInner>> {
    if handle.is_null() {
        return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "core handle is null"));
    }
    Ok(Arc::clone(unsafe { &*handle.cast::<Arc<CoreInner>>() }))
}

fn queue(handle: *mut RamfluxV2Subscription) -> V2Result<Arc<EventQueue>> {
    if handle.is_null() {
        return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "subscription is null"));
    }
    Ok(Arc::clone(unsafe { &*handle.cast::<Arc<EventQueue>>() }))
}

fn millis(value: u32, default: Duration) -> Duration {
    if value == 0 { default } else { Duration::from_millis(u64::from(value)) }
}

/// Report the ABI this core implements. `out_version->struct_size` is set by the host.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_abi_version(out_version: *mut RamfluxV2Version) -> i32 {
    guard(std::ptr::null_mut(), || {
        let declared = declared_size(out_version.cast_const())?;
        let version = RamfluxV2Version {
            struct_size: u32::try_from(declared).unwrap_or(0),
            abi_major: RAMFLUX_V2_ABI_MAJOR,
            abi_minor: RAMFLUX_V2_ABI_MINOR,
            protocol_version: PROTOCOL_VERSION,
            max_frame_bytes: MAX_FRAME_BYTES,
            max_queue_events: MAX_QUEUE_EVENTS,
            // OPEN-VALUE: no generated descriptor is compiled in yet.
            descriptor_fingerprint: [0; 32],
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&raw const version).cast::<u8>(),
                out_version.cast::<u8>(),
                declared,
            );
        }
        Ok(())
    })
}

/// Create a stopped supervisor for a data root. Nothing is opened until `core_start`.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_core_new(
    config: *const RamfluxV2Config,
    out_core: *mut *mut RamfluxV2Core,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        clear_out_ptr(out_core)?;
        let config = read_versioned(config)?;
        if config.host_abi_major != RAMFLUX_V2_ABI_MAJOR
            || config.host_abi_minor > RAMFLUX_V2_ABI_MINOR
        {
            return Err(V2Error::new(
                RamfluxErrorCode::UnsupportedVersion,
                "host was built against an ABI this core does not implement",
            ));
        }
        if config.flags != 0 {
            return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "reserved flags are set"));
        }
        let data_root = required_text(config.data_root, config.data_root_len, "data_root")?;
        let suspend = (config.suspend_deadline_ms != 0)
            .then(|| Duration::from_millis(u64::from(config.suspend_deadline_ms)));
        let host = production_host(data_root.into(), suspend)?;
        let inner = CoreInner::with_host(
            host,
            millis(config.request_deadline_ms, DEFAULT_REQUEST_DEADLINE),
            suspend.unwrap_or(Duration::from_secs(10)),
        )?;
        write_out_ptr(out_core, Box::into_raw(Box::new(inner)).cast::<RamfluxV2Core>())?;
        Ok(())
    })
}

#[cfg(unix)]
fn production_host(
    data_root: std::path::PathBuf,
    suspend_deadline: Option<Duration>,
) -> V2Result<Arc<dyn CoreHost>> {
    Ok(super::host::embedded(data_root, suspend_deadline))
}

#[cfg(not(unix))]
fn production_host(
    _data_root: std::path::PathBuf,
    _suspend_deadline: Option<Duration>,
) -> V2Result<Arc<dyn CoreHost>> {
    Err(V2Error::new(
        RamfluxErrorCode::UnsupportedVersion,
        "no in-process supervisor exists for this platform",
    ))
}

/// Acquire the data-root lock and start the supervisor.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_core_start(
    core_handle: *mut RamfluxV2Core,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        let inner = core(core_handle)?;
        inner.admit()?;
        inner.host.start().map_err(|error| V2Error::from_sdk(&error, Effect::None))
    })
}

/// Close every store and release every file lock. Returns only after the release was
/// observed. `out_report_json` is optional.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_core_suspend(
    core_handle: *mut RamfluxV2Core,
    out_report_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        if !out_report_json.is_null() {
            clear_out_ptr(out_report_json)?;
        }
        let inner = core(core_handle)?;
        inner.admit()?;
        // The shim's own connections go first, so nothing of ours outlives the stores.
        inner.driver.disconnect(inner.suspend_deadline)?;
        let report =
            inner.host.suspend().map_err(|error| V2Error::from_sdk(&error, Effect::None))?;
        if !out_report_json.is_null() {
            let elapsed_ms = u64::try_from(report.elapsed.as_millis()).unwrap_or(u64::MAX);
            write_json_buffer(
                out_report_json,
                &serde_json::json!({
                    "supervisor_joined": report.supervisor_joined,
                    "data_root_lock_released": report.data_root_lock_released,
                    "elapsed_ms": elapsed_ms.to_string(),
                }),
            )?;
        }
        Ok(())
    })
}

/// Reacquire the data-root lock and restart the supervisor after a suspension.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_core_resume(
    core_handle: *mut RamfluxV2Core,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        let inner = core(core_handle)?;
        inner.admit()?;
        inner.host.resume().map_err(|error| V2Error::from_sdk(&error, Effect::None))
    })
}

/// Stop the supervisor. Legal from every state; the handle can be started again.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_core_stop(
    core_handle: *mut RamfluxV2Core,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        let inner = core(core_handle)?;
        inner.admit()?;
        inner.driver.disconnect(inner.suspend_deadline)?;
        inner.host.stop().map_err(|error| V2Error::from_sdk(&error, Effect::None))
    })
}

/// Write 0 (stopped), 1 (running) or 2 (suspended).
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_core_state(core_handle: *mut RamfluxV2Core, out_state: *mut u32) -> i32 {
    guard(std::ptr::null_mut(), || {
        if out_state.is_null() {
            return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "out_state is null"));
        }
        let state = match core(core_handle)?.host.state() {
            LifecycleState::Stopped => 0,
            LifecycleState::Running => 1,
            LifecycleState::Suspended => 2,
        };
        unsafe {
            *out_state = state;
        }
        Ok(())
    })
}

/// Execute one request through the supervisor and wait for its answer.
///
/// On success `out_response_json` receives the response body. On failure the error JSON
/// names the `effect`: `none`, `refused` or `unknown`.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_execute(
    core_handle: *mut RamfluxV2Core,
    request: *const RamfluxV2Request,
    out_response_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        clear_out_ptr(out_response_json)?;
        let inner = core(core_handle)?;
        let request = read_versioned(request)?;
        if request.flags != 0 {
            return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "reserved flags are set"));
        }
        let method = required_text(request.method, request.method_len, "method")?;
        let sdk_api = required_text(request.sdk_api, request.sdk_api_len, "sdk_api")?;
        let account_id = optional_text(request.account_id, request.account_id_len, "account_id")?;
        let operation_id =
            optional_text(request.operation_id, request.operation_id_len, "operation_id")?;
        let body = parse_body(request.body_json, request.body_json_len)?;
        let cancel = (!request.cancel.is_null())
            .then(|| Arc::clone(unsafe { &*request.cancel.cast::<Arc<CancelFlag>>() }));
        let id = inner.next_request.fetch_add(1, Ordering::Relaxed);
        let mut frame =
            LocalBusFrame::request(format!("cabi-v2-{id}"), account_id, sdk_api, method, body);
        // The host's key, or none. The shim never invents one and never resends.
        frame.operation_id = operation_id;
        frame.deadline_ms = (request.deadline_unix_ms != 0).then_some(request.deadline_unix_ms);
        let response = inner.execute(frame, cancel.as_deref())?;
        write_json_buffer(out_response_json, &response)?;
        Ok(())
    })
}

fn parse_body(pointer: *const u8, len: usize) -> V2Result<serde_json::Value> {
    if len == 0 {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    let bytes = zeroize::Zeroizing::new(bounded_bytes(pointer, len, "body_json")?);
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        V2Error::new(RamfluxErrorCode::InvalidCanonicalJson, "body_json is not valid JSON")
    })?;
    if !value.is_object() {
        return Err(V2Error::new(
            RamfluxErrorCode::InvalidCanonicalJson,
            "body_json must be a JSON object",
        ));
    }
    Ok(value)
}

/// Create a cancel handle.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_cancel_new(out_cancel: *mut *mut RamfluxV2Cancel) -> i32 {
    guard(std::ptr::null_mut(), || {
        clear_out_ptr(out_cancel)?;
        let flag = Box::new(Arc::new(CancelFlag::default()));
        write_out_ptr(out_cancel, Box::into_raw(flag).cast::<RamfluxV2Cancel>())?;
        Ok(())
    })
}

/// Cancel every request that names this handle. A request not yet handed to the supervisor
/// has no effect; one already handed over keeps running and reports `effect = "unknown"`.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_cancel(cancel: *mut RamfluxV2Cancel) -> i32 {
    guard(std::ptr::null_mut(), || {
        if cancel.is_null() {
            return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "cancel handle is null"));
        }
        unsafe { &*cancel.cast::<Arc<CancelFlag>>() }.cancel();
        Ok(())
    })
}

/// Release a cancel handle. Requests that still name it keep their own reference.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_cancel_free(cancel: *mut RamfluxV2Cancel) {
    let _ignored = catch_unwind(AssertUnwindSafe(|| {
        if !cancel.is_null() {
            drop(unsafe { Box::from_raw(cancel.cast::<Arc<CancelFlag>>()) });
        }
    }));
}

/// Open a subscription with a bounded queue.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_subscribe(
    core_handle: *mut RamfluxV2Core,
    options: *const RamfluxV2SubscribeOptions,
    out_subscription: *mut *mut RamfluxV2Subscription,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        clear_out_ptr(out_subscription)?;
        let inner = core(core_handle)?;
        let options = read_versioned(options)?;
        let capacity = match options.queue_capacity {
            0 => DEFAULT_QUEUE_EVENTS,
            value if value <= MAX_QUEUE_EVENTS => value,
            _ => {
                return Err(V2Error::new(
                    RamfluxErrorCode::InvalidArgument,
                    "queue_capacity exceeds the limit reported by ramflux_v2_abi_version",
                ));
            }
        };
        let account_id = optional_text(options.account_id, options.account_id_len, "account_id")?;
        let body = parse_body(options.body_json, options.body_json_len)?;
        let queue =
            inner.subscribe(account_id, body, usize::try_from(capacity).unwrap_or(64))?;
        write_out_ptr(
            out_subscription,
            Box::into_raw(Box::new(queue)).cast::<RamfluxV2Subscription>(),
        )?;
        Ok(())
    })
}

/// Take up to `max_events` events, blocking at most `timeout_ms` when none is queued.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_subscription_poll(
    subscription: *mut RamfluxV2Subscription,
    max_events: u32,
    timeout_ms: u32,
    out_events_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        clear_out_ptr(out_events_json)?;
        let events =
            queue(subscription)?.poll(max_events, Duration::from_millis(u64::from(timeout_ms)))?;
        write_buffer(out_events_json, events)?;
        Ok(())
    })
}

/// End a subscription. A blocked poll returns with the terminal `cancelled` record.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_subscription_cancel(subscription: *mut RamfluxV2Subscription) -> i32 {
    guard(std::ptr::null_mut(), || {
        queue(subscription)?.terminate(Terminal::Cancelled);
        Ok(())
    })
}

/// Cancel and release a subscription. Must not race with a poll on the same handle.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_subscription_free(subscription: *mut RamfluxV2Subscription) {
    let _ignored = catch_unwind(AssertUnwindSafe(|| {
        if subscription.is_null() {
            return;
        }
        let queue = unsafe { Box::from_raw(subscription.cast::<Arc<EventQueue>>()) };
        queue.terminate(Terminal::Cancelled);
    }));
}

/// Close admission, fail waiters with `closed`, and stop the supervisor. Idempotent.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_core_close(
    core_handle: *mut RamfluxV2Core,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || core(core_handle)?.close())
}

/// Close and release a core. Must not race with any other call on the same handle.
/// Subscriptions and cancel handles stay valid and are freed on their own.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_core_free(core_handle: *mut RamfluxV2Core) {
    let _ignored = catch_unwind(AssertUnwindSafe(|| {
        if core_handle.is_null() {
            return;
        }
        let inner = unsafe { Box::from_raw(core_handle.cast::<Arc<CoreInner>>()) };
        let _ignored = inner.close();
    }));
}

/// Erase and release a buffer that held secret material, such as a recovery secret.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_buffer_wipe_free(buffer: *mut RamfluxBuffer) {
    let _ignored = catch_unwind(AssertUnwindSafe(|| {
        if buffer.is_null() {
            return;
        }
        let owned = unsafe { &*buffer };
        if !owned.ptr.is_null() && owned.len > 0 {
            use zeroize::Zeroize;
            unsafe { std::slice::from_raw_parts_mut(owned.ptr, owned.len) }.zeroize();
        }
        super::super::ramflux_buffer_free(buffer);
    }));
}
