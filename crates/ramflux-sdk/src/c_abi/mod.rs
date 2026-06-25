#![allow(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::{RamfluxClient as RustRamfluxClient, SdkError};
use ramflux_sync::{McpGrantState, McpToolManifest, RiskLevel, parse_mcp_capability};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::os::raw::c_uchar;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

const ABI_VERSION_MAJOR: u32 = 1;
const ABI_VERSION_MINOR: u32 = 0;
const PROTOCOL_VERSION: u32 = 1;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamfluxErrorCode {
    Ok = 0,
    InvalidArgument = 1,
    InvalidCanonicalJson = 2,
    UnsupportedVersion = 3,
    CapabilityRejected = 4,
    AuthFailed = 5,
    DeviceRevoked = 6,
    CryptoFailed = 7,
    StorageFailed = 8,
    TransportUnavailable = 9,
    Timeout = 10,
    ReplayRejected = 11,
    PermissionDenied = 12,
    McpGrantRejected = 13,
    ObjectTransferFailed = 14,
    RateLimited = 15,
    Internal = 16,
    PanicAborted = 17,
}

impl RamfluxErrorCode {
    const fn name(self) -> &'static str {
        match self {
            Self::Ok => "Ok",
            Self::InvalidArgument => "InvalidArgument",
            Self::InvalidCanonicalJson => "InvalidCanonicalJson",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::CapabilityRejected => "CapabilityRejected",
            Self::AuthFailed => "AuthFailed",
            Self::DeviceRevoked => "DeviceRevoked",
            Self::CryptoFailed => "CryptoFailed",
            Self::StorageFailed => "StorageFailed",
            Self::TransportUnavailable => "TransportUnavailable",
            Self::Timeout => "Timeout",
            Self::ReplayRejected => "ReplayRejected",
            Self::PermissionDenied => "PermissionDenied",
            Self::McpGrantRejected => "McpGrantRejected",
            Self::ObjectTransferFailed => "ObjectTransferFailed",
            Self::RateLimited => "RateLimited",
            Self::Internal => "Internal",
            Self::PanicAborted => "PanicAborted",
        }
    }
}

#[repr(C)]
pub struct RamfluxBuffer {
    pub ptr: *mut c_uchar,
    pub len: usize,
}

#[repr(C)]
pub struct RamfluxClient {
    _private: [u8; 0],
}

#[repr(C)]
pub struct RamfluxEventQueue {
    _private: [u8; 0],
}

struct CAbiClientInner {
    runtime: tokio::runtime::Runtime,
    client: Mutex<RustRamfluxClient>,
    event_bus: Arc<CAbiEventBus>,
    closing: AtomicBool,
    next_operation_id: AtomicU64,
}

struct CAbiEventBus {
    queue: Mutex<VecDeque<Value>>,
}

struct CAbiEventQueue {
    event_bus: Arc<CAbiEventBus>,
    polling: AtomicBool,
}

#[derive(Debug)]
struct CAbiError {
    code: RamfluxErrorCode,
    message: String,
}

type CAbiResult<T> = Result<T, CAbiError>;

#[derive(Deserialize)]
struct ClientConfigJson {
    account_root: String,
}

#[derive(Deserialize)]
struct CapabilityRequestJson {
    sdk_abi_version: u32,
    protocol_version: u32,
    min_protocol_version: u32,
    #[serde(default)]
    supported_transports: Vec<String>,
}

#[derive(Deserialize)]
struct UnlockAccountJson {
    local_account_id: String,
    account_secret: String,
}

#[derive(Deserialize)]
struct AppendEventJson {
    event_id: String,
    event_type: String,
    body_base64: String,
}

#[derive(Deserialize)]
struct ReadProjectionJson {
    event_id: Option<String>,
    projection_name: Option<String>,
}

#[derive(Deserialize)]
struct ValidateMcpGrantJson {
    server_id: String,
    tool_name: String,
    capability: String,
    #[serde(default)]
    tool_scope: Option<String>,
    declared_risk: RiskLevel,
    grant: McpGrantState,
}

#[derive(Deserialize)]
struct PutObjectJson {
    object_id: String,
    plaintext_base64: String,
}

#[derive(Serialize)]
struct ErrorJson<'a> {
    code: i32,
    name: &'a str,
    message: &'a str,
    retry_after_ms: Option<u64>,
    correlation_id: String,
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_sdk_abi_version_major() -> u32 {
    catch_unwind(|| ABI_VERSION_MAJOR).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_sdk_abi_version_minor() -> u32 {
    catch_unwind(|| ABI_VERSION_MINOR).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_sdk_protocol_version() -> u32 {
    catch_unwind(|| PROTOCOL_VERSION).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_new(
    config_json: *const c_uchar,
    config_json_len: usize,
    out_client: *mut *mut RamfluxClient,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_client)?;
        let config: ClientConfigJson = parse_json_input(config_json, config_json_len)?;
        let mut client = RustRamfluxClient::new();
        client.open_account_index(&config.account_root).map_err(|error| map_sdk_error(&error))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|source| CAbiError::new(RamfluxErrorCode::Internal, source.to_string()))?;
        let inner = Box::new(CAbiClientInner {
            runtime,
            client: Mutex::new(client),
            event_bus: Arc::new(CAbiEventBus { queue: Mutex::new(VecDeque::new()) }),
            closing: AtomicBool::new(false),
            next_operation_id: AtomicU64::new(1),
        });
        write_out_ptr(out_client, Box::into_raw(inner).cast::<RamfluxClient>())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_close(
    client: *mut RamfluxClient,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        let inner = client_inner(client)?;
        close_inner(inner);
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_free(client: *mut RamfluxClient) {
    let _ignored = catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return;
        }
        let inner = unsafe { Box::from_raw(client.cast::<CAbiClientInner>()) };
        close_inner(&inner);
    }));
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_buffer_free(buffer: *mut RamfluxBuffer) {
    let _ignored = catch_unwind(AssertUnwindSafe(|| {
        if buffer.is_null() {
            return;
        }
        let buffer = unsafe { Box::from_raw(buffer) };
        if !buffer.ptr.is_null() && buffer.len > 0 {
            let slice = ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
            let _bytes = unsafe { Box::from_raw(slice) };
        }
    }));
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_event_queue_new(
    client: *mut RamfluxClient,
    out_queue: *mut *mut RamfluxEventQueue,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_queue)?;
        let inner = client_inner(client)?;
        let queue = Box::new(CAbiEventQueue {
            event_bus: Arc::clone(&inner.event_bus),
            polling: AtomicBool::new(false),
        });
        write_out_ptr(out_queue, Box::into_raw(queue).cast::<RamfluxEventQueue>())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_event_queue_poll(
    queue: *mut RamfluxEventQueue,
    max_events: u32,
    out_events_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_events_json)?;
        let queue = event_queue(queue)?;
        if queue.polling.swap(true, Ordering::AcqRel) {
            return Err(CAbiError::new(
                RamfluxErrorCode::RateLimited,
                "event queue is already being polled",
            ));
        }
        let result = poll_events(queue, max_events);
        queue.polling.store(false, Ordering::Release);
        let events = result?;
        write_json_buffer(out_events_json, &events)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_event_queue_free(queue: *mut RamfluxEventQueue) {
    let _ignored = catch_unwind(AssertUnwindSafe(|| {
        if queue.is_null() {
            return;
        }
        let _queue = unsafe { Box::from_raw(queue.cast::<CAbiEventQueue>()) };
    }));
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_negotiate_capabilities(
    client: *mut RamfluxClient,
    request_json: *const c_uchar,
    request_json_len: usize,
    out_decision_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_decision_json)?;
        let inner = client_inner(client)?;
        let request: CapabilityRequestJson = parse_json_input(request_json, request_json_len)?;
        let decision = negotiate_capabilities(&request)?;
        push_event(&inner.event_bus, capability_changed_event(&decision))?;
        write_json_buffer(out_decision_json, &decision)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_unlock_account(
    client: *mut RamfluxClient,
    request_json: *const c_uchar,
    request_json_len: usize,
    out_account_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_account_json)?;
        let inner = client_inner(client)?;
        let request: UnlockAccountJson = parse_json_input(request_json, request_json_len)?;
        let mut client = lock_client(inner)?;
        client
            .unlock_account(&request.local_account_id, request.account_secret.as_bytes())
            .map_err(|error| map_sdk_error(&error))?;
        write_json_buffer(
            out_account_json,
            &json!({
                "local_account_id": request.local_account_id,
                "unlocked": true
            }),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_create_device_session(
    client: *mut RamfluxClient,
    request_json: *const c_uchar,
    request_json_len: usize,
    out_session_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_session_json)?;
        let _inner = client_inner(client)?;
        let _request: Value = parse_json_input(request_json, request_json_len)?;
        Err(CAbiError::new(
            RamfluxErrorCode::UnsupportedVersion,
            "device session C-ABI facade is not available in this SDK version",
        ))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_append_event(
    client: *mut RamfluxClient,
    event_json: *const c_uchar,
    event_json_len: usize,
    out_event_id_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_event_id_json)?;
        let inner = client_inner(client)?;
        let request: AppendEventJson = parse_json_input(event_json, event_json_len)?;
        let body = ramflux_protocol::decode_base64url(&request.body_base64).map_err(|source| {
            CAbiError::new(RamfluxErrorCode::InvalidArgument, source.to_string())
        })?;
        let client = lock_client(inner)?;
        client
            .append_event(&request.event_id, &request.event_type, &body)
            .map_err(|error| map_sdk_error(&error))?;
        write_json_buffer(
            out_event_id_json,
            &json!({
                "event_id": request.event_id
            }),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_read_projection(
    client: *mut RamfluxClient,
    request_json: *const c_uchar,
    request_json_len: usize,
    out_projection_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_projection_json)?;
        let inner = client_inner(client)?;
        let request: ReadProjectionJson = parse_json_input(request_json, request_json_len)?;
        let client = lock_client(inner)?;
        let response = if let Some(event_id) = request.event_id {
            let body = client.event_body(&event_id).map_err(|error| map_sdk_error(&error))?;
            json!({
                "event_id": event_id,
                "body_base64": body.map(|bytes| ramflux_protocol::encode_base64url(&bytes))
            })
        } else if let Some(projection_name) = request.projection_name {
            let checkpoint = client
                .projection_checkpoint(&projection_name)
                .map_err(|error| map_sdk_error(&error))?;
            json!({
                "projection_name": projection_name,
                "checkpoint": checkpoint
            })
        } else {
            return Err(CAbiError::new(
                RamfluxErrorCode::InvalidArgument,
                "read projection requires event_id or projection_name",
            ));
        };
        write_json_buffer(out_projection_json, &response)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_validate_mcp_grant(
    client: *mut RamfluxClient,
    request_json: *const c_uchar,
    request_json_len: usize,
    out_decision_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_decision_json)?;
        let inner = client_inner(client)?;
        let request: ValidateMcpGrantJson = parse_json_input(request_json, request_json_len)?;
        let (capability, parsed_scope) =
            parse_mcp_capability(&request.capability).map_err(SdkError::from).map_err(|error| {
                CAbiError::new(RamfluxErrorCode::InvalidArgument, error.to_string())
            })?;
        let mut client = lock_client(inner)?;
        client.install_mcp_tool(McpToolManifest {
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            capability: capability.clone(),
            tool_scope: request.tool_scope.or(parsed_scope),
            declared_risk: request.declared_risk,
            manifest_version: 1,
        });
        match client.invoke_mcp_tool(&request.server_id, &request.tool_name, &request.grant) {
            Ok(invocation_id) => write_json_buffer(
                out_decision_json,
                &json!({
                    "allowed": true,
                    "effective_capability": ramflux_sync::mcp_capability_wire_name(&capability),
                    "invocation_id": invocation_id
                }),
            ),
            Err(error) => Err(map_mcp_error(&error)),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_submit_envelope(
    client: *mut RamfluxClient,
    envelope_json: *const c_uchar,
    envelope_json_len: usize,
    out_operation_id: *mut u64,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_u64_out(out_operation_id)?;
        let inner = client_inner(client)?;
        reject_if_closing(inner)?;
        let operation_id = next_operation_id(inner);
        let _envelope: Value = parse_json_input(envelope_json, envelope_json_len)?;
        write_u64_out(out_operation_id, operation_id)?;
        push_event(&inner.event_bus, accepted_event(operation_id, "submit_envelope"))?;
        push_event(
            &inner.event_bus,
            failed_event(
                operation_id,
                &CAbiError::new(
                    RamfluxErrorCode::TransportUnavailable,
                    "gateway submit requires an established gateway session",
                ),
            ),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ramflux_client_put_object(
    client: *mut RamfluxClient,
    request_json: *const c_uchar,
    request_json_len: usize,
    out_operation_id: *mut u64,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_u64_out(out_operation_id)?;
        let inner = client_inner(client)?;
        reject_if_closing(inner)?;
        let request: PutObjectJson = parse_json_input(request_json, request_json_len)?;
        let operation_id = next_operation_id(inner);
        write_u64_out(out_operation_id, operation_id)?;
        push_event(&inner.event_bus, accepted_event(operation_id, "put_object"))?;
        let plaintext =
            ramflux_protocol::decode_base64url(&request.plaintext_base64).map_err(|source| {
                CAbiError::new(RamfluxErrorCode::InvalidArgument, source.to_string())
            })?;
        let result = {
            let mut client = lock_client(inner)?;
            client
                .put_encrypted_object(&request.object_id, &plaintext)
                .map_err(|error| map_sdk_error(&error))
        };
        match result {
            Ok(object) => push_event(
                &inner.event_bus,
                completed_event(operation_id, "ObjectManifest", &json!(object)),
            ),
            Err(error) => push_event(&inner.event_bus, failed_event(operation_id, &error)),
        }
    })
}

fn ffi_result(
    out_error_json: *mut *mut RamfluxBuffer,
    function: impl FnOnce() -> CAbiResult<()>,
) -> i32 {
    clear_optional_out_error(out_error_json);
    match catch_unwind(AssertUnwindSafe(function)) {
        Ok(Ok(())) => RamfluxErrorCode::Ok as i32,
        Ok(Err(error)) => {
            write_error_buffer(out_error_json, &error);
            error.code as i32
        }
        Err(_panic) => {
            let error =
                CAbiError::new(RamfluxErrorCode::PanicAborted, "panic crossed C-ABI boundary");
            write_error_buffer(out_error_json, &error);
            RamfluxErrorCode::PanicAborted as i32
        }
    }
}

fn parse_json_input<T: for<'de> Deserialize<'de>>(
    ptr: *const c_uchar,
    len: usize,
) -> CAbiResult<T> {
    let bytes = input_bytes(ptr, len)?;
    serde_json::from_slice(&bytes).map_err(|source| {
        CAbiError::new(RamfluxErrorCode::InvalidCanonicalJson, source.to_string())
    })
}

fn input_bytes(ptr: *const c_uchar, len: usize) -> CAbiResult<Vec<u8>> {
    if len > 0 && ptr.is_null() {
        return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "input pointer is null"));
    }
    if len == 0 {
        Ok(Vec::new())
    } else {
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
    }
}

fn client_inner<'a>(client: *mut RamfluxClient) -> CAbiResult<&'a CAbiClientInner> {
    if client.is_null() {
        return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "client pointer is null"));
    }
    Ok(unsafe { &*client.cast::<CAbiClientInner>() })
}

fn event_queue<'a>(queue: *mut RamfluxEventQueue) -> CAbiResult<&'a CAbiEventQueue> {
    if queue.is_null() {
        return Err(CAbiError::new(
            RamfluxErrorCode::InvalidArgument,
            "event queue pointer is null",
        ));
    }
    Ok(unsafe { &*queue.cast::<CAbiEventQueue>() })
}

fn lock_client(inner: &CAbiClientInner) -> CAbiResult<MutexGuard<'_, RustRamfluxClient>> {
    inner
        .client
        .lock()
        .map_err(|source| CAbiError::new(RamfluxErrorCode::Internal, source.to_string()))
}

fn lock_events(event_bus: &CAbiEventBus) -> CAbiResult<MutexGuard<'_, VecDeque<Value>>> {
    event_bus
        .queue
        .lock()
        .map_err(|source| CAbiError::new(RamfluxErrorCode::Internal, source.to_string()))
}

fn poll_events(queue: &CAbiEventQueue, max_events: u32) -> CAbiResult<Value> {
    let limit = usize::try_from(max_events)
        .map_err(|source| CAbiError::new(RamfluxErrorCode::InvalidArgument, source.to_string()))?;
    let mut events = lock_events(&queue.event_bus)?;
    let take = if limit == 0 { events.len() } else { limit.min(events.len()) };
    let drained = events.drain(..take).collect::<Vec<_>>();
    Ok(Value::Array(drained))
}

fn push_event(event_bus: &CAbiEventBus, event: Value) -> CAbiResult<()> {
    lock_events(event_bus)?.push_back(event);
    Ok(())
}

fn close_inner(inner: &CAbiClientInner) {
    if inner.closing.swap(true, Ordering::AcqRel) {
        return;
    }
    let _entered = inner.runtime.enter();
    let _ignored = push_event(
        &inner.event_bus,
        json!({
            "kind": "shutdown",
            "reason": "client_closed"
        }),
    );
}

fn reject_if_closing(inner: &CAbiClientInner) -> CAbiResult<()> {
    if inner.closing.load(Ordering::Acquire) {
        Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "client is closed"))
    } else {
        Ok(())
    }
}

fn next_operation_id(inner: &CAbiClientInner) -> u64 {
    inner.next_operation_id.fetch_add(1, Ordering::AcqRel)
}

fn negotiate_capabilities(request: &CapabilityRequestJson) -> CAbiResult<Value> {
    if request.sdk_abi_version > ABI_VERSION_MAJOR
        || request.protocol_version < request.min_protocol_version
        || request.min_protocol_version > PROTOCOL_VERSION
    {
        return Err(CAbiError::new(
            RamfluxErrorCode::UnsupportedVersion,
            "incompatible SDK ABI or protocol version",
        ));
    }
    let supported = ["quic_quinn", "https_json", "grpc_h2"];
    let selected = request
        .supported_transports
        .iter()
        .find(|transport| supported.contains(&transport.as_str()))
        .cloned()
        .ok_or_else(|| {
            CAbiError::new(
                RamfluxErrorCode::CapabilityRejected,
                "no supported transport intersection",
            )
        })?;
    let disabled = request
        .supported_transports
        .iter()
        .filter(|transport| !supported.contains(&transport.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let decision = if disabled.is_empty() { "accepted" } else { "downgraded" };
    Ok(json!({
        "decision": decision,
        "protocol_version": PROTOCOL_VERSION,
        "selected_transport": selected,
        "enabled_features": ["canonical_json", "mcp_grant_validation"],
        "disabled_features": disabled,
        "expires_at": 0
    }))
}

fn accepted_event(operation_id: u64, operation_type: &str) -> Value {
    json!({
        "kind": "accepted",
        "operation_id": operation_id,
        "operation_type": operation_type
    })
}

fn completed_event(operation_id: u64, result_type: &str, result: &Value) -> Value {
    json!({
        "kind": "completed",
        "operation_id": operation_id,
        "result_type": result_type,
        "result": result
    })
}

fn failed_event(operation_id: u64, error: &CAbiError) -> Value {
    json!({
        "kind": "failed",
        "operation_id": operation_id,
        "error": error_json(error)
    })
}

fn capability_changed_event(decision: &Value) -> Value {
    json!({
        "kind": "capability_changed",
        "decision": decision.get("decision").cloned().unwrap_or(Value::Null),
        "capabilities": decision
    })
}

fn write_json_buffer<T: Serialize>(out: *mut *mut RamfluxBuffer, value: &T) -> CAbiResult<()> {
    let bytes = ramflux_protocol::canonical_json_bytes(value).map_err(|source| {
        CAbiError::new(RamfluxErrorCode::InvalidCanonicalJson, source.to_string())
    })?;
    write_buffer(out, bytes)
}

fn write_error_buffer(out_error_json: *mut *mut RamfluxBuffer, error: &CAbiError) {
    if out_error_json.is_null() {
        return;
    }
    let value = error_json(error);
    let bytes = serde_json::to_vec(&value).unwrap_or_else(|_source| {
        br#"{"code":16,"name":"Internal","message":"failed to serialize error","retry_after_ms":null,"correlation_id":"cabi-error"}"#.to_vec()
    });
    let _ignored = write_buffer(out_error_json, bytes);
}

fn error_json(error: &CAbiError) -> ErrorJson<'_> {
    ErrorJson {
        code: error.code as i32,
        name: error.code.name(),
        message: &error.message,
        retry_after_ms: None,
        correlation_id: format!("cabi-{}", current_millis()),
    }
}

fn write_buffer(out: *mut *mut RamfluxBuffer, bytes: Vec<u8>) -> CAbiResult<()> {
    if out.is_null() {
        return Err(CAbiError::new(
            RamfluxErrorCode::InvalidArgument,
            "output buffer pointer is null",
        ));
    }
    let mut boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    let len = boxed.len();
    std::mem::forget(boxed);
    let buffer = Box::new(RamfluxBuffer { ptr, len });
    unsafe {
        *out = Box::into_raw(buffer);
    }
    Ok(())
}

fn clear_out_ptr<T>(out: *mut *mut T) -> CAbiResult<()> {
    if out.is_null() {
        return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "output pointer is null"));
    }
    unsafe {
        *out = ptr::null_mut();
    }
    Ok(())
}

fn write_out_ptr<T>(out: *mut *mut T, value: *mut T) -> CAbiResult<()> {
    if out.is_null() {
        return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "output pointer is null"));
    }
    unsafe {
        *out = value;
    }
    Ok(())
}

fn clear_u64_out(out: *mut u64) -> CAbiResult<()> {
    if out.is_null() {
        return Err(CAbiError::new(
            RamfluxErrorCode::InvalidArgument,
            "operation id pointer is null",
        ));
    }
    unsafe {
        *out = 0;
    }
    Ok(())
}

fn write_u64_out(out: *mut u64, value: u64) -> CAbiResult<()> {
    if out.is_null() {
        return Err(CAbiError::new(
            RamfluxErrorCode::InvalidArgument,
            "operation id pointer is null",
        ));
    }
    unsafe {
        *out = value;
    }
    Ok(())
}

fn clear_optional_out_error(out_error_json: *mut *mut RamfluxBuffer) {
    if out_error_json.is_null() {
        return;
    }
    unsafe {
        *out_error_json = ptr::null_mut();
    }
}

fn map_sdk_error(error: &SdkError) -> CAbiError {
    let message = error.to_string();
    let code = match error {
        SdkError::Crypto(_) | SdkError::SignatureVerificationFailed(_) => {
            RamfluxErrorCode::CryptoFailed
        }
        SdkError::Storage(_) | SdkError::AccountIndexNotOpen | SdkError::AccountDbNotUnlocked => {
            RamfluxErrorCode::StorageFailed
        }
        SdkError::IdentityRootMissing => RamfluxErrorCode::AuthFailed,
        SdkError::Transport(_)
        | SdkError::GatewaySessionRejected(_)
        | SdkError::GatewaySessionNotEstablished => RamfluxErrorCode::TransportUnavailable,
        SdkError::Protocol(_) | SdkError::Json(_) | SdkError::InvalidGatewayCursor(_) => {
            RamfluxErrorCode::InvalidCanonicalJson
        }
        SdkError::Io(_) => RamfluxErrorCode::Internal,
        SdkError::Sync(_)
        | SdkError::CapabilityDenied(_)
        | SdkError::GrantInvalidated
        | SdkError::RemoteAppApprovalRequired
        | SdkError::LocalBusPermissionDenied => RamfluxErrorCode::PermissionDenied,
        SdkError::LocalBus(_) => RamfluxErrorCode::InvalidArgument,
    };
    CAbiError::new(code, message)
}

fn map_mcp_error(error: &SdkError) -> CAbiError {
    let mut mapped = map_sdk_error(error);
    if matches!(mapped.code, RamfluxErrorCode::PermissionDenied) {
        mapped.code = RamfluxErrorCode::McpGrantRejected;
    }
    mapped
}

fn current_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

impl CAbiError {
    fn new(code: RamfluxErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}
