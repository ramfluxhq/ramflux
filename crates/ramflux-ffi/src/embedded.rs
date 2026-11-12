// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `CorePort` over the SDK's embedded in-process supervisor.
//!
//! The supervisor runs the account actors on its own thread. This adapter adds one bridge
//! thread with a current-thread Tokio runtime that owns the in-process bus connections. The
//! bridge is torn down BEFORE the supervisor is suspended, so no connection of ours keeps a
//! store open, and replies that were in flight end their waiters as "reply lost".

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use ramflux_sdk::{
    EmbeddedConfig, EmbeddedSupervisor, HostLifecycle, HostPaths, LifecycleState, LocalBusClient,
    LocalBusErrorBody, LocalBusFrame, LocalBusFrameKind, SdkError,
};
use tokio::sync::{Notify, mpsc};

use crate::error::{CoreError, code};
use crate::port::{CorePort, PortRequest, PortSubscription, UpdateSink};
use crate::types::{
    CoreConfig, CoreResponse, CoreState, NetworkChange, SubscribeFilter, SubscriptionEnd,
    SuspendEvidence, UpdateRow, UpdateState,
};
use crate::wait::ClaimKind;

/// Requests the bridge may hold before admission is refused. Equal to the bus client's
/// in-flight limit, so a refusal here is back-pressure, never loss.
const ADMISSION_DEPTH: usize = 64;
/// Longest the host waits for the bridge to open a stream or to become ready.
const BRIDGE_REPLY: Duration = Duration::from_secs(10);

/// Methods the supervisor runs as keyed lifecycle operations and retains past their waiter.
/// OPEN-VALUE: mirrors the `Lifecycle` route of the SDK method table, which is not public.
const LIFECYCLE_METHODS: &[&str] = &["account.lock", "account.passphrase.rotate", "account.unlock"];

enum Command {
    Request(PortRequest),
    Subscribe {
        filter: SubscribeFilter,
        sink: Arc<dyn UpdateSink>,
        cancel: Arc<Notify>,
        opened: SyncSender<Result<(), CoreError>>,
    },
}

struct Bridge {
    commands: mpsc::Sender<Command>,
    thread: JoinHandle<()>,
}

struct EmbeddedPort {
    supervisor: Arc<EmbeddedSupervisor>,
    bridge: Mutex<Option<Bridge>>,
    last_network: Mutex<Option<NetworkChange>>,
}

/// Build the embedded port for `config`. Nothing is opened until `start`.
///
/// # Errors
/// `InvalidArgument` when the data root is not an absolute path.
pub(crate) fn port(config: &CoreConfig) -> Result<Arc<dyn CorePort>, CoreError> {
    let data_root = PathBuf::from(&config.data_root);
    if !data_root.is_absolute() {
        return Err(CoreError::plain(code::INVALID_ARGUMENT, "data_root must be an absolute path"));
    }
    let supervisor = EmbeddedSupervisor::new(EmbeddedConfig::new(HostPaths { data_root }));
    Ok(Arc::new(EmbeddedPort {
        supervisor: Arc::new(supervisor),
        bridge: Mutex::new(None),
        last_network: Mutex::new(None),
    }))
}

impl EmbeddedPort {
    fn bridge(&self) -> MutexGuard<'_, Option<Bridge>> {
        match self.bridge.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn start_bridge(&self) -> Result<(), CoreError> {
        let (commands, receiver) = mpsc::channel(ADMISSION_DEPTH);
        let (ready, is_ready) = sync_channel(1);
        let supervisor = Arc::clone(&self.supervisor);
        let thread = std::thread::Builder::new()
            .name("ramflux-ffi-bridge".to_owned())
            .spawn(move || run_bridge(&supervisor, receiver, &ready))
            .map_err(|error| CoreError::plain(code::INTERNAL, format!("bridge thread: {error}")))?;
        match is_ready.recv_timeout(BRIDGE_REPLY) {
            Ok(Ok(())) => {
                *self.bridge() = Some(Bridge { commands, thread });
                Ok(())
            }
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => Err(CoreError::plain(code::INTERNAL, "bridge did not become ready")),
        }
    }

    /// Drop every bus connection of ours and wait for the bridge thread to leave.
    fn stop_bridge(&self) {
        let bridge = self.bridge().take();
        if let Some(Bridge { commands, thread }) = bridge {
            drop(commands);
            let _ = thread.join();
        }
    }
}

impl CorePort for EmbeddedPort {
    fn start(&self) -> Result<(), CoreError> {
        self.supervisor.start().map_err(|error| lifecycle_error(&error))?;
        self.start_bridge().inspect_err(|_| {
            let _ = self.supervisor.stop();
        })
    }

    fn suspend(&self) -> Result<SuspendEvidence, CoreError> {
        self.stop_bridge();
        let report = self.supervisor.suspend().map_err(|error| lifecycle_error(&error))?;
        Ok(SuspendEvidence {
            supervisor_joined: report.supervisor_joined,
            data_root_lock_released: report.data_root_lock_released,
            elapsed_ms: u64::try_from(report.elapsed.as_millis()).unwrap_or(u64::MAX),
        })
    }

    fn resume(&self) -> Result<(), CoreError> {
        self.supervisor.resume().map_err(|error| lifecycle_error(&error))?;
        self.start_bridge().inspect_err(|_| {
            let _ = self.supervisor.suspend();
        })
    }

    fn stop(&self) -> Result<(), CoreError> {
        self.stop_bridge();
        self.supervisor.stop().map_err(|error| lifecycle_error(&error))
    }

    fn state(&self) -> CoreState {
        match self.supervisor.state() {
            LifecycleState::Stopped => CoreState::Stopped,
            LifecycleState::Running => CoreState::Running,
            LifecycleState::Suspended => CoreState::Suspended,
        }
    }

    fn network_changed(&self, change: NetworkChange) {
        // The connection policy owns reconnect decisions. Until its monitor is handed to the
        // embedded supervisor, the adapter only remembers the latest report.
        match self.last_network.lock() {
            Ok(mut last) => *last = Some(change),
            Err(poisoned) => *poisoned.into_inner() = Some(change),
        }
    }

    fn submit(&self, request: PortRequest) -> Result<(), CoreError> {
        let bridge = self.bridge();
        let Some(bridge) = bridge.as_ref() else {
            return Err(CoreError::plain(code::TRANSPORT_UNAVAILABLE, "core is not running"));
        };
        bridge.commands.try_send(Command::Request(request)).map_err(|refused| match refused {
            mpsc::error::TrySendError::Full(_) => {
                CoreError::from_code(code::RATE_LIMITED, "admission queue is full", None, Some(50))
            }
            mpsc::error::TrySendError::Closed(_) => {
                CoreError::plain(code::TRANSPORT_UNAVAILABLE, "core is not running")
            }
        })
    }

    fn subscribe(
        &self,
        filter: SubscribeFilter,
        sink: Arc<dyn UpdateSink>,
    ) -> Result<Box<dyn PortSubscription>, CoreError> {
        if filter.topics.is_empty() {
            return Err(CoreError::plain(code::INVALID_ARGUMENT, "name at least one topic"));
        }
        let cancel = Arc::new(Notify::new());
        let (opened, is_open) = sync_channel(1);
        {
            let bridge = self.bridge();
            let Some(bridge) = bridge.as_ref() else {
                return Err(CoreError::plain(code::TRANSPORT_UNAVAILABLE, "core is not running"));
            };
            bridge
                .commands
                .try_send(Command::Subscribe { filter, sink, cancel: Arc::clone(&cancel), opened })
                .map_err(|_| CoreError::plain(code::RATE_LIMITED, "admission queue is full"))?;
        }
        match is_open.recv_timeout(BRIDGE_REPLY) {
            Ok(Ok(())) => Ok(Box::new(Stream(cancel))),
            Ok(Err(error)) => Err(error),
            Err(_) => {
                cancel.notify_one();
                Err(CoreError::plain(code::TIMEOUT, "stream was not opened in time"))
            }
        }
    }
}

struct Stream(Arc<Notify>);

impl PortSubscription for Stream {
    fn cancel(&self) {
        // `notify_one` stores a permit, so a cancel before the task waits is not lost.
        self.0.notify_one();
    }
}

fn run_bridge(
    supervisor: &Arc<EmbeddedSupervisor>,
    mut commands: mpsc::Receiver<Command>,
    ready: &SyncSender<Result<(), CoreError>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_time().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(CoreError::plain(code::INTERNAL, format!("runtime: {error}"))));
            return;
        }
    };
    let local = tokio::task::LocalSet::new();
    let next_id = Arc::new(AtomicU64::new(1));
    local.block_on(&runtime, async {
        let client = match supervisor.connect() {
            Ok(client) => client,
            Err(error) => {
                let _ = ready.send(Err(lifecycle_error(&error)));
                return;
            }
        };
        let _ = ready.send(Ok(()));
        while let Some(command) = commands.recv().await {
            match command {
                Command::Request(request) => {
                    let id = next_id.fetch_add(1, Ordering::Relaxed);
                    tokio::task::spawn_local(run_request(client.clone(), request, id));
                }
                Command::Subscribe { filter, sink, cancel, opened } => {
                    let id = next_id.fetch_add(1, Ordering::Relaxed);
                    // Topics are per connection on the bus, so each stream has its own.
                    let stream = supervisor.connect().map_err(|error| lifecycle_error(&error));
                    match stream {
                        Ok(stream) => {
                            tokio::task::spawn_local(run_stream(
                                stream, filter, sink, cancel, opened, id,
                            ));
                        }
                        Err(error) => {
                            let _ = opened.send(Err(error));
                        }
                    }
                }
            }
        }
        // The command sender is gone: the host suspends or closes. Leaving here drops every
        // connection and every in-flight task; their waiters end as "reply lost".
    });
}

async fn run_request(client: LocalBusClient, port: PortRequest, id: u64) {
    let PortRequest { request, deadline_unix_ms, gate, reply } = port;
    // Everything that can fail without touching the core happens before the claim.
    let body: serde_json::Value = match serde_json::from_str(&request.body_json) {
        Ok(body) => body,
        Err(error) => {
            reply.send(Err(CoreError::plain(code::INVALID_CANONICAL_JSON, error.to_string())));
            return;
        }
    };
    let kind = if LIFECYCLE_METHODS.contains(&request.method.as_str()) {
        ClaimKind::Lifecycle
    } else {
        ClaimKind::Ordinary
    };
    if !gate.try_claim(kind) {
        // The waiter withdrew first. Nothing was sent to the supervisor.
        return;
    }
    // Claimed. From here the supervisor owns the execution: the frame is written to the bus
    // and is never withdrawn, whatever happens to the waiter.
    let mut frame = LocalBusFrame::request(
        format!("ffi_{id}"),
        request.account_id.clone(),
        sdk_api(&request.method),
        request.method.clone(),
        body,
    );
    frame.deadline_ms = Some(deadline_unix_ms);
    frame.operation_id.clone_from(&request.operation_id);
    match client.request_frame_response(frame).await {
        Ok(response) if response.kind == LocalBusFrameKind::Error => {
            reply.send(Err(refusal(response.error)));
        }
        Ok(response) => reply.send(Ok(CoreResponse {
            method: request.method,
            account_id: response.account_id.or(request.account_id),
            body_json: response.body.to_string(),
            operation_id: request.operation_id,
        })),
        Err(SdkError::CustodySetupInvalid) => {
            // Refused by the client before any frame was written.
            reply.send(Err(CoreError::plain(
                code::INVALID_ARGUMENT,
                "custody setup methods are not available on this carrier",
            )));
        }
        Err(_) => {
            // The connection or the reply was lost after the claim. Whether the request ran
            // is unknown, so no error is fabricated: dropping `reply` ends the waiter as
            // `EndedAfterClaim { ReplyLost }` and the host reconciles by operation id.
            drop(reply);
        }
    }
}

async fn run_stream(
    mut client: LocalBusClient,
    filter: SubscribeFilter,
    sink: Arc<dyn UpdateSink>,
    cancel: Arc<Notify>,
    opened: SyncSender<Result<(), CoreError>>,
    id: u64,
) {
    let open = LocalBusFrame::request(
        format!("ffi_{id}"),
        filter.account_id.clone(),
        "subscription",
        "subscription.open",
        serde_json::json!({ "topics": filter.topics }),
    );
    match client.request_frame_response(open).await {
        Ok(response) if response.kind == LocalBusFrameKind::Error => {
            let _ = opened.send(Err(refusal(response.error)));
            return;
        }
        Ok(_) => {
            let _ = opened.send(Ok(()));
        }
        Err(error) => {
            let _ = opened.send(Err(lifecycle_error(&error)));
            return;
        }
    }
    let after = filter.after_journal_sequence.unwrap_or(0);
    loop {
        tokio::select! {
            () = cancel.notified() => return,
            event = client.next_event() => match event {
                Ok(frame) => {
                    let row = update_row(frame);
                    if row.journal_sequence == 0 || row.journal_sequence > after {
                        sink.offer(row);
                    }
                }
                Err(_) => {
                    sink.end(SubscriptionEnd::Failed);
                    return;
                }
            },
        }
    }
}

/// Project one bus event into a typed row. A body this binding does not recognise is still a
/// successful row (`Unknown`), never an error.
fn update_row(frame: LocalBusFrame) -> UpdateRow {
    let identity_json = frame.body.get("identity").map(ToString::to_string);
    let state = if let Some(content) = frame.body.get("content") {
        UpdateState::Content { json: content.to_string() }
    } else if let Some(unsupported) = frame.body.get("unsupported") {
        UpdateState::Unsupported { json: unsupported.to_string() }
    } else if let Some(tombstone) = frame.body.get("tombstone") {
        UpdateState::Tombstone { json: tombstone.to_string() }
    } else {
        UpdateState::Unknown { json: frame.body.to_string() }
    };
    UpdateRow {
        topic: frame.method,
        account_id: frame.account_id,
        journal_sequence: frame.seq.unwrap_or(0),
        identity_json,
        state,
    }
}

/// The bus groups methods by their first name segment.
/// OPEN-VALUE: the SDK has no public method-to-API table; the segment is what `rf` sends.
fn sdk_api(method: &str) -> &str {
    method.split('.').next().unwrap_or(method)
}

/// Map a bus refusal to the stable numeric code. The bus string code is always kept in
/// `reason_code`, so a host can still tell refusals apart that share a numeric code.
fn refusal(error: Option<LocalBusErrorBody>) -> CoreError {
    let Some(error) = error else {
        return CoreError::plain(code::INTERNAL, "core refused without an error body");
    };
    let numeric = match error.code.as_str() {
        "account_busy" | "DataRootInUse" => code::ACCOUNT_BUSY,
        "SchemaResetRequired" => code::SCHEMA_RESET_REQUIRED,
        "AccountSchemaTooNew" | "NetworkingPending" | "CustodyModeDowngrade" => {
            code::UNSUPPORTED_VERSION
        }
        "CustodyForkFenced" => code::CUSTODY_FORK_FENCED,
        "ObjectErased" => code::OBJECT_ERASED,
        "ObjectIdentityConflict" => code::OBJECT_IDENTITY_CONFLICT,
        "ObjectOwnershipUnverified" => code::OBJECT_OWNERSHIP_UNVERIFIED,
        "CapabilityDenied" => code::CAPABILITY_REJECTED,
        "authorization_rejected" | "GroupLeaseUnavailable" | "RemoteAppApprovalRequired" => {
            code::PERMISSION_DENIED
        }
        "GrantInvalidated" => code::MCP_GRANT_REJECTED,
        "Unavailable" | "NoNodeSelected" | "TaskDeliveryTimeout" => code::TRANSPORT_UNAVAILABLE,
        "storage_unavailable"
        | "AccountNotOpen"
        | "ManifestUnreadable"
        | "AccountRestoreFailed"
        | "AccountRestorePending"
        | "restore_setup_required" => code::STORAGE_FAILED,
        "ValidationFailed"
        | "too_large"
        | "TaskDeliveryTooLarge"
        | "InvalidOfflineRetention"
        | "CustodySetupInvalid" => code::INVALID_ARGUMENT,
        "SignatureVerificationFailed" | "CustodyRandomUnavailable" => code::CRYPTO_FAILED,
        "CustodyConfirmationFailed"
        | "CustodyExpired"
        | "CustodyAccountConflict"
        | "OwnDeviceAuthorizationRefreshFailed"
        | "Unauthenticated"
        | "TransportSecurity" => code::AUTH_FAILED,
        "ReplayMismatch" | "OperationReconciliationRequired" => code::REPLAY_REJECTED,
        "transfer_requires_sync" => code::OBJECT_TRANSFER_FAILED,
        _ => code::INTERNAL,
    };
    let reason = error.reason_code.unwrap_or_else(|| error.code.clone());
    CoreError::from_code(numeric, error.message, Some(reason), error.retry_after_ms)
}

/// Map an SDK error raised by a lifecycle transition or a connection attempt.
fn lifecycle_error(error: &SdkError) -> CoreError {
    let numeric = match error {
        SdkError::DataRootInUse => code::ACCOUNT_BUSY,
        SdkError::LocalBus(_) => code::INVALID_ARGUMENT,
        SdkError::Storage(_) => code::STORAGE_FAILED,
        _ => code::INTERNAL,
    };
    CoreError::plain(numeric, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{code, refusal, sdk_api, update_row};
    use crate::types::UpdateState;
    use ramflux_sdk::{LocalBusErrorBody, LocalBusFrame, LocalBusFrameKind};

    fn body(code: &str) -> LocalBusErrorBody {
        LocalBusErrorBody {
            details: None,
            reason_code: None,
            code: code.to_owned(),
            message: "m".to_owned(),
            retry_after_ms: Some(7),
            cause: None,
        }
    }

    #[test]
    fn bus_refusals_keep_their_string_code_and_map_to_stable_numbers() {
        let reset = refusal(Some(body("SchemaResetRequired")));
        assert_eq!(reset.code(), code::SCHEMA_RESET_REQUIRED);
        assert_eq!(reset.detail().reason_code.as_deref(), Some("SchemaResetRequired"));
        assert_eq!(reset.detail().retry_after_ms, Some(7));
        assert_eq!(refusal(Some(body("DataRootInUse"))).code(), code::ACCOUNT_BUSY);
        let unknown = refusal(Some(body("SomethingNew")));
        assert_eq!(unknown.code(), code::INTERNAL);
        assert_eq!(unknown.detail().reason_code.as_deref(), Some("SomethingNew"));
    }

    #[test]
    fn unknown_event_body_is_a_successful_row_not_an_error() {
        let mut frame = LocalBusFrame::request(
            "e1",
            Some("acct".to_owned()),
            "message",
            "message.update",
            serde_json::json!({ "kind": "from.the.future", "x": 1 }),
        );
        frame.kind = LocalBusFrameKind::Event;
        frame.seq = Some(9);
        let row = update_row(frame);
        assert_eq!(row.journal_sequence, 9);
        assert!(matches!(row.state, UpdateState::Unknown { .. }));
    }

    #[test]
    fn api_group_is_the_first_method_segment() {
        assert_eq!(sdk_api("message.receipt.read"), "message");
        assert_eq!(sdk_api("plain"), "plain");
    }
}
