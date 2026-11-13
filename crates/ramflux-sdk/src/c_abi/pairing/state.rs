// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client-local adapter ownership; ceremony decisions remain in the daemon's SDK actor.
use super::super::{CAbiError, CAbiResult, RamfluxErrorCode};
use super::{
    credential::{CallbackProvider, CredentialCallback, Refuse},
    request,
};
use crate::{
    SdkError,
    custody::pairing::{LocalCredentialProvider, private_credential::PairingBusClient},
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    local_dto::{FullStatusEvent, LocalEvent, LocalResult, Outcome},
};
use std::{
    collections::VecDeque,
    ffi::c_void,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

mod events;

pub(in crate::c_abi) struct State {
    pub(super) root: PathBuf,
    pub(super) socket: Option<PathBuf>,
    pub(super) account: Option<String>,
    provider: Mutex<Option<Arc<CallbackProvider>>>,
    events: Arc<Mutex<VecDeque<LocalEvent>>>,
    event_reader: Mutex<Option<events::EventReader>>,
    event_account: Mutex<Option<String>>,
    last: Arc<Mutex<Option<(String, u64)>>>,
    busy: AtomicBool,
    closed: Arc<AtomicBool>,
    stopped: Arc<tokio::sync::Notify>,
}
pub(super) struct Permit<'a>(&'a AtomicBool);
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn internal() -> CAbiError {
    CAbiError::new(RamfluxErrorCode::Internal, "pairing adapter owner unavailable")
}
impl State {
    pub(in crate::c_abi) fn new(
        root: PathBuf,
        socket: Option<String>,
        account: Option<String>,
    ) -> CAbiResult<Self> {
        if let Some(id) = &account {
            crate::custody::valid_id(id).map_err(|_| {
                CAbiError::new(RamfluxErrorCode::InvalidArgument, "invalid pairing account")
            })?;
        }
        Ok(Self {
            root,
            socket: socket.map(PathBuf::from),
            account,
            provider: Mutex::new(None),
            events: Arc::new(Mutex::new(VecDeque::new())),
            event_reader: Mutex::new(None),
            event_account: Mutex::new(None),
            last: Arc::new(Mutex::new(None)),
            busy: AtomicBool::new(false),
            closed: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(tokio::sync::Notify::new()),
        })
    }
    pub(super) fn enter(&self) -> CAbiResult<Permit<'_>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "client is closed"));
        }
        self.busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).map_err(
            |_| CAbiError::new(RamfluxErrorCode::AccountBusy, "pairing call already active"),
        )?;
        Ok(Permit(&self.busy))
    }
    pub(super) fn set_provider(
        &self,
        callback: Option<CredentialCallback>,
        user_data: *mut c_void,
    ) -> CAbiResult<()> {
        let replacement = callback.map(|callback| {
            Arc::new(CallbackProvider::new(self.root.clone(), callback, user_data))
        });
        let mut installed = self.provider.lock().map_err(|_| internal())?;
        if self.closed.load(Ordering::Acquire) {
            return Err(internal());
        }
        let old = std::mem::replace(&mut *installed, replacement);
        // Keep the control owner until the prior callback drains: concurrent close
        // must cover both the old callback and the newly installed provider.
        if let Some(old) = old {
            old.stop_and_drain();
        }
        Ok(())
    }
    pub(in crate::c_abi) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.stopped.notify_waiters();
        let reader =
            self.event_reader.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(reader) = reader {
            reader.stop_and_join();
        }
        let provider =
            self.provider.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(provider) = provider {
            provider.stop_and_drain();
        }
        self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    }
    pub(super) fn stale(&self, body: &serde_json::Value) -> CAbiResult<bool> {
        let last = self.last.lock().map_err(|_| internal())?;
        Ok(last.as_ref().is_some_and(|(id, generation)| {
            body.get("operation_id").and_then(serde_json::Value::as_str) == Some(id.as_str())
                && body
                    .get("generation")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|value| value != *generation)
        }))
    }
    pub(super) async fn call(
        &self,
        account: String,
        method: &str,
        body: serde_json::Value,
    ) -> CAbiResult<LocalResult> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            CAbiError::new(RamfluxErrorCode::InvalidArgument, "pairing_socket is not configured")
        })?;
        let provider: Arc<dyn LocalCredentialProvider> =
            self.provider.lock().map_err(|_| internal())?.as_ref().map_or_else(
                || Arc::new(Refuse) as Arc<dyn LocalCredentialProvider>,
                |provider| provider.clone(),
            );
        let stopped = self.stopped.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self.closed.load(Ordering::Acquire) {
            return Err(internal());
        }
        let event_account = account.clone();
        let remote = async {
            let mut client = PairingBusClient::connect(socket, provider).await?;
            client.request(Some(account), "device", method, body).await
        };
        let response = tokio::select! {
            () = &mut stopped => return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "client is closed")),
            result = tokio::time::timeout(std::time::Duration::from_secs(60), remote) => result.map_err(|_| CAbiError::new(RamfluxErrorCode::Timeout, "pairing call deadline exceeded"))?,
        };
        let result: LocalResult = match response {
            Ok(value) => serde_json::from_value(value).map_err(|_| internal())?,
            Err(SdkError::LocalBusRefused { code, .. }) => return request::refusal(&code),
            Err(error) => return Err(super::super::map_sdk_error(&error)),
        };
        result
            .validate_method(method.strip_prefix("device.").ok_or_else(internal)?)
            .map_err(|_| internal())?;
        *self.event_account.lock().map_err(|_| internal())? = Some(event_account);
        Ok(result)
    }
    pub(super) fn remember(&self, result: &LocalResult) -> CAbiResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(internal());
        }
        let (identity, event) = match &result.outcome {
            Outcome::Begin { value } => {
                (Some((value.operation_id.clone(), value.generation)), None)
            }
            Outcome::Update { value } => (
                Some((value.operation_id.clone(), value.generation)),
                Some(LocalEvent::Update {
                    schema: "ramflux.pairing.LocalEvent.v2".into(),
                    version: 2,
                    update: value.clone(),
                }),
            ),
            Outcome::FullStatus { value } => (
                Some((value.operation_id.clone(), value.generation)),
                Some(LocalEvent::FullStatus {
                    schema: "ramflux.pairing.LocalEvent.v2".into(),
                    version: 2,
                    outcome: FullStatusEvent::FullStatus { value: value.clone() },
                }),
            ),
            Outcome::Error { .. } => (None, None),
        };
        if let Some(identity) = identity {
            let mut last = self.last.lock().map_err(|_| internal())?;
            if last.as_ref() != Some(&identity) {
                self.events.lock().map_err(|_| internal())?.clear();
            }
            *last = Some(identity);
        }
        if let Some(event) = event {
            event.validate().map_err(|_| internal())?;
            let mut events = self.events.lock().map_err(|_| internal())?;
            if self.closed.load(Ordering::Acquire) {
                return Err(internal());
            }
            // These are display snapshots, not operations. Coalesce the oldest display
            // on overflow; the caller already owns the exact result of every call.
            if events.len() == 64 {
                events.pop_front();
            }
            events.push_back(event);
        }
        if let Some(account) = self.event_account.lock().map_err(|_| internal())?.clone() {
            self.start_events(account);
        }
        Ok(())
    }
    pub(super) fn poll(&self) -> CAbiResult<Vec<u8>> {
        self.events
            .lock()
            .map_err(|_| internal())?
            .pop_front()
            .map_or(Ok(Vec::new()), |event| event.to_wire_bytes().map_err(|_| internal()))
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.close();
    }
}
