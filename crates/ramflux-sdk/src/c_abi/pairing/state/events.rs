// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent public-event reader. It owns neither a callback provider nor an account key.
use super::{Arc, LocalEvent, Mutex, Ordering, State, VecDeque};
use crate::{LocalBusClient, SdkError};
use ramflux_protocol::custody::pairing::{PairingWire, local_dto::FullStatusEvent};
pub(super) struct EventReader {
    account: String,
    stop: tokio::sync::watch::Sender<bool>,
    join: std::thread::JoinHandle<()>,
    retry_at: std::time::Instant,
}
impl EventReader {
    pub(super) fn stop_and_join(self) {
        let _ = self.stop.send(true);
        let _ = self.join.join();
    }
}
struct Reader {
    events: Arc<Mutex<VecDeque<LocalEvent>>>,
    last: Arc<Mutex<Option<(String, u64)>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    stopped: Arc<tokio::sync::Notify>,
    stop: tokio::sync::watch::Receiver<bool>,
}
impl State {
    pub(super) fn start_events(&self, account: String) {
        let Some(socket) = self.socket.clone() else { return };
        let Ok(mut slot) = self.event_reader.lock() else { return };
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if slot.as_ref().is_some_and(|reader| {
            reader.account == account
                && (!reader.join.is_finished() || std::time::Instant::now() < reader.retry_at)
        }) {
            return;
        }
        if let Some(reader) = slot.take() {
            reader.stop_and_join();
        }
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let event_account = account.clone();
        let reader = Reader {
            events: self.events.clone(),
            last: self.last.clone(),
            closed: self.closed.clone(),
            stopped: self.stopped.clone(),
            stop: receiver,
        };
        match std::thread::Builder::new().name("pairing-events".into()).spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build()
            else {
                return;
            };
            runtime.block_on(reader.run(socket, account));
        }) {
            Ok(join) => {
                let now = std::time::Instant::now();
                *slot = Some(EventReader {
                    account: event_account,
                    stop,
                    join,
                    retry_at: now.checked_add(std::time::Duration::from_secs(10)).unwrap_or(now),
                });
            }
            Err(error) => {
                tracing::warn!(error_kind = ?error.kind(), "pairing event reader unavailable");
            }
        }
    }
}

impl Reader {
    async fn run(self, socket: std::path::PathBuf, account: String) {
        let stopped = self.stopped.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let mut stop = self.stop.clone();
        if *stop.borrow() {
            return;
        }
        tokio::select! {
            () = &mut stopped => {},
            _ = stop.changed() => {},
            result = self.receive(socket, account) => {
                if let Err(error) = result {
                    tracing::debug!(error_code = crate::bus::io::local_bus_error_code(&error), "pairing event subscription ended");
                }
            }
        }
    }
    async fn receive(&self, socket: std::path::PathBuf, account: String) -> Result<(), SdkError> {
        let mut client = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut client = LocalBusClient::connect(socket).await?;
            client
                .request(
                    Some(account.clone()),
                    "device",
                    "subscription.open",
                    serde_json::json!({"topics":[crate::custody::pairing::PAIRING_EVENT_TOPIC]}),
                )
                .await?;
            Ok::<_, SdkError>(client)
        })
        .await
        .map_err(|_| SdkError::PairingCode("ResumeRequired"))??;
        loop {
            let frame = client.next_event().await?;
            if frame.account_id.as_deref() != Some(account.as_str())
                || frame.method != crate::custody::pairing::PAIRING_EVENT_TOPIC
            {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let event: LocalEvent = serde_json::from_value(frame.body)?;
            event.validate().map_err(|_| SdkError::PairingCode("WrongContext"))?;
            self.remember(event)?;
        }
    }
    fn remember(&self, event: LocalEvent) -> Result<(), SdkError> {
        let (operation, generation) = match &event {
            LocalEvent::Update { update, .. } => (&update.operation_id, update.generation),
            LocalEvent::FullStatus { outcome: FullStatusEvent::FullStatus { value }, .. } => {
                (&value.operation_id, value.generation)
            }
        };
        let last = self.last.lock().map_err(|_| SdkError::PairingCode("Retired"))?;
        if !last.as_ref().is_some_and(|(id, saved_generation)| {
            id == operation && *saved_generation == generation
        }) {
            return Ok(());
        }
        let mut events = self.events.lock().map_err(|_| SdkError::PairingCode("Retired"))?;
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if events.back() == Some(&event) {
            return Ok(());
        }
        if events.len() == 64 {
            events.pop_front();
        }
        events.push_back(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
