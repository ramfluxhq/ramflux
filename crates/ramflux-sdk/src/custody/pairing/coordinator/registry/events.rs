// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded public display snapshots. Tokens and private inputs have no event variant.
use super::{Arc, Entry, PairingActor, Path, SdkError};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    local_dto::{FullStatusEvent, LocalEvent, LocalResult, Outcome, StatusRequest},
};
use std::collections::VecDeque;
const CAPACITY: usize = 64;
#[derive(Default)]
pub(super) struct Events {
    head: u64,
    last: VecDeque<((String, u64), Vec<u8>)>,
    rows: VecDeque<(u64, LocalEvent)>,
}
impl Events {
    pub(super) fn remember(&mut self, result: LocalResult) -> Result<bool, SdkError> {
        let event = match result.outcome {
            Outcome::Update { value } => LocalEvent::Update {
                schema: "ramflux.pairing.LocalEvent.v2".into(),
                version: 2,
                update: value,
            },
            Outcome::FullStatus { value } => LocalEvent::FullStatus {
                schema: "ramflux.pairing.LocalEvent.v2".into(),
                version: 2,
                outcome: FullStatusEvent::FullStatus { value },
            },
            Outcome::Begin { .. } | Outcome::Error { .. } => return Ok(false),
        };
        let bytes = event.to_wire_bytes().map_err(|_| SdkError::PairingCode("WrongContext"))?;
        let (operation, generation) = match &event {
            LocalEvent::Update { update, .. } => (&update.operation_id, update.generation),
            LocalEvent::FullStatus { outcome: FullStatusEvent::FullStatus { value }, .. } => {
                (&value.operation_id, value.generation)
            }
        };
        let identity = (operation.clone(), generation);
        if self.last.iter().any(|(scope, prior)| scope == &identity && *prior == bytes) {
            return Ok(false);
        }
        let head = self
            .head
            .checked_add(1)
            .filter(|head| *head <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or(SdkError::PairingCode("Retired"))?;
        if let Some((_, prior)) = self.last.iter_mut().find(|(scope, _)| scope == &identity) {
            *prior = bytes;
        } else {
            if self.last.len() == CAPACITY {
                self.last.pop_front();
            }
            self.last.push_back((identity, bytes));
        }
        self.head = head;
        if self.rows.len() == CAPACITY {
            self.rows.pop_front();
        }
        self.rows.push_back((self.head, event));
        Ok(true)
    }
    fn floor(&self) -> u64 {
        self.rows.front().map_or(self.head, |(seq, _)| seq.saturating_sub(1))
    }
}
pub(crate) struct PairingEventSubscription(Arc<Entry>);
impl PairingEventSubscription {
    pub(crate) fn bounds(&self) -> Result<(u64, u64), SdkError> {
        self.0.require_live()?;
        let events = self.0.events.lock().map_err(|_| SdkError::PairingCode("Retired"))?;
        Ok((events.floor(), events.head))
    }
    pub(crate) fn page(&self, cursor: u64) -> Result<Vec<(u64, LocalEvent)>, SdkError> {
        self.0.require_live()?;
        let events = self.0.events.lock().map_err(|_| SdkError::PairingCode("Retired"))?;
        if cursor < events.floor() || cursor > events.head {
            return Err(SdkError::PairingCode("ResumeRequired"));
        }
        Ok(events.rows.iter().filter(|(seq, _)| *seq > cursor).cloned().collect())
    }
    pub(crate) fn signal(&self) -> Arc<tokio::sync::Notify> {
        self.0.event_signal.clone()
    }
}
pub(crate) fn pairing_event_stream(
    root: &Path,
    account: &str,
) -> Result<PairingEventSubscription, SdkError> {
    let entry = super::find(root, account)?;
    entry.require_live()?;
    Ok(PairingEventSubscription(entry))
}
impl Entry {
    pub(in crate::custody::pairing::coordinator) fn remember_display(
        &self,
        actor: &PairingActor,
    ) -> Result<(), SdkError> {
        self.require_live()?;
        let mut events = self.events.lock().map_err(|_| SdkError::PairingCode("Retired"))?;
        let mut changed = false;
        if let Some(result) = actor.display_snapshot()? {
            changed |= events.remember(result)?;
        }
        for (operation, job) in &actor.tail_jobs {
            changed |= events.remember(job.result(&StatusRequest {
                schema: "ramflux.pairing.StatusRequest.v2".into(),
                version: 2,
                operation_id: operation.clone(),
                generation: job.generation(),
            })?)?;
        }
        drop(events);
        if changed {
            self.event_signal.notify_waiters();
        }
        Ok(())
    }
}
impl PairingActor {
    fn display_snapshot(&self) -> Result<Option<LocalResult>, SdkError> {
        if let Some(ceremony) = &self.ceremony {
            if let Some(job) = self.tail_jobs.get(&ceremony.operation_id) {
                return job
                    .result(&StatusRequest {
                        schema: "ramflux.pairing.StatusRequest.v2".into(),
                        version: 2,
                        operation_id: ceremony.operation_id.clone(),
                        generation: ceremony.generation,
                    })
                    .map(Some);
            }
            if let Some(value) = self.current_full_status()? {
                return Ok(Some(LocalResult {
                    schema: "ramflux.pairing.LocalResult.v2".into(),
                    version: 2,
                    outcome: Outcome::FullStatus { value: Box::new(value) },
                }));
            }
            return self.status_update().map(Some);
        }
        if let Some(recovered) = &self.recovered_installation {
            return recovered.local_result().map(Some);
        }
        if let Some((operation, job)) = self.tail_jobs.iter().next_back() {
            return job
                .result(&StatusRequest {
                    schema: "ramflux.pairing.StatusRequest.v2".into(),
                    version: 2,
                    operation_id: operation.clone(),
                    generation: job.generation(),
                })
                .map(Some);
        }
        if let Some(status) = &self.recovered_tail_status {
            return self.recovered_tail_result(&StatusRequest {
                schema: "ramflux.pairing.StatusRequest.v2".into(),
                version: 2,
                operation_id: status.operation_id.clone(),
                generation: status.generation,
            });
        }
        Ok(None)
    }
}
