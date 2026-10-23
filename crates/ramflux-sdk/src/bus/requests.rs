// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-request deadlines, responses and legacy response-before-event ordering.

use super::actor::ActorResponse;
use super::supervisor::Supervisor;
use crate::prelude::*;

pub(super) fn deadline(request: &LocalBusFrame) -> Result<Option<tokio::time::Instant>, SdkError> {
    let Some(deadline) = request.deadline_ms else {
        return Ok(None);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis());
    let remaining = u128::from(deadline).saturating_sub(now);
    if remaining == 0 {
        return Err(expired());
    }
    let millis = u64::try_from(remaining).map_err(|_| expired())?;
    tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(millis))
        .map(Some)
        .ok_or_else(expired)
}

pub(super) async fn respond(
    request: LocalBusFrame,
    supervisor: Rc<Supervisor>,
    context: LocalBusConnectionState,
) -> (String, Result<(), SdkError>) {
    let mut stop_response = (request.method == "daemon.stop").then(|| StopResponse {
        supervisor: Rc::clone(&supervisor),
        connection: context.connection_id,
        request: request.request_id.clone(),
        armed: true,
    });
    let result = dispatch(&request, &supervisor, &context).await;
    let (response, events) = match result {
        Ok(result) => (local_bus_response(&request, result.body), result.events),
        Err(error) => (local_bus_error(&request, &error), Vec::new()),
    };
    #[cfg(feature = "itest-bus-fault")]
    if response.ok == Some(true) {
        match crate::itest_bus_fault::should_drop_response(&request.method) {
            Ok(true) => {
                return (
                    request.request_id,
                    Err(SdkError::LocalBus("local bus response dropped".to_owned())),
                );
            }
            Err(error) => return (request.request_id, Err(error)),
            Ok(false) => {}
        }
    }
    let sent =
        context.outbound.send(response).await.map_err(|_| {
            SdkError::LocalBus("local bus outbound response channel closed".to_owned())
        });
    if sent.is_ok() {
        if let Some(guard) = stop_response.as_mut() {
            guard.armed = false;
        }
        supervisor.broadcast(&events);
    }
    (request.request_id, sent)
}

async fn dispatch(
    request: &LocalBusFrame,
    supervisor: &Supervisor,
    context: &LocalBusConnectionState,
) -> Result<ActorResponse, SdkError> {
    if let Some(deadline) = deadline(request)? {
        tokio::time::timeout_at(deadline, supervisor.request(request.clone(), context))
            .await
            .map_err(|_| expired())?
    } else {
        supervisor.request(request.clone(), context).await
    }
}
fn expired() -> SdkError {
    SdkError::LocalBus("request deadline exceeded or outside supported clock range".to_owned())
}

struct StopResponse {
    supervisor: Rc<Supervisor>,
    connection: u64,
    request: String,
    armed: bool,
}
impl Drop for StopResponse {
    fn drop(&mut self) {
        if self.armed {
            self.supervisor.finish_stop_response(self.connection, &self.request);
        }
    }
}
