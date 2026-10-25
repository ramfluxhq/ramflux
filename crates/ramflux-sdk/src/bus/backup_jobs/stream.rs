// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Minimal daemon-scoped job stream with bounded replay and explicit lag/resync.
use super::service::refused;
use crate::backup::BACKUP_JOB_TOPIC;
use crate::bus::supervisor::Supervisor;
use crate::prelude::*;
impl Supervisor {
    pub(crate) async fn subscribe_backup_stream(
        &self,
        request: LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<(), SdkError> {
        let topics = request
            .body
            .get("topics")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| refused("invalid_subscription"))?;
        if topics.len() != 1 || topics[0].as_str() != Some(BACKUP_JOB_TOPIC) {
            return Err(refused("daemon_scope_jobs_only"));
        }
        if request.body.get("attended_frontend").and_then(serde_json::Value::as_bool) == Some(true)
        {
            self.daemon_attended.borrow_mut().insert(connection.connection_id);
        }
        let jobs = self.backup_jobs.clone();
        let (floor, head) = {
            let state = jobs.state.lock().map_err(|_| refused("interrupted"))?;
            (state.events.front().map_or(state.head, |(seq, _)| seq.saturating_sub(1)), state.head)
        };
        let mut cursor =
            request.body.get("since_seq").and_then(serde_json::Value::as_u64).unwrap_or(head);
        if cursor < floor || cursor > head {
            let mut error = local_bus_error(&request, &refused("resync_required"));
            if let Some(body) = &mut error.error {
                body.code = "resync_required".into();
            }
            error.body = serde_json::json!({"floor_seq":floor,"head_seq":head});
            connection.outbound.send(error).await.map_err(|_| refused("interrupted"))?;
            return Ok(());
        }
        connection
            .outbound
            .send(local_bus_response(
                &request,
                serde_json::json!({"subscribed":true,"floor_seq":floor,"head_seq":head}),
            ))
            .await
            .map_err(|_| refused("interrupted"))?;
        let outbound = connection.outbound.clone();
        let push = request.method == "subscription.open";
        let task = tokio::task::spawn_local(async move {
            loop {
                let page = {
                    let Ok(state) = jobs.state.lock() else { return };
                    let floor =
                        state.events.front().map_or(state.head, |(seq, _)| seq.saturating_sub(1));
                    if cursor < floor {
                        None
                    } else {
                        Some(
                            state
                                .events
                                .iter()
                                .filter(|(seq, _)| *seq > cursor)
                                .cloned()
                                .collect::<Vec<_>>(),
                        )
                    }
                };
                let Some(page) = page else {
                    crate::bus::subscription::lagged(&outbound, &request, cursor);
                    return;
                };
                for (seq, row) in page {
                    if outbound.capacity() <= 1 {
                        crate::bus::subscription::lagged(&outbound, &request, cursor);
                        return;
                    }
                    let Ok(body) = serde_json::to_value(row) else { return };
                    let mut frame =
                        local_bus_event(&request, "", "account", BACKUP_JOB_TOPIC, body);
                    frame.account_id = None;
                    frame.seq = Some(seq);
                    if outbound.try_send(frame).is_err() {
                        return;
                    }
                    cursor = seq;
                }
                tokio::select! {()=outbound.closed()=>return,()=tokio::time::sleep(Duration::from_millis(if push{25}else{50}))=>{}}
            }
        });
        self.replace_backup_stream(connection.connection_id, task);
        Ok(())
    }
}
