// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::{Error, Result};
use ramflux_sdk::{LocalBusClient, LocalBusFrame};
use serde_json::Value;
use std::{
    future::Future,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub trait AgentBus {
    /// # Errors
    /// Reports an rfd failure without exposing response bodies or secrets.
    fn request(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> impl Future<Output = Result<Value>>;
    /// # Errors
    /// Reports disconnected or lagged streams.
    fn next_event(&mut self) -> impl Future<Output = Result<LocalBusFrame>>;
}
pub struct RfdBus {
    client: LocalBusClient,
    account: String,
    next: u64,
}
impl RfdBus {
    /// # Errors
    /// Rejects unavailable local sockets (including operator-managed remote socket forwards).
    pub async fn connect(socket: &Path, account: &str) -> Result<Self> {
        Ok(Self {
            client: LocalBusClient::connect(socket).await.map_err(|_| Error::Bus)?,
            account: account.into(),
            next: 0,
        })
    }
}
impl AgentBus for RfdBus {
    async fn request(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> Result<Value> {
        // This is the complete capability surface of this host; approvals cannot pass through.
        if !matches!(
            method,
            "account.status"
                | "device.list"
                | "identity.directory"
                | "conversation.directory"
                | "group.members"
                | "group.list"
                | "message.read"
                | "message.receive"
                | "bus.subscribe"
                | "message.submit"
                | "group.send"
                | "surface.send"
                | "surface.get"
                | "surface.resync"
        ) {
            return Err(Error::Unauthorized);
        }
        self.next = self.next.checked_add(1).ok_or(Error::Limit)?;
        let mut frame = LocalBusFrame::request(
            format!("agent-{}", self.next),
            Some(self.account.clone()),
            "agent",
            method,
            body,
        );
        frame.operation_id = operation.map(str::to_owned);
        frame.deadline_ms = Some(now_ms().saturating_add(30_000));
        let response = self.client.request_frame_response(frame).await.map_err(|_| Error::Bus)?;
        if response.kind == ramflux_sdk::LocalBusFrameKind::Error {
            let error = response.error.ok_or(Error::Bus)?;
            if error.code == "resync_required" {
                return Err(Error::Resync);
            }
            if method.starts_with("surface.")
                && let Ok(reason) = serde_json::from_value(serde_json::json!(error.code))
            {
                return Err(Error::SurfaceRefused(reason));
            }
            return Err(Error::Bus);
        }
        Ok(response.body)
    }
    async fn next_event(&mut self) -> Result<LocalBusFrame> {
        self.client.next_event().await.map_err(|_| Error::Bus)
    }
}
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
