// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One frame dispatcher for idle reads and bounded gateway helpers.

use super::frame_dispatch::{ExpectedReply, FrameClass, FrameKind};
use super::{GatewayClientFrame, GatewayInboxEntry, GatewayServerFrame, GatewaySessionEngine};
use crate::SdkError;
use crate::bus::connection_manager::{DisconnectReason, SessionHub};
use crate::bus::runtime_limits::{SESSION_BUFFER, SESSION_BUFFER_BYTES};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct HostFrames {
    pub hub: Arc<SessionHub>,
    pub resync_needed: Arc<crate::bus::connection_manager::resync::ResyncState>,
    #[cfg(test)]
    pub buffer_stats: Arc<std::sync::Mutex<BufferStats>>,
}

impl GatewaySessionEngine {
    pub(crate) async fn write_frame(&mut self, frame: &GatewayClientFrame) -> Result<(), SdkError> {
        // Even a partial failed write makes the uncorrelated reply stream unsafe to reuse.
        self.wire_writes = self.wire_writes.wrapping_add(1);
        let result = super::write_gateway_client_frame(&mut *self.stream, frame).await;
        if result.is_err() {
            self.terminal_reason = Some(DisconnectReason::Transport);
        }
        result
    }

    pub(crate) fn buffer_delivery(&mut self, entry: GatewayInboxEntry) {
        let bytes = self.last_frame_bytes;
        if self.pending_deliveries.len() >= SESSION_BUFFER
            || self.buffered_bytes.saturating_add(bytes) > SESSION_BUFFER_BYTES
        {
            if let Some(host) = &self.host {
                host.resync_needed.request();
                host.hub.lag();
            }
            #[cfg(test)]
            {
                self.buffer_stats.dropped += 1;
                self.publish_buffer_stats();
            }
            return;
        }
        self.buffered_bytes += bytes;
        self.pending_deliveries.push_back((entry, bytes));
        #[cfg(test)]
        {
            self.buffer_stats.entries =
                self.buffer_stats.entries.max(self.pending_deliveries.len());
            self.buffer_stats.bytes = self.buffer_stats.bytes.max(self.buffered_bytes);
            self.publish_buffer_stats();
        }
    }

    #[cfg(test)]
    fn publish_buffer_stats(&self) {
        if let Some(host) = &self.host {
            *host.buffer_stats.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                self.buffer_stats;
        }
    }

    pub(crate) fn take_pending_deliveries(&mut self) -> Vec<GatewayInboxEntry> {
        self.buffered_bytes = 0;
        self.pending_deliveries.drain(..).map(|(entry, _)| entry).collect()
    }

    pub(crate) async fn read_reply(
        &mut self,
        expected: ExpectedReply,
    ) -> Result<GatewayServerFrame, SdkError> {
        loop {
            let frame = self.read_raw_gateway_frame("gateway response").await?;
            if self.dispatch_frame(&frame, Some(expected))? {
                return Ok(frame);
            }
        }
    }

    // The current gateway returns Deliver as the durable ordinary-Submit receipt.
    // Only the pending envelope id admits that named compatibility exception.
    pub(crate) async fn read_submit_reply(
        &mut self,
        envelope_id: &str,
    ) -> Result<GatewayServerFrame, SdkError> {
        loop {
            let frame = self.read_raw_gateway_frame("submit response").await?;
            if matches!(&frame,GatewayServerFrame::Deliver {entry} if entry.envelope.envelope_id==envelope_id)
            {
                return Ok(frame);
            }
            if self.dispatch_frame(&frame, Some(ExpectedReply::Submit))? {
                return Ok(frame);
            }
        }
    }

    /// Reads one complete frame, retaining partial transport bytes if this future is cancelled.
    pub(crate) async fn idle_read(&mut self) -> Result<(), SdkError> {
        let bytes = self.stream.recv_idle_frame().await?;
        self.last_frame_bytes = bytes.len();
        let frame = serde_json::from_slice(&bytes)?;
        self.dispatch_frame(&frame, None)?;
        Ok(())
    }

    /// Returns true only for a reply admitted by the active helper's set.
    pub(crate) fn dispatch_frame(
        &mut self,
        frame: &GatewayServerFrame,
        expected: Option<ExpectedReply>,
    ) -> Result<bool, SdkError> {
        self.dispatch_frame_for_request(frame, expected, None)
    }

    pub(crate) fn dispatch_frame_for_request(
        &mut self,
        frame: &GatewayServerFrame,
        expected: Option<ExpectedReply>,
        request_id: Option<&str>,
    ) -> Result<bool, SdkError> {
        let kind = FrameKind::of(frame);
        match kind.class() {
            FrameClass::PushRoute => {
                let matched = matches!(expected, Some(ExpectedReply::PushRoute))
                    && request_id.is_some()
                    && super::push_route::push_route_reply_id(frame) == request_id;
                if let Err(error) = self.apply_push_route_reply(frame.clone()) {
                    tracing::warn!(%error, "push route registration refused");
                }
                if !matched && let Some(host) = &self.host {
                    host.hub.publish(frame.clone());
                }
                Ok(matched)
            }
            FrameClass::Event => {
                if let GatewayServerFrame::Deliver { entry } = frame {
                    self.buffer_delivery(entry.clone());
                }
                if let Some(host) = &self.host {
                    host.hub.publish(frame.clone());
                }
                Ok(false)
            }
            FrameClass::Reply if expected.is_some_and(|set| set.accepts(kind)) => Ok(true),
            FrameClass::Terminal => {
                self.terminal_reason = Some(if matches!(kind, FrameKind::Drain) {
                    DisconnectReason::Drain
                } else {
                    DisconnectReason::Close
                });
                Err(ramflux_transport::TransportError::ShutdownDraining.into())
            }
            FrameClass::Reply | FrameClass::Unexpected => {
                self.terminal_reason = Some(DisconnectReason::UnexpectedReply);
                tracing::warn!(?kind, ?expected, "unexpected gateway reply; retiring session");
                Err(SdkError::GatewaySessionRejected(format!("unexpected gateway reply: {kind:?}")))
            }
        }
    }

    pub(crate) async fn read_raw_gateway_frame(
        &mut self,
        operation: &'static str,
    ) -> Result<GatewayServerFrame, SdkError> {
        if let Some(frame) = self.deferred_frames.pop_front() {
            return Ok(frame);
        }
        self.read_stream_frame(operation).await
    }

    pub(crate) async fn read_stream_frame(
        &mut self,
        operation: &'static str,
    ) -> Result<GatewayServerFrame, SdkError> {
        let result = super::engine::frame_timeout(self.frame_timeout, operation, async {
            self.stream.recv_frame().await.map_err(SdkError::from)
        })
        .await;
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(error) => {
                self.terminal_reason =
                    Some(if matches!(error, SdkError::GatewaySessionRejected(_)) {
                        DisconnectReason::CallTimeout
                    } else {
                        DisconnectReason::Transport
                    });
                return Err(error);
            }
        };
        self.last_frame_bytes = bytes.len();
        serde_json::from_slice(&bytes).map_err(|error| {
            self.terminal_reason = Some(DisconnectReason::Transport);
            SdkError::from(error)
        })
    }
}

#[cfg(test)]
#[derive(Default, Clone, Copy)]
pub(crate) struct BufferStats {
    pub entries: usize,
    pub bytes: usize,
    pub dropped: usize,
}
