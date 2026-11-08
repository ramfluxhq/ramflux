// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One frame dispatcher for idle reads and bounded gateway helpers.

use super::engine::PendingDelivery;
use super::frame_dispatch::{ExpectedReply, FrameClass, FrameKind};
use super::session_push::{CapableEvent, CapableServerFrame, PushMeta, SessionMode};
use super::{GatewayClientFrame, GatewayInboxEntry, GatewayServerFrame, GatewaySessionEngine};
use crate::SdkError;
use crate::bus::connection_manager::{DisconnectReason, SessionHub};
use crate::bus::runtime_limits::{SESSION_BUFFER, SESSION_BUFFER_BYTES};
use std::sync::Arc;

/// What the caller of a read is waiting for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wait {
    /// A legacy reply or event; a capable reply retires the session.
    Legacy,
    /// A submit reply: the legacy forms or a capable `submit_accepted`.
    Submit,
    /// A `resume_page`, or a keyed refusal for this session.
    ResumePage,
    /// `entry`, `entry_too_large` or `entry_gone`, or a keyed refusal. Dormant until a caller.
    #[allow(dead_code)]
    Fetch,
    /// `ack_batch`, or a keyed refusal. Dormant until a caller.
    #[allow(dead_code)]
    AckBatch,
    /// The capable single `ack`, or a keyed refusal.
    Ack,
}

/// A frame returned to the caller of `read_step`.
pub(crate) enum Step {
    Legacy(Box<GatewayServerFrame>),
    SubmitAccepted(Box<CapableServerFrame>),
    ResumePage(Box<CapableServerFrame>),
    /// The reply of a point read, a batch ACK or a single ACK; the caller checks its fields.
    Reply(Box<CapableServerFrame>),
    /// A capable `nack` keyed to this session's incarnation.
    Refused(super::session_push::PushNackReason),
}

#[derive(Clone)]
pub(crate) struct HostFrames {
    pub hub: Arc<SessionHub>,
    pub resync_needed: Arc<crate::bus::connection_manager::resync::ResyncState>,
    #[cfg(test)]
    pub buffer_stats: Arc<std::sync::Mutex<BufferStats>>,
    #[cfg(test)]
    pub dispatch_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl HostFrames {
    #[cfg(test)]
    pub(crate) fn record_dispatch(&self) {
        self.dispatch_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl GatewaySessionEngine {
    /// Writes a negotiated client frame; it can only exist if its constructor accepted it.
    pub(crate) async fn write_capable_frame(
        &mut self,
        frame: &super::session_push::CapableClientFrame,
    ) -> Result<(), SdkError> {
        self.wire_writes = self.wire_writes.wrapping_add(1);
        let result = ramflux_transport::write_gateway_session_json(&mut *self.stream, frame)
            .await
            .map_err(SdkError::from);
        if result.is_err() {
            self.terminal_reason = Some(DisconnectReason::Transport);
        }
        result
    }

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
        self.buffer(entry, None);
    }

    /// Buffers a negotiated-session deliver under the same bounds and overflow action as a
    /// legacy one.
    pub(crate) fn buffer_capable_delivery(&mut self, entry: GatewayInboxEntry, meta: PushMeta) {
        self.buffer(entry, Some(meta));
    }

    fn buffer(&mut self, entry: GatewayInboxEntry, push: Option<PushMeta>) {
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
        self.pending_deliveries.push_back(PendingDelivery { entry, push, bytes });
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
        self.pending_deliveries.drain(..).map(|pending| pending.entry).collect()
    }

    /// Drains the buffer with the push metadata of each delivery. Unused until the receive
    /// adapters of a later part consume it; the carrier test exercises it.
    #[allow(dead_code)]
    pub(crate) fn take_pending_capable(&mut self) -> Vec<(GatewayInboxEntry, Option<PushMeta>)> {
        self.buffered_bytes = 0;
        self.pending_deliveries.drain(..).map(|pending| (pending.entry, pending.push)).collect()
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
        if let Some(Step::Legacy(frame)) = self.route_bytes(&bytes, false, Wait::Legacy)? {
            self.dispatch_frame(&frame, None)?;
        }
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
                    #[cfg(test)]
                    host.record_dispatch();
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
        match self.read_step(operation, Wait::Legacy).await? {
            Step::Legacy(frame) => Ok(*frame),
            Step::SubmitAccepted(_) | Step::ResumePage(_) | Step::Reply(_) | Step::Refused(_) => {
                Err(self.retire("capable reply outside a capable wait"))
            }
        }
    }

    /// Reads until a frame for the caller arrives. Capable events are carried on the way, and
    /// only the reply kinds the `wait` names are returned.
    pub(crate) async fn read_step(
        &mut self,
        operation: &'static str,
        wait: Wait,
    ) -> Result<Step, SdkError> {
        loop {
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
            // `None` means a capable event was carried; keep waiting for the caller's frame.
            if let Some(step) = self.route_bytes(&bytes, true, wait)? {
                return Ok(step);
            }
        }
    }

    /// Routes one raw frame. `None` means a capable event was carried. Every outcome the wait
    /// does not name retires the session.
    fn route_bytes(
        &mut self,
        bytes: &[u8],
        transport_on_decode_error: bool,
        wait: Wait,
    ) -> Result<Option<Step>, SdkError> {
        use super::session_push::{CapableServerFrame, RouteError, Routed, route};
        match route(bytes, &self.mode) {
            Ok(Routed::Legacy(frame)) => Ok(Some(Step::Legacy(frame))),
            Ok(Routed::Capable(frame)) => match CapableEvent::try_from(*frame) {
                Ok(event) => {
                    self.check_event(&event)?;
                    self.accept_capable(event);
                    Ok(None)
                }
                Err(reply) => match (wait, reply) {
                    (Wait::Submit, accepted @ CapableServerFrame::SubmitAccepted { .. }) => {
                        Ok(Some(Step::SubmitAccepted(Box::new(accepted))))
                    }
                    (Wait::Submit, _) => {
                        Err(self.retire("unexpected capable reply while awaiting a submit"))
                    }
                    (Wait::ResumePage, page @ CapableServerFrame::ResumePage { .. }) => {
                        Ok(Some(Step::ResumePage(Box::new(page))))
                    }
                    (
                        Wait::Fetch,
                        reply @ (CapableServerFrame::Entry { .. }
                        | CapableServerFrame::EntryTooLarge { .. }
                        | CapableServerFrame::EntryGone { .. }),
                    )
                    | (Wait::AckBatch, reply @ CapableServerFrame::AckBatch { .. })
                    | (Wait::Ack, reply @ CapableServerFrame::Ack { .. }) => {
                        Ok(Some(Step::Reply(Box::new(reply))))
                    }
                    (
                        Wait::ResumePage | Wait::Fetch | Wait::AckBatch | Wait::Ack,
                        CapableServerFrame::Nack { reason, incarnation_id: Some(id) },
                    ) => {
                        if matches!(&self.mode, SessionMode::Push { incarnation } if *incarnation == id)
                        {
                            Ok(Some(Step::Refused(reason)))
                        } else {
                            Err(self.retire("capable nack with a foreign incarnation"))
                        }
                    }
                    (Wait::ResumePage, _) => {
                        Err(self.retire("unexpected capable reply while awaiting a page"))
                    }
                    (Wait::Fetch | Wait::AckBatch | Wait::Ack, _) => {
                        Err(self.retire("unexpected capable reply while awaiting a point reply"))
                    }
                    (Wait::Legacy, _) => Err(self.retire("capable reply outside a capable wait")),
                },
            },
            Err(RouteError::Retire(why)) => Err(self.retire(why)),
            Err(RouteError::Capable(_)) => Err(self.retire("malformed capable frame")),
            Err(RouteError::Legacy(error)) => {
                if transport_on_decode_error {
                    self.terminal_reason = Some(DisconnectReason::Transport);
                }
                Err(SdkError::from(error))
            }
        }
    }

    /// An event of another incarnation, or a deliver for another target, is never carried.
    fn check_event(&mut self, event: &CapableEvent) -> Result<(), SdkError> {
        let SessionMode::Push { incarnation } = &self.mode else {
            return Ok(());
        };
        let (event_incarnation, target) = match event {
            CapableEvent::Deliver { entry, incarnation_id, .. } => {
                (incarnation_id, Some(&entry.target_delivery_id))
            }
            CapableEvent::Resync { incarnation_id, .. } => (incarnation_id, None),
        };
        if event_incarnation != incarnation {
            return Err(self.retire("capable event with a foreign incarnation"));
        }
        if target.is_some_and(|target| *target != self.config.target_delivery_id) {
            return Err(self.retire("capable deliver for a foreign target"));
        }
        Ok(())
    }

    /// Buffers a deliver and publishes the event; nothing is dropped silently.
    fn accept_capable(&mut self, event: CapableEvent) {
        if let CapableEvent::Deliver { entry, incarnation_id, retain_until } = &event {
            let meta =
                PushMeta { incarnation_id: incarnation_id.clone(), retain_until: *retain_until };
            self.buffer_capable_delivery(entry.clone(), meta);
        }
        if let Some(host) = &self.host {
            #[cfg(test)]
            host.record_dispatch();
            host.hub.publish_capable(event);
        }
    }

    pub(crate) fn retire(&mut self, why: &str) -> SdkError {
        self.terminal_reason = Some(DisconnectReason::UnexpectedReply);
        tracing::warn!(%why, "unexpected gateway frame; retiring session");
        SdkError::GatewaySessionRejected(format!("unexpected gateway frame: {why}"))
    }
}

#[cfg(test)]
#[derive(Default, Clone, Copy)]
pub(crate) struct BufferStats {
    pub entries: usize,
    pub bytes: usize,
    pub dropped: usize,
}
