// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The `resume_page` operation on a negotiated session, and the adapters that let the public
//! resume entry points use it.

use super::host_frames::{Step, Wait};
use super::session_push::{
    CapableClientFrame, CapableServerFrame, KnownLoss, PageEntryRecord, PushNackReason, SessionMode,
};
use super::{GatewayInboxEntry, GatewayResumeFrame, GatewaySessionEngine};
use crate::SdkError;
use crate::dm::dedup_gateway_entries;

/// A validated `resume_page` reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResumePage {
    pub(crate) after_inbox_seq: u64,
    pub(crate) covered_through_seq: u64,
    pub(crate) issued_inbox_seq: u64,
    pub(crate) settled_through_seq: u64,
    pub(crate) entries: Vec<PageEntryRecord>,
    pub(crate) known_losses: Vec<KnownLoss>,
    pub(crate) oversize_next: Option<u64>,
    pub(crate) more: bool,
}

/// What the gateway answered to one `resume`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PageReply {
    Page(Box<ResumePage>),
    /// A refusal keyed to this session's incarnation. The session stays usable.
    Refused(PushNackReason),
}

impl PushNackReason {
    /// The wire spelling of the reason.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::IncarnationMismatch => "incarnation_mismatch",
            Self::InvalidSeq => "invalid_seq",
            Self::InvalidLimit => "invalid_limit",
            Self::CursorAhead => "cursor_ahead",
            Self::PayloadTooLarge => "payload_too_large",
            Self::AckBackpressureRetry => "ack_backpressure_retry",
            Self::GatewayRequestInvalid => "gateway_request_invalid",
            Self::InvalidResumeToken => "invalid_resume_token",
            Self::Busy => "busy",
        }
    }
}

fn local_refusal(why: &str) -> SdkError {
    SdkError::GatewaySessionRejected(format!("resume_page refused locally: {why}"))
}

impl GatewaySessionEngine {
    /// Requests one resume page on a negotiated session.
    ///
    /// A capable `deliver` arriving during the wait is buffered and the wait continues. The
    /// reply must carry this session's incarnation and target and echo `after`. Any other
    /// reply retires the session.
    ///
    /// # Errors
    /// Refuses locally, before any write, on a session that is not negotiated or when
    /// `limit == 0`. Otherwise returns an error when the session is retired or the transport
    /// fails.
    pub(crate) async fn resume_page(
        &mut self,
        after: u64,
        limit: usize,
    ) -> Result<PageReply, SdkError> {
        let SessionMode::Push { incarnation } = &self.mode else {
            return Err(local_refusal("the session is not negotiated"));
        };
        let incarnation = incarnation.clone();
        let resume = GatewayResumeFrame {
            target_delivery_id: self.config.target_delivery_id.clone(),
            after_inbox_seq: after,
            limit,
            resume_token: self.session.resume_token.clone(),
        };
        let frame = CapableClientFrame::resume(incarnation.as_str(), resume)
            .map_err(|_| local_refusal("the limit is zero"))?;
        self.write_capable_frame(&frame).await?;
        loop {
            match self.read_step("resume page", Wait::ResumePage).await? {
                Step::ResumePage(page) => return self.check_page(*page, after),
                Step::Refused(reason) => return Ok(PageReply::Refused(reason)),
                Step::Legacy(frame) => {
                    // Events are handled by the dispatcher; a legacy reply of any kind
                    // retires the session (no legacy reply is valid here).
                    self.dispatch_frame(&frame, None)?;
                }
                Step::SubmitAccepted(_) => {
                    return Err(self.retire("unexpected capable reply while awaiting a page"));
                }
            }
        }
    }

    fn check_page(&mut self, page: CapableServerFrame, after: u64) -> Result<PageReply, SdkError> {
        let CapableServerFrame::ResumePage {
            target_delivery_id,
            incarnation_id,
            after_inbox_seq,
            covered_through_seq,
            issued_inbox_seq,
            settled_through_seq,
            entries,
            known_losses,
            oversize_next,
            more,
        } = page
        else {
            return Err(self.retire("unexpected capable reply while awaiting a page"));
        };
        let SessionMode::Push { incarnation } = &self.mode else {
            return Err(self.retire("resume_page on an unnegotiated session"));
        };
        if &incarnation_id != incarnation {
            return Err(self.retire("resume_page with a foreign incarnation"));
        }
        if target_delivery_id != self.config.target_delivery_id {
            return Err(self.retire("resume_page for a different target"));
        }
        if after_inbox_seq != after {
            return Err(self.retire("resume_page for a different cursor"));
        }
        if entries.iter().any(|record| record.entry.target_delivery_id != target_delivery_id) {
            return Err(self.retire("resume_page entry for a different target"));
        }
        Ok(PageReply::Page(Box::new(ResumePage {
            after_inbox_seq,
            covered_through_seq,
            issued_inbox_seq,
            settled_through_seq,
            entries,
            known_losses,
            oversize_next,
            more,
        })))
    }

    /// The page entries as the public type.
    async fn adapted_page(
        &mut self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<GatewayInboxEntry>, SdkError> {
        match self.resume_page(after, limit).await? {
            PageReply::Page(page) => {
                Ok(page.entries.into_iter().map(|record| record.entry).collect())
            }
            PageReply::Refused(reason) => {
                Err(SdkError::GatewaySessionRejected(reason.as_str().to_owned()))
            }
        }
    }

    /// `resume_after` on a negotiated session: buffered deliveries, then the page.
    pub(crate) async fn push_resume_after(
        &mut self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<GatewayInboxEntry>, SdkError> {
        let mut delivered = self.take_pending_deliveries();
        let page = self.adapted_page(after, limit).await?;
        delivered.extend(self.take_pending_deliveries());
        delivered.extend(page);
        Ok(dedup_gateway_entries(delivered))
    }

    /// `resume_authoritative_after` on a negotiated session: the page only.
    pub(crate) async fn push_resume_authoritative(
        &mut self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<GatewayInboxEntry>, SdkError> {
        let page = self.adapted_page(after, limit).await?;
        self.take_pending_deliveries();
        Ok(dedup_gateway_entries(page))
    }
}
