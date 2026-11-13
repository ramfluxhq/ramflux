// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receipt presentation never upgrades acceptance into delivery or read.

/// Semantic receipt facts supplied by the SDK adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Receipt {
    /// Awaiting acceptance.
    Sending,
    /// Retry is scheduled before acceptance, at monotonic milliseconds.
    WaitingForNode { retry_at_ms: u64 },
    /// An attempt failed; retries require explicit backend permission.
    Failed { retryable: bool },
    /// Accepted by the node.
    Sent,
    /// Delivered to the peer device.
    Delivered,
    /// Read by the peer.
    Read,
}

/// Interface-neutral receipt facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiptPresentation {
    /// Original semantic state; no inference from elapsed time.
    pub state: Receipt,
    /// Manual retry is safe only after a known pre-acceptance failure.
    pub manual_retry: bool,
    /// Remaining scheduled delay, bounded below by zero.
    pub remaining_ms: Option<u64>,
}

/// Projects an outgoing receipt. Incoming messages have no outgoing receipt.
#[must_use]
pub fn present(outgoing: bool, state: Receipt, now_ms: u64) -> Option<ReceiptPresentation> {
    outgoing.then(|| ReceiptPresentation {
        state,
        manual_retry: matches!(state, Receipt::Failed { retryable: true }),
        remaining_ms: match state {
            Receipt::WaitingForNode { retry_at_ms } => Some(retry_at_ms.saturating_sub(now_ms)),
            _ => None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_and_retry_facts_are_never_inferred() {
        assert_eq!(
            present(false, Receipt::Read, 0),
            None,
            "incoming messages must not show our delivery status"
        );
        let sent = present(true, Receipt::Sent, u64::MAX).expect("test: outgoing receipt");
        assert_eq!(sent.state, Receipt::Sent, "time cannot turn acceptance into delivery");
        assert!(!sent.manual_retry, "accepted sends cannot be manually duplicated");
        let failed =
            present(true, Receipt::Failed { retryable: false }, 0).expect("test: failed send");
        assert!(!failed.manual_retry, "unknown outcomes require reconciliation");
        let waiting = present(true, Receipt::WaitingForNode { retry_at_ms: 1 }, 2)
            .expect("test: scheduled send");
        assert_eq!(waiting.remaining_ms, Some(0), "a passed deadline cannot underflow");
        assert!(!waiting.manual_retry, "automatic scheduling is not permission for a second send");
    }
}
