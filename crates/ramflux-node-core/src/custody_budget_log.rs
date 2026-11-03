// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refusals describe only budget counters, never client identities or transport addresses.
use ramflux_protocol::custody::{CustodyRefusal, CustodyServerFrame, RetryHint, RetryScope};

/// Retry interval for bounded node state without a meaningful release-time prediction.
pub(crate) const NODE_CAPACITY_RETRY_AFTER_MS: u32 = 30_000;

/// A listener/admission refusal preserves the typed server retry interval to the wire.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("custody admission refused: {code}")]
pub struct CustodyAdmissionRefusal {
    pub code: CustodyRefusal,
    pub retry: Option<RetryHint>,
}
impl From<CustodyRefusal> for CustodyAdmissionRefusal {
    fn from(code: CustodyRefusal) -> Self {
        Self { code, retry: None }
    }
}
impl CustodyAdmissionRefusal {
    #[must_use]
    pub fn into_frame(self) -> CustodyServerFrame {
        CustodyServerFrame::Refused { code: self.code, capacity: None, retry: self.retry }
    }
}
pub(crate) fn node_retry() -> RetryHint {
    RetryHint::new(RetryScope::NodeCapacity, NODE_CAPACITY_RETRY_AFTER_MS)
}
pub(crate) fn source_retry() -> RetryHint {
    RetryHint::new(RetryScope::PreAuthSource, NODE_CAPACITY_RETRY_AFTER_MS)
}

pub(crate) fn refuse(
    budget: &str,
    count: usize,
    limit: usize,
    code: CustodyRefusal,
    retry: Option<RetryHint>,
) -> CustodyAdmissionRefusal {
    tracing::warn!(budget, count, limit, refusal = ?code, "custody admission refused");
    CustodyAdmissionRefusal { code, retry: retry.map(RetryHint::clamped) }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{cell::RefCell, sync::OnceLock};
    use tracing::{Event, Level, Metadata, Subscriber, field::Visit, span};
    std::thread_local! {
        static LINES: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    }
    struct Warnings;
    impl Subscriber for Warnings {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() == Level::WARN && metadata.target().starts_with("ramflux_node_core")
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            struct Fields(String);
            impl Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write;
                    let _ = write!(self.0, "{}={value:?} ", field.name());
                }
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            LINES.with(|lines| {
                if let Some(lines) = lines.borrow_mut().as_mut() {
                    lines.push(fields.0);
                }
            });
        }
    }
    /// Isolate tracing callsite initialization from unrelated parallel tests.
    pub(crate) fn run_isolated() -> Result<bool, Box<dyn std::error::Error>> {
        const MARKER: &str = "RAMFLUX_CUSTODY_WARNING_TEST";
        let thread = std::thread::current();
        let name = thread.name().ok_or("test thread name unavailable")?;
        if std::env::var(MARKER).as_deref() == Ok(name) {
            return Ok(false);
        }
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", name, "--nocapture"])
            .env(MARKER, name)
            .status()?;
        assert!(status.success(), "isolated warning assertions failed: {name}: {status}");
        Ok(true)
    }
    pub(crate) fn capture_warnings<T>(operation: impl FnOnce() -> T) -> (T, Vec<String>) {
        // Retain one dispatcher across parallel tests so callsite interest cannot become
        // stale as short-lived scoped subscribers are created and dropped on other threads.
        static DISPATCH: OnceLock<tracing::Dispatch> = OnceLock::new();
        let dispatch = DISPATCH.get_or_init(|| tracing::Dispatch::new(Warnings));
        LINES.with(|lines| *lines.borrow_mut() = Some(Vec::new()));
        let result = tracing::dispatcher::with_default(dispatch, operation);
        let lines = LINES.with(|lines| lines.borrow_mut().take().unwrap_or_default());
        (result, lines)
    }
    pub(crate) fn assert_warning<T>(
        budget: &str,
        count: usize,
        limit: usize,
        operation: impl FnOnce() -> T,
    ) -> T {
        let (result, lines) = capture_warnings(operation);
        assert_eq!(lines.len(), 1, "one warning per {budget} refusal: {lines:?}");
        for expected in
            [format!("budget={budget:?}"), format!("count={count} "), format!("limit={limit} ")]
        {
            assert!(lines[0].contains(&expected), "missing {expected}: {lines:?}");
        }
        for forbidden in
            ["192.0.2.1", "connection", "challenge_nonce", "proof_id", "account_anchor"]
        {
            assert!(!lines[0].contains(forbidden), "sensitive refusal field: {lines:?}");
        }
        result
    }
}
