// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refusals describe only budget counters, never client identities or transport addresses.
use ramflux_protocol::custody::CustodyRefusal;

pub(crate) fn refuse(
    budget: &str,
    count: usize,
    limit: usize,
    code: CustodyRefusal,
) -> CustodyRefusal {
    tracing::warn!(budget, count, limit, refusal = ?code, "custody admission refused");
    code
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};
    use tracing::{Event, Level, Metadata, Subscriber, field::Visit, span};
    #[derive(Clone, Default)]
    struct Warnings(Arc<Mutex<Vec<String>>>);
    impl Subscriber for Warnings {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() == Level::WARN && metadata.target().starts_with("ramflux_node_core")
        }
        fn register_callsite(
            &self,
            _: &'static Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
            Some(tracing::metadata::LevelFilter::WARN)
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
            self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(fields.0);
        }
    }
    pub(crate) fn assert_warning<T>(
        budget: &str,
        count: usize,
        limit: usize,
        operation: impl FnOnce() -> T,
    ) -> T {
        let warnings = Warnings::default();
        let result = tracing::subscriber::with_default(warnings.clone(), operation);
        let lines = warnings.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
