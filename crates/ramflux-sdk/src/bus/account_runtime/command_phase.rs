// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Metadata-only timing of command preparation, mutation and completion.

pub(super) struct Phase {
    name: &'static str,
    method: String,
    started: tokio::time::Instant,
}

impl Phase {
    pub(super) fn start(name: &'static str, method: &str) -> Self {
        tracing::debug!(phase = name, event = "begin", method, "account command phase");
        Self { name, method: method.to_owned(), started: tokio::time::Instant::now() }
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        tracing::debug!(phase = self.name, event = "end", method = %self.method,
            elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "account command phase");
    }
}
